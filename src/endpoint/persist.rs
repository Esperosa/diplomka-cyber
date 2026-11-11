//! Perzistence normalizovaných koncových událostí v `engine-state.sqlite` (krok 8).
//!
//! Příjem (CLI `endpoint ingest`, REST `POST /api/endpoint/ingest`) jen parsuje, omezuje
//! a ukládá; identita hosta se řeší až při běhu enginu proti aktuálnímu inventáři
//! (inventář se mezi příjmem a během mění). Tabulka je omezená počtem řádků a stářím,
//! deduplikace je v databázi (UNIQUE na otisk).

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use super::{
    EndpointEvent, Format, ParsedBatch,
    correlate::{Limits, Policy},
    parse_batch,
};
use crate::error::{BakulaError, Result};

/// Nejvíc řádků v tabulce; starší se mažou (krok 8, A2 bod 3).
pub const MAX_ROWS: i64 = 500_000;

fn db_error(error: rusqlite::Error) -> BakulaError {
    BakulaError::Processing(format!("endpoint_events SQLite chyba: {error}"))
}

pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS endpoint_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fp TEXT NOT NULL UNIQUE,
            ts INTEGER NOT NULL,
            received INTEGER NOT NULL,
            body TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS endpoint_events_ts ON endpoint_events (ts);",
    )
    .map_err(db_error)
}

/// Souhrn příjmu dávky (vrací se volajícímu, CLI i API).
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IngestSummary {
    pub parsed: usize,
    pub stored: usize,
    pub duplicates: usize,
    pub rejected_time: usize,
    pub skipped: usize,
    pub errors: usize,
    pub truncated: bool,
}

/// Zpracuje dávku textu (JSONL) a uloží platné nové události.
pub fn ingest_text(
    conn: &mut Connection,
    format: Format,
    text: &str,
    now: DateTime<Utc>,
    limits: &Limits,
) -> Result<IngestSummary> {
    migrate(conn)?;
    let ParsedBatch {
        events,
        skipped,
        errors,
        truncated,
    } = parse_batch(format, text, limits);
    let mut summary = IngestSummary {
        parsed: events.len(),
        skipped,
        errors,
        truncated,
        ..Default::default()
    };
    let now_s = now.timestamp();
    let tx = conn.transaction().map_err(db_error)?;
    {
        let mut stmt = tx
            .prepare(
                "INSERT OR IGNORE INTO endpoint_events (fp, ts, received, body)
                 VALUES (?1, ?2, ?3, ?4)",
            )
            .map_err(db_error)?;
        for event in &events {
            if event.ts > now_s + limits.max_future_s || event.ts < now_s - limits.max_age_s {
                summary.rejected_time += 1;
                continue;
            }
            let body = serde_json::to_string(event).map_err(BakulaError::Json)?;
            let changed = stmt
                .execute(params![
                    format!("{:016x}", event.fingerprint()),
                    event.ts,
                    now_s,
                    body
                ])
                .map_err(db_error)?;
            if changed == 0 {
                summary.duplicates += 1;
            } else {
                summary.stored += 1;
            }
        }
    }
    // strop počtu řádků a stáří
    tx.execute(
        "DELETE FROM endpoint_events WHERE ts < ?1",
        params![now_s - limits.max_age_s],
    )
    .map_err(db_error)?;
    tx.execute(
        "DELETE FROM endpoint_events WHERE id <= (SELECT MAX(id) FROM endpoint_events) - ?1",
        params![MAX_ROWS],
    )
    .map_err(db_error)?;
    tx.commit().map_err(db_error)?;
    Ok(summary)
}

/// Události z posledního okna pro běh enginu (nejvýš `MAX_ROWS`).
pub fn load_recent(
    conn: &Connection,
    now: DateTime<Utc>,
    policy: &Policy,
    limits: &Limits,
) -> Result<Vec<EndpointEvent>> {
    migrate(conn)?;
    let from = now.timestamp() - policy.lookback_s.max(limits.max_age_s);
    let mut stmt = conn
        .prepare("SELECT body FROM endpoint_events WHERE ts >= ?1 ORDER BY ts LIMIT ?2")
        .map_err(db_error)?;
    let rows = stmt
        .query_map(params![from, MAX_ROWS], |row| row.get::<_, String>(0))
        .map_err(db_error)?;
    let mut out = Vec::new();
    for row in rows {
        let body = row.map_err(db_error)?;
        // poškozený řádek se přeskočí (nikdy nesmí shodit běh)
        if let Ok(event) = serde_json::from_str::<EndpointEvent>(&body) {
            out.push(event);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str = r#"{"Event":{"System":{"EventID":1,"Computer":"WS5","TimeCreated":{"SystemTime":"2026-11-11T10:00:00Z"}},"EventData":{"Image":"C:\\Windows\\System32\\cmd.exe","ParentImage":"C:\\inetpub\\w3wp.exe","CommandLine":"cmd /c whoami"}}}"#;

    #[test]
    fn ingest_is_idempotent_and_bounded() {
        let mut conn = Connection::open_in_memory().unwrap();
        let now = DateTime::parse_from_rfc3339("2026-11-11T10:05:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let text = format!("{LINE}\n{LINE}\nnot json\n");
        let limits = Limits::default();
        let a = ingest_text(&mut conn, Format::Sysmon, &text, now, &limits).unwrap();
        assert_eq!((a.stored, a.duplicates, a.errors), (1, 1, 1), "{a:?}");
        let b = ingest_text(&mut conn, Format::Sysmon, &text, now, &limits).unwrap();
        assert_eq!(b.stored, 0);
        let loaded = load_recent(&conn, now, &Policy::default(), &limits).unwrap();
        assert_eq!(loaded.len(), 1);
        // událost z dávné minulosti se odmítne
        let later = now + chrono::Duration::days(3);
        let c = ingest_text(&mut conn, Format::Sysmon, LINE, later, &limits).unwrap();
        assert_eq!((c.stored, c.rejected_time), (0, 1));
    }
}
