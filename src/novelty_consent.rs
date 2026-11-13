//! Úzký expirující souhlas člověka s novou vazbou ven (krok 7, B5).
//!
//! Souhlas platí jen pro přesnou dvojici (vnitřní host, vnější cíl, protokol, port),
//! nejvýš `MAX_DAYS` dní, a jen potlačí nový poplach novosti téže dvojice. Profil se
//! dvojici „z trvání“ nenaučí: souhlasená dvojice zůstává pro učení profilu zmrazená
//! (poznamenaná), takže po vypršení souhlasu se poplach znovu objeví, pokud vazba
//! trvá. Souhlasy jsou v append-only tabulce (server vkládá, pipeline čte).

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use crate::error::{SalticusError, Result};

pub const MAX_DAYS: i64 = 30;

fn db_error(error: rusqlite::Error) -> SalticusError {
    SalticusError::Processing(format!("novelty_consent SQLite chyba: {error}"))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Consent {
    pub host: String,
    pub peer: String,
    pub proto: String,
    pub port: u16,
    pub expires: DateTime<Utc>,
    pub actor: String,
}

impl Consent {
    /// Klíč dvojice ve tvaru nálezu novosti (`host|peer|proto/port`).
    pub fn pair_key(&self) -> String {
        format!("{}|{}|{}/{}", self.host, self.peer, self.proto, self.port)
    }
}

pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS novelty_consents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at INTEGER NOT NULL,
            host TEXT NOT NULL,
            peer TEXT NOT NULL,
            proto TEXT NOT NULL,
            port INTEGER NOT NULL,
            expires INTEGER NOT NULL,
            actor TEXT NOT NULL,
            note TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS novelty_consents_no_update BEFORE UPDATE ON novelty_consents
        BEGIN SELECT RAISE(ABORT, 'novelty_consents je append-only'); END;",
    )
    .map_err(db_error)
}

/// API: zapíše souhlas (nejvýš `MAX_DAYS` dní, jen platné IP adresy).
#[allow(clippy::too_many_arguments)]
pub fn grant(
    conn: &Connection,
    host: &str,
    peer: &str,
    proto: &str,
    port: u16,
    days: i64,
    actor: &str,
    note: &str,
    at: DateTime<Utc>,
) -> Result<DateTime<Utc>> {
    if host.parse::<std::net::IpAddr>().is_err() || peer.parse::<std::net::IpAddr>().is_err() {
        return Err(SalticusError::Processing(
            "souhlas jen pro presne IP adresy".into(),
        ));
    }
    if !matches!(proto, "tcp" | "udp") || port == 0 {
        return Err(SalticusError::Processing(
            "souhlas jen pro tcp nebo udp a konkretni port".into(),
        ));
    }
    migrate(conn)?;
    let expires = at + chrono::Duration::days(days.clamp(1, MAX_DAYS));
    conn.execute(
        "INSERT INTO novelty_consents (at, host, peer, proto, port, expires, actor, note)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            at.timestamp(),
            host,
            peer,
            proto,
            port as i64,
            expires.timestamp(),
            actor,
            note.chars().take(500).collect::<String>()
        ],
    )
    .map_err(db_error)?;
    Ok(expires)
}

/// Platné souhlasy v čase `now`.
pub fn active(conn: &Connection, now: DateTime<Utc>) -> Result<Vec<Consent>> {
    migrate(conn)?;
    let mut stmt = conn
        .prepare(
            "SELECT host, peer, proto, port, expires, actor FROM novelty_consents
             WHERE expires > ?1 ORDER BY id",
        )
        .map_err(db_error)?;
    let rows = stmt
        .query_map(params![now.timestamp()], |row| {
            Ok(Consent {
                host: row.get(0)?,
                peer: row.get(1)?,
                proto: row.get(2)?,
                port: row.get::<_, i64>(3)?.clamp(0, u16::MAX as i64) as u16,
                expires: DateTime::<Utc>::from_timestamp(row.get(4)?, 0).unwrap_or_default(),
                actor: row.get(5)?,
            })
        })
        .map_err(db_error)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db_error)
}

/// Klíč dvojice nálezu novosti (`novel_*`, služba `out/<cíl>/<proto>/<port>`).
pub fn finding_pair(finding: &crate::model::Finding) -> Option<String> {
    if !crate::behavior::novelty::is_novelty_type(&finding.finding_type) {
        return None;
    }
    let host = finding.host_key.as_deref()?;
    let service = finding.service_key.as_deref()?;
    let rest = service.strip_prefix(&format!("{host}/out/"))?;
    let mut parts = rest.rsplitn(3, '/');
    let port = parts.next()?;
    let proto = parts.next()?;
    let peer = parts.next()?;
    Some(format!("{host}|{peer}|{proto}/{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(days: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_767_571_200 + days * 86_400, 0).unwrap()
    }

    #[test]
    fn consent_is_narrow_capped_and_expires() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(grant(&conn, "10.0.0.5", "*", "tcp", 443, 5, "a", "", at(0)).is_err());
        assert!(
            grant(
                &conn,
                "10.0.0.5",
                "198.51.100.7",
                "tcp",
                0,
                5,
                "a",
                "",
                at(0)
            )
            .is_err()
        );
        let expires = grant(
            &conn,
            "10.0.0.5",
            "198.51.100.7",
            "tcp",
            443,
            365,
            "a",
            "",
            at(0),
        )
        .unwrap();
        assert_eq!(expires, at(MAX_DAYS));
        assert_eq!(active(&conn, at(1)).unwrap().len(), 1);
        assert!(active(&conn, at(MAX_DAYS + 1)).unwrap().is_empty());
        let finding = crate::behavior::finding(
            "novel_persistent_peer",
            "10.0.0.5",
            "out/198.51.100.7/tcp/443",
            crate::model::Severity::Medium,
            crate::model::Confidence::Low,
            String::new(),
            String::new(),
            Vec::new(),
            "",
        );
        assert_eq!(
            finding_pair(&finding).as_deref(),
            Some(active(&conn, at(1)).unwrap()[0].pair_key().as_str())
        );
    }
}
