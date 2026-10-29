use chrono::Utc;
use serde::Serialize;

use crate::{
    error::{BakulaError, Result},
    platform,
};

#[derive(Debug, Clone)]
pub struct RedisBrokerConfig {
    pub uri: String,
    pub stream_key: String,
    pub group: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrokerMessage {
    pub stream_id: String,
    pub job_id: i64,
}

impl RedisBrokerConfig {
    pub fn for_uri(uri: &str) -> Self {
        Self {
            uri: uri.to_string(),
            stream_key: "bakula.jobs".to_string(),
            group: "bakula-workers".to_string(),
        }
    }
}

pub fn ensure_group(config: &RedisBrokerConfig) -> Result<()> {
    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    let mut conn = client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))?;
    let result: redis::RedisResult<String> = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(&config.stream_key)
        .arg(&config.group)
        .arg("0")
        .arg("MKSTREAM")
        .query(&mut conn);
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.to_string().contains("BUSYGROUP") => Ok(()),
        Err(error) => Err(BakulaError::Processing(format!(
            "Nelze vytvorit Redis consumer group: {error}"
        ))),
    }
}

pub fn publish_job(config: &RedisBrokerConfig, job_id: i64) -> Result<String> {
    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    let mut conn = client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))?;
    let message_id: String = redis::cmd("XADD")
        .arg(&config.stream_key)
        .arg("*")
        .arg("job_id")
        .arg(job_id)
        .arg("queued_at")
        .arg(Utc::now().to_rfc3339())
        .query(&mut conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XADD chyba: {error}")))?;
    Ok(message_id)
}

pub fn publish_due_jobs(config: &RedisBrokerConfig, db: &std::path::Path) -> Result<Vec<i64>> {
    ensure_group(config)?;
    let due = platform::list_due_job_ids(db)?;
    let mut published = Vec::new();
    for job_id in due {
        let _ = publish_job(config, job_id)?;
        published.push(job_id);
    }
    Ok(published)
}

/// Pred cekanim na NOVE zpravy nejdriv zkusi prevzit zaznam z pending entries listu
/// (PEL), ktery je needotknuty dele nez `min_idle_ms` - konzument, ktery predtim
/// zavolal XREADGROUP a spadl pred XACK, by jinak svou zpravu zablokoval navzdy
/// (XREADGROUP s `>` cte jen nove zpravy, nikdy PEL).
pub fn claim_one(
    config: &RedisBrokerConfig,
    consumer: &str,
    block_ms: usize,
    min_idle_ms: usize,
) -> Result<Option<BrokerMessage>> {
    ensure_group(config)?;

    let mut reclaimed = reclaim_stale(config, consumer, min_idle_ms, 1)?;
    if let Some(message) = reclaimed.pop() {
        return Ok(Some(message));
    }

    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    let mut conn = client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))?;
    let response: redis::Value = redis::cmd("XREADGROUP")
        .arg("GROUP")
        .arg(&config.group)
        .arg(consumer)
        .arg("COUNT")
        .arg(1)
        .arg("BLOCK")
        .arg(block_ms)
        .arg("STREAMS")
        .arg(&config.stream_key)
        .arg(">")
        .query(&mut conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XREADGROUP chyba: {error}")))?;

    parse_claimed_message(response)
}

/// Prevezme az `count` pending zaznamu (XAUTOCLAIM), ktere jsou needotknute dele nez
/// `min_idle_ms` - crash recovery pro konzumenty, kteri spadli mezi XREADGROUP a XACK.
/// Idempotence navazujicich kroku: `platform::claim_job_by_id`/`claim_due_job` uz maji
/// vlastni gating podle stavu jobu v DB (`status IN (...)`), takze i kdyby stejna zprava
/// byla kratce prevzata dvakrat (napr. race pri souberne reclaim), druhe zpracovani
/// najde job uz jako 'running'/'done' a je bezpecne no-op - zadny dalsi dedup v brokeru
/// neni potreba, dokud tohle drzi.
pub fn reclaim_stale(
    config: &RedisBrokerConfig,
    consumer: &str,
    min_idle_ms: usize,
    count: usize,
) -> Result<Vec<BrokerMessage>> {
    ensure_group(config)?;
    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    let mut conn = client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))?;
    let response: redis::Value = redis::cmd("XAUTOCLAIM")
        .arg(&config.stream_key)
        .arg(&config.group)
        .arg(consumer)
        .arg(min_idle_ms)
        .arg("0-0")
        .arg("COUNT")
        .arg(count)
        .query(&mut conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XAUTOCLAIM chyba: {error}")))?;

    parse_autoclaim_entries(response)
}

pub fn ack(config: &RedisBrokerConfig, stream_id: &str) -> Result<()> {
    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    let mut conn = client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))?;
    let _: i64 = redis::cmd("XACK")
        .arg(&config.stream_key)
        .arg(&config.group)
        .arg(stream_id)
        .query(&mut conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XACK chyba: {error}")))?;
    Ok(())
}

/// Sdilena logika pro XREADGROUP i XAUTOCLAIM - oba vraceji zaznamy ve tvaru
/// `[stream_id, [field, value, field, value, ...]]`, jen jsou jinak zabalene navenek
/// (XREADGROUP do seznamu streamu, XAUTOCLAIM primo do seznamu zaznamu).
fn parse_entry(entry: &redis::Value) -> Result<Option<BrokerMessage>> {
    let Some(entry) = entry.as_sequence() else {
        return Ok(None);
    };
    let Some(stream_id) = entry.first().and_then(redis_value_as_string) else {
        return Ok(None);
    };
    let stream_id = stream_id.to_string();
    let fields = entry
        .get(1)
        .and_then(|item| item.as_sequence())
        .ok_or_else(|| BakulaError::Processing("Redis zaznam nema fields.".to_string()))?;
    let mut job_id = None;
    let mut index = 0;
    while index + 1 < fields.len() {
        let key = redis_value_as_string(&fields[index]).unwrap_or_default();
        let value = redis_value_as_string(&fields[index + 1]).unwrap_or_default();
        if key == "job_id" {
            job_id = Some(value.parse::<i64>().map_err(|error| {
                BakulaError::Processing(format!("Neplatne job_id z Redis zaznamu: {error}"))
            })?);
        }
        index += 2;
    }
    Ok(job_id.map(|job_id| BrokerMessage { stream_id, job_id }))
}

fn parse_claimed_message(value: redis::Value) -> Result<Option<BrokerMessage>> {
    let Some(streams) = value.as_sequence() else {
        return Ok(None);
    };
    let Some(first_stream) = streams.first().and_then(|item| item.as_sequence()) else {
        return Ok(None);
    };
    let Some(entries) = first_stream.get(1).and_then(|item| item.as_sequence()) else {
        return Ok(None);
    };
    let Some(entry) = entries.first() else {
        return Ok(None);
    };
    parse_entry(entry)
}

/// XAUTOCLAIM vraci `[next_cursor, claimed_entries, deleted_message_ids]` - zajima nas
/// jen prostredni prvek.
fn parse_autoclaim_entries(value: redis::Value) -> Result<Vec<BrokerMessage>> {
    let Some(parts) = value.as_sequence() else {
        return Ok(Vec::new());
    };
    let Some(entries) = parts.get(1).and_then(|item| item.as_sequence()) else {
        return Ok(Vec::new());
    };
    let mut messages = Vec::new();
    for entry in entries {
        if let Some(message) = parse_entry(entry)? {
            messages.push(message);
        }
    }
    Ok(messages)
}

fn redis_value_as_string(value: &redis::Value) -> Option<&str> {
    match value {
        redis::Value::BulkString(bytes) => std::str::from_utf8(bytes).ok(),
        redis::Value::SimpleString(value) => Some(value.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `redis://127.0.0.1:6379` odpovida Redis service kontejneru v CI (`.github/
    /// workflows/ci.yml`); lokalne lze prepsat `BAKULA_TEST_REDIS_URL`, napr. kdyz
    /// bezi docasny kontejner na jinem portu.
    fn test_config() -> RedisBrokerConfig {
        let uri = std::env::var("BAKULA_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        // Kazdy test potrebuje vlastni stream/group, aby se navzajem neovlivnovaly
        // (testy mohou bezet paralelne v ramci jednoho `cargo test`).
        RedisBrokerConfig {
            uri,
            stream_key: format!("bakula.test.{}", uuid::Uuid::new_v4()),
            group: "bakula-test-workers".to_string(),
        }
    }

    fn cleanup(config: &RedisBrokerConfig) {
        if let Ok(client) = redis::Client::open(config.uri.as_str())
            && let Ok(mut conn) = client.get_connection()
        {
            let _: redis::RedisResult<i64> =
                redis::cmd("DEL").arg(&config.stream_key).query(&mut conn);
        }
    }

    #[test]
    fn ack_removes_message_from_pending_entries() {
        let config = test_config();
        publish_job(&config, 1).expect("publish");

        let message = claim_one(&config, "consumer-a", 100, 30_000)
            .expect("claim ok")
            .expect("musi najit zpravu");
        assert_eq!(message.job_id, 1);

        ack(&config, &message.stream_id).expect("ack");

        // Po ACK nesmi byt zprava v PEL - reclaim s min_idle=0 nesmi nic najit.
        let reclaimed = reclaim_stale(&config, "consumer-b", 0, 10).expect("reclaim ok");
        assert!(
            reclaimed.is_empty(),
            "po ACK nesmi zustat zadny pending zaznam k prevzeti"
        );

        cleanup(&config);
    }

    /// Regresni test na bezpecnostni bug: konzument zavola XREADGROUP (`claim_one`)
    /// a spadne pred ACK - bez XAUTOCLAIM by zprava zustala v PEL navzdy nedostupna
    /// zadnemu dalsimu workeru. `reclaim_stale`/`claim_one` to musi opravit.
    #[test]
    fn crashed_consumer_message_is_recovered_by_another_consumer() {
        let config = test_config();
        publish_job(&config, 42).expect("publish");

        // "consumer-a" precte zpravu a spadne - nikdy nezavola ack().
        let first = claim_one(&config, "consumer-a", 100, 30_000)
            .expect("claim ok")
            .expect("prvni claim musi najit zpravu");
        assert_eq!(first.job_id, 42);

        // Okamzite po precteni (idle ~0ms) jeste nesmi byt dost "stara" na reclaim
        // s rozumnym prahem - jinak by se zpravy zacaly krast konzumentum, kteri
        // je prave aktivne zpracovavaji.
        let too_soon = reclaim_stale(&config, "consumer-b", 60_000, 10).expect("reclaim ok");
        assert!(
            too_soon.is_empty(),
            "cerstvy pending zaznam se nesmi prevzit pred uplynutim min_idle"
        );

        std::thread::sleep(std::time::Duration::from_millis(50));

        // Po uplynuti (kratkeho, testovaciho) prahu uz je zaznam "stary" a dalsi
        // konzument ho musi prevzit.
        let recovered = reclaim_stale(&config, "consumer-b", 10, 10).expect("reclaim ok");
        assert_eq!(
            recovered.len(),
            1,
            "stary pending zaznam musi prevzit dalsi konzument"
        );
        assert_eq!(recovered[0].job_id, 42);
        assert_eq!(recovered[0].stream_id, first.stream_id);

        ack(&config, &recovered[0].stream_id).expect("ack po reclaimu");
        cleanup(&config);
    }

    #[test]
    fn claim_one_prefers_reclaiming_stale_pending_over_blocking_for_new_messages() {
        let config = test_config();
        publish_job(&config, 7).expect("publish prvni job");

        let first = claim_one(&config, "consumer-a", 100, 30_000)
            .expect("claim ok")
            .expect("prvni claim musi najit prvni job");
        assert_eq!(first.job_id, 7);

        // Druhy job pribude do streamu AZ POTE, co prvni zustal nepotvrzeny v PEL.
        publish_job(&config, 8).expect("publish druhy job");
        std::thread::sleep(std::time::Duration::from_millis(30));

        // claim_one s velmi kratkym min_idle musi preferovat stary pending zaznam
        // (job 7) pred novou zpravou (job 8), aby se zaseknute zpravy neobchazely
        // navzdy jen proto, ze fronta ma i jine, nove prace.
        let next = claim_one(&config, "consumer-b", 100, 10)
            .expect("claim ok")
            .expect("musi najit neco");
        assert_eq!(
            next.job_id, 7,
            "stary nepotvrzeny zaznam ma prioritu pred novou zpravou ve streamu"
        );

        ack(&config, &next.stream_id).expect("ack reclaimed");
        cleanup(&config);
    }
}
