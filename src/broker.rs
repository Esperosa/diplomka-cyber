//! H5 krok (produkcni-plan.md): dve veci, ktere `reclaim_stale`/`claim_one` drive
//! nemely.
//!
//! **Opakovane otevirani spojeni v ramci JEDNE logicke operace.** `claim_one`
//! drive otviralo az 4 samostatna TCP/Redis spojeni na jedno volani (vlastni
//! `ensure_group`, `reclaim_stale`'s vlastni `ensure_group` + vlastni spojeni pro
//! XAUTOCLAIM, pak jeste vlastni spojeni pro XREADGROUP) - zadne z nich se
//! nikdy nesdilelo. Produkcni CLI invokace jsou dnes vzdy jednorazove (jeden
//! `broker worker-run` = nejvyse 1 claim, pak proces skonci), takze "pool pres
//! cely zivot procesu" by nemel realny prinos - pridani r2d2 by bylo neuzivana
//! infrastruktura. Realna, merena neefektivita je uvnitr JEDNE operace: ted
//! `claim_one` otevira presne 1 spojeni (`open_connection` + `_on` varianty funkci,
//! ktere spojeni prijmou jako parametr misto aby si otviraly vlastni).
//!
//! **Zadny strop na opakovane doruceni (zadna DLQ).** Zprava, ktera se vzdy znovu
//! objevi v PEL (napr. job, ktery pri zpracovani spolehlive spadne pred ACK), by se
//! donekonecna reclaimovala pres XAUTOCLAIM - "poison message" by nikdy neopustila
//! fronto a brala by prioritu pred novou praci (`claim_one_prefers_reclaiming_...`).
//! `reclaim_stale` ted pocita pokusy per `stream_id` (Redis HASH), a po prekroceni
//! `RedisBrokerConfig::max_delivery_attempts` zpravu presune do dedikovaneho DLQ
//! streamu (`{stream_key}.dlq`, `dead_letter_messages`) namisto dalsiho doruceni.

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
    /// Po kolikatem REKLAIMU (ne prvnim doruceni) se zprava presune do DLQ.
    pub max_delivery_attempts: u64,
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
            max_delivery_attempts: 5,
        }
    }
}

fn open_connection(config: &RedisBrokerConfig) -> Result<redis::Connection> {
    let client = redis::Client::open(config.uri.as_str())
        .map_err(|error| BakulaError::Processing(format!("Redis client chyba: {error}")))?;
    client
        .get_connection()
        .map_err(|error| BakulaError::Processing(format!("Redis connection chyba: {error}")))
}

fn ensure_group_on(conn: &mut redis::Connection, config: &RedisBrokerConfig) -> Result<()> {
    let result: redis::RedisResult<String> = redis::cmd("XGROUP")
        .arg("CREATE")
        .arg(&config.stream_key)
        .arg(&config.group)
        .arg("0")
        .arg("MKSTREAM")
        .query(conn);
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.to_string().contains("BUSYGROUP") => Ok(()),
        Err(error) => Err(BakulaError::Processing(format!(
            "Nelze vytvorit Redis consumer group: {error}"
        ))),
    }
}

pub fn ensure_group(config: &RedisBrokerConfig) -> Result<()> {
    let mut conn = open_connection(config)?;
    ensure_group_on(&mut conn, config)
}

pub fn publish_job(config: &RedisBrokerConfig, job_id: i64) -> Result<String> {
    let mut conn = open_connection(config)?;
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
/// (XREADGROUP s `>` cte jen nove zpravy, nikdy PEL). Cele volani (vcetne reklaimu)
/// bezi na JEDNOM otevrenem spojeni.
pub fn claim_one(
    config: &RedisBrokerConfig,
    consumer: &str,
    block_ms: usize,
    min_idle_ms: usize,
) -> Result<Option<BrokerMessage>> {
    let mut conn = open_connection(config)?;
    ensure_group_on(&mut conn, config)?;

    let mut reclaimed = reclaim_stale_on(&mut conn, config, consumer, min_idle_ms, 1)?;
    if let Some(message) = reclaimed.pop() {
        return Ok(Some(message));
    }

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
    let mut conn = open_connection(config)?;
    ensure_group_on(&mut conn, config)?;
    reclaim_stale_on(&mut conn, config, consumer, min_idle_ms, count)
}

/// Stejna logika jako verejne `reclaim_stale`, ale na uz-otevrenem spojeni (volano z
/// `claim_one`, aby se nezduplikovalo spojeni). Kazdy reklaimovany zaznam se napocita
/// do `reclaim-counts` hash; po prekroceni `max_delivery_attempts` se presune do DLQ
/// namisto toho, aby se vratil jako dalsi doruceni volajicimu.
fn reclaim_stale_on(
    conn: &mut redis::Connection,
    config: &RedisBrokerConfig,
    consumer: &str,
    min_idle_ms: usize,
    count: usize,
) -> Result<Vec<BrokerMessage>> {
    let response: redis::Value = redis::cmd("XAUTOCLAIM")
        .arg(&config.stream_key)
        .arg(&config.group)
        .arg(consumer)
        .arg(min_idle_ms)
        .arg("0-0")
        .arg("COUNT")
        .arg(count)
        .query(conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XAUTOCLAIM chyba: {error}")))?;

    let claimed = parse_autoclaim_entries(response)?;
    let mut deliverable = Vec::with_capacity(claimed.len());
    for message in claimed {
        let attempts = bump_reclaim_count(conn, config, &message.stream_id)?;
        if attempts > config.max_delivery_attempts {
            move_to_dead_letter(conn, config, &message, attempts)?;
        } else {
            deliverable.push(message);
        }
    }
    Ok(deliverable)
}

fn reclaim_counts_key(config: &RedisBrokerConfig) -> String {
    format!("{}.reclaim-counts", config.stream_key)
}

fn dead_letter_key(config: &RedisBrokerConfig) -> String {
    format!("{}.dlq", config.stream_key)
}

fn bump_reclaim_count(
    conn: &mut redis::Connection,
    config: &RedisBrokerConfig,
    stream_id: &str,
) -> Result<u64> {
    redis::cmd("HINCRBY")
        .arg(reclaim_counts_key(config))
        .arg(stream_id)
        .arg(1)
        .query(conn)
        .map_err(|error| BakulaError::Processing(format!("Redis HINCRBY chyba: {error}")))
}

/// Presune zpravu, ktera prekrocila `max_delivery_attempts`, z hlavniho streamu do
/// DLQ: zapsat do DLQ streamu, ACK na puvodnim streamu (odstrani z PEL, jinak by se
/// XAUTOCLAIM pokusel prevzit ji znovu), a smazat jeji citac pokusu.
/// Audit nalez (Haiku, 30.10.2026): drive 3 oddelene round-tripy (XADD, XACK, HDEL) -
/// kdyby spojeni spadlo mezi XADD a XACK, zprava by skoncila v DLQ I SOUCASNE
/// zustala v PEL puvodniho streamu (dalsi reclaim by ji zkusil znovu, pripadne vytvoril
/// duplicitni DLQ zaznam). `redis::pipe().atomic()` (MULTI/EXEC) zajisti, ze vsechny
/// 3 prikazy se provedou jako jedna neprerusitelna jednotka.
fn move_to_dead_letter(
    conn: &mut redis::Connection,
    config: &RedisBrokerConfig,
    message: &BrokerMessage,
    attempts: u64,
) -> Result<()> {
    let _: () = redis::pipe()
        .atomic()
        .cmd("XADD")
        .arg(dead_letter_key(config))
        .arg("*")
        .arg("job_id")
        .arg(message.job_id)
        .arg("original_stream_id")
        .arg(&message.stream_id)
        .arg("delivery_attempts")
        .arg(attempts)
        .arg("moved_at")
        .arg(Utc::now().to_rfc3339())
        .ignore()
        .cmd("XACK")
        .arg(&config.stream_key)
        .arg(&config.group)
        .arg(&message.stream_id)
        .ignore()
        .cmd("HDEL")
        .arg(reclaim_counts_key(config))
        .arg(&message.stream_id)
        .ignore()
        .query(conn)
        .map_err(|error| BakulaError::Processing(format!("Redis presun do DLQ chyba: {error}")))?;

    Ok(())
}

/// Vycte vsechny zpravy presunute do DLQ (napr. pro operatorsky nastroj/alert, ktery
/// rozhodne, jestli se job ma rucne znovu zaradit nebo zahodit). Zadne automaticke
/// znovu-zarazeni - DLQ je vedomy koncovy stav, ne dalsi fronta k samo-obsluze.
pub fn dead_letter_messages(config: &RedisBrokerConfig) -> Result<Vec<BrokerMessage>> {
    let mut conn = open_connection(config)?;
    let response: redis::Value = redis::cmd("XRANGE")
        .arg(dead_letter_key(config))
        .arg("-")
        .arg("+")
        .query(&mut conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XRANGE (DLQ) chyba: {error}")))?;
    let Some(entries) = response.as_sequence() else {
        return Ok(Vec::new());
    };
    let mut messages = Vec::with_capacity(entries.len());
    for entry in entries {
        if let Some(message) = parse_entry(entry)? {
            messages.push(message);
        }
    }
    Ok(messages)
}

/// Audit nalez (Haiku, 30.10.2026): drive mazalo jen XACK, nikdy ne `reclaim-counts`
/// HASH zaznam pro `stream_id` - kazda zprava, ktera byla alespon jednou reklaimovana
/// a POTE uspesne potvrzena, by navzdy zustala jako "zapomenute" pole v HASH (neomezeny
/// rust v Redisu v case). Ted se oba zaznamy mazaji spolecne v jedne (atomicke) pipeline.
pub fn ack(config: &RedisBrokerConfig, stream_id: &str) -> Result<()> {
    let mut conn = open_connection(config)?;
    let _: () = redis::pipe()
        .atomic()
        .cmd("XACK")
        .arg(&config.stream_key)
        .arg(&config.group)
        .arg(stream_id)
        .ignore()
        .cmd("HDEL")
        .arg(reclaim_counts_key(config))
        .arg(stream_id)
        .ignore()
        .query(&mut conn)
        .map_err(|error| BakulaError::Processing(format!("Redis XACK/HDEL chyba: {error}")))?;
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
            max_delivery_attempts: 5,
        }
    }

    fn cleanup(config: &RedisBrokerConfig) {
        if let Ok(client) = redis::Client::open(config.uri.as_str())
            && let Ok(mut conn) = client.get_connection()
        {
            let _: redis::RedisResult<i64> = redis::cmd("DEL")
                .arg(&config.stream_key)
                .arg(dead_letter_key(config))
                .arg(reclaim_counts_key(config))
                .query(&mut conn);
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

    /// Regresni test na chybejici strop: bez DLQ by zprava, kterou konzument nikdy
    /// nepotvrdi, kolovala mezi `reclaim_stale` volani NAVZDY (poison message, viz
    /// modulova dokumentace). `max_delivery_attempts=2` znamena: prvni dorouceni
    /// (XREADGROUP) se nepocita, 1. a 2. reclaim jeste projdou, 3. reclaim musi
    /// zpravu presunout do DLQ a uz ji NESMI vratit volajicimu.
    #[test]
    fn messages_exceeding_max_delivery_attempts_move_to_dead_letter_queue() {
        let mut config = test_config();
        config.max_delivery_attempts = 2;
        publish_job(&config, 99).expect("publish");

        let first = claim_one(&config, "consumer-a", 100, 30_000)
            .expect("claim ok")
            .expect("prvni claim (puvodni doruceni) musi najit zpravu");
        assert_eq!(first.job_id, 99);
        // "consumer-a" nikdy nezavola ack() - simuluje opakovane padajiciho workera.

        let reclaim_1 = reclaim_stale(&config, "consumer-b", 0, 10).expect("reclaim 1 ok");
        assert_eq!(
            reclaim_1.len(),
            1,
            "1. reclaim (attempts=1) jeste musi byt pod limitem (2) a vratit zpravu"
        );
        assert_eq!(reclaim_1[0].job_id, 99);

        let reclaim_2 = reclaim_stale(&config, "consumer-b", 0, 10).expect("reclaim 2 ok");
        assert_eq!(
            reclaim_2.len(),
            1,
            "2. reclaim (attempts=2) je presne na limitu, jeste musi vratit zpravu"
        );

        let reclaim_3 = reclaim_stale(&config, "consumer-b", 0, 10).expect("reclaim 3 ok");
        assert!(
            reclaim_3.is_empty(),
            "3. reclaim (attempts=3 > limit 2) NESMI vratit zpravu volajicimu - musi jit do DLQ"
        );

        let dead_letters = dead_letter_messages(&config).expect("dead_letter_messages ok");
        assert_eq!(
            dead_letters.len(),
            1,
            "zprava, co prekrocila max_delivery_attempts, musi skoncit presne jednou v DLQ"
        );
        assert_eq!(dead_letters[0].job_id, 99);

        // Po presunu do DLQ uz neni v PEL puvodniho streamu - dalsi reclaim nenajde nic.
        let reclaim_after_dlq = reclaim_stale(&config, "consumer-b", 0, 10).expect("reclaim ok");
        assert!(
            reclaim_after_dlq.is_empty(),
            "po presunu do DLQ nesmi zustat zadny pending zaznam na puvodnim streamu"
        );

        cleanup(&config);
    }

    /// Regresni test na audit nalez (Haiku, 30.10.2026): `ack()` drive mazalo jen
    /// XACK, nikdy ne `reclaim-counts` HASH zaznam - zprava, ktera byla alespon 1x
    /// reklaimovana a POTE uspesne potvrzena, by navzdy zustala jako zapomenute pole
    /// v HASH (neomezeny rust v Redisu v case). Primo cte hash pres `redis` klienta
    /// (ne verejne API), aby overil skutecny stav v Redisu, ne jen chovani brokeru.
    #[test]
    fn ack_also_clears_the_reclaim_attempt_counter() {
        let config = test_config();
        publish_job(&config, 55).expect("publish");

        let first = claim_one(&config, "consumer-a", 100, 30_000)
            .expect("claim ok")
            .expect("prvni claim musi najit zpravu");
        assert_eq!(first.job_id, 55);

        // Reclaim jednou - vytvori zaznam v reclaim-counts HASH.
        let reclaimed = reclaim_stale(&config, "consumer-b", 0, 10).expect("reclaim ok");
        assert_eq!(reclaimed.len(), 1);

        let client = redis::Client::open(config.uri.as_str()).expect("redis client");
        let mut conn = client.get_connection().expect("redis connection");
        let count_before: Option<String> = redis::cmd("HGET")
            .arg(reclaim_counts_key(&config))
            .arg(&reclaimed[0].stream_id)
            .query(&mut conn)
            .expect("hget pred ack");
        assert_eq!(
            count_before,
            Some("1".to_string()),
            "po 1 reklaimu musi existovat citac s hodnotou 1"
        );

        ack(&config, &reclaimed[0].stream_id).expect("ack");

        let count_after: Option<String> = redis::cmd("HGET")
            .arg(reclaim_counts_key(&config))
            .arg(&reclaimed[0].stream_id)
            .query(&mut conn)
            .expect("hget po ack");
        assert_eq!(
            count_after, None,
            "po ack() nesmi v reclaim-counts HASH zustat zadny zaznam pro potvrzenou zpravu"
        );

        cleanup(&config);
    }
}
