//! H5 krok (produkcni-plan.md): dosavadni "konzument A/B" testy v `src/broker.rs`
//! simulovaly vice konzumentu jen jako ruzna JMENA v JEDNOM OS procesu/vlakne -
//! nikdy nedokazaly, ze crash recovery/no-double-claim drzi i mezi SKUTECNE
//! oddelenymi OS procesy (zadne sdilene paměťové stavy, zadna shoda v planovani
//! vlaken jednoho procesu). Tenhle test spousti dve REALNE binarky (`bakula-program
//! broker worker-run`) soucasne a necha je soutezit o stejnou, uz publikovanou
//! zpravu - Redis je jediny bod synchronizace, presne jak by to fungovalo v realnem
//! nasazeni na 2 ruznych workerech.

use std::env;
use std::process::{Command, Stdio};

use bakula_program::broker::{self, RedisBrokerConfig};
use serde_json::Value;
use uuid::Uuid;

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_bakula-program")
}

fn test_config() -> RedisBrokerConfig {
    let uri =
        env::var("BAKULA_TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    RedisBrokerConfig {
        uri,
        stream_key: format!("bakula.twoproc.{}", Uuid::new_v4()),
        group: "bakula-twoproc-workers".to_string(),
        max_delivery_attempts: 5,
    }
}

fn cleanup(config: &RedisBrokerConfig) {
    if let Ok(client) = redis::Client::open(config.uri.as_str())
        && let Ok(mut conn) = client.get_connection()
    {
        // Audit nalez (30.10.2026): drive mazalo jen hlavni stream, ne DLQ/
        // reclaim-counts klice, co `src/broker.rs` take pouziva - zustavaly by jako
        // neuklizene zbytky po kazdem behu testu (byt kvuli uuid stream_key bez
        // dopadu na dalsi testy, jen zbytecny rust v testovacim Redisu).
        let _: redis::RedisResult<i64> = redis::cmd("DEL")
            .arg(&config.stream_key)
            .arg(format!("{}.dlq", config.stream_key))
            .arg(format!("{}.reclaim-counts", config.stream_key))
            .query(&mut conn);
    }
}

/// Spusti `broker worker-run` jako samostatny OS proces (ne vlakno) a vrati, jaky
/// (pokud vubec nejaky) `job_id` prevzal. `--db` je povinny argument CLI parseru,
/// ale tenhle handler ho nikdy nečte (jen `broker_uri`/`stream_key`/`node_id` jdou do
/// `broker::claim_one`) - staci libovolna neexistujici cesta.
fn spawn_worker_process(config: &RedisBrokerConfig, node_id: &str) -> std::process::Child {
    Command::new(bin_path())
        .args([
            "broker",
            "worker-run",
            "--db",
            "unused-by-worker-run.sqlite",
            "--broker-uri",
            &config.uri,
            "--stream-key",
            &config.stream_key,
            "--node-id",
            node_id,
            "--lease-s",
            "120",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spusteni broker worker-run procesu")
}

fn claimed_job_id_from_output(output: &std::process::Output) -> Option<i64> {
    assert!(
        output.status.success(),
        "broker worker-run selhal: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let parsed: Value =
        serde_json::from_slice(&output.stdout).expect("stdout musi byt platny JSON");
    parsed.get("job_id").and_then(Value::as_i64)
}

/// 2 REALNE OS procesy soutezi o jednu, uz publikovanou zpravu - presne 1 z nich ji
/// musi prevzit, druhy musi dostat `null`. Opakovano vicekrat s cerstvym jobem v
/// kazdem kole, aby nahodna vyhra "prvniho" procesu v jednom kole nezakryla
/// pripadny double-claim v jinem.
#[test]
fn two_separate_os_processes_never_double_claim_the_same_message() {
    let config = test_config();
    let rounds = 20;
    let mut claimed_job_ids: Vec<i64> = Vec::new();

    for round in 0..rounds {
        let job_id = 10_000 + round;
        broker::publish_job(&config, job_id).expect("publish_job (primo pres knihovnu)");

        let worker_a = spawn_worker_process(&config, "proc-a");
        let worker_b = spawn_worker_process(&config, "proc-b");

        let output_a = worker_a.wait_with_output().expect("cekani na proc-a");
        let output_b = worker_b.wait_with_output().expect("cekani na proc-b");

        let claimed_a = claimed_job_id_from_output(&output_a);
        let claimed_b = claimed_job_id_from_output(&output_b);

        let claims: Vec<i64> = [claimed_a, claimed_b].into_iter().flatten().collect();
        assert_eq!(
            claims.len(),
            1,
            "kolo {round}: presne 1 ze 2 REALNYCH OS procesu musi prevzit zpravu job_id={job_id}, ne {} (a={claimed_a:?}, b={claimed_b:?})",
            claims.len()
        );
        assert_eq!(
            claims[0], job_id,
            "kolo {round}: prevzaty job_id musi odpovidat prave publikovane zprave"
        );
        claimed_job_ids.push(claims[0]);
    }

    let mut expected: Vec<i64> = (0..rounds).map(|round| 10_000 + round).collect();
    let mut actual = claimed_job_ids.clone();
    expected.sort_unstable();
    actual.sort_unstable();
    assert_eq!(
        actual, expected,
        "po {rounds} kolech musi byt kazdy publikovany job_id prevzaty presne jednou - zadny chybejici, zadny zdvojeny"
    );

    cleanup(&config);
}
