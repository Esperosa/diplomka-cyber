//! Doplnkove "nohy" soak behu, ktere bezi vedle simulovanych siti po celou dobu:
//! - anchor: realna data (CTU-13/IoT-23) dokola, pruchody musi byt bitove shodne,
//! - ops_stress: souborove `ops.sqlite` pod soubeznou zatezi (skutecny disk, skutecne
//!   hodiny), latence operaci, rust audit logu, periodicka kontrola hash-retezce,
//! - broker: H5 - propustnost Redis Streams brokeru podle poctu konzumentu, vcetne
//!   "padajicich" konzumentu (zprava bez ACK se musi znovu dorucit, nic se neztrati).
//! Vsechny tri maji vlastni stav v checkpointu (pri navazani pokracuji).

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::{
    broker::{self, RedisBrokerConfig},
    enforcement::{BlockIpRequest, ProtectedRanges},
    eval::anchor::{AnchorRow, anchor_digest, anchor_pass_with},
    ops::{EnforcementMode, OpsStore, ProposeError},
    soak::{hist::LogHistogram, kernel::SimKernel, rng::Rng},
};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AnchorRowState {
    pub label: String,
    pub flows: usize,
    pub malicious: usize,
    pub f1: f64,
    pub trivial_f1: f64,
    pub source_lift: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnchorState {
    pub passes: u64,
    pub first_digest: u64,
    pub nondeterministic_passes: u64,
    pub last_pass_secs: f64,
    pub scenarios: usize,
    pub rows: Vec<AnchorRowState>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpsStressState {
    pub threads: usize,
    pub iterations: u64,
    pub proposed: u64,
    pub applied: u64,
    pub duplicates: u64,
    pub rejected_guard: u64,
    pub sweeps: u64,
    pub errors: u64,
    pub latency: BTreeMap<String, LogHistogram>,
    pub chain_checks: u64,
    pub chain_failures: u64,
    pub chain_verify_secs_last: f64,
    pub audit_rows: u64,
    pub db_mb: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BrokerRound {
    pub consumers: usize,
    pub jobs: u64,
    pub secs: f64,
    pub processed: u64,
    pub duplicates: u64,
    pub lost: u64,
    pub crashed_before_ack: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BrokerState {
    pub available: bool,
    pub rounds_total: u64,
    pub recent: Vec<BrokerRound>,
    pub lost_total: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LegsState {
    pub anchor: AnchorState,
    pub ops_stress: OpsStressState,
    pub broker: BrokerState,
}

pub type SharedLegs = Arc<Mutex<LegsState>>;

fn sleep_until_or_stop(stop: &AtomicBool, seconds: f64) {
    let deadline = Instant::now() + Duration::from_secs_f64(seconds);
    while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(250));
    }
}

// --- anchor ---------------------------------------------------------------------

pub fn anchor_leg(
    repo_root: PathBuf,
    include_ctu13: bool,
    interval_s: f64,
    stop: &AtomicBool,
    legs: &SharedLegs,
) {
    while !stop.load(Ordering::SeqCst) {
        let started = Instant::now();
        let outcome = anchor_pass_with(&repo_root, include_ctu13);
        let mut guard = legs.lock().unwrap();
        match outcome {
            Ok(rows) => {
                let digest = anchor_digest(&rows);
                let state = &mut guard.anchor;
                if state.passes == 0 && state.first_digest == 0 {
                    state.first_digest = digest;
                } else if state.first_digest != digest && !rows.is_empty() {
                    state.nondeterministic_passes += 1;
                }
                state.passes += 1;
                state.scenarios = rows.len();
                state.last_pass_secs = started.elapsed().as_secs_f64();
                state.error = if rows.is_empty() {
                    Some("zadna realna data nenalezena v labs/datasets".to_string())
                } else {
                    None
                };
                state.rows = rows
                    .iter()
                    .map(|r: &AnchorRow| AnchorRowState {
                        label: r.label.clone(),
                        flows: r.flows,
                        malicious: r.malicious,
                        f1: r.f1,
                        trivial_f1: r.trivial_f1,
                        source_lift: r.source_lift,
                    })
                    .collect();
            }
            Err(error) => guard.anchor.error = Some(error.to_string()),
        }
        drop(guard);
        sleep_until_or_stop(stop, interval_s);
    }
}

// --- ops stress ------------------------------------------------------------------

pub fn ops_stress_leg(
    out: &Path,
    threads: usize,
    iterations_per_second: f64,
    stop: &AtomicBool,
    legs: &SharedLegs,
) {
    let path = out.join("ops-stress.sqlite");
    let store = match OpsStore::open(&path) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            legs.lock().unwrap().ops_stress.errors += 1;
            eprintln!("soak: ops_stress nelze otevrit DB: {error}");
            return;
        }
    };
    legs.lock().unwrap().ops_stress.threads = threads;
    let clock = Arc::new(AtomicI64::new(Utc::now().timestamp()));
    let kernel = Arc::new(SimKernel::new(clock.clone(), 0.005, 0x0951));
    let protected = ProtectedRanges::with_additional(vec!["10.0.0.0/8".parse().unwrap()]);

    std::thread::scope(|scope| {
        for worker in 0..threads {
            let (store, kernel, clock, protected, path) =
                (&store, &kernel, &clock, &protected, &path);
            scope.spawn(move || {
                let mut rng = Rng::new(0x5EED_0000 + worker as u64);
                let mut local: BTreeMap<String, LogHistogram> = BTreeMap::new();
                let (
                    mut iterations,
                    mut proposed,
                    mut applied,
                    mut duplicates,
                    mut rejected,
                    mut sweeps,
                    mut errors,
                ) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
                let mut last_flush = Instant::now();
                let mut last_chain = Instant::now();
                let delay =
                    Duration::from_secs_f64(threads as f64 / iterations_per_second.max(0.1));
                // aspon jedna iterace, i kdyz se stop prijde behem pomaleho startu
                let mut first_pass = true;
                while first_pass || !stop.load(Ordering::SeqCst) {
                    first_pass = false;
                    let tick = Instant::now();
                    clock.store(Utc::now().timestamp(), Ordering::SeqCst);
                    let ip = format!(
                        "{}.{}.{}.{}",
                        rng.pick(&[45u64, 61, 77, 91, 103, 154, 178, 193]),
                        rng.range(0, 255),
                        rng.range(0, 255),
                        rng.range(1, 254)
                    );
                    let request = BlockIpRequest {
                        ip,
                        ttl_seconds: rng.range(60, 3600),
                        reason: "ops-stress".to_string(),
                        finding_id: None,
                    };
                    let started = Instant::now();
                    match store.propose(&request, protected, "stress") {
                        Ok(Ok(action)) => {
                            local
                                .entry("propose".into())
                                .or_default()
                                .record(started.elapsed().as_secs_f64());
                            proposed += 1;
                            let decide_start = Instant::now();
                            let approve = rng.chance(0.8);
                            match store.decide(action.id, approve, "stress-op") {
                                Ok(_) => {
                                    local
                                        .entry("decide".into())
                                        .or_default()
                                        .record(decide_start.elapsed().as_secs_f64());
                                    if approve {
                                        let apply_start = Instant::now();
                                        match store.apply_approved(
                                            action.id,
                                            EnforcementMode::Enforce,
                                            protected,
                                            kernel.as_ref(),
                                            "stress-op",
                                        ) {
                                            Ok(done) => {
                                                local
                                                    .entry("apply".into())
                                                    .or_default()
                                                    .record(apply_start.elapsed().as_secs_f64());
                                                applied += (done.status == "applied") as u64;
                                            }
                                            Err(_) => errors += 1,
                                        }
                                    }
                                }
                                Err(_) => errors += 1,
                            }
                        }
                        Ok(Err(ProposeError::AlreadyActive)) => duplicates += 1,
                        Ok(Err(ProposeError::Rejected(_))) => rejected += 1,
                        Err(_) => errors += 1,
                    }
                    if iterations % 10 == 0 {
                        let start = Instant::now();
                        if store.audit_list(50).is_ok() {
                            local
                                .entry("audit_list".into())
                                .or_default()
                                .record(start.elapsed().as_secs_f64());
                        } else {
                            errors += 1;
                        }
                    }
                    if iterations % 20 == 0 {
                        let start = Instant::now();
                        match store.sweep(EnforcementMode::Enforce, kernel.as_ref(), Utc::now()) {
                            Ok(_) => {
                                local
                                    .entry("sweep".into())
                                    .or_default()
                                    .record(start.elapsed().as_secs_f64());
                                sweeps += 1;
                            }
                            Err(_) => errors += 1,
                        }
                    }
                    iterations += 1;

                    if worker == 0 && last_chain.elapsed() > Duration::from_secs(6 * 3600) {
                        last_chain = Instant::now();
                        let start = Instant::now();
                        let ok = store.verify_audit_chain().unwrap_or(false);
                        let secs = start.elapsed().as_secs_f64();
                        let mut guard = legs.lock().unwrap();
                        guard.ops_stress.chain_checks += 1;
                        guard.ops_stress.chain_failures += (!ok) as u64;
                        guard.ops_stress.chain_verify_secs_last = secs;
                    }
                    if last_flush.elapsed() > Duration::from_secs(5) {
                        last_flush = Instant::now();
                        let mut guard = legs.lock().unwrap();
                        let s = &mut guard.ops_stress;
                        s.iterations += iterations;
                        s.proposed += proposed;
                        s.applied += applied;
                        s.duplicates += duplicates;
                        s.rejected_guard += rejected;
                        s.sweeps += sweeps;
                        s.errors += errors;
                        for (name, hist) in std::mem::take(&mut local) {
                            s.latency.entry(name).or_default().merge(&hist);
                        }
                        if let Ok(meta) = std::fs::metadata(path) {
                            s.db_mb = meta.len() as f64 / 1_048_576.0;
                        }
                        if let Ok(rows) = store.audit_list(1) {
                            s.audit_rows =
                                rows.first().map(|r| r.id as u64).unwrap_or(s.audit_rows);
                        }
                        (
                            iterations, proposed, applied, duplicates, rejected, sweeps, errors,
                        ) = (0, 0, 0, 0, 0, 0, 0);
                    }
                    let spent = tick.elapsed();
                    if spent < delay {
                        std::thread::sleep(delay - spent);
                    }
                }
                // zaverecny flush: bez nej by se po zastaveni ztratilo az 5 s mereni
                let mut guard = legs.lock().unwrap();
                let s = &mut guard.ops_stress;
                s.iterations += iterations;
                s.proposed += proposed;
                s.applied += applied;
                s.duplicates += duplicates;
                s.rejected_guard += rejected;
                s.sweeps += sweeps;
                s.errors += errors;
                for (name, hist) in std::mem::take(&mut local) {
                    s.latency.entry(name).or_default().merge(&hist);
                }
            });
        }
    });
}

// --- broker (H5) --------------------------------------------------------------------

pub fn broker_leg(uri: &str, stop: &AtomicBool, legs: &SharedLegs) {
    let sizes = [1usize, 2, 4, 8, 16];
    let mut round_no: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        let consumers = sizes[(round_no as usize) % sizes.len()];
        let config = RedisBrokerConfig {
            stream_key: format!("bakula.soak.{}.{}", std::process::id(), round_no),
            ..RedisBrokerConfig::for_uri(uri)
        };
        match run_broker_round(&config, consumers, 1500, round_no, stop) {
            Ok(round) => {
                let mut guard = legs.lock().unwrap();
                guard.broker.available = true;
                guard.broker.error = None;
                guard.broker.rounds_total += 1;
                guard.broker.lost_total += round.lost;
                guard.broker.recent.push(round);
                let excess = guard.broker.recent.len().saturating_sub(100);
                guard.broker.recent.drain(..excess);
            }
            Err(error) => {
                let mut guard = legs.lock().unwrap();
                guard.broker.available = false;
                guard.broker.error = Some(error.to_string());
                drop(guard);
                sleep_until_or_stop(stop, 300.0);
            }
        }
        round_no += 1;
        sleep_until_or_stop(stop, 20.0);
    }
}

fn delete_stream(config: &RedisBrokerConfig) {
    if let Ok(client) = redis::Client::open(config.uri.as_str()) {
        if let Ok(mut conn) = client.get_connection() {
            let _: redis::RedisResult<i64> = redis::cmd("DEL")
                .arg(&config.stream_key)
                .arg(format!("{}.dlq", config.stream_key))
                .arg(format!("{}.reclaim-counts", config.stream_key))
                .query(&mut conn);
        }
    }
}

fn run_broker_round(
    config: &RedisBrokerConfig,
    consumers: usize,
    jobs: u64,
    round: u64,
    stop: &AtomicBool,
) -> crate::error::Result<BrokerRound> {
    broker::ensure_group(config)?;
    let processed: Mutex<HashSet<i64>> = Mutex::new(HashSet::new());
    let duplicates = std::sync::atomic::AtomicU64::new(0);
    let crashed = std::sync::atomic::AtomicU64::new(0);
    let done = AtomicBool::new(false);
    let started = Instant::now();
    let base = (round as i64 + 1) * 1_000_000;

    std::thread::scope(|scope| -> crate::error::Result<()> {
        for consumer in 0..consumers {
            let (processed, duplicates, crashed, done) = (&processed, &duplicates, &crashed, &done);
            scope.spawn(move || {
                let mut rng = Rng::new(round * 1000 + consumer as u64);
                let name = format!("soak-consumer-{consumer}");
                while !done.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
                    match broker::claim_one(config, &name, 200, 4000) {
                        Ok(Some(message)) => {
                            // "spadne pred ACK": zprava zustane v PEL a musi se znovu dorucit.
                            if rng.chance(0.01) {
                                crashed.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            let fresh = processed.lock().unwrap().insert(message.job_id);
                            if !fresh {
                                duplicates.fetch_add(1, Ordering::Relaxed);
                            }
                            let _ = broker::ack(config, &message.stream_id);
                        }
                        Ok(None) => {}
                        Err(_) => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
            });
        }
        for job in 0..jobs {
            broker::publish_job(config, base + job as i64)?;
        }
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
            if processed.lock().unwrap().len() as u64 >= jobs {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        done.store(true, Ordering::SeqCst);
        Ok(())
    })?;

    let seen = processed.lock().unwrap().len() as u64;
    let round_result = BrokerRound {
        consumers,
        jobs,
        secs: started.elapsed().as_secs_f64(),
        processed: seen,
        duplicates: duplicates.load(Ordering::Relaxed),
        lost: if stop.load(Ordering::SeqCst) {
            0
        } else {
            jobs.saturating_sub(seen)
        },
        crashed_before_ack: crashed.load(Ordering::Relaxed),
    };
    delete_stream(config);
    Ok(round_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_stress_leg_runs_briefly_keeps_audit_chain_and_records_latencies() {
        let dir = tempfile::tempdir().unwrap();
        let stop = AtomicBool::new(false);
        let legs: SharedLegs = Arc::new(Mutex::new(LegsState::default()));
        std::thread::scope(|scope| {
            scope.spawn(|| ops_stress_leg(dir.path(), 2, 200.0, &stop, &legs));
            std::thread::sleep(Duration::from_secs(7));
            stop.store(true, Ordering::SeqCst);
        });
        let state = legs.lock().unwrap().ops_stress.clone();
        assert!(
            state.proposed >= 1,
            "proposed={} iterations={} errors={}",
            state.proposed,
            state.iterations,
            state.errors
        );
        assert!(state.latency.contains_key("propose"));
        assert_eq!(state.chain_failures, 0);
        let store = OpsStore::open(&dir.path().join("ops-stress.sqlite")).unwrap();
        assert!(store.verify_audit_chain().unwrap());
    }

    #[test]
    fn anchor_leg_replays_committed_data_and_stays_deterministic() {
        let stop = AtomicBool::new(false);
        let legs: SharedLegs = Arc::new(Mutex::new(LegsState::default()));
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        std::thread::scope(|scope| {
            scope.spawn(|| anchor_leg(root, false, 0.2, &stop, &legs));
            // pod zatizenim trva pruchod ruzne dlouho: cekame na 2 pruchody, nejvyse 120 s
            let started = Instant::now();
            while legs.lock().unwrap().anchor.passes < 2
                && started.elapsed() < Duration::from_secs(120)
            {
                std::thread::sleep(Duration::from_millis(250));
            }
            stop.store(true, Ordering::SeqCst);
        });
        let state = legs.lock().unwrap().anchor.clone();
        assert!(
            state.passes >= 2,
            "passes={} error={:?}",
            state.passes,
            state.error
        );
        assert_eq!(state.nondeterministic_passes, 0);
        assert!(state.scenarios > 0);
    }
}
