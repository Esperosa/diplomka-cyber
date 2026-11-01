//! Orchestrace dlouheho behu: bloky siti rozdelene mezi vlakna, atomicke
//! checkpointy (beh jde kdykoli zastavit a navazat), casova rada do CSV,
//! periodicky markdown report, a `verify` = znovu-prehrani nahodnych bloku z
//! seedu a porovnani otisku (dukaz reprodukovatelnosti).
//!
//! Spolehlivost behu na desitky hodin:
//! - blok je atomicka jednotka: do agregatu se pripocte az cely; pri pádu/restartu se
//!   nedokoncene bloky pocitaji znovu (deterministicky stejny vysledek, zadne dvojite
//!   pocitani, protoze vysledek bloku se zapocita jen jednou),
//! - panika v jedne siti se zachyti (`catch_unwind`), zapise se seed pro presne
//!   prehrani a beh pokracuje,
//! - kontrola `STOP` souboru v `out` adresari = ciste zastaveni z druheho okna.

use std::{
    collections::{BTreeSet, VecDeque},
    fs::{self, OpenOptions},
    io::Write,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{BakulaError, Result},
    soak::{
        alloc,
        episode::{EpisodeConfig, WorldMask, run_episode, run_with_counterfactual},
        report,
        rng::mix,
        stats::Aggregate,
    },
    storage::write_atomic,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoakConfig {
    pub out: PathBuf,
    pub run_seed: u64,
    /// 0 = bez casoveho limitu (zastavi `max_networks` nebo soubor STOP).
    pub wall_hours: f64,
    pub max_networks: Option<u64>,
    pub threads: usize,
    pub block_size: u64,
    /// 0 = nahodna delka epizodu (24/48/72/96 virtualnich hodin).
    pub episode_hours: u32,
    pub checkpoint_secs: u64,
    pub report_secs: u64,
    pub scratch: PathBuf,
    /// Doplnkove nohy (realna data, ops stress, broker). Vychozi zapnuto.
    #[serde(default = "default_true")]
    pub legs: bool,
    /// Rezim jadra (`--engine legacy|v3`, `--v3-off`).
    #[serde(default)]
    pub engine: crate::engine::EngineConfig,
    /// Zasahy ovlivnuji generator (vychozi ano); `false` = parove A/B bez zpetne vazby.
    #[serde(default = "default_true")]
    pub feedback: bool,
    /// Kontrafaktualni atribuce (krok 2A): kazda sit se pusti i bez utoku.
    #[serde(default)]
    pub counterfactual: bool,
    /// Pocet leave-one-out svetu na sit (validace kontrafaktualu bez vsech utoku).
    #[serde(default)]
    pub cf_loo: usize,
    /// Kalibrace posteriory zebriku (JSON z `tools/soak_calib.py`), krok 2C.
    #[serde(default)]
    pub calibration: Option<PathBuf>,
    /// Volby sveta (krok 3): `--noise`.
    #[serde(default)]
    pub world: crate::soak::episode::WorldOptions,
}

fn default_true() -> bool {
    true
}

impl SoakConfig {
    pub fn with_defaults(out: PathBuf) -> Self {
        let scratch = out.join("scratch");
        Self {
            out,
            run_seed: 20_260_131,
            wall_hours: 0.0,
            max_networks: None,
            threads: std::thread::available_parallelism()
                .map(|n| (n.get() * 3 / 4).max(1))
                .unwrap_or(4),
            block_size: 16,
            episode_hours: 0,
            checkpoint_secs: 300,
            report_secs: 600,
            scratch,
            legs: true,
            engine: crate::engine::EngineConfig::default(),
            feedback: true,
            counterfactual: false,
            cf_loo: 0,
            calibration: None,
            world: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    pub config: SoakConfig,
    pub git_sha: String,
    /// Strom mel necommitnute zmeny (binarka nemusi odpovidat `git_sha`).
    #[serde(default)]
    pub git_dirty: bool,
    pub started_at: String,
    pub elapsed_wall_s: f64,
    pub sessions: u32,
    pub next_block: u64,
    pub watermark: u64,
    pub committed_sparse: Vec<u64>,
    pub aggregate: Aggregate,
    #[serde(default)]
    pub legs: crate::soak::legs::LegsState,
}

struct Shared {
    state: PersistedState,
    committed: BTreeSet<u64>,
    todo: VecDeque<u64>,
    last_commit: Instant,
}

fn git_sha() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn git_dirty() -> bool {
    std::process::Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| !o.stdout.is_empty())
}

fn panic_text(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panika bez textu".to_string())
}

/// Spusti jeden blok siti. Vraci (agregat bloku, otisk bloku).
pub fn run_block(cfg: &SoakConfig, block: u64) -> (Aggregate, u64) {
    let (agg, digest, _) = run_block_with_summaries(cfg, block);
    (agg, digest)
}

/// Jako `run_block`, navic souhrny jednotlivych siti (pro `networks.jsonl`).
pub fn run_block_with_summaries(
    cfg: &SoakConfig,
    block: u64,
) -> (Aggregate, u64, Vec<crate::soak::stats::NetworkSummary>) {
    let mut agg = Aggregate::default();
    let mut summaries = Vec::new();
    let mut digest = mix(block);
    let calibration = cfg.calibration.as_ref().and_then(|path| {
        crate::calibration::IsotonicCalibrator::load(path)
            .map_err(|e| eprintln!("soak: kalibraci {} nelze nacist: {e}", path.display()))
            .ok()
            .map(std::sync::Arc::new)
    });
    for offset in 0..cfg.block_size {
        let network_id = block * cfg.block_size + offset;
        let episode = EpisodeConfig {
            run_seed: cfg.run_seed,
            network_id,
            hours: cfg.episode_hours,
            scratch: cfg.scratch.join(format!("w{}", block % 4096)),
            engine: cfg.engine,
            feedback: cfg.feedback,
            mask: WorldMask::None,
            counterfactual: None,
            calibration: calibration.clone(),
            world: cfg.world,
        };
        let run = || {
            if cfg.counterfactual {
                run_with_counterfactual(&episode, cfg.cf_loo)
            } else {
                run_episode(&episode)
            }
        };
        match catch_unwind(AssertUnwindSafe(run)) {
            Ok(result) => {
                digest = mix(digest ^ result.digest);
                agg.merge(&result.agg);
                summaries.push(result.summary);
            }
            Err(payload) => {
                agg.panics += 1;
                agg.networks += 1;
                summaries.push(crate::soak::stats::NetworkSummary {
                    run_seed: cfg.run_seed,
                    network_id,
                    engine: cfg.engine.label(),
                    panics: 1,
                    ..Default::default()
                });
                if agg.panic_samples.len() < 20 {
                    agg.panic_samples.push(format!(
                        "run_seed={} network_id={network_id}: {}",
                        cfg.run_seed,
                        panic_text(&payload)
                    ));
                }
                digest = mix(digest ^ 0xDEAD);
            }
        }
    }
    (agg, digest, summaries)
}

fn state_path(out: &Path) -> PathBuf {
    out.join("state.json")
}

fn save_state(out: &Path, state: &PersistedState) -> Result<()> {
    write_atomic(&state_path(out), serde_json::to_string(state)?.as_bytes())
}

pub fn load_state(out: &Path) -> Result<PersistedState> {
    let text = fs::read_to_string(state_path(out))?;
    Ok(serde_json::from_str(&text)?)
}

fn append_line(path: &Path, line: &str) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

pub fn run(mut cfg: SoakConfig, resume: bool) -> Result<()> {
    fs::create_dir_all(&cfg.out)?;
    let session_started = Instant::now();
    let state = if resume {
        let mut persisted = load_state(&cfg.out)?;
        // Navazani zachova puvodni seed/velikost bloku/delku epizodu (jinak by se
        // zmenila identita bloku); cas/vlakna/limity jdou prepsat z noveho volani.
        let old = persisted.config.clone();
        cfg.run_seed = old.run_seed;
        cfg.block_size = old.block_size;
        cfg.episode_hours = old.episode_hours;
        persisted.config = cfg.clone();
        persisted.sessions += 1;
        persisted
    } else {
        if state_path(&cfg.out).exists() {
            return Err(BakulaError::Config(format!(
                "{} uz obsahuje beh (state.json) - pouzij --resume, nebo jiny adresar",
                cfg.out.display()
            )));
        }
        PersistedState {
            config: cfg.clone(),
            git_sha: git_sha(),
            git_dirty: git_dirty(),
            started_at: chrono::Utc::now().to_rfc3339(),
            elapsed_wall_s: 0.0,
            sessions: 1,
            next_block: 0,
            watermark: 0,
            committed_sparse: Vec::new(),
            aggregate: Aggregate::default(),
            legs: Default::default(),
        }
    };
    let committed: BTreeSet<u64> = state.committed_sparse.iter().copied().collect();
    let todo: VecDeque<u64> = (state.watermark..state.next_block)
        .filter(|b| !committed.contains(b))
        .collect();
    fs::create_dir_all(&cfg.scratch)?;
    let _ = fs::remove_file(cfg.out.join("STOP"));
    eprintln!(
        "soak: start (session {}), vlaken {}, blok {} siti, navazuji od bloku {} (znovu {} nedokoncenych)",
        state.sessions,
        cfg.threads,
        cfg.block_size,
        state.next_block,
        todo.len()
    );

    let previous_elapsed = state.elapsed_wall_s;
    let legs: crate::soak::legs::SharedLegs = std::sync::Arc::new(Mutex::new(state.legs.clone()));
    let redis_uri =
        std::env::var("BAKULA_SOAK_REDIS").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let repo_root = std::env::var("BAKULA_SOAK_REPO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let shared = Mutex::new(Shared {
        state,
        committed,
        todo,
        last_commit: Instant::now(),
    });
    let stop = AtomicBool::new(false);
    let max_blocks = cfg.max_networks.map(|n| n.div_ceil(cfg.block_size));
    let wall_limit_s = cfg.wall_hours * 3600.0;

    std::thread::scope(|scope| {
        if cfg.legs {
            let (stop, legs, cfg, repo_root, redis_uri) =
                (&stop, &legs, &cfg, &repo_root, &redis_uri);
            scope.spawn(move || {
                crate::soak::legs::anchor_leg(repo_root.clone(), true, 3600.0, stop, legs)
            });
            scope.spawn(move || crate::soak::legs::ops_stress_leg(&cfg.out, 2, 20.0, stop, legs));
            scope.spawn(move || crate::soak::legs::broker_leg(redis_uri, stop, legs));
        }
        for worker in 0..cfg.threads {
            let (shared, stop, cfg) = (&shared, &stop, &cfg);
            scope.spawn(move || {
                let _ = worker;
                while !stop.load(Ordering::SeqCst) {
                    let block = {
                        let mut guard = shared.lock().unwrap();
                        if let Some(block) = guard.todo.pop_front() {
                            block
                        } else if max_blocks.is_some_and(|max| guard.state.next_block >= max) {
                            return;
                        } else {
                            let block = guard.state.next_block;
                            guard.state.next_block += 1;
                            block
                        }
                    };
                    let (agg, digest, summaries) = run_block_with_summaries(cfg, block);
                    let mut guard = shared.lock().unwrap();
                    guard.state.aggregate.merge(&agg);
                    guard.committed.insert(block);
                    while guard.committed.contains(&guard.state.watermark) {
                        let mark = guard.state.watermark;
                        guard.committed.remove(&mark);
                        guard.state.watermark += 1;
                    }
                    guard.last_commit = Instant::now();
                    let line = format!(
                        "{{\"block\":{block},\"digest\":\"{digest:016x}\",\"networks\":{}}}",
                        cfg.block_size
                    );
                    let _ = append_line(&cfg.out.join("blocks.jsonl"), &line);
                    for summary in &summaries {
                        if let Ok(json) = serde_json::to_string(summary) {
                            let _ = append_line(&cfg.out.join("networks.jsonl"), &json);
                        }
                    }
                }
            });
        }

        // --- monitor: checkpointy, report, podminky zastaveni ---
        let mut last_checkpoint = Instant::now();
        let mut last_report = Instant::now();
        let mut last_series = (Instant::now(), 0u64, 0u64);
        let mut warned_stall = false;
        let mut header_written = cfg.out.join("timeseries.csv").exists();
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let elapsed = previous_elapsed + session_started.elapsed().as_secs_f64();
            let (done, stall) = {
                let guard = shared.lock().unwrap();
                let done_by_max = max_blocks
                    .is_some_and(|max| guard.state.watermark >= max && guard.todo.is_empty());
                (done_by_max, guard.last_commit.elapsed())
            };
            if stall > Duration::from_secs(900) && !warned_stall {
                warned_stall = true;
                let _ = append_line(
                    &cfg.out.join("events.log"),
                    &format!(
                        "{} VAROVANI: zadny dokonceny blok {} s",
                        chrono::Utc::now().to_rfc3339(),
                        stall.as_secs()
                    ),
                );
            }
            if stall < Duration::from_secs(60) {
                warned_stall = false;
            }
            let stop_now = done
                || (wall_limit_s > 0.0 && elapsed >= wall_limit_s)
                || cfg.out.join("STOP").exists();

            if last_checkpoint.elapsed() >= Duration::from_secs(cfg.checkpoint_secs) || stop_now {
                last_checkpoint = Instant::now();
                let mut guard = shared.lock().unwrap();
                guard.state.elapsed_wall_s = elapsed;
                guard.state.legs = legs.lock().unwrap().clone();
                let sparse: Vec<u64> = guard.committed.iter().copied().collect();
                guard.state.committed_sparse = sparse;
                if let Err(error) = save_state(&cfg.out, &guard.state) {
                    eprintln!("soak: checkpoint selhal: {error}");
                }
                let row = report::timeseries_row(
                    &guard.state,
                    elapsed,
                    last_series.1,
                    last_series.2,
                    last_series.0.elapsed().as_secs_f64(),
                );
                last_series = (
                    Instant::now(),
                    guard.state.aggregate.cycles,
                    guard.state.aggregate.networks,
                );
                drop(guard);
                if !header_written {
                    let _ = append_line(&cfg.out.join("timeseries.csv"), report::TIMESERIES_HEADER);
                    header_written = true;
                }
                let _ = append_line(&cfg.out.join("timeseries.csv"), &row);
            }
            if last_report.elapsed() >= Duration::from_secs(cfg.report_secs) || stop_now {
                last_report = Instant::now();
                let mut snapshot = shared.lock().unwrap().state.clone();
                snapshot.legs = legs.lock().unwrap().clone();
                let _ = write_atomic(
                    &cfg.out.join("status.md"),
                    report::render_markdown(&snapshot, elapsed, false).as_bytes(),
                );
            }
            if stop_now {
                stop.store(true, Ordering::SeqCst);
                break;
            }
        }
    });

    let guard = shared.into_inner().unwrap();
    let mut state = guard.state;
    state.elapsed_wall_s = previous_elapsed + session_started.elapsed().as_secs_f64();
    state.legs = legs.lock().unwrap().clone();
    state.committed_sparse = guard.committed.iter().copied().collect();
    save_state(&cfg.out, &state)?;
    write_atomic(
        &cfg.out.join("final-report.md"),
        report::render_markdown(&state, state.elapsed_wall_s, true).as_bytes(),
    )?;
    write_atomic(
        &cfg.out.join("final-report.json"),
        serde_json::to_string_pretty(&state.aggregate)?.as_bytes(),
    )?;
    eprintln!(
        "soak: hotovo, {} siti, {:.1} h, heap peak {:.0} MiB; report: {}",
        state.aggregate.networks,
        state.elapsed_wall_s / 3600.0,
        alloc::heap_peak() as f64 / 1_048_576.0,
        cfg.out.join("final-report.md").display()
    );
    Ok(())
}

/// Znovu-prehraje `samples` nahodnych bloku a porovna otisky s `blocks.jsonl`.
pub fn verify(out: &Path, samples: usize, seed: u64) -> Result<(usize, usize)> {
    let state = load_state(out)?;
    let text = fs::read_to_string(out.join("blocks.jsonl"))?;
    let mut blocks: Vec<(u64, String)> = Vec::new();
    for line in text.lines() {
        let value: serde_json::Value = serde_json::from_str(line)?;
        if let (Some(block), Some(digest)) = (value["block"].as_u64(), value["digest"].as_str()) {
            blocks.push((block, digest.to_string()));
        }
    }
    if blocks.is_empty() {
        return Err(BakulaError::Config("blocks.jsonl je prazdny".to_string()));
    }
    // Nahodny vyber deterministicky ze `seed` (Fisher-Yates nad indexy).
    let mut rng = crate::soak::rng::Rng::new(seed);
    let picks = rng.sample_distinct(blocks.len(), samples);
    let mut cfg = state.config.clone();
    cfg.scratch = out.join("verify-scratch");
    let mut ok = 0usize;
    let mut report_lines = vec![format!(
        "# Verifikace reprodukovatelnosti\n\nvybrano {} bloku z {} (seed vyberu {seed})\n",
        picks.len(),
        blocks.len()
    )];
    for index in &picks {
        let (block, expected) = &blocks[*index];
        let (_, digest) = run_block(&cfg, *block);
        let actual = format!("{digest:016x}");
        let same = &actual == expected;
        ok += same as usize;
        report_lines.push(format!(
            "- blok {block}: ocekavano `{expected}`, znovu-prehrano `{actual}` -> {}",
            if same { "SHODA" } else { "ROZDIL" }
        ));
    }
    report_lines.push(format!(
        "\n**Vysledek: {ok}/{} bloku bit po bitu shodnych.**\n",
        picks.len()
    ));
    write_atomic(
        &out.join("verify-report.md"),
        report_lines.join("\n").as_bytes(),
    )?;
    let _ = fs::remove_dir_all(&cfg.scratch);
    Ok((ok, picks.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_cfg(dir: &Path) -> SoakConfig {
        let mut cfg = SoakConfig::with_defaults(dir.to_path_buf());
        cfg.threads = 2;
        cfg.block_size = 2;
        cfg.episode_hours = 6;
        cfg.max_networks = Some(8);
        cfg.checkpoint_secs = 1;
        cfg.report_secs = 1;
        cfg
    }

    #[test]
    fn run_stop_resume_counts_every_network_exactly_once_and_verify_confirms_reproducibility() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = small_cfg(dir.path());
        cfg.max_networks = Some(4);
        run(cfg.clone(), false).unwrap();
        let first = load_state(dir.path()).unwrap();
        assert_eq!(first.aggregate.networks, 4);

        // navazani s vyssim limitem: dopocita zbytek, nic dvakrat
        let mut cfg2 = small_cfg(dir.path());
        cfg2.max_networks = Some(8);
        run(cfg2, true).unwrap();
        let second = load_state(dir.path()).unwrap();
        assert_eq!(second.aggregate.networks, 8, "kazda sit prave jednou");
        assert_eq!(second.sessions, 2);
        assert!(dir.path().join("final-report.md").exists());
        assert!(dir.path().join("timeseries.csv").exists());

        let (ok, total) = verify(dir.path(), 3, 99).unwrap();
        assert_eq!((ok, total), (3, 3), "znovu-prehrani musi dat shodne otisky");
    }

    #[test]
    fn refuses_to_overwrite_an_existing_run_without_resume() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = small_cfg(dir.path());
        cfg.max_networks = Some(2);
        run(cfg.clone(), false).unwrap();
        assert!(run(cfg, false).is_err());
    }
}
