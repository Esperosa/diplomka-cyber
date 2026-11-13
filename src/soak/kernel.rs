//! Simulovane jadro firewallu: implementuje stejne `NftExecutor` rozhrani, ktere
//! pouziva produkcni `ops.rs`, ale drzi stav jen v pameti a ve virtualnim case.
//! Navic umi vstrikovat zavady, ktere v realu nastavaji: selhani prikazu, predcasne
//! zmizeni prvku (rucni zasah / kratsi timeout), flush setu, pad tabulky (reboot).
//! Zadny skutecny `nft` se tu nikdy nevola.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
};

use chrono::{DateTime, Utc};

use crate::{
    error::{SalticusError, Result},
    ops::NftExecutor,
    soak::{rng::Rng, traffic::BlockOracle, traffic::ts},
};

#[derive(Default)]
struct State {
    table: bool,
    /// ip -> virtualni cas vyprseni (sekundy epochy)
    elements: HashMap<String, i64>,
    rulesets_applied: u64,
    commands_ok: u64,
    commands_failed: u64,
    faults: u64,
}

pub struct SimKernel {
    state: Mutex<State>,
    now: Arc<AtomicI64>,
    fail_p: f64,
    fail_rng: Mutex<Rng>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelStats {
    pub rulesets_applied: u64,
    pub commands_ok: u64,
    pub commands_failed: u64,
    pub faults_injected: u64,
}

impl SimKernel {
    pub fn new(now: Arc<AtomicI64>, fail_p: f64, seed: u64) -> Self {
        Self {
            state: Mutex::new(State::default()),
            now,
            fail_p,
            fail_rng: Mutex::new(Rng::new(seed)),
        }
    }

    fn expire(state: &mut State, now: i64) {
        state.elements.retain(|_, expires| *expires > now);
    }

    pub fn blocked_now(&self) -> Vec<String> {
        let mut state = self.state.lock().unwrap();
        Self::expire(&mut state, self.now.load(Ordering::SeqCst));
        state.elements.keys().cloned().collect()
    }

    pub fn stats(&self) -> KernelStats {
        let state = self.state.lock().unwrap();
        KernelStats {
            rulesets_applied: state.rulesets_applied,
            commands_ok: state.commands_ok,
            commands_failed: state.commands_failed,
            faults_injected: state.faults,
        }
    }

    /// Vstrikne zavadu realneho sveta (volat jednou za cyklus). Vraci popis zavady.
    pub fn inject_faults(&self, rng: &mut Rng) -> Option<&'static str> {
        let mut state = self.state.lock().unwrap();
        Self::expire(&mut state, self.now.load(Ordering::SeqCst));
        if state.table && rng.chance(0.004) {
            state.table = false;
            state.elements.clear();
            state.faults += 1;
            return Some("table_lost_reboot");
        }
        if !state.elements.is_empty() && rng.chance(0.01) {
            let keys: Vec<String> = state.elements.keys().cloned().collect();
            let victim = keys[rng.range(0, keys.len() as u64 - 1) as usize].clone();
            state.elements.remove(&victim);
            state.faults += 1;
            return Some("element_vanished");
        }
        if state.table && rng.chance(0.002) {
            // Rucni "nft add element" mimo bakulu (drift opacnym smerem).
            let ip = format!("198.18.{}.{}", rng.range(0, 255), rng.range(1, 254));
            let expires = self.now.load(Ordering::SeqCst) + 3600;
            state.elements.insert(ip, expires);
            state.faults += 1;
            return Some("foreign_element_added");
        }
        None
    }
}

impl BlockOracle for SimKernel {
    fn is_blocked(&self, ip: &str, at: DateTime<Utc>) -> bool {
        let state = self.state.lock().unwrap();
        state.table
            && state
                .elements
                .get(ip)
                .is_some_and(|expires| *expires > at.timestamp())
    }
}

fn parse_element(argument: &str) -> Option<(String, Option<i64>)> {
    let inner = argument
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    let mut parts = inner.split_whitespace();
    let ip = parts.next()?.to_string();
    let timeout = match (parts.next(), parts.next()) {
        (Some("timeout"), Some(value)) => value.trim_end_matches('s').parse::<i64>().ok(),
        _ => None,
    };
    Some((ip, timeout))
}

impl NftExecutor for SimKernel {
    fn table_exists(&self) -> Result<bool> {
        Ok(self.state.lock().unwrap().table)
    }

    fn apply_ruleset(&self, _text: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.table = true;
        state.rulesets_applied += 1;
        Ok(())
    }

    fn run(&self, args: &[String]) -> Result<()> {
        if self.fail_p > 0.0 && self.fail_rng.lock().unwrap().chance(self.fail_p) {
            self.state.lock().unwrap().commands_failed += 1;
            return Err(SalticusError::Processing(
                "simulovane selhani nft".to_string(),
            ));
        }
        let mut state = self.state.lock().unwrap();
        let now = self.now.load(Ordering::SeqCst);
        if !state.table {
            state.commands_failed += 1;
            return Err(SalticusError::Processing(
                "tabulka inet salticus neexistuje".to_string(),
            ));
        }
        let verb = args.first().map(String::as_str).unwrap_or("");
        let target_set = args.get(4).map(String::as_str).unwrap_or("");
        if !target_set.starts_with("blocked_ips") {
            state.commands_failed += 1;
            return Err(SalticusError::Processing(format!("neznamy set {target_set}")));
        }
        let Some((ip, timeout)) = args.last().and_then(|a| parse_element(a)) else {
            state.commands_failed += 1;
            return Err(SalticusError::Processing(
                "nelze naparsovat prvek".to_string(),
            ));
        };
        match verb {
            "add" => {
                state.elements.insert(ip, now + timeout.unwrap_or(0));
            }
            "delete" => {
                state.elements.remove(&ip);
            }
            other => {
                state.commands_failed += 1;
                return Err(SalticusError::Processing(format!(
                    "nepodporovany prikaz {other}"
                )));
            }
        }
        state.commands_ok += 1;
        Ok(())
    }

    fn list_elements(&self, set: &str) -> Result<Vec<String>> {
        let mut state = self.state.lock().unwrap();
        Self::expire(&mut state, self.now.load(Ordering::SeqCst));
        let want_v6 = set == "blocked_ips6";
        Ok(state
            .elements
            .keys()
            .filter(|ip| ip.contains(':') == want_v6)
            .cloned()
            .collect())
    }
}

/// Pomocnik: virtualni cas jako `DateTime`.
pub fn virtual_now(clock: &AtomicI64) -> DateTime<Utc> {
    ts(clock.load(Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(fail_p: f64) -> (Arc<AtomicI64>, SimKernel) {
        let now = Arc::new(AtomicI64::new(1000));
        (now.clone(), SimKernel::new(now, fail_p, 1))
    }

    fn add(ip: &str, ttl: u64) -> Vec<String> {
        vec![
            "add".into(),
            "element".into(),
            "inet".into(),
            "salticus".into(),
            "blocked_ips".into(),
            format!("{{ {ip} timeout {ttl}s }}"),
        ]
    }

    #[test]
    fn element_blocks_until_virtual_timeout_then_expires_by_itself() {
        let (now, kernel) = kernel(0.0);
        kernel.apply_ruleset("x").unwrap();
        kernel.run(&add("203.0.113.5", 600)).unwrap();
        assert!(kernel.is_blocked("203.0.113.5", ts(1100)));
        assert!(
            !kernel.is_blocked("203.0.113.5", ts(1700)),
            "po vyprseni uz neblokuje"
        );
        now.store(1700, Ordering::SeqCst);
        assert!(kernel.list_elements("blocked_ips").unwrap().is_empty());
    }

    #[test]
    fn commands_fail_without_table_and_after_table_loss() {
        let (_now, kernel) = kernel(0.0);
        assert!(kernel.run(&add("203.0.113.5", 60)).is_err());
        kernel.apply_ruleset("x").unwrap();
        assert!(kernel.run(&add("203.0.113.5", 60)).is_ok());
        let mut rng = Rng::new(1);
        let mut lost = false;
        for _ in 0..5000 {
            if kernel.inject_faults(&mut rng) == Some("table_lost_reboot") {
                lost = true;
                break;
            }
        }
        assert!(lost);
        assert!(!kernel.table_exists().unwrap());
        assert!(
            !kernel.is_blocked("203.0.113.5", ts(1010)),
            "po rebootu nic neblokuje"
        );
    }

    #[test]
    fn delete_removes_element_and_ipv6_set_is_listed_separately() {
        let (_now, kernel) = kernel(0.0);
        kernel.apply_ruleset("x").unwrap();
        kernel.run(&add("203.0.113.5", 600)).unwrap();
        kernel
            .run(&[
                "delete".into(),
                "element".into(),
                "inet".into(),
                "salticus".into(),
                "blocked_ips".into(),
                "{ 203.0.113.5 }".into(),
            ])
            .unwrap();
        assert!(kernel.list_elements("blocked_ips").unwrap().is_empty());
        let mut v6 = add("2001:db8::1", 60);
        v6[4] = "blocked_ips6".to_string();
        kernel.run(&v6).unwrap();
        assert_eq!(
            kernel.list_elements("blocked_ips6").unwrap(),
            vec!["2001:db8::1".to_string()]
        );
        assert!(kernel.list_elements("blocked_ips").unwrap().is_empty());
    }

    #[test]
    fn failure_probability_one_always_fails_and_is_counted() {
        let (_now, kernel) = kernel(1.0);
        kernel.apply_ruleset("x").unwrap();
        assert!(kernel.run(&add("203.0.113.5", 60)).is_err());
        assert_eq!(kernel.stats().commands_failed, 1);
    }
}
