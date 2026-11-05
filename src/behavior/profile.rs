//! Naučený profil hostu: per-host allowlist obvyklých cílů a portů s hysterezí (krok 3E).
//!
//! Účel: POZITIVNÍ důkaz neškodnosti pro žebřík ověřování. Krok 2 rozhodl automaticky
//! jen ~0,9 % odlišných stavů, protože prázdný výsledek kontroly záměrně není důkaz
//! neškodnosti (RQ6 Z3). „Tenhle host na tenhle cíl a port mluví už ≥ 3 dny“ je
//! doložený neškodný důkaz (LR < 1), ne nepřítomnost dat. Opora: RQ5-053 (Z-12,
//! střední jistota): deterministický allowlist porazil učené modely F1 i MCC na všech
//! čtyřech datasetech DARPA TC (jiná úloha: názvy procesů, ne toky).
//!
//! Ochrana proti zneužití (útočník se „naučí“ do allowlistu pomalým provozem):
//! - zvyk se stane zavedeným až po opakování (`min_days` různých dní, `min_obs`) A stáří
//!   (`min_age_s`); jednorázový nebo krátký útok se nenaučí nikdy,
//! - dvojice nebo host s otevřeným poplachem se v okně neučí a dvojice, která kdy
//!   měla poplach, je „poznamenaná“ a zavedenou se nestane (gating RQ2 Z3),
//! - rychlost učení je omezená (nejvýš `max_promotions_per_host_day` povýšení na host
//!   a den, `max_promotions_per_window` za okno), přebytek čeká na další den,
//! - každé povýšení jde do auditu (čas, host, zvyk, důvod), audit má strop,
//! - hystereze: zavedený zvyk zmizí až po `forget_s` bez výskytu.
//!
//! Zbytkové riziko: útok přítomný od začátku a pravidelný déle než `min_days` se naučí;
//! měří se zvlášť (útoky začínající v prvních dnech epizody).

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{behavior::evict_oldest, passive::ConnectionObservation};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfilePolicy {
    pub min_days: u16,
    pub min_age_s: i64,
    pub min_obs: u32,
    pub max_promotions_per_host_day: u16,
    pub max_promotions_per_window: u32,
    pub max_habits_per_host: usize,
    pub max_hosts: usize,
    /// Kandidát bez výskytu déle než toto zmizí (s).
    pub candidate_forget_s: i64,
    /// Zavedený zvyk bez výskytu déle než toto zmizí (s).
    pub forget_s: i64,
    /// Profil hostu je zralý po tolika dnech dat (nový cíl je pak slabý podezřelý rys).
    pub mature_s: i64,
    /// Flotila: zavedeno u aspoň tolika hostů a podílu peer skupiny.
    pub fleet_min: u32,
    pub fleet_share: f64,
    pub audit_cap: usize,
    /// Krok 7 (A2): poznamenaná dvojice (poplach) se drží až `forget_s` a ze stropu
    /// zvyků hostu se vyřazuje až po nepoznamenaných kandidátech, takže nevyřešená
    /// novost nebo graf se nestane zvykem ani po zapomenutí poznámky.
    #[serde(default)]
    pub keep_tainted: bool,
}

impl Default for ProfilePolicy {
    fn default() -> Self {
        Self {
            min_days: 3,
            min_age_s: 72 * 3600,
            min_obs: 6,
            max_promotions_per_host_day: 10,
            max_promotions_per_window: 2_000,
            max_habits_per_host: 128,
            max_hosts: 50_000,
            candidate_forget_s: 4 * 86_400,
            forget_s: 14 * 86_400,
            mature_s: 5 * 86_400,
            fleet_min: 3,
            fleet_share: 0.3,
            audit_cap: 2_000,
            keep_tainted: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Habit {
    first: i64,
    last: i64,
    last_day: i64,
    days: u16,
    obs: u32,
    established: Option<i64>,
    tainted: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HostProfile {
    first: i64,
    last: i64,
    habits: HashMap<String, Habit>,
    promoted_day: i64,
    promoted_today: u16,
}

/// Záznam auditu povýšení zvyku na zavedený.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileAudit {
    pub at: i64,
    pub host: String,
    pub habit: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HostProfiles {
    hosts: HashMap<String, HostProfile>,
    /// zvyk -> počet hostů, u kterých je zavedený (flotila).
    established_index: HashMap<String, u32>,
    pub audit: VecDeque<ProfileAudit>,
    pub promotions: u64,
    pub rate_limited: u64,
    pub tainted: u64,
    pub evicted: u64,
}

/// Výsledek dotazu profilu pro žebřík.
#[derive(Debug, Clone, PartialEq)]
pub enum ProfileVerdict {
    /// Zvyk je u hostu zavedený (od, dní pozorování).
    Established { since: i64, days: u16 },
    /// Zvyk je zavedený u flotily (počet hostů), u tohoto hostu ne.
    Fleet { hosts: u32 },
    /// Zralý profil hostu a cíl v něm není (slabý podezřelý rys, RQ4 Z10).
    NewForMature { profile_days: f64 },
    /// Nic neplyne (nový host, kandidát, poznamenaný zvyk): bez vlivu na víru.
    Unknown(String),
}

pub fn habit_key(peer: &str, proto: &str, port: u16) -> String {
    format!("{peer}|{proto}/{port}")
}

fn is_success(flow: &ConnectionObservation) -> bool {
    let state = flow.conn_state.as_deref().unwrap_or("");
    !matches!(state, "S0" | "REJ" | "RSTOS0" | "SH" | "RSTRH") && flow.resp_bytes.unwrap_or(0) > 0
}

impl HostProfiles {
    /// Naučí zvyky z toků okna. `frozen` = hosté (`ip`) a dvojice (`ip|peer`) s poplachem.
    #[allow(private_interfaces, private_bounds)]
    pub fn learn<'a>(
        &mut self,
        flows: impl Iterator<Item = &'a ConnectionObservation>,
        frozen: &HashSet<String>,
        now: i64,
        policy: &ProfilePolicy,
    ) {
        let day = now.div_euclid(86_400);
        let mut window_promotions = 0u32;
        for flow in flows {
            let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
                continue;
            };
            if !is_success(flow) {
                continue;
            }
            let pair = format!("{src}|{}", flow.dst_ip);
            let host = self
                .hosts
                .entry(src.to_string())
                .or_insert_with(|| HostProfile {
                    first: now,
                    ..Default::default()
                });
            host.last = now;
            let key = habit_key(&flow.dst_ip, &flow.proto, port);
            if frozen.contains(&pair) {
                // dvojice s poplachem: poznamenat, nikdy nepovysit; krok 7 (A2): poznamka
                // se s opakovanym poplachem obnovuje (nezapomene se behem poplachu)
                if policy.keep_tainted
                    && let Some(habit) = host.habits.get_mut(&key)
                {
                    habit.last = now;
                }
                if let Some(habit) = host.habits.get_mut(&key)
                    && !habit.tainted
                {
                    habit.tainted = true;
                    self.tainted += 1;
                } else if let std::collections::hash_map::Entry::Vacant(slot) =
                    host.habits.entry(key)
                {
                    slot.insert(Habit {
                        first: now,
                        last: now,
                        last_day: day,
                        days: 1,
                        tainted: true,
                        ..Default::default()
                    });
                    self.tainted += 1;
                }
                continue;
            }
            if frozen.contains(src) {
                continue; // host s poplachem se v tomto okne neuci
            }
            let habit = host.habits.entry(key.clone()).or_insert_with(|| Habit {
                first: now,
                last_day: day - 1,
                ..Default::default()
            });
            habit.last = now;
            habit.obs = habit.obs.saturating_add(1);
            if habit.last_day != day {
                habit.last_day = day;
                habit.days = habit.days.saturating_add(1);
            }
            if habit.established.is_some()
                || habit.tainted
                || habit.days < policy.min_days
                || now - habit.first < policy.min_age_s
                || habit.obs < policy.min_obs
            {
                continue;
            }
            if host.promoted_day != day {
                host.promoted_day = day;
                host.promoted_today = 0;
            }
            if host.promoted_today >= policy.max_promotions_per_host_day
                || window_promotions >= policy.max_promotions_per_window
            {
                self.rate_limited += 1;
                continue;
            }
            host.promoted_today += 1;
            window_promotions += 1;
            habit.established = Some(now);
            self.promotions += 1;
            *self.established_index.entry(key.clone()).or_default() += 1;
            self.audit.push_back(ProfileAudit {
                at: now,
                host: src.to_string(),
                habit: key,
                reason: format!(
                    "{} dni, {} spojeni, prvni vyskyt {}",
                    habit.days, habit.obs, habit.first
                ),
            });
            while self.audit.len() > policy.audit_cap {
                self.audit.pop_front();
            }
        }
        if now.rem_euclid(6 * 3600) < 1800 {
            self.sweep(now, policy);
        }
    }

    /// Zapomenutí starých zvyků (hystereze) a stropy.
    pub fn sweep(&mut self, now: i64, policy: &ProfilePolicy) {
        let index = &mut self.established_index;
        for host in self.hosts.values_mut() {
            host.habits.retain(|key, habit| {
                let keep = match habit.established {
                    Some(_) => now - habit.last <= policy.forget_s,
                    None if policy.keep_tainted && habit.tainted => {
                        now - habit.last <= policy.forget_s
                    }
                    None => now - habit.last <= policy.candidate_forget_s,
                };
                if !keep && habit.established.is_some() {
                    decrement(index, key);
                }
                keep
            });
            if host.habits.len() > policy.max_habits_per_host {
                let keep_tainted = policy.keep_tainted;
                let mut order: Vec<(bool, bool, i64, String)> = host
                    .habits
                    .iter()
                    .map(|(k, h)| {
                        (
                            keep_tainted && h.tainted,
                            h.established.is_some(),
                            h.last,
                            k.clone(),
                        )
                    })
                    .collect();
                order.sort();
                let remove = host.habits.len() - policy.max_habits_per_host;
                for (_, established, _, key) in order.into_iter().take(remove) {
                    host.habits.remove(&key);
                    if established {
                        decrement(index, &key);
                    }
                }
            }
        }
        if self.hosts.len() > policy.max_hosts {
            let before: HashSet<String> = self.hosts.keys().cloned().collect();
            let removed = evict_oldest(&mut self.hosts, policy.max_hosts, |h| h.last);
            self.evicted += removed as u64;
            // index po vyrazeni hostu prepocitat (vzacne)
            if removed > 0 && before.len() != self.hosts.len() {
                self.rebuild_index();
            }
        }
    }

    fn rebuild_index(&mut self) {
        self.established_index.clear();
        for host in self.hosts.values() {
            for (key, habit) in &host.habits {
                if habit.established.is_some() {
                    *self.established_index.entry(key.clone()).or_default() += 1;
                }
            }
        }
    }

    pub fn hosts(&self) -> usize {
        self.hosts.len()
    }

    /// Krok 6: první výskyt hostu v profilu (stáří profilu pro novost vztahů).
    pub fn host_first(&self, host: &str) -> Option<i64> {
        self.hosts.get(host).map(|p| p.first)
    }

    /// Krok 6: profil o vztahu ví (kandidát, zvyk i poznamenaná dvojice). Nový vztah
    /// = profil ho nikdy neviděl, ani jako kandidáta (zapomenutí po `candidate_forget_s`).
    pub fn knows(&self, host: &str, peer: &str, proto: &str, port: u16) -> bool {
        self.hosts
            .get(host)
            .is_some_and(|p| p.habits.contains_key(&habit_key(peer, proto, port)))
    }

    /// Zavedený a nepoznamenaný zvyk hostu (krok 4: periodicita na zvyk není nová).
    pub fn is_habit(&self, host: &str, peer: &str, proto: &str, port: u16) -> bool {
        self.hosts
            .get(host)
            .and_then(|p| p.habits.get(&habit_key(peer, proto, port)))
            .is_some_and(|h| h.established.is_some() && !h.tainted)
    }

    /// Verdikt pro dvojici (host, cíl, protokol, port). `group_size` = velikost peer
    /// skupiny hostu (typ zařízení a podsíť), pokud je známá.
    #[allow(clippy::too_many_arguments)]
    pub fn verdict(
        &self,
        host: &str,
        peer: &str,
        proto: &str,
        port: u16,
        group_size: Option<usize>,
        now: i64,
        policy: &ProfilePolicy,
    ) -> ProfileVerdict {
        let key = habit_key(peer, proto, port);
        let profile = self.hosts.get(host);
        if let Some(habit) = profile.and_then(|p| p.habits.get(&key)) {
            if habit.tainted {
                return ProfileVerdict::Unknown("dvojice mela poplach, neuci se".into());
            }
            if let Some(since) = habit.established {
                return ProfileVerdict::Established {
                    since,
                    days: habit.days,
                };
            }
        }
        let fleet = self.established_index.get(&key).copied().unwrap_or(0);
        let share_ok = match group_size {
            Some(size) if size > 0 => fleet as f64 / size as f64 >= policy.fleet_share,
            _ => fleet as f64 / self.hosts.len().max(1) as f64 >= policy.fleet_share / 3.0,
        };
        if fleet >= policy.fleet_min && share_ok {
            return ProfileVerdict::Fleet { hosts: fleet };
        }
        match profile {
            None => ProfileVerdict::Unknown("bez profilu hostu".into()),
            Some(p) if now - p.first >= policy.mature_s => {
                let seen = p.habits.get(&key).is_some_and(|h| h.days >= 2);
                if seen {
                    ProfileVerdict::Unknown("kandidat zvyku, jeste nezavedeny".into())
                } else {
                    ProfileVerdict::NewForMature {
                        profile_days: (now - p.first) as f64 / 86_400.0,
                    }
                }
            }
            Some(_) => ProfileVerdict::Unknown("profil hostu jeste nezraly".into()),
        }
    }
}

/// Dvojice (aktér, protistrana, protokol, port) případu žebříku pro dotaz na profil:
/// behaviorální nález = aktér je entita a protistrana cíl ze služby (`out/<cíl>/..`,
/// `chain/<další hop>/..`), u flotily první zdroj; nález na službě s jediným zdrojem =
/// aktér je zdroj a protistrana cílová služba. Jinak `None` (profil nic neříká).
pub fn case_pair(case: &crate::verify_ladder::CaseInput) -> Option<(String, String, String, u16)> {
    let service = case.key.service.split('#').next().unwrap_or("");
    let mut parts = service.rsplit('/');
    let port: u16 = parts.next()?.parse().ok()?;
    let proto = parts.next()?.to_string();
    if crate::behavior::is_behavior_type(&case.finding_type) {
        let segments: Vec<&str> = service.split('/').collect();
        let peer = match segments.as_slice() {
            [_, peer, _, _] if *peer != "fleet" => peer.to_string(),
            _ => case.sources.first()?.clone(),
        };
        Some((case.host_ip.clone(), peer, proto, port))
    } else if case.sources.len() == 1 {
        Some((case.sources[0].clone(), case.host_ip.clone(), proto, port))
    } else {
        None
    }
}

/// Verdikt profilu pro případ žebříku (společné pro soak i produkci).
pub fn case_verdict(
    profiles: &HostProfiles,
    policy: &ProfilePolicy,
    case: &crate::verify_ladder::CaseInput,
    group_size: Option<usize>,
    now: i64,
) -> ProfileVerdict {
    if case.finding_type == "unexpected_traffic"
        && case.sources.len() != 1
        && let Some(verdict) = service_habit_verdict(profiles, policy, case)
    {
        return verdict;
    }
    let Some((actor, peer, proto, port)) = case_pair(case) else {
        return ProfileVerdict::Unknown("pripad nema jednu dvojici host-cil".into());
    };
    profiles.verdict(&actor, &peer, &proto, port, group_size, now, policy)
}

/// Krok 4 (3b, pozitivní důkaz neškodnosti): neočekávaný provoz na službu mimo inventář
/// s více klienty. Když je spojení na tuto službu zavedený zvyk všech dominantních
/// zdrojů, nebo (bez dominantního zdroje) aspoň `fleet_min` hostů, služba běží dlouho
/// a nález vysvětluje zastaralý inventář, ne nový port (A08). Zvyk vzniká jen ze
/// spojení bez poplachu, po opakování a stáří (viz modul), takže krátký útok ho nevytvoří.
fn service_habit_verdict(
    profiles: &HostProfiles,
    policy: &ProfilePolicy,
    case: &crate::verify_ladder::CaseInput,
) -> Option<ProfileVerdict> {
    let service = case.key.service.split('#').next().unwrap_or("");
    let mut parts = service.rsplit('/');
    let port: u16 = parts.next()?.parse().ok()?;
    let proto = parts.next()?;
    let key = habit_key(&case.host_ip, proto, port);
    if case.sources.is_empty() {
        let hosts = profiles.established_index.get(&key).copied().unwrap_or(0);
        return (hosts >= policy.fleet_min).then_some(ProfileVerdict::Fleet { hosts });
    }
    let mut since = i64::MIN;
    let mut days = u16::MAX;
    for source in &case.sources {
        let habit = profiles.hosts.get(source)?.habits.get(&key)?;
        if habit.tainted {
            return None;
        }
        since = since.max(habit.established?);
        days = days.min(habit.days);
    }
    Some(ProfileVerdict::Established { since, days })
}

/// Dvojice s poplachem v okně (neučí se do profilu, RQ2 Z3): aktér a každý zdroj
/// nálezu v obou směrech (`ip|peer`).
pub fn frozen_pairs<'a>(items: impl Iterator<Item = (&'a str, &'a [String])>) -> HashSet<String> {
    let mut frozen = HashSet::new();
    for (host, sources) in items {
        frozen.insert(host.to_string());
        for source in sources {
            frozen.insert(format!("{host}|{source}"));
            frozen.insert(format!("{source}|{host}"));
        }
    }
    frozen
}

fn decrement(index: &mut HashMap<String, u32>, key: &str) {
    if let Some(n) = index.get_mut(key) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            index.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    /// Krok 7 (A2): dvojice s poplachem (novost, graf) se nestane zvykem ani přes strop
    /// zvyků, zametání a serializaci; poznámka vydrží `forget_s` od posledního výskytu.
    #[test]
    fn property_tainted_pairs_never_become_habits() {
        let policy = ProfilePolicy {
            keep_tainted: true,
            max_habits_per_host: 10,
            ..ProfilePolicy::default()
        };
        for seed in 1..=20u64 {
            let mut state = seed.wrapping_mul(0x2545_F491_4F6C_DD1D) | 1;
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let mut p = HostProfiles::default();
            let mut tainted: HashMap<String, i64> = HashMap::new();
            let t0 = 1_700_006_400;
            for w in 0..(12 * 48) {
                let at = t0 + w * 1800;
                let flows: Vec<ConnectionObservation> = (0..6)
                    .map(|i| {
                        let peer = format!("198.51.100.{}", (next() % 24) + i);
                        conn("10.0.0.5", &peer, 443, at)
                    })
                    .collect();
                let mut frozen = HashSet::new();
                for flow in &flows {
                    // poplach jen u peti dvojic (pod stropem), ostatni tlaci na strop
                    let index: u64 = flow.dst_ip.rsplit('.').next().unwrap().parse().unwrap();
                    if index < 5 && next() % 4 == 0 {
                        frozen.insert(format!("10.0.0.5|{}", flow.dst_ip));
                        tainted.insert(flow.dst_ip.clone(), at);
                    }
                }
                for flow in &flows {
                    if tainted.contains_key(&flow.dst_ip) {
                        tainted.insert(flow.dst_ip.clone(), at);
                    }
                }
                p.learn(flows.iter(), &frozen, at, &policy);
                if next() % 7 == 0 {
                    p = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
                }
                for (peer, last) in &tainted {
                    let verdict = p.verdict("10.0.0.5", peer, "tcp", 443, None, at, &policy);
                    assert!(
                        !matches!(verdict, ProfileVerdict::Established { .. }),
                        "seed {seed}: {peer} se stal zvykem"
                    );
                    if at - last <= policy.forget_s {
                        assert!(
                            p.knows("10.0.0.5", peer, "tcp", 443),
                            "seed {seed}: poznamka {peer} ztracena"
                        );
                    }
                }
            }
        }
    }

    fn conn(src: &str, dst: &str, port: u16, at: i64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(at, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: Some(1.0),
            orig_bytes: Some(300),
            resp_bytes: Some(300),
            total_bytes: Some(600),
            orig_pkts: Some(2),
            resp_pkts: Some(2),
            total_pkts: Some(4),
            conn_state: Some("SF".to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    fn feed(
        p: &mut HostProfiles,
        src: &str,
        dst: &str,
        days: i64,
        per_day: i64,
        frozen: &HashSet<String>,
        policy: &ProfilePolicy,
    ) {
        for d in 0..days {
            for k in 0..per_day {
                let at = 1_700_006_400 + d * 86_400 + k * 1800;
                p.learn([conn(src, dst, 443, at)].iter(), frozen, at, policy);
            }
        }
    }

    #[test]
    fn habit_needs_repetition_and_age_before_it_is_benign_evidence() {
        let policy = ProfilePolicy::default();
        let mut p = HostProfiles::default();
        let none = HashSet::new();
        feed(&mut p, "10.0.0.5", "203.0.113.4", 2, 10, &none, &policy);
        let now = 1_700_006_400 + 2 * 86_400;
        assert!(matches!(
            p.verdict("10.0.0.5", "203.0.113.4", "tcp", 443, None, now, &policy),
            ProfileVerdict::Unknown(_)
        ));
        feed(&mut p, "10.0.0.5", "203.0.113.4", 4, 10, &none, &policy);
        let now = 1_700_006_400 + 4 * 86_400;
        assert!(matches!(
            p.verdict("10.0.0.5", "203.0.113.4", "tcp", 443, None, now, &policy),
            ProfileVerdict::Established { .. }
        ));
        assert_eq!(p.promotions, 1);
        assert_eq!(p.audit.len(), 1);
        assert_eq!(p.audit[0].host, "10.0.0.5");
    }

    #[test]
    fn alarmed_pair_is_tainted_and_never_promoted() {
        let policy = ProfilePolicy::default();
        let mut p = HostProfiles::default();
        let frozen: HashSet<String> = ["10.0.0.5|203.0.113.4".to_string()].into();
        feed(&mut p, "10.0.0.5", "203.0.113.4", 1, 2, &frozen, &policy);
        feed(
            &mut p,
            "10.0.0.5",
            "203.0.113.4",
            8,
            10,
            &HashSet::new(),
            &policy,
        );
        let now = 1_700_006_400 + 8 * 86_400;
        assert!(matches!(
            p.verdict("10.0.0.5", "203.0.113.4", "tcp", 443, None, now, &policy),
            ProfileVerdict::Unknown(r) if r.contains("poplach")
        ));
        assert_eq!(p.promotions, 0);
    }

    #[test]
    fn promotions_are_rate_limited_per_host_and_day() {
        let policy = ProfilePolicy {
            max_promotions_per_host_day: 2,
            ..Default::default()
        };
        let mut p = HostProfiles::default();
        for d in 0..4i64 {
            for k in 0..8i64 {
                let at = 1_700_006_400 + d * 86_400 + k * 1800;
                let flows: Vec<_> = (0..5)
                    .map(|i| conn("10.0.0.5", &format!("203.0.113.{i}"), 443, at))
                    .collect();
                p.learn(flows.iter(), &HashSet::new(), at, &policy);
            }
        }
        // ctvrty den splni podminky vsech 5 zvyku, povysit smi jen 2
        assert_eq!(p.promotions, 2);
        assert!(p.rate_limited >= 3);
    }

    /// Krok 4 (3b): neočekávaný provoz na dlouho používanou službu mimo inventář má
    /// pozitivní důkaz z profilu klientů; nový port bez zvyku ne.
    #[test]
    fn unexpected_traffic_on_long_standing_service_is_benign_evidence() {
        use crate::finding_memory::FindingKey;
        let policy = ProfilePolicy::default();
        let mut p = HostProfiles::default();
        for i in 1..=4 {
            feed(
                &mut p,
                &format!("10.0.0.{i}"),
                "10.0.0.9",
                6,
                6,
                &HashSet::new(),
                &policy,
            );
        }
        let now = 1_700_006_400 + 6 * 86_400;
        let case = |sources: &[&str], port: u16| crate::verify_ladder::CaseInput {
            key: FindingKey::new("10.0.0.9", "unexpected_traffic", &format!("tcp/{port}")),
            finding_id: "finding:unexpected_traffic:10.0.0.9".into(),
            finding_type: "unexpected_traffic".into(),
            host_ip: "10.0.0.9".into(),
            port: Some(port),
            sources: sources.iter().map(|s| s.to_string()).collect(),
            volume: 10.0,
            history_key: None,
            high_impact: false,
            prior: 0.15,
            protected: false,
        };
        assert_eq!(
            case_verdict(&p, &policy, &case(&[], 443), None, now),
            ProfileVerdict::Fleet { hosts: 4 }
        );
        assert!(matches!(
            case_verdict(
                &p,
                &policy,
                &case(&["10.0.0.1", "10.0.0.2"], 443),
                None,
                now
            ),
            ProfileVerdict::Established { .. }
        ));
        // jeden ze zdroju bez zvyku: nic neplyne
        assert!(matches!(
            case_verdict(
                &p,
                &policy,
                &case(&["10.0.0.1", "10.0.0.7"], 443),
                None,
                now
            ),
            ProfileVerdict::Unknown(_)
        ));
        // jiny port: zadny zvyk
        assert!(matches!(
            case_verdict(&p, &policy, &case(&[], 8443), None, now),
            ProfileVerdict::Unknown(_)
        ));
    }

    #[test]
    fn fleet_and_new_for_mature_host_verdicts() {
        let policy = ProfilePolicy::default();
        let mut p = HostProfiles::default();
        for i in 1..=4 {
            feed(
                &mut p,
                &format!("10.0.0.{i}"),
                "198.51.100.8",
                6,
                6,
                &HashSet::new(),
                &policy,
            );
        }
        let now = 1_700_006_400 + 6 * 86_400;
        // novy host flotily: zvyk zavedeny u 4 z 10 hostu skupiny
        assert_eq!(
            p.verdict(
                "10.0.0.9",
                "198.51.100.8",
                "tcp",
                443,
                Some(10),
                now,
                &policy
            ),
            ProfileVerdict::Fleet { hosts: 4 }
        );
        assert!(matches!(
            p.verdict(
                "10.0.0.1",
                "203.0.113.200",
                "tcp",
                4444,
                Some(10),
                now,
                &policy
            ),
            ProfileVerdict::NewForMature { .. }
        ));
        // zapomenuti po 14 dnech bez vyskytu
        p.sweep(now + 15 * 86_400, &policy);
        assert!(matches!(
            p.verdict(
                "10.0.0.1",
                "198.51.100.8",
                "tcp",
                443,
                None,
                now + 15 * 86_400,
                &policy
            ),
            ProfileVerdict::NewForMature { .. }
        ));
    }
}
