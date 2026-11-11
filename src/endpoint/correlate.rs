//! Identita hosta, sklad událostí s limity, verdikt hosta, spojení s toky a pokrytí
//! (krok 8, A1 až A3; studie 08, bod 3).
//!
//! Invarianty:
//! - událost s nejednoznačnou nebo neznámou identitou do verdiktu nevstupuje (ani jako
//!   podezřelá, ani jako neškodná; jen se počítá do pokrytí),
//! - neškodný vzor vyžaduje známý podepsaný proces, pravidelnost a stáří vzoru a
//!   neplatí, jakmile má host jakýkoli podezřelý indikátor,
//! - prázdná telemetrie hosta je `NoCoverage`, nikdy neškodné,
//! - sklad je omezený (události na host, počet hostů, rychlost, stáří, budoucnost).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::model::{Conn, EndpointEvent, EventKind, Logon, Process};

/// Meze nedůvěryhodného vstupu a skladu (předregistrace A2, bod 3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub max_line_bytes: usize,
    pub max_batch_bytes: usize,
    pub max_batch_events: usize,
    pub max_events_per_host: usize,
    pub max_hosts: usize,
    /// Nejvýš událostí jednoho hosta za cyklus (30 min).
    pub max_per_host_cycle: u32,
    pub max_future_s: i64,
    pub max_age_s: i64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line_bytes: 64 * 1024,
            max_batch_bytes: 8 * 1024 * 1024,
            max_batch_events: 50_000,
            max_events_per_host: 4096,
            max_hosts: 20_000,
            max_per_host_cycle: 2000,
            max_future_s: 3600,
            max_age_s: 24 * 3600,
        }
    }
}

// ---------------------------------------------------------------- identita

/// Výsledek přiřazení události hostu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Unique(String),
    Ambiguous(Vec<String>),
    Unknown,
}

/// Adresář hostů z inventáře (klíč hosta = jeho IP, jako klíče nálezů v jádru).
#[derive(Debug, Clone, Default)]
pub struct HostDirectory {
    by_ip: HashMap<String, Vec<String>>,
    by_name: HashMap<String, Vec<String>>,
    by_mac: HashMap<String, Vec<String>>,
    keys: BTreeSet<String>,
}

fn push_unique(map: &mut HashMap<String, Vec<String>>, id: String, key: &str) {
    let list = map.entry(id).or_default();
    if !list.iter().any(|k| k == key) {
        list.push(key.to_string());
    }
}

impl HostDirectory {
    pub fn add(&mut self, key: &str, hostname: Option<&str>, ips: &[String], mac: Option<&str>) {
        self.keys.insert(key.to_string());
        push_unique(&mut self.by_ip, key.to_string(), key);
        for ip in ips {
            push_unique(&mut self.by_ip, ip.clone(), key);
        }
        if let Some(name) = hostname.filter(|n| !n.is_empty()) {
            push_unique(&mut self.by_name, name.to_ascii_lowercase(), key);
        }
        if let Some(mac) = mac.filter(|m| !m.is_empty()) {
            push_unique(
                &mut self.by_mac,
                mac.to_ascii_lowercase().replace('-', ":"),
                key,
            );
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Host je v inventáři (události hostů, které z něj zmizely, se nehodnotí).
    pub fn contains(&self, key: &str) -> bool {
        self.keys.contains(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.keys.iter()
    }

    /// Jednoznačná shoda aspoň jednoho identifikátoru bez sporu mezi identifikátory.
    pub fn resolve(&self, host: &super::model::HostRef) -> Resolution {
        let mut sets: Vec<&Vec<String>> = Vec::new();
        if let Some(name) = &host.hostname
            && let Some(list) = self.by_name.get(&name.to_ascii_lowercase())
        {
            sets.push(list);
        }
        for ip in &host.ips {
            if let Some(list) = self.by_ip.get(ip) {
                sets.push(list);
            }
        }
        for mac in &host.macs {
            if let Some(list) = self.by_mac.get(&mac.to_ascii_lowercase().replace('-', ":")) {
                sets.push(list);
            }
        }
        let Some(first) = sets.first() else {
            return Resolution::Unknown;
        };
        if first.len() == 1 && sets.iter().all(|s| s.len() == 1 && s[0] == first[0]) {
            return Resolution::Unique(first[0].clone());
        }
        let mut all: Vec<String> = sets.iter().flat_map(|s| s.iter().cloned()).collect();
        all.sort();
        all.dedup();
        Resolution::Ambiguous(all)
    }
}

// ------------------------------------------------------------------- sklad

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Accepted,
    Duplicate,
    RateLimited,
    TooOld,
    Future,
    Ambiguous,
    Unknown,
    HostCap,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IngestStats {
    pub accepted: u64,
    pub duplicates: u64,
    pub rate_limited: u64,
    pub too_old: u64,
    pub future: u64,
    pub ambiguous: u64,
    pub unknown: u64,
    pub host_cap: u64,
    pub evicted: u64,
}

#[derive(Debug, Clone, Default)]
struct HostLog {
    events: VecDeque<EndpointEvent>,
    seen: HashSet<u64>,
    bucket: (i64, u32),
}

/// Sklad událostí po hostech (klíč hosta z `HostDirectory`).
#[derive(Debug, Clone, Default)]
pub struct EndpointStore {
    pub limits: Limits,
    hosts: HashMap<String, HostLog>,
    pub stats: IngestStats,
    /// Počty událostí s neřešitelnou identitou za poslední okno (pokrytí).
    pub ambiguous_hosts: BTreeSet<String>,
}

impl EndpointStore {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            ..Default::default()
        }
    }

    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    pub fn event_count(&self) -> usize {
        self.hosts.values().map(|h| h.events.len()).sum()
    }

    /// Přijme jednu událost. `now` = čas příjmu (epocha, s).
    pub fn ingest(&mut self, event: EndpointEvent, resolution: &Resolution, now: i64) -> Outcome {
        let key = match resolution {
            Resolution::Unique(key) => key,
            Resolution::Ambiguous(_) => {
                self.stats.ambiguous += 1;
                if let Some(name) = &event.host.hostname {
                    if self.ambiguous_hosts.len() < 1024 {
                        self.ambiguous_hosts.insert(name.clone());
                    }
                }
                return Outcome::Ambiguous;
            }
            Resolution::Unknown => {
                self.stats.unknown += 1;
                return Outcome::Unknown;
            }
        };
        if event.ts > now + self.limits.max_future_s {
            self.stats.future += 1;
            return Outcome::Future;
        }
        if event.ts < now - self.limits.max_age_s {
            self.stats.too_old += 1;
            return Outcome::TooOld;
        }
        if !self.hosts.contains_key(key) && self.hosts.len() >= self.limits.max_hosts {
            self.stats.host_cap += 1;
            return Outcome::HostCap;
        }
        let limits = self.limits.clone();
        let log = self.hosts.entry(key.clone()).or_default();
        let fingerprint = event.fingerprint();
        if log.seen.contains(&fingerprint) {
            self.stats.duplicates += 1;
            return Outcome::Duplicate;
        }
        let bucket = now.div_euclid(1800);
        if log.bucket.0 != bucket {
            log.bucket = (bucket, 0);
        }
        if log.bucket.1 >= limits.max_per_host_cycle {
            self.stats.rate_limited += 1;
            return Outcome::RateLimited;
        }
        log.bucket.1 += 1;
        log.seen.insert(fingerprint);
        // řazení podle času události (příchod bývá zpožděný a promíchaný)
        let at = log.events.partition_point(|e| e.ts <= event.ts);
        log.events.insert(at, event);
        while log.events.len() > limits.max_events_per_host {
            if let Some(old) = log.events.pop_front() {
                log.seen.remove(&old.fingerprint());
                self.stats.evicted += 1;
            }
        }
        self.stats.accepted += 1;
        Outcome::Accepted
    }

    /// Zahodí události starší než `max_age_s` a prázdné hosty.
    pub fn prune(&mut self, now: i64) {
        let cutoff = now - self.limits.max_age_s;
        for log in self.hosts.values_mut() {
            while log.events.front().is_some_and(|e| e.ts < cutoff) {
                if let Some(old) = log.events.pop_front() {
                    log.seen.remove(&old.fingerprint());
                }
            }
        }
        self.hosts.retain(|_, log| !log.events.is_empty());
    }

    pub fn events_of(&self, host: &str) -> impl Iterator<Item = &EndpointEvent> {
        self.hosts
            .get(host)
            .into_iter()
            .flat_map(|l| l.events.iter())
    }

    pub fn hosts(&self) -> impl Iterator<Item = &String> {
        self.hosts.keys()
    }
}

// ------------------------------------------------------------------ politika

/// Seznamy a prahy pravidel (volba autora, nejsou odhadnuté z dat; viz studie 08).
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// Okno verdiktu (periodicita potřebuje delší okno než jeden cyklus).
    pub lookback_s: i64,
    /// Host má živého agenta, když poslal událost v tomto okně.
    pub alive_s: i64,
    pub min_samples: usize,
    pub max_cv: f64,
    /// Neškodný vzor musí trvat aspoň tak dlouho (první až poslední vzorek).
    pub pattern_age_s: i64,
    pub threshold: u32,
    pub known_vendors: Vec<&'static str>,
    pub system_prefixes: Vec<&'static str>,
    pub writable_markers: Vec<&'static str>,
    pub server_procs: Vec<&'static str>,
    pub shells: Vec<&'static str>,
    pub remote_exec_tools: Vec<&'static str>,
    pub critical_paths: Vec<&'static str>,
    pub fail_burst: usize,
    pub lr_suspicious: f64,
    pub lr_benign: f64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            lookback_s: 12 * 3600,
            alive_s: 6 * 3600,
            min_samples: 6,
            max_cv: 0.2,
            pattern_age_s: 6 * 3600,
            threshold: 3,
            known_vendors: vec![
                "microsoft",
                "google",
                "mozilla",
                "adobe",
                "veeam",
                "vmware",
                "apple",
                "canonical",
                "red hat",
                "eset",
                "crowdstrike",
                "dell",
                "intel",
                "zoom",
            ],
            system_prefixes: vec![
                "c:\\windows\\system32\\",
                "c:\\windows\\syswow64\\",
                "c:\\program files\\",
                "c:\\program files (x86)\\",
            ],
            writable_markers: vec![
                "\\temp\\",
                "\\appdata\\",
                "\\users\\public\\",
                "\\downloads\\",
                "/tmp/",
                "/dev/shm/",
                "/var/tmp/",
            ],
            server_procs: vec![
                "w3wp.exe",
                "httpd.exe",
                "nginx.exe",
                "tomcat9.exe",
                "php-cgi.exe",
                "httpd",
                "nginx",
                "apache2",
                "php-fpm",
                "java",
                "tomcat",
                "sqlservr.exe",
            ],
            shells: vec![
                "cmd.exe",
                "powershell.exe",
                "pwsh.exe",
                "sh",
                "bash",
                "dash",
                "wscript.exe",
                "cscript.exe",
            ],
            remote_exec_tools: vec![
                "psexec.exe",
                "psexec64.exe",
                "paexec.exe",
                "psexesvc.exe",
                "winrs.exe",
            ],
            critical_paths: vec![
                "/etc/passwd",
                "/etc/shadow",
                "authorized_keys",
                "\\windows\\system32\\",
                "/etc/cron",
            ],
            fail_burst: 10,
            lr_suspicious: 12.0,
            lr_benign: 0.3,
        }
    }
}

fn base(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

impl Policy {
    fn writable(&self, image: &str) -> bool {
        let lower = image.to_ascii_lowercase();
        self.writable_markers.iter().any(|m| lower.contains(m))
    }

    /// Známý podepsaný proces: výslovný podpis, nebo systémová cesta + známý výrobce
    /// (Windows), nebo cesta správce balíčků (Unix). Zapisovatelná cesta nikdy.
    pub fn known_signed(&self, image: &str, vendor: Option<&str>, signed: Option<bool>) -> bool {
        if signed == Some(false) || self.writable(image) {
            return false;
        }
        let lower = image.to_ascii_lowercase();
        let in_system = self.system_prefixes.iter().any(|p| lower.starts_with(p));
        let unix_pkg = ["/usr/", "/bin/", "/sbin/", "/lib/"]
            .iter()
            .any(|p| lower.starts_with(p));
        let vendor_ok = vendor.is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            self.known_vendors.iter().any(|k| v.contains(k))
        });
        match signed {
            Some(true) => in_system || unix_pkg || vendor_ok,
            _ => unix_pkg || (in_system && vendor_ok),
        }
    }
}

// ------------------------------------------------------------------ verdikt

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub code: &'static str,
    pub weight: u32,
    pub detail: String,
    /// Protistrana (cíl spojení, zdroj přihlášení), pokud je.
    pub peer: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HostAssessment {
    pub host: String,
    pub score: u32,
    pub indicators: Vec<Indicator>,
    /// Protistrana -> důvod: pravidelné spojení známého podepsaného procesu.
    pub benign_peers: BTreeMap<(String, u16), String>,
    pub events: usize,
    pub last_event: i64,
}

impl HostAssessment {
    pub fn suspicious(&self, policy: &Policy) -> bool {
        self.score >= policy.threshold
    }

    pub fn reasons(&self) -> String {
        self.indicators
            .iter()
            .map(|i| format!("{}: {}", i.code, i.detail))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn cv(intervals: &[f64]) -> f64 {
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return f64::INFINITY;
    }
    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    var.sqrt() / mean
}

fn shell_child(policy: &Policy, p: &Process) -> Option<&'static str> {
    let child = base(&p.image);
    let parent = base(p.parent_image.as_deref()?);
    if policy.server_procs.iter().any(|s| *s == parent) && policy.shells.iter().any(|s| *s == child)
    {
        return Some("web_shell_spawn");
    }
    None
}

fn suspicious_cmdline(cmd: &str) -> bool {
    let c = cmd.to_ascii_lowercase();
    c.contains(" -enc ")
        || c.contains("-encodedcommand")
        || c.contains("frombase64string")
        || (c.contains("certutil") && c.contains("-urlcache"))
        || c.contains("bitsadmin /transfer")
        || (c.contains("curl ") || c.contains("wget "))
            && (c.contains("| sh") || c.contains("| bash"))
}

/// Verdikt hosta z událostí v okně `[now - lookback, now]`.
pub fn assess(
    host: &str,
    events: impl Iterator<Item = impl std::borrow::Borrow<EndpointEvent>>,
    now: i64,
    policy: &Policy,
) -> HostAssessment {
    let from = now - policy.lookback_s;
    let mut out = HostAssessment {
        host: host.to_string(),
        ..Default::default()
    };
    let mut seen_codes: HashSet<(&'static str, String)> = HashSet::new();
    let mut add = |out: &mut HostAssessment,
                   code: &'static str,
                   weight: u32,
                   detail: String,
                   peer: Option<String>| {
        if seen_codes.insert((code, detail.clone())) {
            out.score += weight;
            out.indicators.push(Indicator {
                code,
                weight,
                detail,
                peer,
            });
        }
    };
    let mut conns: BTreeMap<(String, String, u16, bool), (Vec<i64>, bool, Option<String>)> =
        BTreeMap::new();
    let mut fails: BTreeMap<String, usize> = BTreeMap::new();
    let mut remote_logons: Vec<(i64, String, Option<String>)> = Vec::new();
    let mut remote_exec: Vec<i64> = Vec::new();
    for event in events {
        let event = event.borrow();
        if event.ts < from || event.ts > now + 1 {
            continue;
        }
        out.events += 1;
        out.last_event = out.last_event.max(event.ts);
        match &event.kind {
            EventKind::ProcessCreate(p) => {
                if let Some(code) = shell_child(policy, p) {
                    add(
                        &mut out,
                        code,
                        3,
                        format!(
                            "{} z {}",
                            base(&p.image),
                            p.parent_image.as_deref().map(base).unwrap_or_default()
                        ),
                        None,
                    );
                }
                if suspicious_cmdline(&p.cmdline) {
                    add(&mut out, "encoded_or_download_cmd", 3, base(&p.image), None);
                }
                if policy.writable(&p.image)
                    && !policy.known_signed(&p.image, p.vendor.as_deref(), p.signed)
                {
                    add(
                        &mut out,
                        "unsigned_from_writable_path",
                        2,
                        p.image.clone(),
                        None,
                    );
                }
                if policy
                    .remote_exec_tools
                    .iter()
                    .any(|t| *t == base(&p.image))
                {
                    add(&mut out, "remote_exec_tool", 2, base(&p.image), None);
                    remote_exec.push(event.ts);
                }
                if let Some(parent) = p.parent_image.as_deref().map(base)
                    && matches!(
                        parent.as_str(),
                        "wmiprvse.exe" | "winrshost.exe" | "psexesvc.exe"
                    )
                {
                    remote_exec.push(event.ts);
                }
            }
            EventKind::ProcessAccess { source, target, .. } => {
                if base(target) == "lsass.exe" && !policy.known_signed(source, None, None) {
                    add(&mut out, "lsass_access", 3, base(source), None);
                }
            }
            EventKind::ServiceInstall {
                name,
                image,
                signed,
            } => {
                let lower = image.to_ascii_lowercase();
                if policy.writable(image) || lower.contains("cmd /c") || lower.contains("%comspec%")
                {
                    add(&mut out, "service_unsigned", 3, name.clone(), None);
                    remote_exec.push(event.ts);
                } else if !policy.known_signed(image, None, *signed) {
                    add(&mut out, "service_unknown", 2, name.clone(), None);
                    remote_exec.push(event.ts);
                }
            }
            EventKind::Persistence {
                target,
                image,
                signed,
                ..
            } => {
                let img = image.as_deref().unwrap_or(target);
                if policy.writable(target) || policy.writable(img) {
                    add(&mut out, "persistence_writable", 2, target.clone(), None);
                } else if image
                    .as_deref()
                    .is_some_and(|i| signed == &Some(false) && !i.is_empty())
                {
                    add(&mut out, "persistence_unsigned", 2, target.clone(), None);
                }
            }
            EventKind::Integrity { path, change } => {
                let lower = path.to_ascii_lowercase();
                if policy.critical_paths.iter().any(|c| lower.contains(c)) {
                    add(
                        &mut out,
                        "critical_file_change",
                        2,
                        format!("{change} {path}"),
                        None,
                    );
                }
            }
            EventKind::Alert {
                rule_id,
                level,
                description,
                ..
            } => {
                if *level >= 10 {
                    add(
                        &mut out,
                        "ids_rule_high",
                        3,
                        format!("{rule_id}: {description}"),
                        None,
                    );
                } else if *level >= 7 {
                    add(
                        &mut out,
                        "ids_rule_medium",
                        2,
                        format!("{rule_id}: {description}"),
                        None,
                    );
                }
            }
            EventKind::Logon(Logon {
                user,
                logon_type,
                src_ip,
                success,
            }) => {
                if !success {
                    *fails.entry(src_ip.clone().unwrap_or_default()).or_default() += 1;
                } else if matches!(logon_type, 3 | 10) || (*logon_type == 0 && src_ip.is_some()) {
                    remote_logons.push((event.ts, user.clone(), src_ip.clone()));
                }
            }
            EventKind::NetConnect(Conn {
                image,
                dst_ip,
                dst_port,
                vendor,
                signed,
                ..
            }) => {
                let img = image.clone().unwrap_or_default();
                let known =
                    !img.is_empty() && policy.known_signed(&img, vendor.as_deref(), *signed);
                let entry = conns
                    .entry((img.clone(), dst_ip.clone(), *dst_port, known))
                    .or_insert_with(|| (Vec::new(), policy.writable(&img), None));
                entry.0.push(event.ts);
            }
            EventKind::FileCreate { .. } => {}
        }
    }
    for (src, n) in fails {
        if n >= policy.fail_burst {
            let peer = (!src.is_empty()).then_some(src.clone());
            add(&mut out, "logon_failures", 2, format!("{n}x z {src}"), peer);
        }
    }
    // vzdálené přihlášení těsně před vzdáleným spuštěním (pohyb do stran)
    for (t, user, src) in &remote_logons {
        if remote_exec.iter().any(|e| *e >= *t && *e - *t <= 600) {
            add(
                &mut out,
                "lateral_remote_exec",
                3,
                format!("{user} z {}", src.clone().unwrap_or_default()),
                src.clone(),
            );
        }
    }
    for ((image, dst, dport, known), (mut times, writable, _)) in conns {
        if times.len() < policy.min_samples {
            continue;
        }
        times.sort_unstable();
        let intervals: Vec<f64> = times.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
        if intervals.is_empty() || cv(&intervals) > policy.max_cv {
            continue;
        }
        let span = times[times.len() - 1] - times[0];
        if known {
            if span >= policy.pattern_age_s {
                out.benign_peers.insert(
                    (dst.clone(), dport),
                    format!(
                        "{} spojuje pravidelne ({} vzorku za {} h)",
                        base(&image),
                        times.len(),
                        span / 3600
                    ),
                );
            }
        } else {
            // pravidelne spojeni nepodepsaneho procesu z bezne cesty je slaby rys (vlastni
            // software), ze zapisovatelne cesty (docasne slozky) silny; slaby se pocita
            // jednou na obraz, ne na kazdou protistranu
            let (weight, detail) = if writable {
                (
                    3,
                    format!("{} -> {dst}:{dport} ({}x)", base(&image), times.len()),
                )
            } else {
                (1, base(&image))
            };
            add(
                &mut out,
                "periodic_unsigned_connection",
                weight,
                detail,
                Some(dst),
            );
        }
    }
    // podezřelý host nemá neškodný vzor (spoofing: útočník nesmí „ukrýt“ aktivitu)
    if out.score > 0 {
        out.benign_peers.clear();
    }
    out
}

// ------------------------------------------------------------------ pohled

/// Signál koncové telemetrie pro případ žebříku.
#[derive(Debug, Clone, PartialEq)]
pub enum EndpointSignal {
    Suspicious(String),
    Benign(String),
    /// Host je pokrytý, ale nic relevantního (nezjištěno).
    NoSignal(String),
    /// Host bez živého agenta (nedostupné, ne neškodné).
    NoCoverage(String),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EndpointCoverage {
    pub hosts_total: usize,
    pub hosts_covered: usize,
    pub hosts_silent: usize,
    pub covered_percent: f64,
    pub ambiguous_events: u64,
    pub unknown_events: u64,
    pub accepted_events: u64,
    pub duplicates: u64,
    pub rate_limited: u64,
}

/// Verdikty hostů v jednom cyklu.
#[derive(Debug, Clone, Default)]
pub struct EndpointView {
    pub policy: Policy,
    assessments: HashMap<String, HostAssessment>,
    covered: HashSet<String>,
    pub coverage: EndpointCoverage,
}

impl EndpointView {
    pub fn build(
        store: &EndpointStore,
        directory: &HostDirectory,
        now: i64,
        policy: &Policy,
    ) -> Self {
        let mut assessments = HashMap::new();
        let mut covered = HashSet::new();
        let mut silent = 0usize;
        for host in store.hosts() {
            if !directory.contains(host) {
                continue;
            }
            let a = assess(host, store.events_of(host), now, policy);
            if now - a.last_event <= policy.alive_s && a.events > 0 {
                covered.insert(host.clone());
            } else {
                silent += 1;
            }
            assessments.insert(host.clone(), a);
        }
        let total = directory.len();
        let coverage = EndpointCoverage {
            hosts_total: total,
            hosts_covered: covered.len(),
            hosts_silent: silent,
            covered_percent: if total == 0 {
                0.0
            } else {
                100.0 * covered.len() as f64 / total as f64
            },
            ambiguous_events: store.stats.ambiguous,
            unknown_events: store.stats.unknown,
            accepted_events: store.stats.accepted,
            duplicates: store.stats.duplicates,
            rate_limited: store.stats.rate_limited,
        };
        Self {
            policy: policy.clone(),
            assessments,
            covered,
            coverage,
        }
    }

    pub fn covered(&self, host: &str) -> bool {
        self.covered.contains(host)
    }

    pub fn assessment(&self, host: &str) -> Option<&HostAssessment> {
        self.assessments.get(host)
    }

    /// Hosté s podezřelým verdiktem (pro samostatné nálezy `endpoint_alert`).
    pub fn suspicious_hosts(&self) -> Vec<&HostAssessment> {
        let mut list: Vec<&HostAssessment> = self
            .assessments
            .values()
            .filter(|a| self.covered.contains(&a.host) && a.suspicious(&self.policy))
            .collect();
        list.sort_by(|a, b| a.host.cmp(&b.host));
        list
    }

    /// Signál pro případ: host nálezu a dominantní zdroje.
    pub fn signal(&self, host_ip: &str, port: Option<u16>, sources: &[String]) -> EndpointSignal {
        let mut hosts: Vec<&str> = vec![host_ip];
        hosts.extend(sources.iter().map(String::as_str));
        // podezřelý proces kdekoli na souvisejícím pokrytém hostu zvyšuje jistotu
        for h in &hosts {
            if self.covered.contains(*h)
                && let Some(a) = self.assessments.get(*h)
                && a.suspicious(&self.policy)
            {
                return EndpointSignal::Suspicious(format!("{h}: {}", a.reasons()));
            }
        }
        if !self.covered.contains(host_ip) && !sources.iter().any(|s| self.covered.contains(s)) {
            return EndpointSignal::NoCoverage(format!(
                "host {host_ip} nema zivou koncovou telemetrii"
            ));
        }
        // neškodné: každý zdroj má vysvětlení (vlastní agent nebo agent cíle)
        if !sources.is_empty() {
            // neškodný vzor musí sedět na port nálezu (jiná služba téhož páru není vysvětlení)
            let Some(port) = port else {
                return EndpointSignal::NoSignal("nalez bez portu, vzor nelze porovnat".into());
            };
            let target = self
                .assessments
                .get(host_ip)
                .filter(|_| self.covered.contains(host_ip));
            let mut reasons = Vec::new();
            for s in sources {
                let own = self
                    .assessments
                    .get(s)
                    .filter(|_| self.covered.contains(s))
                    .and_then(|a| a.benign_peers.get(&(host_ip.to_string(), port)));
                let via_target = target.and_then(|a| a.benign_peers.get(&(s.clone(), port)));
                match own.or(via_target) {
                    Some(reason) => reasons.push(format!("{s}: {reason}")),
                    None => {
                        return EndpointSignal::NoSignal(
                            "aspon jeden zdroj nema pravidelny podepsany proces".into(),
                        );
                    }
                }
            }
            reasons.truncate(3);
            return EndpointSignal::Benign(reasons.join("; "));
        }
        EndpointSignal::NoSignal("nalez bez zdroje".into())
    }
}

/// Samostatný nález `endpoint_alert` (chráněný typ) z podezřelého hosta: nález,
/// síla signálu a protistrany.
pub fn alert_finding(a: &HostAssessment) -> (crate::model::Finding, u32, Vec<String>) {
    let peers: Vec<String> = a
        .indicators
        .iter()
        .filter_map(|i| i.peer.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let finding = crate::behavior::finding(
        "endpoint_alert",
        &a.host,
        "endpoint",
        if a.score >= 6 {
            crate::model::Severity::High
        } else {
            crate::model::Severity::Medium
        },
        crate::model::Confidence::Medium,
        format!("Podezrela koncova aktivita na hostu {}", a.host),
        format!(
            "Indikatory koncove telemetrie (soucet vah {}): {}",
            a.score,
            a.reasons()
        ),
        peers
            .iter()
            .map(|p| format!("{} <-> {p}", a.host))
            .collect(),
        "Overit proces a uzivatele na hostu; nalez se automaticky nezavira.",
    );
    (finding, a.score, peers)
}

// --------------------------------------------------------- spojení s toky

/// Tok viděný sítí (pro spojení s koncovou událostí).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRef {
    pub src_ip: String,
    pub src_port: Option<u16>,
    pub dst_ip: String,
    pub dst_port: u16,
    pub proto: String,
    pub ts: i64,
}

fn proto_number(proto: &str) -> u8 {
    match proto {
        "udp" => 17,
        _ => 6,
    }
}

/// Klíč spojení: Community ID, když jsou známé oba porty, jinak směrová trojice.
pub fn flow_key(
    proto: &str,
    src: &str,
    sport: Option<u16>,
    dst: &str,
    dport: u16,
) -> Option<String> {
    if let (Some(sp), Ok(s), Ok(d)) = (sport, src.parse(), dst.parse()) {
        return crate::passive::community_id::community_id_v1(s, sp, d, dport, proto_number(proto));
    }
    Some(format!("{proto}|{src}>{dst}:{dport}"))
}

/// Dvojice (index události, index toku, rozdíl času toku a události), jen shoda klíče a
/// čas v toleranci `tol_s`; každý tok a událost nejvýš jednou (nejbližší).
pub fn link_flows(
    events: &[&EndpointEvent],
    flows: &[FlowRef],
    tol_s: i64,
) -> Vec<(usize, usize, i64)> {
    let mut by_key: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, f) in flows.iter().enumerate() {
        if let Some(k) = flow_key(&f.proto, &f.src_ip, f.src_port, &f.dst_ip, f.dst_port) {
            by_key.entry(k).or_default().push(i);
        }
    }
    let mut used: HashSet<usize> = HashSet::new();
    let mut out = Vec::new();
    for (ei, event) in events.iter().enumerate() {
        let EventKind::NetConnect(c) = &event.kind else {
            continue;
        };
        let Some(src) = c.src_ip.as_deref() else {
            continue;
        };
        let Some(k) = flow_key(&c.proto, src, c.src_port, &c.dst_ip, c.dst_port) else {
            continue;
        };
        let best = by_key
            .get(&k)
            .into_iter()
            .flatten()
            .filter(|i| !used.contains(i))
            .map(|i| (*i, flows[*i].ts - event.ts))
            .filter(|(_, d)| d.abs() <= tol_s)
            .min_by_key(|(_, d)| d.abs());
        if let Some((fi, delta)) = best {
            used.insert(fi);
            out.push((ei, fi, delta));
        }
    }
    out
}

/// Odhad posunu hodin agenta z rozdílů spojených dvojic: medián, aspoň 5 dvojic,
/// ořez na ±600 s. `None` = málo dat (posun se neopravuje, platí tolerance).
pub fn estimate_skew(deltas: &[i64]) -> Option<i64> {
    if deltas.len() < 5 {
        return None;
    }
    let mut d = deltas.to_vec();
    d.sort_unstable();
    Some(d[d.len() / 2].clamp(-600, 600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::model::{EndpointSource, HostRef};

    fn ev(ts: i64, kind: EventKind) -> EndpointEvent {
        EndpointEvent {
            source: EndpointSource::Sim,
            host: HostRef {
                hostname: Some("h1".into()),
                ..Default::default()
            },
            ts,
            kind,
        }
    }

    fn conn(
        ts: i64,
        image: &str,
        dst: &str,
        signed: Option<bool>,
        vendor: Option<&str>,
    ) -> EndpointEvent {
        ev(
            ts,
            EventKind::NetConnect(Conn {
                image: Some(image.into()),
                proto: "tcp".into(),
                src_ip: Some("10.0.0.5".into()),
                src_port: None,
                dst_ip: dst.into(),
                dst_port: 443,
                vendor: vendor.map(str::to_string),
                signed,
            }),
        )
    }

    const T0: i64 = 1_800_000_000;

    #[test]
    fn identity_is_unique_ambiguous_or_unknown() {
        let mut dir = HostDirectory::default();
        dir.add(
            "10.0.0.5",
            Some("WS5"),
            &["10.0.0.5".into()],
            Some("aa:bb:cc:00:00:05"),
        );
        dir.add("10.0.0.6", Some("ws6"), &[], None);
        let by_name = HostRef {
            hostname: Some("ws5".into()),
            ..Default::default()
        };
        assert_eq!(dir.resolve(&by_name), Resolution::Unique("10.0.0.5".into()));
        // jméno jednoho hosta a IP druhého = spor, nikdy ne sloučení
        let spoof = HostRef {
            hostname: Some("ws5".into()),
            ips: vec!["10.0.0.6".into()],
            ..Default::default()
        };
        assert!(matches!(dir.resolve(&spoof), Resolution::Ambiguous(_)));
        let other = HostRef {
            hostname: Some("nic".into()),
            ..Default::default()
        };
        assert_eq!(dir.resolve(&other), Resolution::Unknown);
    }

    #[test]
    fn store_dedups_orders_limits_and_rejects_bad_time() {
        let mut store = EndpointStore::new(Limits {
            max_per_host_cycle: 3,
            max_events_per_host: 100,
            ..Limits::default()
        });
        let r = Resolution::Unique("10.0.0.5".into());
        let a = conn(T0 - 100, "x", "1.1.1.1", None, None);
        assert_eq!(store.ingest(a.clone(), &r, T0), Outcome::Accepted);
        assert_eq!(store.ingest(a, &r, T0), Outcome::Duplicate);
        assert_eq!(
            store.ingest(conn(T0 - 300, "x", "1.1.1.1", None, None), &r, T0),
            Outcome::Accepted
        );
        assert_eq!(
            store.ingest(conn(T0 - 200, "x", "1.1.1.1", None, None), &r, T0),
            Outcome::Accepted
        );
        assert_eq!(
            store.ingest(conn(T0 - 50, "x", "1.1.1.1", None, None), &r, T0),
            Outcome::RateLimited
        );
        let order: Vec<i64> = store.events_of("10.0.0.5").map(|e| e.ts).collect();
        assert_eq!(order, vec![T0 - 300, T0 - 200, T0 - 100]);
        let far = conn(T0 + 10_000, "x", "1.1.1.1", None, None);
        assert_eq!(store.ingest(far, &r, T0 + 1800), Outcome::Future);
        let old = conn(T0 - 90_000, "x", "1.1.1.1", None, None);
        assert_eq!(store.ingest(old, &r, T0 + 1800), Outcome::TooOld);
        assert_eq!(
            store.ingest(
                conn(T0, "x", "2.2.2.2", None, None),
                &Resolution::Ambiguous(vec![]),
                T0
            ),
            Outcome::Ambiguous
        );
    }

    #[test]
    fn web_server_spawning_shell_is_suspicious() {
        let p = Policy::default();
        let e = ev(
            T0,
            EventKind::ProcessCreate(Process {
                image: "C:\\Windows\\System32\\cmd.exe".into(),
                parent_image: Some("C:\\inetpub\\w3wp.exe".into()),
                cmdline: "cmd /c whoami".into(),
                user: None,
                signed: None,
                vendor: None,
            }),
        );
        let a = assess("h", [e].iter(), T0 + 10, &p);
        assert!(a.suspicious(&p), "{}", a.reasons());
    }

    #[test]
    fn regular_known_signed_connection_is_benign_only_when_old_and_clean() {
        let p = Policy::default();
        let regular: Vec<EndpointEvent> = (0..16)
            .map(|i| {
                conn(
                    T0 + i * 1800,
                    "C:\\Program Files\\Veeam\\agent.exe",
                    "8.8.8.8",
                    Some(true),
                    Some("Veeam"),
                )
            })
            .collect();
        let now = T0 + 16 * 1800;
        let a = assess("h", regular.iter(), now, &p);
        assert!(
            a.benign_peers.contains_key(&("8.8.8.8".to_string(), 443)),
            "{a:?}"
        );
        assert_eq!(a.score, 0);
        // stejné spojení z nepodepsaného procesu v dočasné složce = podezření, ne neškodné
        let bad: Vec<EndpointEvent> = (0..16)
            .map(|i| {
                conn(
                    T0 + i * 1800,
                    "C:\\Users\\x\\AppData\\Local\\Temp\\u.exe",
                    "8.8.8.8",
                    None,
                    None,
                )
            })
            .collect();
        let b = assess("h", bad.iter(), now, &p);
        assert!(b.benign_peers.is_empty() && b.suspicious(&p), "{b:?}");
        // jakýkoli podezřelý indikátor smaže neškodné vzory téhož hosta
        let mut mixed = regular.clone();
        mixed.extend(bad);
        let m = assess("h", mixed.iter(), now, &p);
        assert!(m.benign_peers.is_empty());
        // krátký vzor (pod stářím) není neškodný
        let short: Vec<EndpointEvent> = (0..8)
            .map(|i| {
                conn(
                    T0 + i * 600,
                    "C:\\Program Files\\Veeam\\agent.exe",
                    "8.8.8.8",
                    Some(true),
                    Some("Veeam"),
                )
            })
            .collect();
        assert!(
            assess("h", short.iter(), T0 + 8 * 600, &p)
                .benign_peers
                .is_empty()
        );
    }

    #[test]
    fn view_never_calls_missing_telemetry_benign() {
        let p = Policy::default();
        let store = EndpointStore::new(Limits::default());
        let mut dir = HostDirectory::default();
        dir.add("10.0.0.5", Some("h"), &[], None);
        let view = EndpointView::build(&store, &dir, T0, &p);
        assert!(matches!(
            view.signal("10.0.0.5", Some(443), &["8.8.8.8".into()]),
            EndpointSignal::NoCoverage(_)
        ));
        assert_eq!(view.coverage.hosts_total, 1);
        assert_eq!(view.coverage.hosts_covered, 0);
    }

    #[test]
    fn flow_linking_tolerates_clock_skew_and_estimates_it() {
        let c = |ts, sport| EndpointEvent {
            source: EndpointSource::Sim,
            host: HostRef::default(),
            ts,
            kind: EventKind::NetConnect(Conn {
                image: None,
                proto: "tcp".into(),
                src_ip: Some("10.0.0.5".into()),
                src_port: Some(sport),
                dst_ip: "1.1.1.1".into(),
                dst_port: 443,
                vendor: None,
                signed: None,
            }),
        };
        let events: Vec<EndpointEvent> = (0..6)
            .map(|i| c(T0 + i * 100 - 40, 40_000 + i as u16))
            .collect();
        let refs: Vec<&EndpointEvent> = events.iter().collect();
        let flows: Vec<FlowRef> = (0..6)
            .map(|i| FlowRef {
                src_ip: "10.0.0.5".into(),
                src_port: Some(40_000 + i as u16),
                dst_ip: "1.1.1.1".into(),
                dst_port: 443,
                proto: "tcp".into(),
                ts: T0 + i * 100,
            })
            .collect();
        let links = link_flows(&refs, &flows, 120);
        assert_eq!(links.len(), 6);
        let deltas: Vec<i64> = links.iter().map(|l| l.2).collect();
        assert_eq!(estimate_skew(&deltas), Some(40));
        assert_eq!(estimate_skew(&deltas[..3]), None);
        assert!(link_flows(&refs, &flows, 10).is_empty());
    }
}
