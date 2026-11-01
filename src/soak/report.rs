//! Reporty soak behu: casova rada (CSV) a markdown souhrn s intervaly spolehlivosti,
//! latencemi, trendem pameti a vsemi invarianty. Cisla v reportu jsou jen to, co
//! beh skutecne zmeril - zadne "dalsi hodnoty na odhad".

use std::fmt::Write as _;

use crate::soak::{
    alloc,
    runner::PersistedState,
    stats::{Aggregate, TTD_BINS, wilson},
};

pub const TIMESERIES_HEADER: &str = "wall_s,networks,cycles,observations,findings,cycles_per_s,networks_per_s,heap_live_mb,heap_peak_mb,rss_mb,cycle_p50_ms,cycle_p99_ms,recall_any_pct,fp_noise_per_net_day,violations,panics";

fn mib(bytes: u64) -> f64 {
    bytes as f64 / 1_048_576.0
}

fn pct(k: u64, n: u64) -> f64 {
    if n == 0 {
        0.0
    } else {
        100.0 * k as f64 / n as f64
    }
}

pub fn timeseries_row(
    state: &PersistedState,
    elapsed: f64,
    prev_cycles: u64,
    prev_networks: u64,
    dt_s: f64,
) -> String {
    let a = &state.aggregate;
    let dt = dt_s.max(1e-6);
    let cycle = a.perf.get("cycle_total");
    let (truth, detected) = a
        .families
        .iter()
        .filter(|(k, _)| !k.ends_with("__ranked"))
        .fold((0u64, 0u64), |acc, (_, f)| {
            (acc.0 + f.truth, acc.1 + f.detected_any)
        });
    let net_days = a.virtual_hours / 24.0;
    let violations: u64 = a.invariant_violations.values().sum();
    format!(
        "{:.0},{},{},{},{},{:.2},{:.3},{:.1},{:.1},{:.1},{:.2},{:.2},{:.2},{:.3},{},{}",
        elapsed,
        a.networks,
        a.cycles,
        a.observations,
        a.findings,
        (a.cycles.saturating_sub(prev_cycles)) as f64 / dt,
        (a.networks.saturating_sub(prev_networks)) as f64 / dt,
        mib(alloc::heap_live()),
        mib(alloc::heap_peak()),
        alloc::process_rss_bytes().map(mib).unwrap_or(0.0),
        cycle.map(|h| h.percentile(0.5) * 1000.0).unwrap_or(0.0),
        cycle.map(|h| h.percentile(0.99) * 1000.0).unwrap_or(0.0),
        pct(detected, truth),
        if net_days > 0.0 {
            a.fp_noise as f64 / net_days
        } else {
            0.0
        },
        violations,
        a.panics
    )
}

fn median_bin(bins: &[u64]) -> Option<usize> {
    let total: u64 = bins.iter().sum();
    if total == 0 {
        return None;
    }
    let mut seen = 0;
    for (index, count) in bins.iter().enumerate() {
        seen += count;
        if seen * 2 >= total {
            return Some(index);
        }
    }
    None
}

fn ci(k: u64, n: u64) -> String {
    let (p, lo, hi) = wilson(k, n);
    format!("{:.1} % [{:.1}; {:.1}]", p * 100.0, lo * 100.0, hi * 100.0)
}

fn family_table(out: &mut String, a: &Aggregate) {
    let _ = writeln!(
        out,
        "| rodina utoku | pozorovatelnych | detekovano (jakykoli nalez) | spravny typ nalezu | median latence | zadrzeno (blok) | IDS videlo |"
    );
    let _ = writeln!(out, "|---|---:|---|---|---:|---|---:|");
    for (label, f) in a.families.iter().filter(|(k, _)| !k.ends_with("__ranked")) {
        let median = median_bin(&f.ttd_cycles)
            .map(|b| format!("{} min{}", b * 30, if b == TTD_BINS - 1 { "+" } else { "" }))
            .unwrap_or_else(|| "-".to_string());
        let _ = writeln!(
            out,
            "| {label} | {} | {} | {} | {median} | {} | {} |",
            f.truth,
            ci(f.detected_any, f.truth),
            ci(f.detected_typed, f.truth),
            ci(f.contained, f.truth),
            f.ids_visible
        );
    }
}

fn ranked_table(out: &mut String, a: &Aggregate) {
    let _ = writeln!(
        out,
        "| rodina (vnitrni utocnik) | utoku | utocnik v top-{} dle zdroje, viditelne toky (produkcni filtr dst v scope) | totez vcetne odchozich toku (egress) |",
        3
    );
    let _ = writeln!(out, "|---|---:|---|---|");
    for (label, f) in a.families.iter().filter(|(k, _)| k.ends_with("__ranked")) {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            label.trim_end_matches("__ranked"),
            f.truth,
            ci(f.detected_any, f.truth),
            ci(f.detected_typed, f.truth)
        );
    }
}

fn perf_table(out: &mut String, a: &Aggregate) {
    let _ = writeln!(out, "| faze | vzorku | prumer | p50 | p95 | p99 | max |");
    let _ = writeln!(out, "|---|---:|---:|---:|---:|---:|---:|");
    for (stage, h) in &a.perf {
        let _ = writeln!(
            out,
            "| {stage} | {} | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms | {:.1} ms |",
            h.total,
            h.mean() * 1000.0,
            h.percentile(0.5) * 1000.0,
            h.percentile(0.95) * 1000.0,
            h.percentile(0.99) * 1000.0,
            h.max * 1000.0
        );
    }
}

/// Smernice lineární regrese `y ~ a + b*x`; vraci (b, r2).
fn slope(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    if points.len() < 8 {
        return None;
    }
    let n = points.len() as f64;
    let (sx, sy): (f64, f64) = points
        .iter()
        .fold((0.0, 0.0), |acc, p| (acc.0 + p.0, acc.1 + p.1));
    let (mx, my) = (sx / n, sy / n);
    let sxx: f64 = points.iter().map(|p| (p.0 - mx).powi(2)).sum();
    let sxy: f64 = points.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
    let syy: f64 = points.iter().map(|p| (p.1 - my).powi(2)).sum();
    if sxx == 0.0 || syy == 0.0 {
        return Some((0.0, 0.0));
    }
    Some((sxy / sxx, (sxy * sxy) / (sxx * syy)))
}

fn memory_trend(out: &mut String, state: &PersistedState) {
    let path = state.config.out.join("timeseries.csv");
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let rows: Vec<Vec<f64>> = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            line.split(',')
                .map(|c| c.parse::<f64>().ok())
                .collect::<Option<Vec<_>>>()
        })
        .collect();
    if rows.len() < 8 {
        let _ = writeln!(out, "Trend pameti: zatim malo vzorku ({}).", rows.len());
        return;
    }
    let skip = rows.len() / 10; // rozjezd (warm-up) se nepocita
    let heap: Vec<(f64, f64)> = rows[skip..].iter().map(|r| (r[0] / 3600.0, r[7])).collect();
    let rss: Vec<(f64, f64)> = rows[skip..].iter().map(|r| (r[0] / 3600.0, r[9])).collect();
    let rate: Vec<(f64, f64)> = rows[skip..].iter().map(|r| (r[0] / 3600.0, r[5])).collect();
    if let Some((b, r2)) = slope(&heap) {
        let verdict = if b > 5.0 && r2 > 0.5 {
            "**PODEZRENI NA UNIK**"
        } else {
            "bez trendu"
        };
        let _ = writeln!(
            out,
            "- halda (zive bajty): {b:+.2} MiB/h (R2 {r2:.2}) - {verdict}"
        );
    }
    if let Some((b, r2)) = slope(&rss) {
        let verdict = if b > 20.0 && r2 > 0.5 {
            "**PODEZRENI NA UNIK**"
        } else {
            "bez trendu"
        };
        let _ = writeln!(out, "- RSS procesu: {b:+.2} MiB/h (R2 {r2:.2}) - {verdict}");
    }
    if let Some((b, r2)) = slope(&rate) {
        let _ = writeln!(
            out,
            "- propustnost (cyklu/s): {b:+.3} za hodinu (R2 {r2:.2}) - pokles = degradace s casem"
        );
    }
}

pub fn render_markdown(state: &PersistedState, elapsed: f64, finished: bool) -> String {
    let a = &state.aggregate;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Soak: {}\n",
        if finished {
            "zaverecny report"
        } else {
            "prubezny stav"
        }
    );
    let _ = writeln!(
        out,
        "- commit: `{}`, seed `{}`, vlaken {}, blok {} siti, session {}",
        state.git_sha,
        state.config.run_seed,
        state.config.threads,
        state.config.block_size,
        state.sessions
    );
    let _ = writeln!(
        out,
        "- zahajeno {}, behu {:.2} h ({:.0} s)",
        state.started_at,
        elapsed / 3600.0,
        elapsed
    );
    let _ = writeln!(
        out,
        "- pamet: halda zive {:.0} MiB, peak {:.0} MiB, RSS {:.0} MiB\n",
        mib(alloc::heap_live()),
        mib(alloc::heap_peak()),
        alloc::process_rss_bytes().map(mib).unwrap_or(0.0)
    );

    let _ = writeln!(out, "## Rozsah\n");
    let _ = writeln!(out, "| | |\n|---|---:|");
    for (name, value) in [
        ("simulovanych siti", a.networks),
        ("cyklu (30 virt. minut)", a.cycles),
        ("pozorovani (toku)", a.observations),
        ("Suricata alertu", a.alerts),
        ("udalosti po fuzi", a.events),
        ("nalezu", a.findings),
        ("vypadku telemetrie (cyklu)", a.outage_cycles),
    ] {
        let _ = writeln!(out, "| {name} | {value} |");
    }
    let _ = writeln!(out, "| virtualni sit-dny | {:.0} |", a.virtual_hours / 24.0);
    let _ = writeln!(
        out,
        "| sit-dny celkem (virtualni) | {:.1} |",
        a.virtual_hours / 24.0
    );
    if elapsed > 0.0 {
        let _ = writeln!(
            out,
            "| propustnost | {:.1} cyklu/s, {:.2} siti/s, {:.0} toku/s |",
            a.cycles as f64 / elapsed,
            a.networks as f64 / elapsed,
            a.observations as f64 / elapsed
        );
    }
    let _ = writeln!(
        out,
        "\nArchetypy siti: {}\n",
        a.archetypes
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let _ = writeln!(out, "## Detekce utoku (ground truth)\n");
    let _ = writeln!(
        out,
        "Interval = Wilsonuv 95 %. \"Pozorovatelny\" utok = aspon jeden jeho tok dorazil do telemetrie (nezablokovany, bez vypadku). Pripsani nalezu utoku: nalez ma `host_key` mezi klicovymi IP utoku, nebo je zmineni v jeho textu/evidenci, v okne utoku +2 cykly.\n"
    );
    family_table(&mut out, a);
    let _ = writeln!(
        out,
        "\n### Zdrojove poradi (diagnosticky vystup, ne klasifikator)\n"
    );
    ranked_table(&mut out, a);

    let _ = writeln!(out, "\n## Falesne poplachy\n");
    let net_days = (a.virtual_hours / 24.0).max(1e-9);
    let _ = writeln!(
        out,
        "- behavioralni nalezy bez pripsatelne pricinu: **{}** ({:.3} / sit-den)",
        a.fp_noise,
        a.fp_noise as f64 / net_days
    );
    let _ = writeln!(
        out,
        "- behavioralni nalezy pripsane utokum: {}",
        a.behavioral_tp
    );
    let _ = writeln!(
        out,
        "- sit-dny bez jakehokoli utoku: {:.1}",
        a.quiet_network_days
    );
    let mut by_type: Vec<_> = a.fp_noise_by_type.iter().collect();
    by_type.sort_by(|x, y| y.1.cmp(x.1));
    for (kind, count) in by_type.iter().take(8) {
        let _ = writeln!(out, "  - {kind}: {count}");
    }
    let _ = writeln!(out, "\nBenigni lookalike udalosti (tvrde negativy):\n");
    let _ = writeln!(
        out,
        "| udalost | vyskytu | z toho s falesnym nalezem | nalezy pripsatelne jen jim |\n|---|---:|---|---:|"
    );
    for (label, l) in &a.lookalikes {
        let _ = writeln!(
            out,
            "| {label} | {} | {} | {} |",
            l.occurrences,
            ci(l.occurrences_with_fp, l.occurrences),
            l.fp_findings
        );
    }
    coverage_section(&mut out, a);

    let _ = writeln!(out, "\n## Expozice z inventare\n");
    let _ = writeln!(
        out,
        "- ocekavane nalezy (plaintext sluzba, CVSS>=7): {}, nalezeno {} -> {}",
        a.exposure.expected,
        a.exposure.found,
        ci(a.exposure.found, a.exposure.expected)
    );

    let e = &a.enforcement;
    let _ = writeln!(out, "\n## Zasahy (simulovane jadro + produkcni `ops.rs`)\n");
    let _ = writeln!(
        out,
        "| navrzeno | zamitnuto guardem | duplicit | schvaleno | zamitnuto operatorem | aplikovano | selhalo | vyprselo | drift odstranen | drift chybi | sweep selhal |"
    );
    let _ = writeln!(
        out,
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    );
    let _ = writeln!(
        out,
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
        e.proposed,
        e.rejected_guard,
        e.duplicates,
        e.approved,
        e.rejected_operator,
        e.applied,
        e.failed,
        e.expired,
        e.drift_removed,
        e.drift_missing,
        e.sweep_failed
    );
    let _ = writeln!(
        out,
        "\n- chyby operatora (navrh blokovat nahodnou vnitrni adresu): {}, z toho zachyceno chranenym rozsahem: {}",
        e.operator_error_attempts, e.operator_error_blocked_by_guard
    );
    let _ = writeln!(
        out,
        "- kolaterala: {} z {} legitimnich toku zahozeno jadrem ({:.4} %)",
        e.collateral_flows,
        e.benign_flows_total,
        pct(e.collateral_flows, e.benign_flows_total)
    );
    let _ = writeln!(
        out,
        "- zavady jadra: {} vstrikli, {} prikazu selhalo; chranene IP v jadre: {}",
        e.kernel_faults, e.kernel_cmd_failed, e.protected_in_kernel_violations
    );
    let flows: (u64, u64) = a
        .families
        .iter()
        .filter(|(k, _)| !k.ends_with("__ranked"))
        .fold((0, 0), |acc, (_, f)| {
            (acc.0 + f.flows_emitted, acc.1 + f.flows_blocked)
        });
    let _ = writeln!(
        out,
        "- utocnikovy provoz zahozeny jadrem: {} z {} toku ({:.2} %)",
        flows.1,
        flows.0,
        pct(flows.1, flows.0)
    );

    let v = &a.verification;
    let _ = writeln!(out, "\n## Overovaci kontroly\n");
    let _ = writeln!(
        out,
        "planu {}, vykonano {}, znovu pouzito {}, vyzaduje schvaleni {}, mimo rozpocet {}, mimo scope {}, selhalo {}; **porušeni**: rozpocet {}, schvaleni {}, scope {}",
        v.plans,
        v.executed,
        v.reused,
        v.needs_approval,
        v.skipped_budget,
        v.skipped_scope,
        v.failed,
        v.budget_violations,
        v.approval_violations,
        v.scope_violations
    );

    let i = &a.identity;
    let l = &a.learning;
    let _ = writeln!(out, "\n## Uceni (Case Memory) a ochrana proti otraveni\n");
    if l.predictions > 0 {
        let n = l.predictions as f64;
        let _ = writeln!(
            out,
            "- predikci probability s ground truth: {}, Brier **{:.4}** (naivni 0,5: {:.4}) -> {}",
            l.predictions,
            l.brier_sum / n,
            l.baseline_brier_sum / n,
            if l.brier_sum < l.baseline_brier_sum {
                "lepsi nez naivni"
            } else {
                "NEPREKONAVA naivni referenci"
            }
        );
        let names = ["0-9", "10-29", "30-99", "100+"];
        for (index, name) in names.iter().enumerate() {
            if let (Some(count), Some(sum)) = (l.by_cases_n.get(index), l.by_cases_brier.get(index))
            {
                if *count > 0 {
                    let _ = writeln!(
                        out,
                        "  - efektivnich pripadu {name}: {count} predikci, Brier {:.4}",
                        sum / *count as f64
                    );
                }
            }
        }
        let _ = writeln!(out, "- kalibrace (predikovano -> skutecna frekvence):");
        for bin in 0..10 {
            if let (Some(count), Some(pos), Some(psum)) =
                (l.bins_n.get(bin), l.bins_pos.get(bin), l.bins_psum.get(bin))
            {
                if *count >= 50 {
                    let _ = writeln!(
                        out,
                        "  - [{:.1}; {:.1}): n={count}, predikce {:.3}, skutecnost {:.3}",
                        bin as f64 / 10.0,
                        (bin + 1) as f64 / 10.0,
                        psum / *count as f64,
                        *pos as f64 / *count as f64
                    );
                }
            }
        }
    } else {
        let _ = writeln!(out, "- zatim zadna predikce s ground truth");
    }
    let _ = writeln!(
        out,
        "- pripadu prijato {}, operatorskych verdiktu {}, poctivych zaznamu v karantene {}",
        l.cases_accepted, l.verdicts_recorded, l.honest_quarantined
    );
    let _ = writeln!(
        out,
        "- otraveni: {} epizod s utocnikem, {} falesnych zaznamu odeslano, **{} zachyceno guardem** ({}), zdroju oznaceno {}",
        l.poison_episodes,
        l.poison_submitted,
        l.poison_quarantined,
        ci(l.poison_quarantined, l.poison_submitted),
        l.flagged_sources
    );

    let _ = writeln!(out, "\n## Identita zarizeni\n");
    let _ = writeln!(
        out,
        "- zarizeni (MAC) {}, falesne rozdelena (vic asset ID): {} ({}), asset ID {}, falesne sloucenych (vic MAC): {} ({}), ambiguous oznaceno {}, zmen adres (DHCP/swap) {}",
        i.devices,
        i.devices_false_split,
        ci(i.devices_false_split, i.devices),
        i.asset_ids,
        i.asset_ids_false_merge,
        ci(i.asset_ids_false_merge, i.asset_ids),
        i.ambiguous_flagged,
        i.churn_events
    );

    let legs = &state.legs;
    let _ = writeln!(out, "\n## Realna data jako kotva (CTU-13 + IoT-23)\n");
    if legs.anchor.passes == 0 {
        let _ = writeln!(
            out,
            "zatim zadny pruchod{}",
            legs.anchor
                .error
                .as_ref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        );
    } else {
        let _ = writeln!(
            out,
            "- pruchodu {}, scenaru {}, posledni pruchod {:.1} s, **nedeterministickych pruchodu: {}**{}",
            legs.anchor.passes,
            legs.anchor.scenarios,
            legs.anchor.last_pass_secs,
            legs.anchor.nondeterministic_passes,
            legs.anchor
                .error
                .as_ref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        );
        let _ = writeln!(
            out,
            "\n| scenar | toku | malicious | F1 (ablace A) | F1 triv. baseline | zdrojovy lift |\n|---|---:|---:|---:|---:|---:|"
        );
        for r in &legs.anchor.rows {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {:.3} | {:.3} | {:.2}x |",
                r.label, r.flows, r.malicious, r.f1, r.trivial_f1, r.source_lift
            );
        }
        let wins = legs
            .anchor
            .rows
            .iter()
            .filter(|r| r.malicious > 0 && r.f1 > r.trivial_f1)
            .count();
        let with_malicious = legs.anchor.rows.iter().filter(|r| r.malicious > 0).count();
        let _ = writeln!(
            out,
            "\nablace A porazi triviální baseline na {wins} z {with_malicious} scenaru s malicious provozem."
        );
    }

    let o = &legs.ops_stress;
    let _ = writeln!(
        out,
        "\n## Souborove ops.sqlite pod zatezi (skutecny disk, skutecne hodiny)\n"
    );
    let _ = writeln!(
        out,
        "- vlaken {}, iteraci {}, navrzeno {}, aplikovano {}, duplicit {}, guard {}, sweepu {}, chyb **{}**",
        o.threads,
        o.iterations,
        o.proposed,
        o.applied,
        o.duplicates,
        o.rejected_guard,
        o.sweeps,
        o.errors
    );
    let _ = writeln!(
        out,
        "- audit log: {} zaznamu, databaze {:.0} MiB, kontrol retezce {} (selhani **{}**), posledni overeni {:.1} s",
        o.audit_rows, o.db_mb, o.chain_checks, o.chain_failures, o.chain_verify_secs_last
    );
    if !o.latency.is_empty() {
        let _ = writeln!(
            out,
            "\n| operace | vzorku | prumer | p50 | p95 | p99 | max |\n|---|---:|---:|---:|---:|---:|---:|"
        );
        for (name, h) in &o.latency {
            let _ = writeln!(
                out,
                "| {name} | {} | {:.2} ms | {:.2} ms | {:.2} ms | {:.2} ms | {:.1} ms |",
                h.total,
                h.mean() * 1000.0,
                h.percentile(0.5) * 1000.0,
                h.percentile(0.95) * 1000.0,
                h.percentile(0.99) * 1000.0,
                h.max * 1000.0
            );
        }
    }

    let b = &legs.broker;
    let _ = writeln!(
        out,
        "\n## Broker (H5): propustnost podle poctu konzumentu\n"
    );
    if !b.available {
        let _ = writeln!(
            out,
            "Redis nedostupny{}",
            b.error
                .as_ref()
                .map(|e| format!(": {e}"))
                .unwrap_or_default()
        );
    } else {
        let _ = writeln!(
            out,
            "- kol celkem {}, **ztracenych jobu {}** (zprava nikdy nesmi zmizet)",
            b.rounds_total, b.lost_total
        );
        let mut by_consumers: std::collections::BTreeMap<usize, (u64, f64, u64, u64)> =
            std::collections::BTreeMap::new();
        for r in &b.recent {
            let e = by_consumers.entry(r.consumers).or_default();
            e.0 += r.processed;
            e.1 += r.secs;
            e.2 += r.duplicates;
            e.3 += r.crashed_before_ack;
        }
        let _ = writeln!(
            out,
            "\n| konzumentu | zpracovano | cas | propustnost | duplicit (at-least-once) | pad pred ACK |\n|---:|---:|---:|---:|---:|---:|"
        );
        for (consumers, (processed, secs, dup, crashed)) in by_consumers {
            let _ = writeln!(
                out,
                "| {consumers} | {processed} | {secs:.0} s | {:.0} jobu/s | {dup} | {crashed} |",
                processed as f64 / secs.max(1e-9)
            );
        }
    }

    let _ = writeln!(out, "\n## Vykon\n");
    perf_table(&mut out, a);
    let _ = writeln!(out, "\n### Trend zdroju\n");
    memory_trend(&mut out, state);

    let _ = writeln!(out, "\n## Invarianty a chyby\n");
    let total_violations: u64 = a.invariant_violations.values().sum();
    let _ = writeln!(
        out,
        "- porušeni invariantu: **{total_violations}**, paniky: **{}**",
        a.panics
    );
    for (name, count) in &a.invariant_violations {
        let _ = writeln!(out, "  - {name}: {count}");
    }
    for sample in a.violation_samples.iter().take(10) {
        let _ = writeln!(out, "  - vzorek: {sample}");
    }
    for sample in a.panic_samples.iter().take(5) {
        let _ = writeln!(out, "  - panika: {sample}");
    }
    let _ = writeln!(out, "\n## Reprodukovatelnost\n");
    let _ = writeln!(
        out,
        "Kazdy blok ma otisk v `blocks.jsonl`; `bakula-program soak verify --out <adresar> --samples N` znovu prehraje nahodne bloky z (seed, id site) a porovna otisky bit po bitu."
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slope_recovers_known_line_and_flags_flat_series_as_trendless() {
        let line: Vec<(f64, f64)> = (0..20).map(|i| (i as f64, 3.0 + 2.5 * i as f64)).collect();
        let (b, r2) = slope(&line).unwrap();
        assert!((b - 2.5).abs() < 1e-9 && r2 > 0.999);
        let flat: Vec<(f64, f64)> = (0..20).map(|i| (i as f64, 100.0)).collect();
        assert_eq!(slope(&flat).unwrap().0, 0.0);
        assert!(slope(&line[..4]).is_none());
    }

    #[test]
    fn median_bin_and_percent_helpers_behave() {
        assert_eq!(median_bin(&[0, 0, 0]), None);
        assert_eq!(median_bin(&[1, 5, 1]), Some(1));
        assert_eq!(pct(1, 4), 25.0);
        assert_eq!(pct(1, 0), 0.0);
    }
}

const SIZE_ORDER: [&str; 6] = crate::soak::netmodel::SIZE_CLASSES;

fn segment_table(out: &mut String, a: &Aggregate, prefix: &str, order: &[String]) {
    let _ = writeln!(
        out,
        "| rez | siti | prum. zarizeni | prum. podsiti | virt. sit-dnu | utoku | detekovano | spravny typ | FP / sit-den | benigni udalosti | z toho s FP |\n|---|---:|---:|---:|---:|---:|---|---|---:|---:|---|"
    );
    for name in order {
        let Some(seg) = a.segments.get(&format!("{prefix}|{name}")) else {
            let _ = writeln!(out, "| {name} | **0 (NEPOKRYTO)** | | | | | | | | | |");
            continue;
        };
        let n = seg.networks.max(1) as f64;
        let _ = writeln!(
            out,
            "| {name} | {} | {:.0} | {:.1} | {:.0} | {} | {} | {} | {:.2} | {} | {} |",
            seg.networks,
            seg.devices as f64 / n,
            seg.subnets as f64 / n,
            seg.virtual_days,
            seg.attacks,
            ci(seg.detected_any, seg.attacks),
            ci(seg.detected_typed, seg.attacks),
            seg.fp_noise as f64 / seg.virtual_days.max(1e-9),
            seg.benign_events,
            ci(seg.benign_with_fp, seg.benign_events)
        );
    }
}

fn coverage_section(out: &mut String, a: &Aggregate) {
    use crate::soak::{
        netmodel::{Archetype, Role},
        traffic::Family,
    };
    let _ = writeln!(
        out,
        "\n## Pokryti: velikosti siti, typy zarizeni, utoky, delka\n"
    );
    let _ = writeln!(
        out,
        "Kazda radka musi mit data; `NEPOKRYTO` = scenar se v behu nevyskytl (mezera v generatoru, ne dobry vysledek).\n"
    );
    let _ = writeln!(out, "### Podle velikosti site\n");
    let sizes: Vec<String> = SIZE_ORDER.iter().map(|s| s.to_string()).collect();
    segment_table(out, a, "size", &sizes);
    let _ = writeln!(out, "\n### Podle archetypu\n");
    let archs: Vec<String> = Archetype::ALL.iter().map(|x| format!("{x:?}")).collect();
    segment_table(out, a, "arch", &archs);
    let _ = writeln!(out, "\n### Podle delky behu (virtualni hodiny)\n");
    let mut durs: Vec<u32> = a
        .segments
        .keys()
        .filter_map(|k| k.strip_prefix("dur|")?.strip_suffix('h')?.parse().ok())
        .collect();
    durs.sort_unstable();
    let dur_names: Vec<String> = durs.iter().map(|d| format!("{d}h")).collect();
    segment_table(out, a, "dur", &dur_names);

    let _ = writeln!(
        out,
        "\n### Detekce: rodina utoku x velikost site (podil detekovanych, v zavorce pocet utoku)\n"
    );
    let _ = write!(out, "| rodina |");
    for size in SIZE_ORDER {
        let _ = write!(out, " {size} |");
    }
    let _ = writeln!(out);
    let _ = write!(out, "|---|");
    for _ in SIZE_ORDER {
        let _ = write!(out, "---:|");
    }
    let _ = writeln!(out);
    for family in Family::ALL {
        let _ = write!(out, "| {} |", family.label());
        for size in SIZE_ORDER {
            match a.segments.get(&format!("cell|{}|{size}", family.label())) {
                Some(seg) if seg.attacks > 0 => {
                    let _ = write!(
                        out,
                        " {:.0} % ({}) |",
                        100.0 * seg.detected_any as f64 / seg.attacks as f64,
                        seg.attacks
                    );
                }
                _ => {
                    let _ = write!(out, " - |");
                }
            }
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(out, "\n### Typy zarizeni (instance napric vsemi sitemi)\n");
    for role in Role::ALL {
        let count = a.roles.get(role.label()).copied().unwrap_or(0);
        let _ = writeln!(
            out,
            "- {}: {}{}",
            role.label(),
            count,
            if count == 0 { " **NEPOKRYTO**" } else { "" }
        );
    }
    let mut services: Vec<_> = a.services.iter().collect();
    services.sort_by(|x, y| y.1.cmp(x.1));
    let _ = writeln!(
        out,
        "\n### Sluzby/servery (instance): {}\n",
        services
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let o = &a.ops;
    let _ = writeln!(out, "### Provozni realita (pady, patche, restarty)\n");
    let _ = writeln!(
        out,
        "- restarty enginu (ztrata inventare, obnova identity z uloziste): {}",
        o.engine_restarts
    );
    let _ = writeln!(
        out,
        "- zarizeni-cyklu mimo provoz (pady, patchovaci restarty, odstaveni): {}",
        o.device_down_cycles
    );
    let _ = writeln!(
        out,
        "- patchnuta zarizeni: {}, nove nasazena: {}, vyrazena: {}",
        o.patched_devices, o.onboarded_devices, o.decommissioned_devices
    );
    let _ = writeln!(
        out,
        "- zastarale nalezy zranitelnosti po patchi: {} z {} kontrol",
        o.stale_exposure_findings, o.exposure_checks_after_patch
    );
    let _ = writeln!(
        out,
        "- cykly s vypadlym senzorem: {}, poskozene/nevalidni radky alertu zpracovane bez padu: {}",
        o.sensor_down_cycles, o.corrupt_alert_lines
    );
}
