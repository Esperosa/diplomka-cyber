#!/usr/bin/env python3
"""Parove A/B soak behu po sitich (krok 1, docs/diplomka/eval/impl-krok1.md).

Vstup: adresare behu (`soak run`), kazdy s `networks.jsonl` (jeden radek = sit).
Ramena A a B se parují podle (run_seed, network_id); stejny seed a sit = stejny
provoz i utoky (generator je deterministicky). Statistika:
- metriky "na sit-den" = soucet / soucet virtualnich dni (pomer souctu),
- relativni pokles B proti A s 95% bootstrap intervalem: resampling SITI
  (cluster = sit), stratifikovany podle seedu, B = 2000, pevny seed,
- detekce po rodinach: podil detekovanych utoku, parovy rozdil B - A v p. b.
  s bootstrap intervalem, jen rodiny s >= 100 utoky dostanou verdikt,
- zavreno omylem: Wilsonuv 95% interval.

Pouziti:
  python tools/soak_ab.py --a DIR [DIR ...] --b DIR [DIR ...] [--label-a X --label-b Y] [--out FILE]
Bez zavislosti mimo standardni knihovnu.
"""
import argparse
import json
import math
import os
import random
import sys
from collections import defaultdict

Z = 1.959963984540054
BOOT = 2000


def wilson(k, n):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + Z * Z / n
    center = (p + Z * Z / (2 * n)) / denom
    margin = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / denom
    lo = 0.0 if k == 0 else max(0.0, center - margin)
    hi = 1.0 if k == n else min(1.0, center + margin)
    return (p, lo, hi)


def load(dirs):
    rows = {}
    for d in dirs:
        path = os.path.join(d, "networks.jsonl")
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                rows[(row["run_seed"], row["network_id"])] = row
    return rows


def get(row, path):
    value = row
    for part in path.split("."):
        if isinstance(value, dict):
            value = value.get(part, 0)
        else:
            return 0
    return 0 if value is None else value


def boot_indices(keys, rng):
    by_seed = defaultdict(list)
    for index, key in enumerate(keys):
        by_seed[key[0]].append(index)
    out = []
    for seed in sorted(by_seed):
        members = by_seed[seed]
        out.extend(members[rng.randrange(len(members))] for _ in members)
    return out


def ratio_change(a_rows, b_rows, metric, denom="virtual_days"):
    """Relativni zmena (B/A - 1) metriky na sit-den, s bootstrap CI."""
    keys = sorted(a_rows)
    av = [get(a_rows[k], metric) for k in keys]
    bv = [get(b_rows[k], metric) for k in keys]
    days = [get(a_rows[k], denom) for k in keys]
    def stat(idx):
        sa = sum(av[i] for i in idx)
        sb = sum(bv[i] for i in idx)
        sd = sum(days[i] for i in idx) or 1.0
        return sa / sd, sb / sd, (sb / sa - 1.0) if sa > 0 else float("nan")
    full = stat(range(len(keys)))
    rng = random.Random(20261101)
    samples = []
    for _ in range(BOOT):
        value = stat(boot_indices(keys, rng))[2]
        if not math.isnan(value):
            samples.append(value)
    samples.sort()
    if samples:
        lo = samples[int(0.025 * len(samples))]
        hi = samples[min(len(samples) - 1, int(0.975 * len(samples)))]
    else:
        lo = hi = float("nan")
    return full[0], full[1], full[2], lo, hi


def family_table(a_rows, b_rows, field_a, field_b):
    keys = sorted(a_rows)
    families = sorted({f for k in keys for f in get(a_rows[k], "families")})
    rng = random.Random(7)
    boots = [boot_indices(keys, rng) for _ in range(BOOT)]
    out = []
    for fam in families:
        truth = [get(a_rows[k], f"families.{fam}.truth") for k in keys]
        da = [get(a_rows[k], f"families.{fam}.{field_a}") for k in keys]
        db = [get(b_rows[k], f"families.{fam}.{field_b}") for k in keys]
        n = sum(truth)
        if n == 0:
            continue
        pa = sum(da) / n
        pb = sum(db) / n
        diffs = []
        for idx in boots:
            nt = sum(truth[i] for i in idx)
            if nt:
                diffs.append((sum(db[i] for i in idx) - sum(da[i] for i in idx)) / nt)
        diffs.sort()
        lo = diffs[int(0.025 * len(diffs))] if diffs else float("nan")
        hi = diffs[min(len(diffs) - 1, int(0.975 * len(diffs)))] if diffs else float("nan")
        out.append((fam, n, pa, pb, pb - pa, lo, hi))
    return out


def excess_table(a_rows, b_rows, kind="displayed"):
    """Detekce nad pozadim: (detekce - placebo) na utocich s placebo oknem, parove."""
    keys = sorted(a_rows)
    families = sorted({f for k in keys for f in get(a_rows[k], "families")})
    rng = random.Random(11)
    boots = [boot_indices(keys, rng) for _ in range(BOOT)]
    out = []
    for fam in families:
        n = [get(a_rows[k], f"families.{fam}.placebo_windows") for k in keys]
        if sum(n) == 0:
            continue
        def ex(rows):
            det = [get(rows[k], f"families.{fam}.placebo_detected_{kind}") for k in keys]
            hit = [get(rows[k], f"families.{fam}.placebo_hits_{kind}") for k in keys]
            return [d - h for d, h in zip(det, hit)], det, hit
        ea, da, ha = ex(a_rows)
        eb, db, hb = ex(b_rows)
        total = sum(n)
        diffs = []
        for idx in boots:
            nt = sum(n[i] for i in idx)
            if nt:
                diffs.append((sum(eb[i] for i in idx) - sum(ea[i] for i in idx)) / nt)
        diffs.sort()
        lo = diffs[int(0.025 * len(diffs))] if diffs else float("nan")
        hi = diffs[min(len(diffs) - 1, int(0.975 * len(diffs)))] if diffs else float("nan")
        out.append((fam, total, sum(da) / total, sum(ha) / total, sum(db) / total, sum(hb) / total,
                    (sum(eb) - sum(ea)) / total, lo, hi))
    return out


def pct(x):
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x * 100:+.1f} %"


def num(x):
    return f"{x:,.1f}".replace(",", " ")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--a", nargs="+", required=True)
    parser.add_argument("--b", nargs="+", required=True)
    parser.add_argument("--label-a", default="A")
    parser.add_argument("--label-b", default="B")
    parser.add_argument("--out")
    args = parser.parse_args()
    a_rows = load(args.a)
    b_rows = load(args.b)
    common = sorted(set(a_rows) & set(b_rows))
    a_rows = {k: a_rows[k] for k in common}
    b_rows = {k: b_rows[k] for k in common}
    days = sum(get(a_rows[k], "virtual_days") for k in common)
    lines = []
    lines.append(f"Parovano {len(common)} siti, {num(days)} virtualnich sit-dni; "
                 f"A = `{args.label_a}` ({next(iter(a_rows.values()))['engine'] if common else '-'}), "
                 f"B = `{args.label_b}` ({next(iter(b_rows.values()))['engine'] if common else '-'}).")
    lines.append("")
    lines.append("| metrika (na sit-den) | A | B | zmena B/A | 95% CI |")
    lines.append("|---|---:|---:|---:|---|")
    metrics = [
        ("zobrazene polozky", "output.displayed"),
        ("zobrazene behavioralni", "output.displayed_behavioral"),
        ("zobrazene falesne poplachy", "output.displayed_fp"),
        ("nalezy x cykly (vse)", "findings"),
        ("FP nalezy x cykly (legacy metrika)", "fp_noise"),
        ("odlisne stavy - zachyceno", "output.states_captured"),
        ("odlisne FP stavy", "output.states_fp"),
        ("ceka na cloveka (stavy)", "output.states_awaiting_human"),
        ("ceka na cloveka - FP stavy", "output.states_awaiting_human_fp"),
        ("automaticky vyreseno (stavy)", "output.states_auto_resolved"),
        ("overovaci plany", "verification_plans"),
    ]
    for label, metric in metrics:
        a, b, change, lo, hi = ratio_change(a_rows, b_rows, metric)
        lines.append(f"| {label} | {num(a)} | {num(b)} | {pct(change)} | {pct(lo)} az {pct(hi)} |")
    lines.append("")
    # FP po typech (zobrazene)
    types = sorted({t for k in common for t in get(a_rows[k], "displayed_fp_by_type")} |
                   {t for k in common for t in get(b_rows[k], "displayed_fp_by_type")})
    lines.append("| zobrazene FP podle typu (na sit-den) | A | B | zmena |")
    lines.append("|---|---:|---:|---:|")
    for t in types:
        a, b, change, _, _ = ratio_change(a_rows, b_rows, f"displayed_fp_by_type.{t}")
        if a > 0.05 or b > 0.05:
            lines.append(f"| {t} | {num(a)} | {num(b)} | {pct(change)} |")
    lines.append("")
    # zavreno omylem
    closures = sum(get(b_rows[k], "output.auto_closures") for k in common)
    wrong = sum(get(b_rows[k], "output.auto_closures_wrong") for k in common)
    sampled = sum(get(b_rows[k], "output.audit_sampled") for k in common)
    audit_wrong = sum(get(b_rows[k], "output.audit_wrong") for k in common)
    causal = sum(get(b_rows[k], "output.auto_closures_wrong_causal") for k in common)
    audit_causal = sum(get(b_rows[k], "output.audit_wrong_causal") for k in common)
    p, lo, hi = wilson(wrong, closures)
    pc, loc, hic = wilson(causal, closures)
    ps, los, his = wilson(audit_causal, sampled)
    lines.append(f"Automaticka zavreni v B: {closures}. Zavreno omylem PRICINNE (utok v tom cyklu posilal toky "
                 f"na cil nalezu nebo z jeho dominantniho zdroje): {causal} = {pc * 100:.2f} % "
                 f"(95% CI {loc * 100:.2f} az {hic * 100:.2f} %). Siroka atribuce (nalez jen zminuje klicovou IP "
                 f"utoku v okne): {wrong} = {p * 100:.2f} % ({lo * 100:.2f} az {hi * 100:.2f} %). "
                 f"Audit 10% vzorku (pricinne): {audit_causal}/{sampled} = {ps * 100:.2f} % "
                 f"(95% CI {los * 100:.2f} az {his * 100:.2f} %).")
    by_reason = defaultdict(lambda: [0, 0])
    for k in common:
        for reason, count in get(b_rows[k], "output.auto_closures_by_reason").items():
            by_reason[reason][0] += count
        for reason, count in get(b_rows[k], "output.auto_closures_wrong_by_reason").items():
            by_reason[reason][1] += count
    if by_reason:
        lines.append("")
        lines.append("| duvod zavreni | zavreni | omylem (siroka atribuce) | podil (95% CI) |")
        lines.append("|---|---:|---:|---|")
        for reason, (n, k) in sorted(by_reason.items()):
            p, lo, hi = wilson(k, n)
            lines.append(f"| {reason} | {n} | {k} | {p * 100:.2f} % ({lo * 100:.2f} az {hi * 100:.2f}) |")
    lines.append("")
    for title, fa, fb in [("detekce ze ZOBRAZENYCH polozek (A zobrazene vs B zobrazene)", "detected_displayed", "detected_displayed"),
                          ("detekce zachycena (jakykoli nalez, legacy metrika)", "detected", "detected"),
                          ("spravny typ ze zobrazenych", "typed_displayed", "typed_displayed")]:
        lines.append(f"**{title}**")
        lines.append("")
        lines.append("| rodina | n | A | B | B-A (p. b.) | 95% CI | verdikt (>= 100 utoku, mez -5 p. b.) |")
        lines.append("|---|---:|---:|---:|---:|---|---|")
        for fam, n, pa, pb, d, lo, hi in family_table(a_rows, b_rows, fa, fb):
            verdict = "-" if n < 100 else ("OK" if d >= -0.05 else "ZTRATA")
            lines.append(f"| {fam} | {n} | {pa * 100:.1f} % | {pb * 100:.1f} % | {d * 100:+.1f} | "
                         f"{lo * 100:+.1f} az {hi * 100:+.1f} | {verdict} |")
        lines.append("")
    # detekce nad pozadim (placebo)
    if any(get(a_rows[k], "families") and any(get(v, "placebo_detected_displayed") for v in get(a_rows[k], "families").values()) for k in common):
        lines.append("**detekce nad pozadim = detekce - placebo (zobrazene, utoky s placebo oknem)**")
        lines.append("")
        lines.append("| rodina | n (placebo) | A det | A placebo | B det | B placebo | (B-A) nad pozadim p. b. | 95% CI | verdikt (n >= 100, mez -5 p. b.) |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---|---|")
        for fam, n, da, ha, db, hb, d, lo, hi in excess_table(a_rows, b_rows):
            verdict = "-" if n < 100 else ("OK" if lo >= -0.05 or d >= -0.05 else "ZTRATA")
            lines.append(f"| {fam} | {n} | {da * 100:.1f} % | {ha * 100:.1f} % | {db * 100:.1f} % | {hb * 100:.1f} % | "
                         f"{d * 100:+.1f} | {lo * 100:+.1f} az {hi * 100:+.1f} | {verdict} |")
        lines.append("")
    # kontrafaktual (krok 2A): utok se pripise jen nalezu, ktery ve svete bez utoku chybi
    cf_rows = any(get(v, "cf_attacks") for k in common for v in get(a_rows[k], "families").values())
    if cf_rows:
        def cf_table(field, title):
            lines.append(f"**{title}**")
            lines.append("")
            lines.append("| rodina | n | A | B | B-A (p. b.) | 95% CI | verdikt (>= 100 utoku, mez -5 p. b.) |")
            lines.append("|---|---:|---:|---:|---:|---|---|")
            keys = sorted(a_rows)
            fams_cf = sorted({f for k in keys for f in get(a_rows[k], "families")})
            rng = random.Random(13)
            boots = [boot_indices(keys, rng) for _ in range(BOOT)]
            for fam in fams_cf:
                n = [get(a_rows[k], f"families.{fam}.cf_attacks") for k in keys]
                if sum(n) == 0:
                    continue
                da = [get(a_rows[k], f"families.{fam}.{field}") for k in keys]
                db = [get(b_rows[k], f"families.{fam}.{field}") for k in keys]
                total = sum(n)
                diffs = []
                for idx in boots:
                    nt = sum(n[i] for i in idx)
                    if nt:
                        diffs.append((sum(db[i] for i in idx) - sum(da[i] for i in idx)) / nt)
                diffs.sort()
                lo = diffs[int(0.025 * len(diffs))] if diffs else float("nan")
                hi = diffs[min(len(diffs) - 1, int(0.975 * len(diffs)))] if diffs else float("nan")
                pa, pb = sum(da) / total, sum(db) / total
                d = pb - pa
                verdict = "-" if total < 100 else ("OK" if d >= -0.05 else "ZTRATA")
                lines.append(f"| {fam} | {total} | {pa * 100:.1f} % | {pb * 100:.1f} % | {d * 100:+.1f} | "
                             f"{lo * 100:+.1f} az {hi * 100:+.1f} | {verdict} |")
            lines.append("")
        cf_table("cf_detected_displayed", "KONTRAFAKTUALNI detekce ze zobrazenych (nalez chybi ve svete bez utoku)")
        cf_table("cf_detected", "kontrafaktualni detekce zachycena (jakykoli nalez)")
        cf_table("cf_detected_displayed_strict", "kontrafaktualni zobrazena, prisne (chybi i v sousednich cyklech)")
        cf_table("cf_typed_displayed", "kontrafaktualni spravny typ ze zobrazenych")
        lines.append("**nahodna shoda: detekce oknem minus kontrafaktualni (zobrazene)**")
        lines.append("")
        lines.append("| rodina | n | A okno | A cf | A shoda | B okno | B cf | B shoda |")
        lines.append("|---|---:|---:|---:|---:|---:|---:|---:|")
        for fam in sorted({f for k in common for f in get(a_rows[k], "families")}):
            n = sum(get(a_rows[k], f"families.{fam}.cf_attacks") for k in common)
            if n == 0:
                continue
            row = [fam, str(n)]
            for rows in (a_rows, b_rows):
                win = sum(get(rows[k], f"families.{fam}.detected_displayed") for k in common) / n
                cfv = sum(get(rows[k], f"families.{fam}.cf_detected_displayed") for k in common) / n
                row += [f"{win * 100:.1f} %", f"{cfv * 100:.1f} %", f"{(win - cfv) * 100:.1f} p. b."]
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        loo_n = sum(get(v, "loo_n") for k in common for v in get(b_rows[k], "families").values())
        if loo_n:
            lines.append("**validace: kontrafaktual bez vsech utoku vs leave-one-out (zobrazene)**")
            lines.append("")
            lines.append("| rameno | n LOO | LOO detekce | bez vsech detekce | shoda (95% CI) |")
            lines.append("|---|---:|---:|---:|---|")
            for side, rows in (("A", a_rows), ("B", b_rows)):
                fam_vals = [v for k in common for v in get(rows[k], "families").values()]
                n = sum(get(v, "loo_n") for v in fam_vals)
                if not n:
                    continue
                loo = sum(get(v, "loo_detected_displayed") for v in fam_vals)
                allm = sum(get(v, "loo_all_detected_displayed") for v in fam_vals)
                agree = sum(get(v, "loo_agree") for v in fam_vals)
                p, lo, hi = wilson(agree, n)
                lines.append(f"| {side} | {n} | {loo / n * 100:.1f} % | {allm / n * 100:.1f} % | "
                             f"{p * 100:.1f} % ({lo * 100:.1f} az {hi * 100:.1f}) |")
            lines.append("")
        lines.append("**typy nalezu kontrafaktualne pripsane utokum (podil utoku rodiny, zobrazene)**")
        lines.append("")
        lines.append("| rodina | A: typy | B: typy |")
        lines.append("|---|---|---|")
        for fam in sorted({f for k in common for f in get(a_rows[k], "families")}):
            n = sum(get(a_rows[k], f"families.{fam}.cf_attacks") for k in common)
            if n == 0:
                continue
            cells = []
            for rows in (a_rows, b_rows):
                hits = defaultdict(int)
                for k in common:
                    for key, value in get(rows[k], "cf_type_hits").items():
                        f, _, t = key.partition("|")
                        if f == fam:
                            hits[t] += value
                top = sorted(hits.items(), key=lambda kv: -kv[1])[:4]
                cells.append(", ".join(f"{t} {v / n * 100:.0f} %" for t, v in top) or "-")
            lines.append(f"| {fam} | {cells[0]} | {cells[1]} |")
        lines.append("")
    # placebo
    lines.append("**placebo okna (nahodna shoda s pozadim, zobrazene polozky)**")
    lines.append("")
    lines.append("| rodina | placebo oken | A hit | B hit |")
    lines.append("|---|---:|---:|---:|")
    fams = sorted({f for k in common for f in get(a_rows[k], "families")})
    for fam in fams:
        n = sum(get(a_rows[k], f"families.{fam}.placebo_windows") for k in common)
        if n == 0:
            continue
        ha = sum(get(a_rows[k], f"families.{fam}.placebo_hits_displayed") for k in common)
        hb = sum(get(b_rows[k], f"families.{fam}.placebo_hits_displayed") for k in common)
        lines.append(f"| {fam} | {n} | {ha / n * 100:.1f} % | {hb / n * 100:.1f} % |")
    lines.append("")
    # zebrik overovani (krok 2B) a planovani
    lines.append("**overovani: plany, rozpocet, zebrik (krok 2B)**")
    lines.append("")
    lines.append("Mimo rozpocet = plan, ktery se nikdy neprovedl (zahozeny plan, pripad eskalovany pro rozpocet); "
                 "odlozeni na dalsi cyklus se pocita zvlast.")
    lines.append("")
    lines.append("| rameno | plany+pripady / sit-den | mimo rozpocet (95% CI) | kontroly / sit-den | potvrzeno | vyvraceno | eskalovano | eskalace pro rozpocet | latence rozhodnuti (cykly, prumer / max) |")
    lines.append("|---|---:|---|---:|---:|---:|---:|---:|---|")
    for side, rows in (("A", a_rows), ("B", b_rows)):
        s = lambda m: sum(get(rows[k], m) for k in common)
        plans = s("verification_plans") + s("output.ladder_cases")
        over = s("verification_skipped_budget") + s("output.ladder_escalated_budget")
        p, lo, hi = wilson(over, plans)
        decided = s("output.ladder_confirmed") + s("output.ladder_refuted") + s("output.ladder_escalated")
        lat = s("output.ladder_latency_sum") / decided if decided else 0.0
        lmax = max((get(rows[k], "output.ladder_latency_max") for k in common), default=0)
        lines.append(f"| {side} | {num(plans / days)} | {p * 100:.1f} % ({lo * 100:.1f} az {hi * 100:.1f}) | "
                     f"{num(s('output.ladder_checks') / days)} | {s('output.ladder_confirmed')} | {s('output.ladder_refuted')} | "
                     f"{s('output.ladder_escalated')} | {s('output.ladder_escalated_budget')} | {lat:.2} / {lmax} |")
    lines.append("")
    for side, rows in (("A", a_rows), ("B", b_rows)):
        s = lambda m: sum(get(rows[k], m) for k in common)
        ref = s("output.ladder_refuted")
        if not ref and not s("output.ladder_cases"):
            continue
        wrong = s("output.ladder_refuted_wrong_cf")
        causal = s("output.ladder_refuted_wrong_causal")
        conf = s("output.ladder_confirmed")
        conf_ok = s("output.ladder_confirmed_attack")
        esc = s("output.ladder_escalated")
        esc_att = s("output.ladder_escalated_attack")
        aud_n, aud_w = s("output.ladder_audit_sampled"), s("output.ladder_audit_wrong")
        p1, l1, h1 = wilson(wrong, ref)
        p2, l2, h2 = wilson(causal, ref)
        p3, l3, h3 = wilson(conf_ok, conf)
        p4, l4, h4 = wilson(aud_w, aud_n)
        states_b = s("output.states_behavioral")
        auto_states = s("output.states_auto_resolved")
        p5, l5, h5 = wilson(auto_states, s("output.states_captured"))
        lines.append(f"Zebrik {side}: vyvraceno {ref}, z toho omylem (nalez kontrafaktualne zpusobil utok) {wrong} = "
                     f"{p1 * 100:.2f} % (95% CI {l1 * 100:.2f} az {h1 * 100:.2f}), pricinne {causal} = {p2 * 100:.2f} % "
                     f"({l2 * 100:.2f} az {h2 * 100:.2f}); audit 10% vzorku {aud_w}/{aud_n} = {p4 * 100:.2f} % "
                     f"({l4 * 100:.2f} az {h4 * 100:.2f}). Potvrzeno {conf}, z toho utok {conf_ok} = presnost "
                     f"{p3 * 100:.1f} % ({l3 * 100:.1f} az {h3 * 100:.1f}). Eskalovano {esc}, z toho utok {esc_att}. "
                     f"Automaticky vyresene stavy {auto_states} z {s('output.states_captured')} = {p5 * 100:.1f} % "
                     f"({l5 * 100:.1f} az {h5 * 100:.1f}); behavioralnich stavu {states_b}.")
        by_level = defaultdict(int)
        outcomes = defaultdict(int)
        refuted_types = defaultdict(int)
        wrong_detail = defaultdict(int)
        for k in common:
            for key, v in get(rows[k], "output.ladder_checks_by_level").items():
                by_level[key] += v
            for key, v in get(rows[k], "output.ladder_outcomes").items():
                outcomes[key] += v
            for key, v in get(rows[k], "output.ladder_refuted_by_type").items():
                refuted_types[key] += v
            for key, v in get(rows[k], "output.ladder_refuted_wrong_detail").items():
                wrong_detail[key] += v
        lines.append("")
        lines.append(f"- kontroly podle urovne ({side}): " + ", ".join(f"{k} {v}" for k, v in sorted(by_level.items())))
        lines.append(f"- vysledky kontrol ({side}): " + ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items(), key=lambda kv: -kv[1])))
        lines.append(f"- vyvraceno podle typu ({side}): " + ", ".join(f"{k} {v}" for k, v in sorted(refuted_types.items(), key=lambda kv: -kv[1])))
        if wrong_detail:
            lines.append(f"- vyvraceno omylem typ|rodina ({side}): " + ", ".join(f"{k} {v}" for k, v in sorted(wrong_detail.items(), key=lambda kv: -kv[1])))
        truth = defaultdict(int)
        for k in common:
            for key, v in get(rows[k], "output.ladder_outcome_truth").items():
                truth[key] += v
        n_att, n_ben = truth.get("_cases|attack", 0), truth.get("_cases|benign", 0)
        if n_att and n_ben:
            lines.append("")
            lines.append(f"Empiricke LR vysledku kontrol ({side}; rozhodnute pripady, utok {n_att}, neskodne {n_ben}; "
                         "LR = P(vysledek|utok)/P(vysledek|neskodne), Laplace +0,5):")
            lines.append("")
            lines.append("| kontrola:vysledek | utok | neskodne | empiricke LR |")
            lines.append("|---|---:|---:|---:|")
            tags = sorted({key.split("|")[0] for key in truth if not key.startswith("_")})
            for tag in tags:
                a = truth.get(f"{tag}|attack", 0)
                b = truth.get(f"{tag}|benign", 0)
                lr = ((a + 0.5) / (n_att + 1)) / ((b + 0.5) / (n_ben + 1))
                lines.append(f"| {tag} | {a} | {b} | {lr:.2f} |")
        lines.append("")
    for side, rows in (("A", a_rows), ("B", b_rows)):
        n = sum(get(rows[k], "output.device_classified") for k in common)
        if not n:
            continue
        ok = sum(get(rows[k], "output.device_class_correct") for k in common)
        conf = sum(get(rows[k], "output.device_class_confident") for k in common)
        p, lo, hi = wilson(ok, n)
        lines.append(f"Rozpoznani typu zarizeni {side}: spravne {p * 100:.1f} % (95% CI {lo * 100:.1f} az {hi * 100:.1f}, "
                     f"n = {n} klasifikaci pri skenech), se stredni a vyssi jistotou {conf / n * 100:.1f} %.")
    lines.append("")
    # identita
    for side, rows in (("A", a_rows), ("B", b_rows)):
        dev = sum(get(rows[k], "identity_devices") for k in common)
        split = sum(get(rows[k], "identity_false_split") for k in common)
        assets = sum(get(rows[k], "identity_asset_ids") for k in common)
        merge = sum(get(rows[k], "identity_false_merge") for k in common)
        p1, l1, h1 = wilson(split, dev)
        p2, l2, h2 = wilson(merge, assets)
        lines.append(f"Identita {side}: falesne rozdeleno {p1 * 100:.1f} % ({l1 * 100:.1f} az {h1 * 100:.1f}, n={dev}), "
                     f"falesne slouceno {p2 * 100:.1f} % ({l2 * 100:.1f} az {h2 * 100:.1f}, n={assets}).")
    lines.append("")
    for side, rows in (("A", a_rows), ("B", b_rows)):
        p99 = sorted(get(rows[k], "cycle_p99_s") for k in common)
        wall = sum(get(rows[k], "wall_s") for k in common)
        panics = sum(get(rows[k], "panics") for k in common)
        viol = sum(get(rows[k], "violations") for k in common)
        peak = max((get(rows[k], "output.memory_peak_entries") for k in common), default=0)
        lines.append(f"Provoz {side}: median p99 cyklu {p99[len(p99) // 2] * 1000:.0f} ms, max p99 {p99[-1] * 1000:.0f} ms, "
                     f"CPU cas siti {wall / 60:.1f} min, paniky {panics}, invarianty {viol}, max polozek pameti {peak}.")
    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
