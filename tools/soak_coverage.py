#!/usr/bin/env python3
"""Vyhodnoceni sveta pokryti (krok 5, docs/diplomka/eval/impl-krok5.md, sekce A).

Vstup: adresare behu (`soak run --coverage ...`) s `networks.jsonl`. Radky site maji
pole `attacks` (zaznam po utoku) a `faults` (zaznam po neskodne udalosti).

Detekce utoku = kontrafaktualni zobrazena detekce (`cf`), jednotka = utok s aspon
jednim emitovanym tokem. Intervaly: Wilson 95 % pro podily, bootstrap po sitich
stratifikovany po seedech (B = 2000) pro souhrny a parove rozdily.

Pouziti:
  python tools/soak_coverage.py --arm legacy DIR [DIR ...] --arm v3 DIR [DIR ...]
         [--edges 0.1,0.2,0.3,0.4] [--plan-edges] [--gates] [--tuned-faults DIR ...]
         [--out FILE]
Prvni rameno je zaklad (`legacy`), posledni rameno je hodnocene (`v3`).
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
SENSOR = {"sensor_crash", "collector_replay", "log_corruption"}
OPS = {
    "service_crash", "retry_storm", "device_onboarding", "device_decommission",
    "patch_window", "batch_job", "collector_replay", "sensor_crash", "log_corruption",
    "dns_outage", "dhcp_renumber", "link_flapping", "misconfig", "backup_failed",
    "cert_expired", "segment_power_loss", "vpn_reconnect_storm", "cloud_migration",
}
SIGNATURE = {"suricata_alert", "egress_ids_alert"}
LOFO = {
    "c2_beacon": {"beacon_periodic"},
    "exfiltration": {"egress_volume_anomaly", "long_lived_tunnel"},
    "ssh_bruteforce": {"source_volume_outlier", "connection_timeout_burst"},
    "port_scan_vertical": {"scan_attempts", "connection_timeout_burst"},
    "lateral_movement": {"multi_target_pattern", "pivot_chain"},
    "dns_tunnel": {"egress_volume_anomaly", "source_volume_outlier"},
}
TEMPLATES = ["K-T1", "K-T2", "K-T3", "K-H1", "K-H2", "K-H3"]


def wilson(k, n):
    if n == 0:
        return (float("nan"), 0.0, 1.0)
    p = k / n
    denom = 1 + Z * Z / n
    center = (p + Z * Z / (2 * n)) / denom
    margin = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / denom
    lo = 0.0 if k == 0 else max(0.0, center - margin)
    hi = 1.0 if k == n else min(1.0, center + margin)
    return (p, lo, hi)


def pct(x):
    return "–" if x != x else f"{100 * x:.1f}".replace(".", ",")


def pp(x):
    return "–" if x != x else f"{100 * x:+.1f}".replace(".", ",")


def wtxt(k, n):
    p, lo, hi = wilson(k, n)
    return f"{pct(p)} % ({pct(lo)} až {pct(hi)})"


def load(dirs):
    rows = {}
    for d in dirs:
        with open(os.path.join(d, "networks.jsonl"), encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    row = json.loads(line)
                    rows[(row["run_seed"], row["network_id"])] = row
    return rows


def attacks(rows):
    """(klic site, zaznam) pro utoky s emitovanymi toky a kontrafaktualem."""
    out = []
    for key in sorted(rows):
        for a in rows[key].get("attacks", []):
            if a.get("emitted") and a.get("cf") is not None:
                out.append((key, a))
    return out


def var(a, name, default):
    v = a.get("variation") or {}
    return v.get(name, default)


def boot_indices(keys, rng):
    by_seed = defaultdict(list)
    for index, key in enumerate(keys):
        by_seed[key[0]].append(index)
    out = []
    for seed in sorted(by_seed):
        members = by_seed[seed]
        out.extend(members[rng.randrange(len(members))] for _ in members)
    return out


def cluster_ci(items, stat, seed=20261401):
    """items: list (klic site, hodnota); stat: funkce nad seznamem hodnot -> cislo."""
    by_net = defaultdict(list)
    for key, value in items:
        by_net[key].append(value)
    keys = sorted(by_net)
    full = stat([v for k in keys for v in by_net[k]])
    rng = random.Random(seed)
    samples = []
    for _ in range(BOOT):
        idx = boot_indices(keys, rng)
        value = stat([v for i in idx for v in by_net[keys[i]]])
        if value == value:
            samples.append(value)
    samples.sort()
    if not samples:
        return full, float("nan"), float("nan")
    return (
        full,
        samples[int(0.025 * len(samples))],
        samples[min(len(samples) - 1, int(0.975 * len(samples)))],
    )


def rate(values):
    return sum(values) / len(values) if values else float("nan")


def band(s, edges):
    for i, e in enumerate(edges):
        if s < e:
            return i
    return len(edges)


def classify(k, n):
    if n < 20:
        return "nedostatečná data"
    p = k / n
    if p < 0.5:
        return "SLEPÉ MÍSTO"
    if p < 0.7:
        return "slabé místo"
    return ""


class Report:
    def __init__(self):
        self.lines = []
        self.blind = []

    def add(self, text=""):
        self.lines.append(text)

    def table(self, header, rows):
        self.add("| " + " | ".join(header) + " |")
        self.add("|" + "|".join("---" if i == 0 else "---:" for i in range(len(header))) + "|")
        for r in rows:
            self.add("| " + " | ".join(str(c) for c in r) + " |")
        self.add()


def det_cells(report, arms, cell_of, title, register=True, min_register=20):
    """Tabulka detekce po bunkach pro vsechna ramena; hodnocene rameno = posledni."""
    cells = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for arm, items in arms.items():
        for _, a in items:
            for cell in cell_of(a):
                c = cells[cell][arm]
                c[0] += 1 if a["cf"] else 0
                c[1] += 1
    last = list(arms)[-1]
    rows = []
    for cell in sorted(cells, key=str):
        k, n = cells[cell][last]
        row = [cell, n]
        for arm in arms:
            ka, na = cells[cell][arm]
            row.append(wtxt(ka, na) if na else "–")
        verdict = classify(k, n)
        row.append(verdict)
        if register and verdict and n >= min_register:
            report.blind.append((title, cell, n, k / n if n else 0.0, verdict))
        rows.append(row)
    report.add(f"### {title}")
    report.add()
    report.table(["buňka", "n"] + [f"detekce {a}" for a in arms] + ["registr"], rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", nargs="+", action="append", required=True,
                    metavar=("NAME", "DIR"))
    ap.add_argument("--edges", default="")
    ap.add_argument("--gates", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    rows = {}
    for spec in args.arm:
        rows[spec[0]] = load(spec[1:])
    names = list(rows)
    arms = {name: attacks(r) for name, r in rows.items()}
    last = names[-1]
    rep = Report()

    # pasma skrytosti: kvintily S z planu (nezavisle na detekci) nebo zadane hranice
    # z planu: vsechny naplanovane utoky (i bez emitovanych toku), bez pohledu na detekci
    all_s = sorted(a["stealth"] for r in rows[last].values() for a in r.get("attacks", []))
    if args.edges:
        edges = [float(x) for x in args.edges.split(",")]
        edge_note = "zadané předem"
    else:
        edges = [all_s[int(q * (len(all_s) - 1))] for q in (0.2, 0.4, 0.6, 0.8)] if all_s else []
        edge_note = "kvintily S z plánu tohoto běhu (bez detekce)"
    rep.add("## Pokrytí, křivky skrytosti a registr slepých míst")
    rep.add()
    rep.add(f"Ramena: {', '.join(names)}; hodnocené rameno `{last}`. Detekce = kontrafaktuální "
            "zobrazená detekce na útok (Wilson 95 %; souhrny a rozdíly s bootstrapem po sítích).")
    rep.add()
    rep.add(f"Hranice pásem S ({edge_note}): " + ", ".join(f"{e:.3f}" for e in edges))
    rep.add()

    # --- souhrn ---
    summ = []
    for name in names:
        items = arms[name]
        p, lo, hi = cluster_ci([(k, 1 if a["cf"] else 0) for k, a in items], rate)
        r = rows[name]
        days = sum(x.get("virtual_days", 0) for x in r.values()) or 1
        fp = sum(x.get("output", {}).get("displayed_fp", 0) for x in r.values())
        panics = sum(x.get("panics", 0) for x in r.values())
        viol = sum(x.get("violations", 0) for x in r.values())
        out = [x.get("output", {}) for x in r.values()]
        wrong = sum(o.get("auto_closures_wrong_cf", 0) + o.get("ladder_refuted_wrong_cf", 0) for o in out)
        closed = sum(o.get("auto_closures", 0) + o.get("ladder_refuted", 0) for o in out)
        summ.append([name, len(r), len(items), f"{pct(p)} % ({pct(lo)} až {pct(hi)})",
                     f"{fp / days:.1f}".replace(".", ","), wtxt(wrong, closed) + f" [{wrong}/{closed}]",
                     f"{panics}/{viol}"])
    rep.table(["rameno", "sítí", "útoků", "detekce (bootstrap)", "zobrazené FP/síť-den",
               "zavřeno omylem (G3)", "panik/invariantů"], summ)

    # --- parove rozdily ---
    if len(names) >= 2:
        base = {(k, a["id"]): a for k, a in arms[names[0]]}
        paired = [(k, (1 if a["cf"] else 0) - (1 if base[(k, a["id"])]["cf"] else 0), a)
                  for k, a in arms[last] if (k, a["id"]) in base]
        def diff_for(sel):
            items = [(k, d) for k, d, a in paired if sel(a)]
            return cluster_ci(items, rate), len(items)
        prow = []
        for label, sel in [("vše", lambda a: True),
                           ("Q4 + Q5", lambda a: band(a["stealth"], edges) >= 3),
                           ("Q5", lambda a: band(a["stealth"], edges) == 4)]:
            (d, lo, hi), n = diff_for(sel)
            prow.append([label, n, f"{pp(d)} p. b. ({pp(lo)} až {pp(hi)})"])
        rep.add(f"### Párově `{last}` − `{names[0]}`")
        rep.add()
        rep.table(["výběr", "párů", "rozdíl detekce"], prow)

    # --- krivky skrytosti ---
    det_cells(rep, arms, lambda a: [f"Q{band(a['stealth'], edges) + 1}"], "Křivka skrytosti: pásma S")
    axes = [
        ("intenzita", lambda a: [f"{min(4, int(a['intensity'] * 5)) / 5:.1f}–{min(4, int(a['intensity'] * 5)) / 5 + 0.2:.1f}"]),
        ("tempo", lambda a: [f"{var(a, 'tempo', 1.0):g}×"]),
        ("rozptyl", lambda a: [f"{var(a, 'jitter', 0.0):g}"]),
        ("zdroje", lambda a: [f"{var(a, 'sources', 1)}"]),
        ("doba", lambda a: [f"{var(a, 'duration', 1.0):g}×"]),
        ("objem", lambda a: [f"{var(a, 'volume', 1.0):g}×"]),
        ("mimo pracovní dobu", lambda a: ["ano" if var(a, "off_hours", False) else "ne"]),
        ("míchání s provozem", lambda a: ["ano" if var(a, "blend", False) else "ne"]),
        ("IDS signatura", lambda a: ["ano" if a.get("ids_visible") else "ne"]),
    ]
    for title, fn in axes:
        det_cells(rep, arms, fn, f"Osa: {title}")
    det_cells(rep, arms, lambda a: [a["family"] + (" (H)" if a.get("held") else "")], "Rodiny")
    det_cells(rep, arms, lambda a: [f"{a['family']} | Q{band(a['stealth'], edges) + 1}"],
              "Rodina × pásmo S")
    det_cells(rep, arms, lambda a: [f"{a['family']} | tempo {var(a, 'tempo', 1.0):g}×"]
              + [f"{a['family']} | zdroje {var(a, 'sources', 1)}"]
              + [f"{a['family']} | objem {var(a, 'volume', 1.0):g}×"], "Rodina × osa (tempo, zdroje, objem)")

    # --- soubehy ---
    def overlap_cells(a):
        ops = [o for o in a.get("overlaps", []) if o in OPS]
        if not ops:
            return ["bez souběhu"]
        cells = []
        if any(o in SENSOR for o in ops):
            cells.append("senzorová porucha")
        if any(o not in SENSOR for o in ops):
            cells.append("nesenzorová porucha")
        cells += [f"s {o}" for o in sorted(set(ops))]
        return cells
    det_cells(rep, arms, overlap_cells, "Souběh útoku s provozní poruchou")

    # --- kampane ---
    camp_rows = []
    for name in names:
        by = defaultdict(list)
        for k, a in arms[name]:
            tag = a.get("campaign")
            if tag:
                by[(k, tag["id"], tag["template"])].append(a)
        stats = defaultdict(lambda: [0, 0, 0, 0])
        for (_, _, template), stages in by.items():
            s = stats[TEMPLATES[template]]
            stages.sort(key=lambda a: a["campaign"]["stage"])
            s[0] += 1
            s[1] += any(a["cf"] for a in stages)
            s[2] += stages[0]["cf"] and stages[0]["campaign"]["stage"] == 0
            s[3] += all(a["cf"] for a in stages)
        total = [sum(v[i] for v in stats.values()) for i in range(4)]
        for t in sorted(stats) + ["vše"]:
            s = stats[t] if t != "vše" else total
            camp_rows.append([name, t, s[0], wtxt(s[1], s[0]), wtxt(s[2], s[0]), wtxt(s[3], s[0])])
            if name == last and t != "vše" and s[0] >= 20 and s[1] / s[0] < 0.5:
                rep.blind.append(("Kampaně", t, s[0], s[1] / s[0], "SLEPÉ MÍSTO"))
    rep.add("### Kampaně")
    rep.add()
    rep.table(["rameno", "šablona", "kampaní", "aspoň jedna fáze", "první fáze", "všechny fáze"], camp_rows)

    # --- LOFO ---
    lofo_rows = []
    lofo = {}
    for fam, own in LOFO.items():
        sel = [(k, a) for k, a in arms[last] if a["family"] == fam]
        first = [a for _, a in sel if a.get("first_of_family") and not a.get("ids_visible")]
        generic = [a for a in first if set(a.get("cf_types", [])) - own - SIGNATURE]
        allsig = [a for a in first if a["cf"]]
        k, n = len(generic), len(first)
        p, lo, hi = wilson(k, n)
        ok = n > 0 and p >= 0.5 and lo >= 0.3
        lofo[fam] = (k, n, ok)
        lofo_rows.append([fam, ", ".join(sorted(own)), n, wtxt(len(allsig), n), wtxt(k, n),
                          "zobecňuje" if ok else ("nedostatečná data" if n < 20 else "SLEPÉ MÍSTO")])
        if not ok and n >= 1:
            rep.blind.append(("LOFO (první útok rodiny, bez signatury, bez vlastních typů)", fam, n,
                              k / n if n else 0.0, "SLEPÉ MÍSTO" if n >= 20 else "nedostatečná data"))
    rep.add(f"### Leave-one-family-out (náhrada A5), rameno `{last}`")
    rep.add()
    rep.table(["rodina", "vynechané typy D(X)", "n", "detekce všemi signály", "obecná detekce", "verdikt"], lofo_rows)

    # --- automaticke zavirani u utoku ---
    ac_rows = []
    for name in names:
        for held in (False, True):
            items = [a for _, a in arms[name] if bool(a.get("held")) == held]
            k = sum(1 for a in items if a.get("auto_closed"))
            kf = sum(1 for a in items if a.get("auto_closed_first"))
            ac_rows.append([name, "držené" if held else "laděné", len(items), wtxt(k, len(items)), kf])
    rep.add("### Útoky s automaticky zavřeným připsaným nálezem")
    rep.add()
    rep.table(["rameno", "rodiny", "útoků", "podíl s automatickým zavřením", "z toho první výskyt (A7)"], ac_rows)

    # --- poruchy a lookalike ---
    f_rows = []
    pooled = {}
    for name in names:
        by = defaultdict(lambda: [0, 0, 0])
        for r in rows[name].values():
            for f in r.get("faults", []):
                b = by[f["label"]]
                b[0] += 1
                b[1] += f.get("fp_displayed", False)
                b[2] += f.get("fp_captured", False)
                if f.get("new"):
                    g = pooled.setdefault((name, f.get("held", False)), [0, 0])
                    g[0] += 1
                    g[1] += f.get("fp_displayed", False)
        for label in sorted(by):
            n, kd, kc = by[label]
            held = label in {"cert_expired", "segment_power_loss", "vpn_reconnect_storm", "cloud_migration"}
            verdict = ""
            if n < 20:
                verdict = "nedostatečná data"
            elif kd / n > 0.2:
                verdict = "FP SLEPÉ MÍSTO"
            if name == last and verdict == "FP SLEPÉ MÍSTO":
                rep.blind.append(("Poruchy a lookalike (zobrazené FP)", label, n, kd / n, verdict))
            f_rows.append([name, label + (" (H)" if held else ""), n, wtxt(kd, n), wtxt(kc, n), verdict])
    rep.add("### Poruchy a lookalike: podíl výskytů s FP")
    rep.add()
    rep.table(["rameno", "událost", "výskytů", "zobrazené FP", "zachycené FP", "registr"], f_rows)

    # --- registr ---
    rep.add(f"### Registr slepých míst (rameno `{last}`, automaticky podle A8)")
    rep.add()
    rep.table(["oblast", "buňka", "n", "hodnota", "zařazení"],
              [[a, b, n, f"{pct(v)} %", c] for a, b, n, v, c in rep.blind])

    # --- prahy ---
    if args.gates:
        g = []
        q = defaultdict(lambda: [0, 0])
        for _, a in arms[last]:
            b = band(a["stealth"], edges)
            q[b][0] += a["cf"]
            q[b][1] += 1
        r1 = (q[4][0] / q[4][1]) / (q[0][0] / q[0][1]) if q[4][1] and q[0][1] and q[0][0] else float("nan")
        g.append(["K1", f"Q5/Q1 = {r1:.2f}".replace(".", ","), "ano" if r1 >= 0.5 else "ne"])
        if len(names) >= 2:
            (d_all, lo_a, hi_a), _ = diff_for(lambda a: True)
            (d_q, lo_q, hi_q), _ = diff_for(lambda a: band(a["stealth"], edges) >= 3)
            g.append(["K2", f"vše {pp(d_all)} p. b., Q4+Q5 {pp(d_q)} p. b.",
                      "ano" if d_all >= 0 and d_q >= 0 else "ne"])
        tuned = pooled.get((last, False), [0, 0])
        heldf = pooled.get((last, True), [0, 0])
        if tuned[0] and heldf[0]:
            pt, ph = tuned[1] / tuned[0], heldf[1] / heldf[0]
            g.append(["K3", f"držené {pct(ph)} % vs laděné {pct(pt)} %", "ano" if ph <= pt + 0.10 else "ne"])
        cnt = defaultdict(lambda: [0, 0])
        for _, a in arms[last]:
            cells = overlap_cells(a)
            if "bez souběhu" in cells:
                cnt["none"][0] += a["cf"]; cnt["none"][1] += 1
            elif "nesenzorová porucha" in cells and "senzorová porucha" not in cells:
                cnt["ops"][0] += a["cf"]; cnt["ops"][1] += 1
        if cnt["none"][1] and cnt["ops"][1]:
            d4 = cnt["ops"][0] / cnt["ops"][1] - cnt["none"][0] / cnt["none"][1]
            g.append(["K4", f"{pp(d4)} p. b.", "ano" if d4 >= -0.10 else "ne"])
        g.append(["K5", ", ".join(f"{f}: {k}/{n}" for f, (k, n, _) in lofo.items()),
                  f"{sum(1 for _, _, ok in lofo.values() if ok)} ze 6 zobecňuje"])
        out = [x.get("output", {}) for x in rows[last].values()]
        wrong = sum(o.get("auto_closures_wrong_cf", 0) + o.get("ladder_refuted_wrong_cf", 0) for o in out)
        closed = sum(o.get("auto_closures", 0) + o.get("ladder_refuted", 0) for o in out)
        _, _, hi6 = wilson(wrong, closed)
        g.append(["K6", f"{wrong}/{closed}, horní mez {pct(hi6)} %", "ano" if hi6 <= 0.05 else "ne"])
        ah = [a for _, a in arms[last] if a.get("held")]
        at = [a for _, a in arms[last] if not a.get("held")]
        if ah and at:
            ph = sum(a["auto_closed"] for a in ah) / len(ah)
            pt = sum(a["auto_closed"] for a in at) / len(at)
            g.append(["K6b", f"držené {pct(ph)} % vs laděné {pct(pt)} %", "ano" if ph <= pt + 0.05 else "ne"])
        camps = defaultdict(list)
        for k, a in arms[last]:
            if a.get("campaign"):
                camps[(k, a["campaign"]["id"])].append(a)
        if camps:
            k7 = sum(1 for s in camps.values() if any(a["cf"] for a in s))
            g.append(["K7", wtxt(k7, len(camps)), "ano" if k7 / len(camps) >= 0.9 else "ne"])
        panics = sum(x.get("panics", 0) for n in names for x in rows[n].values())
        viol = sum(x.get("violations", 0) for n in names for x in rows[n].values())
        g.append(["K8", f"{panics} panik, {viol} invariantů", "ano" if panics == 0 and viol == 0 else "ne"])
        rep.add("### Prahy K1 až K8")
        rep.add()
        rep.table(["práh", "hodnota", "splněno"], g)

    text = "\n".join(rep.lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    sys.stdout.buffer.write(text.encode("utf-8"))


if __name__ == "__main__":
    main()
