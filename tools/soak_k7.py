#!/usr/bin/env python3
"""Vyhodnoceni kroku 7 (docs/diplomka/eval/impl-krok7.md, B5 a B6).

Vstup: adresare behu po ramenech (`--arm NAZEV DIR [DIR ...]`), prvni rameno je zaklad
parovych srovnani. Volitelne `--lofo RODINA DIR [DIR ...]` (skutecna ablace, B7).

Metriky: detekce (cf, fronta podezreni) mikro i makro, zobrazene FP a vsechny zobrazene
polozky na sit-den, zavreno omylem (G3) a pocet na utok, tiche potlaceni, habituace,
latence prvni detekce, chranena automaticka zavreni, ops-only utoky, provozni anotace,
poruchy po variantach, kategorie bunek (a/b/c) bez korekce i s Holmovou korekci.
Intervaly: Wilson pro podily, bootstrap clusterovany po sitich a stratifikovany po
seedech (B = 2000) pro souhrny, pomery a parove rozdily. Jen standardni knihovna.
"""
import argparse
import math
import os
import random
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soak_coverage import (  # noqa: E402
    BOOT, LOFO, SIGNATURE, attacks, band, boot_indices, cluster_ci, load, pct, pp, var,
    wilson, wtxt,
)

EDGES = [0.1718, 0.2363, 0.3053, 0.3917]
DEFINITIONAL = {"exfiltration", "port_scan_vertical"}
K3_NEW = {"saas_group", "cert_8443"}


def num(x, digits=1):
    return "–" if x != x else f"{x:.{digits}f}".replace(".", ",")


def fmt_ci(t, scale=100.0, signed=False, digits=1):
    f = (lambda x: f"{scale * x:+.{digits}f}") if signed else (lambda x: f"{scale * x:.{digits}f}")
    full, lo, hi = t
    if full != full:
        return "–"
    return f"{f(full)} ({f(lo)} až {f(hi)})".replace(".", ",")


def paired_ci(base, arm, value, agg="rate"):
    """Parovy rozdil (agg=rate) nebo pomer souctu (agg=ratio) po sitich."""
    keys = sorted(set(base) & set(arm))
    rng = random.Random(20261901)

    def stat(idx):
        if agg == "rate":
            a = [v for i in idx for v in value(arm[keys[i]])]
            b = [v for i in idx for v in value(base[keys[i]])]
            if not a or not b:
                return float("nan")
            return sum(a) / len(a) - sum(b) / len(b)
        num = sum(value(arm[keys[i]]) for i in idx)
        den = sum(value(base[keys[i]]) for i in idx)
        return num / den if den else float("nan")

    full = stat(range(len(keys)))
    samples = []
    for _ in range(BOOT):
        s = stat(boot_indices(keys, rng))
        if s == s:
            samples.append(s)
    samples.sort()
    if not samples:
        return (full, float("nan"), float("nan"))
    return (full, samples[int(0.025 * len(samples))],
            samples[min(len(samples) - 1, int(0.975 * len(samples)))])


def det_values(row):
    return [1 if a["cf"] else 0 for a in row.get("attacks", [])
            if a.get("emitted") and a.get("cf") is not None]


def binom_sf(k, n, p):
    """P(X >= k) pro X ~ Bin(n, p), v logaritmech."""
    if k <= 0:
        return 1.0
    total = 0.0
    lp, lq = math.log(p), math.log(1 - p)
    for i in range(k, n + 1):
        total += math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
                          + i * lp + (n - i) * lq)
    return min(1.0, total)


def holm(pvalues, alpha=0.05):
    order = sorted(range(len(pvalues)), key=lambda i: pvalues[i])
    reject = [False] * len(pvalues)
    m = len(pvalues)
    for rank, i in enumerate(order):
        if pvalues[i] <= alpha / (m - rank):
            reject[i] = True
        else:
            break
    return reject


def per_net(rows, fn):
    return {k: fn(r) for k, r in rows.items()}


def summary(name, rows, out):
    items = attacks(rows)
    det = cluster_ci([(k, 1 if a["cf"] else 0) for k, a in items], lambda v: sum(v) / len(v) if v else float("nan"))
    fams = defaultdict(list)
    for k, a in items:
        fams[a["family"]].append((k, a["family"], 1 if a["cf"] else 0))

    def macro(values):
        by = defaultdict(list)
        for fam, hit in values:
            by[fam].append(hit)
        rates = [sum(v) / len(v) for v in by.values() if v]
        return sum(rates) / len(rates) if rates else float("nan")

    mac = cluster_ci([(k, (a["family"], 1 if a["cf"] else 0)) for k, a in items], macro)
    days = sum(r.get("virtual_days", 0) for r in rows.values())
    fp = sum(r["output"].get("displayed_fp_suspect", r["output"].get("displayed_fp", 0)) for r in rows.values())
    shown = sum(r["output"].get("displayed", 0) for r in rows.values())
    o = defaultdict(int)
    for r in rows.values():
        for key in ("auto_closures", "auto_closures_wrong_cf", "ladder_refuted", "ladder_refuted_wrong_cf"):
            o[key] += r["output"].get(key, 0)
        for key, v in (r["output"].get("k7") or {}).items():
            if not key.startswith("ops_diag|"):
                o["k7." + key] += v
    closed = o["auto_closures"] + o["ladder_refuted"]
    wrong = o["auto_closures_wrong_cf"] + o["ladder_refuted_wrong_cf"]
    k7 = [a.get("k7") for _, a in items if a.get("k7")]
    wrong_attacks = sum(1 for x in k7 if x["wrong_closed"] > 0)
    wrong_findings = sum(x["wrong_closed"] for x in k7)
    vis = sum(x["vis_cycles"] for x in k7)
    post = sum(x["post_cycles"] for x in k7)
    silenced = defaultdict(int)
    for x in k7:
        if x.get("silenced"):
            silenced[x["silenced"]] += 1
    habit = sum(1 for x in k7 if x["habituated"])
    lat = sorted(x["latency"] for x in k7 if x.get("latency") is not None)
    ops_only = sum(1 for _, a in items if a.get("ops_shown") and not a["cf"])
    ops_ann = sum(1 for x in k7 if x.get("ops_annotated"))
    out[name] = dict(
        n=len(items), det=det, macro=mac, fp_nd=fp / days if days else float("nan"),
        load_nd=shown / days if days else float("nan"), closed=closed, wrong=wrong,
        wrong_attacks=wrong_attacks, wrong_findings=wrong_findings,
        vis=vis / post if post else float("nan"), silenced=dict(silenced), habit=habit,
        lat_med=lat[len(lat) // 2] if lat else None,
        lat_p90=lat[min(len(lat) - 1, int(0.9 * len(lat)))] if lat else None,
        protected_closed=o["k7.protected_auto_closed"], protected_shown=o["k7.protected_displayed"],
        ops_only=ops_only, ops_ann=ops_ann, nets=len(rows), days=days,
        fams={f: (sum(h for _, _, h in v), len(v)) for f, v in fams.items()},
    )


def fault_rows(rows):
    out = []
    for key in sorted(rows):
        for f in rows[key].get("faults", []):
            out.append((key, f))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", nargs="+", action="append", required=True)
    ap.add_argument("--lofo", nargs="+", action="append", default=[])
    ap.add_argument("--title", default="Krok 7")
    ap.add_argument("--out")
    args = ap.parse_args()
    arms = {spec[0]: load(spec[1:]) for spec in args.arm}
    names = list(arms)
    base, last = names[0], names[-1]
    lines = [f"## {args.title}", ""]
    stats = {}
    for name in names:
        summary(name, arms[name], stats)

    lines += ["| rameno | sítí | útoků | detekce mikro | detekce makro | FP/síť-den | zobrazeno/síť-den | zavřeno omylem (G3) | útoky s omylem zavřeným nálezem | omylem zavřených nálezů |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name in names:
        s = stats[name]
        lines.append(
            f"| {name} | {s['nets']} | {s['n']} | {fmt_ci(s['det'])} | {fmt_ci(s['macro'])} | "
            f"{num(s['fp_nd'])} | {num(s['load_nd'])} | {wtxt(s['wrong'], s['closed'])} [{s['wrong']}/{s['closed']}] | "
            f"{s['wrong_attacks']} | {s['wrong_findings']} |")
    lines.append("")
    lines += ["| rameno | viditelnost po 1. zobrazení | ztráta viditelnosti (příčina: útoků) | habituace | latence medián / p90 (cykly) | chráněných zobrazeno / automaticky zavřeno | ops-only útoky | útoky s provozní anotací |",
              "|---|---:|---|---:|---:|---:|---:|---:|"]
    for name in names:
        s = stats[name]
        sil = ", ".join(f"{k}: {v}" for k, v in sorted(s["silenced"].items())) or "0"
        lines.append(
            f"| {name} | {pct(s['vis'])} % | {sil} | {s['habit']} | {s['lat_med']} / {s['lat_p90']} | "
            f"{s['protected_shown']} / {s['protected_closed']} | {s['ops_only']} | {s['ops_ann']} |")
    lines.append("")

    # parova srovnani proti zakladu
    lines += [f"### Párově proti `{base}`", "",
              "| rameno | detekce (p. b.) | FP poměr | zobrazeno poměr | nejhorší rodina n ≥ 100 (p. b.) |",
              "|---|---:|---:|---:|---|"]
    fpv = lambda r: r["output"].get("displayed_fp_suspect", r["output"].get("displayed_fp", 0))
    showv = lambda r: r["output"].get("displayed", 0)
    for name in names[1:]:
        d = paired_ci(arms[base], arms[name], det_values)
        f = paired_ci(arms[base], arms[name], fpv, agg="ratio")
        l = paired_ci(arms[base], arms[name], showv, agg="ratio")
        worst = None
        for fam, (k, n) in stats[name]["fams"].items():
            kb, nb = stats[base]["fams"].get(fam, (0, 0))
            if n >= 100 and nb:
                diff = k / n - kb / nb
                if worst is None or diff < worst[1]:
                    worst = (fam, diff)
        wtx = f"{worst[0]} {pp(worst[1])}" if worst else "–"
        lines.append(f"| {name} | {fmt_ci(d, signed=True)} | {fmt_ci(f, 1, digits=3)} | {fmt_ci(l, 1, digits=3)} | {wtx} |")
    lines.append("")

    # rodiny
    fams = sorted({f for s in stats.values() for f in s["fams"]})
    lines += ["### Rodiny", "", "| rodina | n | " + " | ".join(names) + " |",
              "|---|---:|" + "---:|" * len(names)]
    for fam in fams:
        n = stats[last]["fams"].get(fam, (0, 0))[1]
        cells = []
        for name in names:
            k, nn = stats[name]["fams"].get(fam, (0, 0))
            cells.append(wtxt(k, nn) if nn else "–")
        lines.append(f"| {fam} | {n} | " + " | ".join(cells) + " |")
    lines.append("")

    # poruchy
    lines += ["### Poruchy a lookalike (fronta podezření)", "",
              "| porucha | varianta | n | " + " | ".join(f"FP {x}" for x in names) + f" | položek/výskyt {last} | anotace {last} |",
              "|---|---|---:|" + "---:|" * len(names) + "---:|---:|"]
    groups = defaultdict(lambda: defaultdict(list))
    for name in names:
        for key, f in fault_rows(arms[name]):
            k7 = f.get("k7") or {}
            variant = k7.get("variant") or ("low" if k7 and k7.get("intensity", 1) < 0.4 else "-")
            groups[(f["label"], variant)][name].append(f)
    for (label, variant) in sorted(groups):
        g = groups[(label, variant)]
        n = len(g.get(last, []))
        cells = []
        for name in names:
            fs = g.get(name, [])
            k = sum(1 for f in fs if f.get("fp_suspect", f.get("fp_displayed")))
            cells.append(wtxt(k, len(fs)) if fs else "–")
        fs = g.get(last, [])
        items = sum((f.get("k7") or {}).get("suspect_items", 0) for f in fs)
        ann = sum(1 for f in fs if (f.get("k7") or {}).get("ops_annotated"))
        lines.append(f"| {label} | {variant} | {n} | " + " | ".join(cells)
                     + f" | {items / n if n else 0:.2f} | {ann} |")
    lines.append("")

    # diagnostika E1 (B1)
    diag = defaultdict(int)
    for r in arms[last].values():
        for key, v in (r["output"].get("k7") or {}).items():
            if key.startswith("ops_diag|"):
                diag[key[len("ops_diag|"):]] += v
    if diag:
        lines += [f"### Diagnostika E1 (`{last}`, zobrazené položky poruch)", "",
                  "| porucha | typ | tvar klíče | zdroje | shoda | položek |", "|---|---|---|---|---|---:|"]
        for key, v in sorted(diag.items(), key=lambda kv: -kv[1])[:40]:
            parts = key.split("|")
            lines.append("| " + " | ".join(parts) + f" | {v} |")
        lines.append("")

    # bunky a kategorie (hodnocene rameno = posledni)
    items = attacks(arms[last])
    cells = defaultdict(lambda: [0, 0])

    def add(cell, hit):
        c = cells[cell]
        c[0] += hit
        c[1] += 1

    for _, a in items:
        hit = 1 if a["cf"] else 0
        fam = a["family"]
        add(("rodina", fam), hit)
        add(("pásmo S", f"Q{band(a.get('stealth', 0.0), EDGES) + 1}"), hit)
        for axis, default in (("tempo", 1.0), ("jitter", 0.0), ("sources", 1), ("duration", 1.0), ("volume", 1.0)):
            level = var(a, axis, default)
            add((f"rodina × {axis}", f"{fam} {level}"), hit)
            add((axis, str(level)), hit)
        add(("IDS", "ano" if a.get("ids_visible") else "ne"), hit)
    cats = []
    for cell, (k, n) in cells.items():
        p, lo, _ = wilson(k, n)
        if n < 20:
            cat = "c"
        elif p >= 0.7 and lo >= 0.6:
            cat = "a"
        else:
            cat = "b"
        cats.append([cell, k, n, p, lo, cat, binom_sf(k, n, 0.6) if n >= 20 and p >= 0.7 else 1.0])
    rej = holm([c[6] for c in cats])
    counts = defaultdict(int)
    for c, r in zip(cats, rej):
        holm_cat = "a" if (c[5] == "a" and r) else ("c" if c[5] == "c" else "b")
        c.append(holm_cat)
        counts[(c[5], holm_cat)] += 1
    lines += [f"### Kategorie buněk (`{last}`)", "",
              f"Buněk celkem {len(cats)}. Bez korekce: (a) {sum(1 for c in cats if c[5]=='a')}, (b) {sum(1 for c in cats if c[5]=='b')}, (c) {sum(1 for c in cats if c[5]=='c')}. "
              f"S Holmovou korekcí: (a) {sum(1 for c in cats if c[7]=='a')}, (b) {sum(1 for c in cats if c[7]=='b')}, (c) {sum(1 for c in cats if c[7]=='c')}.", "",
              "Buňky v (b) s n ≥ 20 (vedené s mírou a mitigací):", "",
              "| dimenze | buňka | n | detekce (Wilson) | kategorie bez korekce |", "|---|---|---:|---:|---|"]
    for c in sorted(cats, key=lambda c: (c[0][0], c[3])):
        if c[7] == "b":
            lines.append(f"| {c[0][0]} | {c[0][1]} | {c[2]} | {wtxt(c[1], c[2])} | {c[5]} |")
    lines.append("")

    # LOFO skutecnou ablaci
    if args.lofo:
        lines += ["### K5: LOFO skutečnou ablací (první útok rodiny, bez IDS)", "",
                  "| rodina | n | detekce bez vlastních detektorů | zobecňuje | definiční |", "|---|---:|---:|---|---|"]
        for spec in args.lofo:
            fam, dirs = spec[0], spec[1:]
            rows = load(dirs)
            sel = [a for _, a in attacks(rows) if a["family"] == fam and a.get("first_of_family") and not a.get("ids_visible")]
            k = sum(1 for a in sel if a["cf"])
            p, lo, _ = wilson(k, len(sel))
            ok = len(sel) > 0 and p >= 0.5 and lo >= 0.3
            lines.append(f"| {fam} | {len(sel)} | {wtxt(k, len(sel))} | {'ano' if ok else 'ne'} | {'ano' if fam in DEFINITIONAL else 'ne'} |")
        lines.append("")

    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(text)


if __name__ == "__main__":
    main()
