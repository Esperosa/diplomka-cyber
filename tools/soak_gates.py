#!/usr/bin/env python3
"""Vyhodnoceni predregistrovanych prahu G1 az G5 (krok 4, docs/diplomka/eval/impl-krok4.md).

Pouziti:
  python tools/soak_gates.py --legacy D [D ...] --s2 D [D ...] --s4 D [D ...] \
      [--s2-n10 D ...] [--s4-n10 D ...] [--s2-n50 D ...] [--s4-n50 D ...] \
      [--xxxl D ...] [--out FILE]
Rozhoduje bodovy odhad (G3: horni mez Wilsonova intervalu), intervaly se uvadeji.
Statistika stejna jako tools/soak_ab.py (parovy bootstrap po sitich po seedech).
"""
import argparse
import json
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soak_ab as ab  # noqa: E402


def paired(a, b):
    common = sorted(set(a) & set(b))
    return {k: a[k] for k in common}, {k: b[k] for k in common}


def ratio(a_dirs, b_dirs, metric="output.displayed_fp"):
    a, b = paired(ab.load(a_dirs), ab.load(b_dirs))
    va, vb, change, lo, hi = ab.ratio_change(a, b, metric)
    return len(a), va, vb, change, lo, hi


def families(legacy_dirs, s4_dirs, field="cf_detected_displayed"):
    a, b = paired(ab.load(legacy_dirs), ab.load(s4_dirs))
    keys = sorted(a)
    fams = sorted({f for k in keys for f in ab.get(a[k], "families")})
    rng = random.Random(13)
    boots = [ab.boot_indices(keys, rng) for _ in range(ab.BOOT)]
    rows = []
    tot = [[0] * len(keys), [0] * len(keys), [0] * len(keys)]
    for fam in fams:
        n = [ab.get(a[k], f"families.{fam}.cf_attacks") for k in keys]
        if sum(n) == 0:
            continue
        da = [ab.get(a[k], f"families.{fam}.{field}") for k in keys]
        db = [ab.get(b[k], f"families.{fam}.{field}") for k in keys]
        for i in range(len(keys)):
            tot[0][i] += n[i]
            tot[1][i] += da[i]
            tot[2][i] += db[i]
        rows.append((fam,) + diff_ci(n, da, db, boots))
    overall = diff_ci(tot[0], tot[1], tot[2], boots)
    return len(keys), rows, overall


def diff_ci(n, da, db, boots):
    total = sum(n)
    diffs = []
    for idx in boots:
        nt = sum(n[i] for i in idx)
        if nt:
            diffs.append((sum(db[i] for i in idx) - sum(da[i] for i in idx)) / nt)
    diffs.sort()
    lo = diffs[int(0.025 * len(diffs))]
    hi = diffs[min(len(diffs) - 1, int(0.975 * len(diffs)))]
    pa, pb = sum(da) / total, sum(db) / total
    return total, pa, pb, pb - pa, lo, hi


def closures(dirs):
    rows = ab.load(dirs)
    s = lambda m: sum(ab.get(r, m) for r in rows.values())  # noqa: E731
    n = s("output.auto_closures") + s("output.ladder_refuted")
    wrong = s("output.auto_closures_wrong_cf") + s("output.ladder_refuted_wrong_cf")
    return n, wrong, ab.wilson(wrong, n)


def health(dirs):
    rows = ab.load(dirs)
    return (len(rows), sum(ab.get(r, "panics") for r in rows.values()),
            sum(ab.get(r, "violations") for r in rows.values()))


def heap_peak(directory):
    log = directory.rstrip("/\\") + ".log"
    if not os.path.exists(log):
        return None
    with open(log, encoding="utf-8", errors="replace") as handle:
        found = re.findall(r"heap peak (\d+) MiB", handle.read())
    return int(found[-1]) if found else None


def main():
    p = argparse.ArgumentParser()
    for name in ["legacy", "s2", "s4", "s2-n10", "s4-n10", "s2-n50", "s4-n50", "xxxl"]:
        p.add_argument(f"--{name}", nargs="+", default=[])
    p.add_argument("--out")
    args = p.parse_args()
    out = []
    verdict = {}

    n, va, vb, ch, lo, hi = ratio(args.legacy, args.s4)
    verdict["G1a"] = ch <= -0.90
    out.append(f"G1a FP s4 vs legacy (1x, {n} siti): {va:.1f} -> {vb:.1f} na sit-den, "
               f"{ch * 100:+.1f} % (95% CI {lo * 100:+.1f} az {hi * 100:+.1f} %); prah <= -90 %: "
               f"{'SPLNENO' if verdict['G1a'] else 'NESPLNENO'}")
    for key, a_dirs, b_dirs, limit, label in [
        ("G1b", args.s2, args.s4, 1.10, "1x"),
        ("G1c", args.s2_n10, args.s4_n10, 1.5, "10x"),
        ("G1d", args.s2_n50, args.s4_n50, 2.5, "50x"),
    ]:
        if not a_dirs or not b_dirs:
            out.append(f"{key}: chybi data")
            verdict[key] = False
            continue
        n, va, vb, ch, lo, hi = ratio(a_dirs, b_dirs)
        verdict[key] = (1 + ch) <= limit
        out.append(f"{key} FP s4 vs s2 ({label}, {n} siti): {va:.1f} -> {vb:.1f}, pomer {1 + ch:.3f} "
                   f"(95% CI {1 + lo:.3f} az {1 + hi:.3f}); prah <= {limit}: "
                   f"{'SPLNENO' if verdict[key] else 'NESPLNENO'}")

    n, rows, overall = families(args.legacy, args.s4)
    out.append("")
    out.append(f"G2 kontrafaktualni zobrazena detekce, s4 - legacy ({n} siti):")
    out.append("")
    out.append("| rodina | n | legacy | s4 | rozdil (p. b.) | 95% CI | prah (n >= 100: >= -5) |")
    out.append("|---|---:|---:|---:|---:|---|---|")
    g2a = True
    for fam, total, pa, pb, d, lo, hi in rows:
        ok = total < 100 or d >= -0.05
        g2a &= ok
        tag = "-" if total < 100 else ("OK" if ok else "SELHALO")
        out.append(f"| {fam} | {total} | {pa * 100:.1f} % | {pb * 100:.1f} % | {d * 100:+.1f} | "
                   f"{lo * 100:+.1f} az {hi * 100:+.1f} | {tag} |")
    total, pa, pb, d, lo, hi = overall
    verdict["G2a"] = g2a
    verdict["G2b"] = d >= -0.02
    out.append(f"| **souhrnne** | {total} | {pa * 100:.1f} % | {pb * 100:.1f} % | {d * 100:+.1f} | "
               f"{lo * 100:+.1f} az {hi * 100:+.1f} | {'OK' if verdict['G2b'] else 'SELHALO'} (>= -2) |")
    out.append("")
    out.append(f"G2a (rodiny): {'SPLNENO' if g2a else 'NESPLNENO'}; G2b (souhrnne): "
               f"{'SPLNENO' if verdict['G2b'] else 'NESPLNENO'}")

    n_cl, wrong, (p, lo, hi) = closures(args.s4)
    verdict["G3"] = hi <= 0.05
    out.append(f"G3 zavreno omylem (s4): {wrong}/{n_cl} = {p * 100:.2f} % (95% CI {lo * 100:.2f} az "
               f"{hi * 100:.2f} %); prah horni mez <= 5 %: {'SPLNENO' if verdict['G3'] else 'NESPLNENO'}")

    if args.xxxl:
        worst, peaks = 0.0, []
        for d in args.xxxl:
            for r in ab.load([d]).values():
                worst = max(worst, ab.get(r, "cycle_p99_s"))
            peaks.append(heap_peak(d))
        peak = max((x for x in peaks if x is not None), default=None)
        verdict["G4"] = worst < 3.0 and peak is not None and peak < 1536
        out.append(f"G4 XXXL: max p99 cyklu {worst:.2f} s, peak haldy {peak} MiB (po behu: {peaks}); "
                   f"prah p99 < 3 s a peak < 1536 MiB: {'SPLNENO' if verdict['G4'] else 'NESPLNENO'}")
    else:
        verdict["G4"] = False
        out.append("G4: chybi data")

    nets, panics, viol = 0, 0, 0
    for group in [args.s2, args.s4, args.s2_n10, args.s4_n10, args.s2_n50, args.s4_n50, args.xxxl]:
        if group:
            a, b, c = health(group)
            nets, panics, viol = nets + a, panics + b, viol + c
    verdict["G5"] = panics == 0 and viol == 0
    out.append(f"G5 ramena v3: {nets} siti, paniky {panics}, porusene invarianty {viol}: "
               f"{'SPLNENO' if verdict['G5'] else 'NESPLNENO'}")
    lp = health(args.legacy) if args.legacy else (0, 0, 0)
    out.append(f"(legacy pro uplnost: {lp[0]} siti, paniky {lp[1]}, invarianty {lp[2]})")
    out.append("")
    out.append("CELKEM G1 az G5: " + ("SPLNENO" if all(verdict.values()) else
                                      "NESPLNENO: " + ", ".join(k for k, v in verdict.items() if not v)))
    text = "\n".join(out) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
