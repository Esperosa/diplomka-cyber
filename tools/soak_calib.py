#!/usr/bin/env python3
"""Kalibrace posteriory zebriku overovani (krok 2C, docs/diplomka/eval/impl-krok2.md).

Vstup: adresare soak behu (`networks.jsonl`), kazdy radek ma `output.calib_raw` a
`output.calib_used` = 20 kosu [n, pozitivni, soucet p, soucet p^2] posteriory
rozhodnutych BEHAVIORALNICH pripadu proti kontrafaktualni pravde.

- Brier a ECE (10 kosu) pred kalibraci,
- izotonicka regrese (PAVA, vazena poctem) s krizovou validaci NAPRIC SITEMI:
  leave-one-seed-out a 5-fold po sitich (fit na trenovacich sitich, mereni na
  testovacich), RQ2 Z7/Z11 vyhrady v dokumentu,
- kalibracni krivka pred a po,
- `--write DIR`: kalibrace pro jadro (JSON `IsotonicCalibrator`) fitovana bez
  daneho seedu (`cal-excl-<seed>.json`) a ze vsech (`cal-all.json`).

Pouziti: python tools/soak_calib.py DIR [DIR ...] [--field calib_raw] [--write DIR] [--out FILE]
"""
import argparse
import json
import math
import os
import random
import sys

BINS = 20


def load(dirs, field):
    rows = []
    for d in dirs:
        with open(os.path.join(d, "networks.jsonl"), encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                bins = row.get("output", {}).get(field) or []
                if bins:
                    rows.append((row["run_seed"], row["network_id"], bins))
    return rows


def pool(rows):
    out = [[0.0] * 4 for _ in range(BINS)]
    for _, _, bins in rows:
        for i, b in enumerate(bins[:BINS]):
            for k in range(4):
                out[i][k] += b[k]
    return out


def pava(bins):
    """Vazena izotonicka regrese nad kosi: (min skore bloku, p)."""
    points = [(b[2] / b[0], b[1] / b[0], b[0]) for b in bins if b[0] > 0]
    points.sort()
    stack = []
    for score, y, w in points:
        stack.append([score, y * w, w])
        while len(stack) >= 2 and stack[-2][1] / stack[-2][2] > stack[-1][1] / stack[-1][2]:
            b = stack.pop()
            a = stack.pop()
            stack.append([a[0], a[1] + b[1], a[2] + b[2]])
    return [(s, yw / w) for s, yw, w in stack], sum(w for _, _, w in points)


def predict(knots, score):
    value = knots[0][1]
    for low, p in knots:
        if low <= score:
            value = p
        else:
            break
    return value


def metrics(bins, knots=None):
    n = sum(b[0] for b in bins)
    if n == 0:
        return float("nan"), float("nan"), 0
    brier = 0.0
    ece_bins = [[0.0, 0.0, 0.0] for _ in range(10)]
    for b in bins:
        if b[0] == 0:
            continue
        mean_p = b[2] / b[0]
        if knots is None:
            # Brier presne z p^2, soucin p*y aproximovany strednim p kose
            brier += b[3] - 2 * mean_p * b[1] + b[1]
            q = mean_p
        else:
            q = predict(knots, mean_p)
            brier += b[0] * q * q - 2 * q * b[1] + b[1]
        k = min(9, int(q * 10))
        ece_bins[k][0] += b[0]
        ece_bins[k][1] += q * b[0]
        ece_bins[k][2] += b[1]
    ece = sum(e[0] / n * abs(e[1] / e[0] - e[2] / e[0]) for e in ece_bins if e[0] > 0)
    return brier / n, ece, int(n)


def curve(bins, knots=None):
    lines = ["| kos p | n | prumer p | podil utoku |", "|---|---:|---:|---:|"]
    agg = [[0.0, 0.0, 0.0] for _ in range(10)]
    for b in bins:
        if b[0] == 0:
            continue
        mean_p = b[2] / b[0]
        q = mean_p if knots is None else predict(knots, mean_p)
        k = min(9, int(q * 10))
        agg[k][0] += b[0]
        agg[k][1] += q * b[0]
        agg[k][2] += b[1]
    for k, (n, ps, pos) in enumerate(agg):
        if n:
            lines.append(f"| {k / 10:.1f}-{(k + 1) / 10:.1f} | {int(n)} | {ps / n:.3f} | {pos / n:.3f} |")
    return lines


def write_calibrator(path, knots, samples, source):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"knots": [[s, p] for s, p in knots], "samples": samples, "source": source}, handle)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dirs", nargs="+")
    parser.add_argument("--field", default="calib_raw")
    parser.add_argument("--write")
    parser.add_argument("--out")
    args = parser.parse_args()
    rows = load(args.dirs, args.field)
    lines = []
    allbins = pool(rows)
    b0, e0, n0 = metrics(allbins)
    base = sum(b[1] for b in allbins) / max(1.0, sum(b[0] for b in allbins))
    lines.append(f"Behavioralni predikce (posteriora rozhodnutych pripadu, pole `{args.field}`): n = {n0}, "
                 f"{len(rows)} siti, podil utoku {base * 100:.1f} %.")
    lines.append("")
    lines.append(f"Pred kalibraci: Brier {b0:.4f}, ECE {e0:.4f} (referencni Brier konstantni predikce "
                 f"podilu: {base * (1 - base):.4f}).")
    lines.append("")
    # leave-one-seed-out
    seeds = sorted({r[0] for r in rows})
    lines.append("| fold (test) | n test | Brier pred | Brier po | ECE pred | ECE po |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    pooled_after = [0.0, 0.0, 0]
    for seed in seeds:
        train = pool([r for r in rows if r[0] != seed])
        test = pool([r for r in rows if r[0] == seed])
        knots, samples = pava(train)
        bb, eb, nt = metrics(test)
        ba, ea, _ = metrics(test, knots)
        pooled_after[0] += ba * nt
        pooled_after[1] += ea * nt
        pooled_after[2] += nt
        lines.append(f"| seed {seed} | {nt} | {bb:.4f} | {ba:.4f} | {eb:.4f} | {ea:.4f} |")
        if args.write:
            os.makedirs(args.write, exist_ok=True)
            write_calibrator(os.path.join(args.write, f"cal-excl-{seed}.json"), knots, samples,
                             f"PAVA bez seedu {seed}, {samples:.0f} pripadu")
    if pooled_after[2]:
        lines.append(f"| **leave-one-seed-out** | {pooled_after[2]} | {b0:.4f} | "
                     f"{pooled_after[0] / pooled_after[2]:.4f} | {e0:.4f} | {pooled_after[1] / pooled_after[2]:.4f} |")
    # 5-fold po sitich
    rng = random.Random(20261101)
    order = list(range(len(rows)))
    rng.shuffle(order)
    folds = [order[i::5] for i in range(5)]
    briers, eces = [], []
    for fold in folds:
        test_idx = set(fold)
        train = pool([r for i, r in enumerate(rows) if i not in test_idx])
        test = pool([r for i, r in enumerate(rows) if i in test_idx])
        knots, _ = pava(train)
        ba, ea, nt = metrics(test, knots)
        if nt:
            briers.append(ba)
            eces.append(ea)
    if briers:
        mean = lambda v: sum(v) / len(v)
        sd = lambda v: math.sqrt(sum((x - mean(v)) ** 2 for x in v) / max(1, len(v) - 1))
        lines.append(f"| 5-fold po sitich (prumer +- sd) | | | {mean(briers):.4f} +- {sd(briers):.4f} | | "
                     f"{mean(eces):.4f} +- {sd(eces):.4f} |")
    lines.append("")
    knots_all, samples_all = pava(allbins)
    lines.append("Kalibracni krivka PRED (vsechny site):")
    lines.append("")
    lines.extend(curve(allbins))
    lines.append("")
    lines.append("Kalibracni krivka PO (izotonicka, fit na vsech sitich; jen ilustrace, CV cisla vyse):")
    lines.append("")
    lines.extend(curve(allbins, knots_all))
    if args.write:
        write_calibrator(os.path.join(args.write, "cal-all.json"), knots_all, samples_all,
                         f"PAVA vsechny site, {samples_all:.0f} pripadu")
    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
