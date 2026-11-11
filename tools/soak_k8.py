#!/usr/bin/env python3
"""Vyhodnoceni kroku 8 (docs/diplomka/eval/impl-krok8.md, B: prahy E1 az E14).

Vstup: `--arm NAZEV DIR [DIR ...]` pro ramena `off`, `on100`, `on60`, `on30`,
`comp-silent`, `comp-ok` (prvni je zaklad parovych srovnani). Pouziva pomocne funkce
kroku 7 (`soak_coverage.py`, `soak_k7.py`): Wilsonovy intervaly, bootstrap po sitich
stratifikovany po seedech (B = 2000), parove rozdily. Jen standardni knihovna.
"""
import argparse
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soak_coverage import attacks, load, wilson, wtxt  # noqa: E402
from soak_k7 import det_values, fmt_ci, num, paired_ci  # noqa: E402

FAMS = {
    "exploit_attempt": ("exploit",),
    "lateral_movement": ("lateral",),
    "c2_beacon": ("c2_beacon", "c2"),
}


def fam_match(label, keys):
    return any(label == k or label.startswith(k) for k in keys)


def fam_values(label_keys, slow=False):
    def values(row):
        out = []
        for a in row.get("attacks", []):
            if not (a.get("emitted") and a.get("cf") is not None):
                continue
            if not fam_match(a["family"], label_keys):
                continue
            if slow:
                tempo = (a.get("variation") or {}).get("tempo", 1.0)
                if tempo > 0.5:
                    continue
            out.append(1 if a["cf"] else 0)
        return out
    return values


def counters(rows):
    c = defaultdict(int)
    for r in rows.values():
        for key, v in (r["output"].get("k7") or {}).items():
            if key.startswith("endpoint_") or key.startswith("protected_"):
                c[key] += v
    return c


def totals(rows):
    items = attacks(rows)
    hit = sum(1 for _, a in items if a["cf"])
    days = sum(r.get("virtual_days", 0) for r in rows.values())
    fp = sum(r["output"].get("displayed_fp_suspect", r["output"].get("displayed_fp", 0)) for r in rows.values())
    shown = sum(r["output"].get("displayed", 0) for r in rows.values())
    wrong_attacks = sum(1 for _, a in items if (a.get("k7") or {}).get("wrong_closed", 0) > 0)
    closed = sum(r["output"].get("auto_closures", 0) + r["output"].get("ladder_refuted", 0) for r in rows.values())
    wrong = sum(r["output"].get("auto_closures_wrong_cf", 0) + r["output"].get("ladder_refuted_wrong_cf", 0)
                for r in rows.values())
    return dict(n=len(items), hit=hit, days=days, fp=fp, shown=shown, wrong_attacks=wrong_attacks,
                closed=closed, wrong=wrong, nets=len(rows))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", nargs="+", action="append", required=True)
    ap.add_argument("--title", default="Krok 8")
    ap.add_argument("--out")
    args = ap.parse_args()
    arms = {spec[0]: load(spec[1:]) for spec in args.arm}
    names = list(arms)
    base = names[0]
    tot = {n: totals(arms[n]) for n in names}
    cnt = {n: counters(arms[n]) for n in names}
    lines = [f"## {args.title}", ""]
    lines += ["| rameno | sítí | útoků | detekce | FP/síť-den | zobrazeno/síť-den | zavřeno omylem | útoky s omylem zavřeným nálezem |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for n in names:
        t = tot[n]
        lo = wilson(t["hit"], t["n"])
        det = f"{100 * lo[0]:.1f} ({100 * lo[1]:.1f} až {100 * lo[2]:.1f})".replace(".", ",") if t["n"] else "–"
        lines.append(
            f"| {n} | {t['nets']} | {t['n']} | {det} | {num(t['fp'] / t['days'] if t['days'] else float('nan'))} | "
            f"{num(t['shown'] / t['days'] if t['days'] else float('nan'))} | {wtxt(t['wrong'], t['closed'])} | {t['wrong_attacks']} |")
    lines.append("")

    fpv = lambda r: r["output"].get("displayed_fp_suspect", r["output"].get("displayed_fp", 0))
    showv = lambda r: r["output"].get("displayed", 0)
    lines += [f"### Párově proti `{base}`", "",
              "| rameno | detekce souhrn (p. b.) | exploit (p. b.) | lateral (p. b.) | c2_beacon (p. b.) | c2 pomalé tempo ≤ 0,5× (p. b.) | FP poměr | zobrazeno poměr |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    paired = {}
    for n in names[1:]:
        row = {"all": paired_ci(arms[base], arms[n], det_values)}
        for fam, keys in FAMS.items():
            row[fam] = paired_ci(arms[base], arms[n], fam_values(keys))
        row["c2_slow"] = paired_ci(arms[base], arms[n], fam_values(FAMS["c2_beacon"], slow=True))
        row["fp"] = paired_ci(arms[base], arms[n], fpv, agg="ratio")
        row["shown"] = paired_ci(arms[base], arms[n], showv, agg="ratio")
        paired[n] = row
        lines.append(
            f"| {n} | {fmt_ci(row['all'], signed=True)} | {fmt_ci(row['exploit_attempt'], signed=True)} | "
            f"{fmt_ci(row['lateral_movement'], signed=True)} | {fmt_ci(row['c2_beacon'], signed=True)} | "
            f"{fmt_ci(row['c2_slow'], signed=True)} | {fmt_ci(row['fp'], 1, digits=3)} | {fmt_ci(row['shown'], 1, digits=3)} |")
    lines.append("")

    lines += ["### Počítadla koncové telemetrie a ochrany", "",
              "| počítadlo | " + " | ".join(names) + " |", "|---|" + "---:|" * len(names)]
    keys = sorted({k for c in cnt.values() for k in c})
    for k in keys:
        lines.append(f"| {k} | " + " | ".join(str(cnt[n].get(k, 0)) for n in names) + " |")
    lines.append("")

    # prahy
    def ok(flag):
        return "**splněno**" if flag else "**nesplněno**"

    res = []
    full = paired.get("on100")
    if full:
        for code, fam, need in (("E1", "exploit_attempt", 0.10), ("E2", "lateral_movement", 0.08), ("E3", "c2_beacon", 0.08)):
            d, lo, hi = full[fam]
            res.append((code, f"{fam} on100 − off = {100 * d:+.1f} p. b. (dolní mez {100 * lo:+.1f})",
                        d >= need and lo > 0))
        res.append(("E4", f"detekce souhrn {100 * full['all'][0]:+.1f} p. b.", full["all"][0] >= 0))
        res.append(("E5", f"FP poměr {full['fp'][0]:.3f}", full["fp"][0] <= 1.10))
        res.append(("E6", f"zobrazeno poměr {full['shown'][0]:.3f}", full["shown"][0] <= 1.15))
        res.append(("E7", f"útoky s omylem zavřeným nálezem {tot['on100']['wrong_attacks']} proti {tot[base]['wrong_attacks']}",
                    tot["on100"]["wrong_attacks"] <= tot[base]["wrong_attacks"]))
    if "comp-ok" in tot:
        n = tot["comp-ok"]
        extra = n["wrong_attacks"] - tot[base]["wrong_attacks"]
        d = paired["comp-ok"]["all"][0]
        res.append(("E8", f"comp-ok: útoků s omylem zavřeným nálezem {n['wrong_attacks']} proti {tot[base]['wrong_attacks']} "
                          f"(+{extra}, limit 1 % útoků = {0.01 * n['n']:.1f}), detekce {100 * d:+.1f} p. b.",
                    extra <= 0.01 * n["n"] and d >= -0.01))
    if "comp-silent" in tot:
        d = paired["comp-silent"]["all"][0]
        res.append(("E9", f"comp-silent: detekce {100 * d:+.1f} p. b.", d >= -0.01))
    bad = sum(cnt[n].get("protected_auto_closed", 0) + cnt[n].get("endpoint_protected_closed", 0) for n in names)
    res.append(("E10", f"chráněná zavření (všechna ramena) {bad}", bad == 0))
    mono = [paired[n]["all"][0] for n in ("on100", "on60", "on30") if n in paired]
    if len(mono) == 3:
        res.append(("E11", "souhrn on100 {:+.1f}, on60 {:+.1f}, on30 {:+.1f} p. b.".format(*[100 * m for m in mono]),
                    mono[0] >= mono[1] - 0.005 and mono[1] >= mono[2] - 0.005 and mono[2] >= -0.005))
    lines += ["### Prahy (E1 až E11; E12 až E14 viz test a ověření determinismu)", "",
              "| práh | hodnota | výsledek |", "|---|---|---|"]
    for code, text, flag in res:
        lines.append(f"| {code} | {text} | {ok(flag)} |")
    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    print(text)


if __name__ == "__main__":
    main()
