#!/usr/bin/env python3
"""Souhrnna tabulka ablaci: kazda konfigurace v3 proti stejnemu legacy ramenu.

Pouziti: python tools/soak_ablation.py LEGACY_PREFIX NAZEV=PREFIX [NAZEV=PREFIX ...]
PREFIX = adresar bez seedu (napr. F:/Projekty/bakula-soak/ab/r3-v3); seedy 20261102..04.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soak_ab  # noqa: E402

SEEDS = (20261102, 20261103, 20261104)


def dirs(prefix):
    return [f"{prefix}-{seed}" for seed in SEEDS if os.path.exists(f"{prefix}-{seed}/networks.jsonl")]


def main():
    legacy = soak_ab.load(dirs(sys.argv[1]))
    print("| konfigurace | zobrazene/sit-den (zmena, 95% CI) | zobrazene FP/sit-den (zmena, 95% CI) | "
          "ceka na cloveka FP stavy/sit-den | zavreni / pricinne omylem | nejhorsi rodina n>=100: nad pozadim B-A | identita split / merge |")
    print("|---|---|---|---|---|---|---|")
    for spec in sys.argv[2:]:
        name, prefix = spec.split("=", 1)
        arm = soak_ab.load(dirs(prefix))
        common = sorted(set(legacy) & set(arm))
        a = {k: legacy[k] for k in common}
        b = {k: arm[k] for k in common}
        _, disp, ch, lo, hi = soak_ab.ratio_change(a, b, "output.displayed")
        _, fp, chf, lof, hif = soak_ab.ratio_change(a, b, "output.displayed_fp")
        _, hfp, _, _, _ = soak_ab.ratio_change(a, b, "output.states_awaiting_human_fp")
        closures = sum(soak_ab.get(b[k], "output.auto_closures") for k in common)
        causal = sum(soak_ab.get(b[k], "output.auto_closures_wrong_causal") for k in common)
        p, plo, phi = soak_ab.wilson(causal, closures)
        worst = None
        for fam, n, da, ha, db, hb, d, elo, ehi in soak_ab.excess_table(a, b):
            if n >= 100 and (worst is None or d < worst[1]):
                worst = (fam, d, elo, ehi)
        dev = sum(soak_ab.get(b[k], "identity_devices") for k in common)
        split = sum(soak_ab.get(b[k], "identity_false_split") for k in common)
        assets = sum(soak_ab.get(b[k], "identity_asset_ids") for k in common)
        merge = sum(soak_ab.get(b[k], "identity_false_merge") for k in common)
        worst_text = (f"{worst[0]} {worst[1] * 100:+.1f} p. b. ({worst[2] * 100:+.1f} az {worst[3] * 100:+.1f})"
                      if worst else "-")
        print(f"| {name} | {disp:.1f} ({ch * 100:+.1f} %, {lo * 100:+.1f} az {hi * 100:+.1f}) | "
              f"{fp:.1f} ({chf * 100:+.1f} %, {lof * 100:+.1f} az {hif * 100:+.1f}) | {hfp:.2f} | "
              f"{closures} / {p * 100:.1f} % ({plo * 100:.1f} az {phi * 100:.1f}) | {worst_text} | "
              f"{split / max(1, dev) * 100:.1f} % / {merge / max(1, assets) * 100:.1f} % |")


if __name__ == "__main__":
    main()
