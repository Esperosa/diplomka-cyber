#!/usr/bin/env python3
"""Souhrn agregatu soak behu (final-report.json) po typech FP a pricinach R13.

Pouziti: python tools/soak_agg.py DIR [DIR ...]  (adresare se sectou, napr. tri seedy)
Funguje i pro stare behy bez `networks.jsonl` (jen agregat, bez intervalu po sitich).
"""
import json
import os
import sys
from collections import Counter


def main():
    total = Counter()
    fp = Counter()
    causes = Counter()
    families = {}
    for d in sys.argv[1:]:
        a = json.load(open(os.path.join(d, "final-report.json"), encoding="utf-8"))
        total["networks"] += a["networks"]
        total["days"] += a["virtual_hours"] / 24
        total["findings"] += a["findings"]
        total["fp"] += a["fp_noise"]
        total["panics"] += a["panics"]
        total["violations"] += sum(a["invariant_violations"].values())
        total["plans"] += a["verification"]["plans"]
        total["skipped_budget"] += a["verification"]["skipped_budget"]
        idn = a["identity"]
        for k in ("devices", "devices_false_split", "asset_ids", "asset_ids_false_merge"):
            total["id_" + k] += idn[k]
        fp.update(a["fp_noise_by_type"])
        causes.update(a.get("unexpected_causes", {}))
        for name, f in a["families"].items():
            if name.endswith("__ranked"):
                continue
            entry = families.setdefault(name, Counter())
            entry["truth"] += f["truth"]
            entry["detected"] += f["detected_any"]
            entry["typed"] += f["detected_typed"]
    days = total["days"] or 1
    print(f"siti {total['networks']}, sit-dni {days:.1f}, paniky {total['panics']}, invarianty {total['violations']}")
    print(f"nalezy/sit-den {total['findings'] / days:.1f}, FP/sit-den {total['fp'] / days:.1f}")
    print(f"plany {total['plans']}, mimo rozpocet {total['skipped_budget'] / max(1, total['plans']) * 100:.1f} %")
    print(f"identita: falesne rozdeleno {total['id_devices_false_split'] / max(1, total['id_devices']) * 100:.1f} % "
          f"(n={total['id_devices']}), slouceno {total['id_asset_ids_false_merge'] / max(1, total['id_asset_ids']) * 100:.1f} %")
    print("FP podle typu (na sit-den, podil):")
    for name, count in fp.most_common(10):
        print(f"  {name:32s} {count / days:9.1f}  {count / max(1, total['fp']) * 100:5.1f} %")
    if causes:
        print("pricina FP unexpected/unmapped (podil z FP typu):")
        by_type = Counter()
        for key, count in causes.items():
            by_type[key.split("|")[0]] += count
        for key, count in sorted(causes.items(), key=lambda kv: -kv[1]):
            kind = key.split("|")[0]
            print(f"  {key:60s} {count / days:9.1f}  {count / by_type[kind] * 100:5.1f} %")
    print("detekce po rodinach (zachyceno, spravny typ):")
    for name, f in sorted(families.items()):
        n = f["truth"] or 1
        print(f"  {name:22s} n={f['truth']:4d} detekce {f['detected'] / n * 100:5.1f} %  typ {f['typed'] / n * 100:5.1f} %")


if __name__ == "__main__":
    main()
