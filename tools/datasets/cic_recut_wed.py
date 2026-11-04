"""Oprava prekryvu vyrezu stredy (A9): okna wed-dos-slow a wed-dos-hulk-goldeneye se
prekryvala, takze se rozdeli v polovine mezery mezi poslednim tokem pomale skupiny
(15:37:49) a prvnim tokem Hulk (15:43:23): hranice 15:40:36. Bez behu detektoru."""
import csv
import hashlib
import json
import os
import sys
from datetime import datetime

root = sys.argv[1]
cut = datetime(2017, 7, 5, 15, 40, 36)


def recut(name, keep):
    path = os.path.join(root, name, "flows.csv")
    with open(path, encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    header, body = rows[0], rows[1:]
    ti = header.index("Timestamp")
    sel = [r for r in body if keep(datetime.strptime(r[ti], "%d/%m/%Y %I:%M:%S %p"))]
    with open(path, "w", encoding="utf-8", newline="") as handle:
        w = csv.writer(handle)
        w.writerow(header)
        w.writerows(sel)
    mal = sum(1 for r in sel if r[-1].upper() != "BENIGN")
    return {"slice": name, "flows": len(sel), "malicious": mal, "bytes": os.path.getsize(path),
            "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(), "cut": str(cut)}


out = [recut("wed-dos-slow", lambda t: t < cut), recut("wed-dos-hulk-goldeneye", lambda t: t >= cut)]
print(json.dumps(out, indent=1))
with open(os.path.join(root, "manifest-Wednesday-recut.json"), "w", encoding="utf-8") as handle:
    json.dump(out, handle, indent=1)
