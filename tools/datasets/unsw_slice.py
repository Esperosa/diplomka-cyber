"""UNSW-NB15: stazeni z oficialni sdilene slozky UNSW (anonymni odkaz z oficialni
stranky), proudove cteni UNSW-NB15_4.csv a vyrez dvou hodinovych oken (A9, odchylka
zapsana v impl-krok5.md H). Ulozi se jen vyrezy s redukovanymi sloupci.

Pouziti: python -I unsw_slice.py <out_root>
"""
import csv
import hashlib
import http.cookiejar
import io
import json
import os
import sys
import urllib.parse
import urllib.request

SHARE = ("https://unsw-my.sharepoint.com/:f:/g/personal/z5025758_ad_unsw_edu_au/"
         "EnuQZZn3XuNBjgfcUu4DIVMBLCHyoLHqOswirpOQifr1ag?e=gKWkLS")
BASE = "/personal/z5025758_ad_unsw_edu_au/Documents/UNSW-NB15 dataset/CSV Files/"
API = "https://unsw-my.sharepoint.com/personal/z5025758_ad_unsw_edu_au/_api/web/"
KEEP = ["stime", "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes",
        "dbytes", "spkts", "dpkts", "attack_cat", "label"]


def opener():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    op.addheaders = [("User-Agent", "Mozilla/5.0")]
    op.open(SHARE, timeout=60).read()
    return op


def get(op, name):
    url = API + f"GetFileByServerRelativeUrl('{urllib.parse.quote(BASE + name)}')/$value"
    return op.open(url, timeout=300)


def main(out_root):
    op = opener()
    features = get(op, "NUSW-NB15_features.csv").read().decode("latin-1")
    names = []
    for row in csv.reader(io.StringIO(features)):
        if len(row) >= 2 and row[0].strip().isdigit():
            names.append(row[1].strip().lower())
    print("sloupce", len(names), names[:10], names[-4:], file=sys.stderr)
    index = {n: names.index(n) for n in KEEP}
    resp = get(op, "UNSW-NB15_4.csv")
    rows = []
    got = 0
    text = io.TextIOWrapper(resp, encoding="latin-1", newline="")
    for cells in csv.reader(text):
        if len(cells) < len(names):
            continue
        try:
            stime = int(cells[index["stime"]])
        except ValueError:
            continue
        rows.append((stime, [cells[index[n]].strip() for n in KEEP]))
        got += 1
    rows.sort(key=lambda r: r[0])
    t0 = rows[0][0]
    windows = [("unsw-h0", t0, t0 + 3600), ("unsw-h2", t0 + 7200, t0 + 10800)]
    manifest = []
    for name, lo, hi in windows:
        sel = [c for t, c in rows if lo <= t < hi]
        directory = os.path.join(out_root, name)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "flows.csv")
        with open(path, "w", encoding="utf-8", newline="") as handle:
            w = csv.writer(handle)
            w.writerow(KEEP)
            w.writerows(sel)
        cats = {}
        for c in sel:
            if c[-1] == "1":
                cats[c[-2] or "-"] = cats.get(c[-2] or "-", 0) + 1
        manifest.append({"slice": name, "from": lo, "to": hi, "flows": len(sel),
                         "malicious": sum(cats.values()), "categories": cats,
                         "bytes": os.path.getsize(path),
                         "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest()})
    print(json.dumps({"rows": got, "t0": t0, "t_end": rows[-1][0], "slices": manifest}, indent=1))
    with open(os.path.join(out_root, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump({"rows": got, "slices": manifest}, handle, indent=1)


if __name__ == "__main__":
    main(sys.argv[1])
