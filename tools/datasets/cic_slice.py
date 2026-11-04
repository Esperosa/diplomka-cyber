"""CIC-IDS2017 (pregenerovana verze Engelen a kol., WTMC 2021): stazeni jednoho dne
ze ZIPu pres HTTP Range, rozbaleni proudem a vyrez oken podle predregistrace
(docs/diplomka/eval/impl-krok5.md, A9). Cela surova data se neukladaji, jen vyrezy
s redukovanymi sloupci. Zadne osobni udaje (testbed, simulovani uzivatele).

Pouziti: python -I cic_slice.py <out_root> <den>   (den = Monday|Tuesday|...)
"""
import csv
import hashlib
import io
import json
import os
import struct
import sys
import urllib.request
import zlib
from datetime import datetime, timedelta

URL = "https://intrusion-detection.distrinet-research.be/WTMC2021/Dataset/dataset.zip"
MEMBERS = {
    "Friday": (0, 74040350),
    "Monday": (74040451, 64799287),
    "Thursday": (138839839, 53096834),
    "Tuesday": (191936776, 54940233),
    "Wednesday": (246877111, 86963688),
}
# skupiny stitku -> nazev vyrezu (A9)
GROUPS = {
    "Tuesday": [("tue-ftp-patator", ["FTP-Patator"]), ("tue-ssh-patator", ["SSH-Patator"])],
    "Wednesday": [("wed-dos-slow", ["DoS Slowloris", "DoS Slowhttptest"]),
                  ("wed-dos-hulk-goldeneye", ["DoS Hulk", "DoS GoldenEye"])],
    "Thursday": [("thu-web", ["Web Attack"]), ("thu-infiltration", ["Infiltration"])],
    "Friday": [("fri-botnet", ["Botnet", "Bot"]), ("fri-portscan", ["Portscan", "PortScan"]),
               ("fri-ddos", ["DDoS"])],
}
KEEP = ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration",
        "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet",
        "Total Length of Bwd Packet", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "Label"]


def fetch(start, end):
    req = urllib.request.Request(URL, headers={"Range": f"bytes={start}-{end}", "User-Agent": "curl/8"})
    return urllib.request.urlopen(req, timeout=120)


def stream_lines(day):
    offset, csize = MEMBERS[day]
    hdr = fetch(offset, offset + 29).read()
    nlen, elen = struct.unpack("<HH", hdr[26:30])
    start = offset + 30 + nlen + elen
    resp = fetch(start, start + csize - 1)
    inflater = zlib.decompressobj(-15)
    buf = b""
    got = 0
    while True:
        chunk = resp.read(1 << 20)
        if not chunk:
            break
        got += len(chunk)
        buf += inflater.decompress(chunk)
        *lines, buf = buf.split(b"\n")
        for line in lines:
            yield line.decode("utf-8", "replace").rstrip("\r")
    buf += inflater.flush()
    if buf:
        yield buf.decode("utf-8", "replace")
    print(f"{day}: stazeno {got} B (komprimovane)", file=sys.stderr)


def parse_ts(text):
    return datetime.strptime(text.strip(), "%d/%m/%Y %I:%M:%S %p")


def main(out_root, day):
    rows = []
    header = None
    for line in stream_lines(day):
        if not line:
            continue
        if header is None:
            header = next(csv.reader([line]))
            index = {name: header.index(name) for name in KEEP}
            continue
        cells = next(csv.reader([line]))
        if len(cells) < len(header):
            continue
        try:
            when = parse_ts(cells[index["Timestamp"]])
        except ValueError:
            continue
        rows.append((when, [cells[index[name]] for name in KEEP]))
    labels = {}
    for when, cells in rows:
        lab = cells[-1]
        lo, hi, n = labels.get(lab, (when, when, 0))
        labels[lab] = (min(lo, when), max(hi, when), n + 1)
    summary = {lab: [str(lo), str(hi), n] for lab, (lo, hi, n) in sorted(labels.items())}
    print(json.dumps({"day": day, "rows": len(rows), "labels": summary}, indent=1))
    windows = []
    if day == "Monday":
        first = min(w for w, _ in rows)
        windows = [("mon-benign-am", first + timedelta(hours=1), first + timedelta(hours=2)),
                   ("mon-benign-pm", first + timedelta(hours=5), first + timedelta(hours=6))]
    else:
        for name, prefixes in GROUPS.get(day, []):
            match = [(lo, hi) for lab, (lo, hi, _) in labels.items()
                     if any(lab.lower().startswith(p.lower()) for p in prefixes)]
            if not match:
                print(f"{name}: zadny stitek", file=sys.stderr)
                continue
            lo = min(m[0] for m in match) - timedelta(minutes=30)
            hi = max(m[1] for m in match) + timedelta(minutes=30)
            hi = min(hi, lo + timedelta(hours=3))
            windows.append((name, lo, hi))
    manifest = []
    for name, lo, hi in windows:
        directory = os.path.join(out_root, name)
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "flows.csv")
        sel = sorted(((w, c) for w, c in rows if lo <= w <= hi), key=lambda x: x[0])
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(KEEP)
            for _, cells in sel:
                writer.writerow(cells)
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        mal = sum(1 for _, c in sel if c[-1].upper() != "BENIGN")
        manifest.append({"slice": name, "from": str(lo), "to": str(hi), "flows": len(sel),
                         "malicious": mal, "bytes": os.path.getsize(path), "sha256": digest})
    print(json.dumps(manifest, indent=1))
    with open(os.path.join(out_root, f"manifest-{day}.json"), "w", encoding="utf-8") as handle:
        json.dump({"labels": summary, "slices": manifest}, handle, indent=1)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
