#!/usr/bin/env python3
"""Chronologicke prehravani verejneho datasetu celou produkcni cestou v3 (krok 7, C5).

Vstup: Zeek `conn.log.labeled` (IoT-23, CTU). Toky se seradi podle casu a rozdeli do
30min oken. Kazde okno se zapise jako `conn.log` bez stitku a projde skutecnou
produkcni cestou `bakula-program beh spust` (pamet, kontext, zebrik, profil, novost,
audit uzavreni) v docasnem workspace s `[engine] mode = "v3"`. Cas behu je zacatek
okna (`BAKULA_REPLAY_NOW`), takze profil a novost bezi v case dat. Stitky slouzi jen
k vyhodnoceni (skodlivy host = zdroj aspon jednoho toku se stitkem Malicious).

Aktivni kontroly na zaznamu provest nejdou: beh je bez `--execute-verification`,
takze zustanou neprovedene ("nezname") a nikdy nejsou dukazem. Studeny start (prvnich
48 h) a zrale obdobi se hlasi zvlast.

Pouziti:
  python tools/replay_public.py --conn PATH --bin BIN --work DIR [--scope CIDR]
         [--window 1800] [--max-windows N] [--protect] [--out FILE]
"""
import argparse
import ipaddress
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

LABEL_FIELDS = {"label", "detailed-label", "tunnel_parents"}
EMPTY_NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="replay" start="0" version="7.94">
<runstats><finished time="0"/><hosts up="0" down="0" total="0"/></runstats>
</nmaprun>
"""


def read_conn(path):
    fields, rows = None, []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                # IoT-23: posledni pole "tunnel_parents   label   detailed-label"
                if len(fields) == 1 or any(" " in f for f in fields):
                    flat = []
                    for f in fields:
                        flat.extend(f.split())
                    fields = flat
                continue
            if line.startswith("#") or not line.strip() or fields is None:
                continue
            parts = line.split("\t")
            if len(parts) < len(fields):
                tail = parts[-1].split()
                parts = parts[:-1] + tail
            row = dict(zip(fields, parts))
            try:
                row["_ts"] = float(row["ts"])
            except (KeyError, ValueError):
                continue
            rows.append(row)
    rows.sort(key=lambda r: r["_ts"])
    return fields, rows


def auto_scope(rows):
    counts = Counter()
    for r in rows:
        try:
            ip = ipaddress.ip_address(r.get("id.orig_h", ""))
        except ValueError:
            continue
        if ip.version == 4 and ip.is_private:
            counts[str(ipaddress.ip_network(f"{ip}/24", strict=False))] += 1
    return counts.most_common(1)[0][0] if counts else "192.168.1.0/24"


def write_window(path, fields, rows):
    keep = [f for f in fields if f not in LABEL_FIELDS]
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "conn.log"), "w", encoding="utf-8", newline="\n") as out:
        out.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n")
        out.write("#unset_field\t-\n#path\tconn\n")
        out.write("#fields\t" + "\t".join(keep) + "\n")
        for r in rows:
            out.write("\t".join(r.get(f, "-") for f in keep) + "\n")


def latest_report(workspace):
    best = None
    runs = os.path.join(workspace, "runs")
    for name in os.listdir(runs):
        path = os.path.join(runs, name, "report.json")
        if os.path.exists(path):
            mtime = os.path.getmtime(path)
            if best is None or mtime > best[0]:
                best = (mtime, path)
    with open(best[1], encoding="utf-8") as handle:
        return json.load(handle)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--scope")
    ap.add_argument("--window", type=int, default=1800)
    ap.add_argument("--max-windows", type=int, default=0)
    ap.add_argument("--protect", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    fields, rows = read_conn(args.conn)
    if not rows:
        sys.exit("zadne toky")
    malicious = {r.get("id.orig_h") for r in rows if "alicious" in r.get("label", "")}
    scope = args.scope or auto_scope(rows)
    t0 = rows[0]["_ts"]
    windows = defaultdict(list)
    for r in rows:
        windows[int((r["_ts"] - t0) // args.window)].append(r)
    order = sorted(windows)
    if args.max_windows:
        order = order[: args.max_windows]
    workspace = os.path.join(args.work, "ws")
    os.makedirs(workspace, exist_ok=True)
    with open(os.path.join(workspace, "bakula.toml"), "w", encoding="utf-8") as cfg:
        cfg.write('[engine]\nmode = "v3"\n')
        if args.protect:
            cfg.write("[engine.v3]\nprotect = true\n")
    nmap = os.path.join(args.work, "empty-nmap.xml")
    with open(nmap, "w", encoding="utf-8") as handle:
        handle.write(EMPTY_NMAP)

    phases = {"cold": Counter(), "mature": Counter()}
    shown_hosts = {"cold": defaultdict(set), "mature": defaultdict(set)}
    failures = 0
    for index in order:
        start = t0 + index * args.window
        phase = "cold" if start - t0 < 48 * 3600 else "mature"
        wdir = os.path.join(args.work, f"w{index:05d}", "zeek")
        write_window(wdir, fields, windows[index])
        env = dict(os.environ)
        env["BAKULA_REPLAY_NOW"] = datetime.fromtimestamp(start, timezone.utc).isoformat()
        cmd = [args.bin, "beh", "spust", "--workspace", workspace, "--nazev", f"w{index}",
               "--scope", scope, "--nmap-xml", nmap, "--zeek-dir", wdir,
               "--provider", "demo", "--disable-circl"]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            failures += 1
            sys.stderr.write(proc.stderr[-2000:])
            continue
        report = latest_report(workspace)
        findings = {f["finding_id"]: f for f in report.get("findings", [])}
        p = phases[phase]
        p["windows"] += 1
        p["flows"] += len(windows[index])
        for record in report.get("findingLifecycle", []):
            f = findings.get(record["finding_id"], {})
            host = f.get("host_key") or ""
            if record.get("displayed"):
                bad = host in malicious
                p["displayed"] += 1
                p["displayed_malicious_host" if bad else "displayed_other"] += 1
                shown_hosts[phase]["bad" if bad else "other"].add(host)
                if record.get("protection"):
                    p["protected"] += 1
            if record.get("disposition") == "auto_resolved":
                p["auto_resolved"] += 1
        for d in report.get("verificationDecisions", []):
            p["ladder_" + d.get("status", "?")] += 1
        status = report.get("coverageStatus") or {}
        for reason in status.get("reasons", []):
            p["coverage:" + reason] += 1

    lines = [f"## Přehrání `{os.path.basename(os.path.dirname(args.conn))}` celou produkční cestou v3",
             "", f"Toků {len(rows)}, oken {len(order)} po {args.window} s, rozsah {scope}, "
             f"škodlivých hostů podle štítků {len(malicious)}, selhaných běhů {failures}, protect={args.protect}.", "",
             "| období | oken | toků | zobrazeno | na škodlivém hostu | jinde | chráněných | auto zavřeno | žebřík (potvrzeno/vyvráceno/eskalováno) | škodliví hosté zobrazeni | ostatní hosté zobrazeni |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|"]
    for phase in ("cold", "mature"):
        p = phases[phase]
        lines.append(
            f"| {phase} | {p['windows']} | {p['flows']} | {p['displayed']} | {p['displayed_malicious_host']} | "
            f"{p['displayed_other']} | {p['protected']} | {p['auto_resolved']} | "
            f"{p['ladder_confirmed']}/{p['ladder_refuted']}/{p['ladder_escalated']} | "
            f"{len(shown_hosts[phase]['bad'])} z {len(malicious)} | {len(shown_hosts[phase]['other'])} |")
    cov = sorted(k for p in phases.values() for k in p if k.startswith("coverage:"))
    lines += ["", "Degradace pokrytí (oken s důvodem): " + ", ".join(
        f"{k[9:]} {phases['cold'][k] + phases['mature'][k]}" for k in dict.fromkeys(cov)), ""]
    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
    sys.stdout.reconfigure(encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
