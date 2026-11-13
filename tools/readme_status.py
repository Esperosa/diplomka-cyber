#!/usr/bin/env python3
"""Generuje blok "Aktuální stav" v README.md.

Blok leží mezi značkami ``<!-- STATUS:BEGIN -->`` a ``<!-- STATUS:END -->``
a skript přepisuje jen jeho obsah. Čísla se berou ze sledovaných dokumentů
v ``docs/diplomka/eval/`` a z gitu, nic se nepíše ručně. Zdroj, který chybí,
se přeskočí.

Použití::

    python tools/readme_status.py            # přepíše blok v README.md
    python tools/readme_status.py --check    # nic nezapisuje, vrátí 1, když je blok zastaralý
    python tools/readme_status.py --print    # vypíše vygenerovaný blok

Zdroje:

* počet testů: ``cargo test --lib -- --list`` (jen vypíše seznam, testy
  nespouští); ``CARGO_TARGET_DIR`` se bere z prostředí;
* poslední commit a jeho datum: git (commity, které mění jen README.md, se
  nepočítají, aby se blok po commitu README nezměnil);
* krok 7 (držený běh): ``docs/diplomka/eval/k7/held.md`` a registr slepých
  míst a tabulka prahů v ``docs/diplomka/eval/impl-krok7.md``;
* krok 8: ``docs/diplomka/eval/k8/vysledky.md``;
* dlouhý běh: ``final-report.json`` (cesta z ``BAKULA_FINAL_REPORT`` nebo
  ``F:/Projekty/bakula-soak/run-mega-4d/final-report.json``).

Skript používá jen standardní knihovnu Pythonu 3.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

BEGIN = "<!-- STATUS:BEGIN -->"
END = "<!-- STATUS:END -->"

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FINAL_REPORT = "F:/Projekty/bakula-soak/run-mega-4d/final-report.json"

K7_HELD = "docs/diplomka/eval/k7/held.md"
K7_IMPL = "docs/diplomka/eval/impl-krok7.md"
K8_RESULTS = "docs/diplomka/eval/k8/vysledky.md"


# ---------------------------------------------------------------- pomocné


def cz(value: float, digits: int = 1) -> str:
    """Číslo s desetinnou čárkou."""
    return f"{value:.{digits}f}".replace(".", ",")


def wilson(successes: int, total: int, z: float = 1.959964) -> Optional[tuple]:
    """Wilsonův 95% interval pro podíl, v procentech. Pro total == 0 vrací None."""
    if total <= 0:
        return None
    p = successes / total
    z2 = z * z
    denom = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z2 / (4 * total * total)) / denom
    return 100 * p, 100 * max(0.0, center - half), 100 * min(1.0, center + half)


def fmt_interval(successes: int, total: int) -> str:
    w = wilson(successes, total)
    if w is None:
        return "–"
    p, lo, hi = w
    return f"{cz(p)} % ({cz(lo)} až {cz(hi)})"


def read_text(root: Path, rel: str) -> Optional[str]:
    path = root / rel
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def parse_tables(text: str) -> list:
    """Vrátí markdown tabulky jako slovníky {title, header, rows}.

    ``title`` je poslední neprázdný řádek před tabulkou (nadpis nebo popisek).
    """
    tables = []
    lines = text.splitlines()
    i = 0
    last_text = ""
    while i < len(lines):
        line = lines[i]
        is_row = line.lstrip().startswith("|")
        if is_row and i + 1 < len(lines) and re.match(r"^\s*\|[\s:\-|]+\|\s*$", lines[i + 1]):
            header = split_row(line)
            rows = []
            j = i + 2
            while j < len(lines) and lines[j].lstrip().startswith("|"):
                rows.append(split_row(lines[j]))
                j += 1
            tables.append({"title": last_text, "header": header, "rows": rows})
            i = j
            continue
        if line.strip():
            last_text = line.strip()
        i += 1
    return tables


def split_row(line: str) -> list:
    cells = line.strip().strip("|").split("|")
    return [c.strip() for c in cells]


def find_table(tables: list, title_part: str, header_part: Optional[str] = None) -> Optional[dict]:
    for t in tables:
        if title_part in t["title"] and (header_part is None or header_part in t["header"]):
            return t
    return None


def pick(table: dict, names: list) -> tuple:
    """Vybere sloupce podle názvu (chybějící se přeskočí)."""
    idx = [table["header"].index(n) for n in names if n in table["header"]]
    header = [table["header"][k] for k in idx]
    rows = [[r[k] if k < len(r) else "" for k in idx] for r in table["rows"]]
    return header, rows


def md_table(header: list, rows: list) -> str:
    if not header:
        return ""
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for r in rows:
        out.append("| " + " | ".join(r) + " |")
    return "\n".join(out)


# ---------------------------------------------------------------- sekce


def count_tests(root: Path, runner=None) -> Optional[int]:
    """Počet testů z ``cargo test --lib -- --list``; None, když cargo nejde spustit."""
    if runner is None:
        def runner(cmd, cwd):
            return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800)
    try:
        res = runner(["cargo", "test", "--lib", "--", "--list"], str(root))
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return sum(1 for line in res.stdout.splitlines() if line.rstrip().endswith(": test"))


def last_commit(root: Path) -> Optional[tuple]:
    """(zkrácený hash, datum, předmět) posledního commitu, který nemění jen README.md."""
    try:
        res = subprocess.run(
            ["git", "log", "-1", "--format=%h%x09%cs%x09%s", "--", ".", ":(exclude)README.md"],
            cwd=str(root), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0 or not res.stdout.strip():
        return None
    parts = res.stdout.strip().split("\t", 2)
    return tuple(parts) if len(parts) == 3 else None


def section_meta(root: Path, tests: Optional[int]) -> str:
    lines = []
    commit = last_commit(root)
    if commit:
        lines.append(f"- Poslední commit: `{commit[0]}` ze dne {commit[1]} ({commit[2]})")
    if tests is not None:
        lines.append(f"- Počet unit testů knihovny (`cargo test --lib -- --list`): {tests}")
    return "\n".join(lines)


def section_k7(root: Path) -> str:
    held = read_text(root, K7_HELD)
    if held is None:
        return ""
    tables = parse_tables(held)
    out = []
    title = next((l for l in held.splitlines() if l.startswith("## ")), "").lstrip("# ").strip()
    arms = tables[0] if tables else None
    if arms and "rameno" in arms["header"]:
        header, rows = pick(arms, [
            "rameno", "sítí", "útoků", "detekce mikro", "FP/síť-den",
            "zobrazeno/síť-den", "zavřeno omylem (G3)",
        ])
        out.append(f"#### {title.replace('Krok 7, ', 'Krok 7: ', 1)}\n")
        out.append(md_table(header, rows))
        out.append("")
        out.append("Detekce a podíl zavřených omylem jsou s 95% Wilsonovým intervalem v závorce; "
                   "FP/síť-den jsou falešné poplachy na síť a virtuální den.")
    fam = find_table(tables, "Rodiny")
    if fam:
        out.append("\n#### Detekce po rodinách útoků (držený běh, Wilsonův 95% interval)\n")
        out.append(md_table(fam["header"], fam["rows"]))
    return "\n".join(out)


def count_thresholds(table: dict) -> tuple:
    met, unmet, other = 0, [], 0
    status_col = len(table["header"]) - 1
    for r in table["rows"]:
        cell = r[status_col] if status_col < len(r) else ""
        low = cell.lower()
        if "nesplněno" in low:
            unmet.append(r[0])
        elif "splněno" in low:
            met += 1
        else:
            other += 1
    return met, unmet, other


def threshold_line(label: str, table: Optional[dict]) -> str:
    if not table:
        return ""
    met, unmet, other = count_thresholds(table)
    total = met + len(unmet) + other
    text = f"- {label}: splněno {met} z {total}"
    if unmet:
        text += "; nesplněno: " + ", ".join(unmet)
    if other:
        text += f"; ostatní (hlásí se, bez prahu): {other}"
    return text


def section_k8(root: Path) -> str:
    text = read_text(root, K8_RESULTS)
    if text is None:
        return ""
    tables = parse_tables(text)
    out = []
    title = next((l for l in text.splitlines() if l.startswith("## ")), "").lstrip("# ").strip()
    arms = tables[0] if tables else None
    if arms and "rameno" in arms["header"]:
        header, rows = pick(arms, [
            "rameno", "sítí", "útoků", "detekce", "FP/síť-den",
            "zobrazeno/síť-den", "zavřeno omylem", "útoky s omylem zavřeným nálezem",
        ])
        out.append(f"#### {title}\n")
        out.append(md_table(header, rows))
    return "\n".join(out)


def section_thresholds(root: Path) -> str:
    lines = []
    impl7 = read_text(root, K7_IMPL)
    if impl7:
        t = find_table(parse_tables(impl7), "Prahy B6")
        lines.append(threshold_line("Předregistrované prahy kroku 7 (B6)", t))
    k8 = read_text(root, K8_RESULTS)
    if k8:
        t = find_table(parse_tables(k8), "Prahy")
        lines.append(threshold_line("Předregistrované prahy kroku 8 (E1 až E11)", t))
    return "\n".join(l for l in lines if l)


def section_blind_spots(root: Path) -> str:
    impl7 = read_text(root, K7_IMPL)
    if impl7 is None:
        return ""
    t = find_table(parse_tables(impl7), "Registr slepých míst po kroku 7")
    if not t:
        return ""
    # Řádek o výkonu XXXL je v samostatné části, tady jen skutečná slepá místa.
    rows = [r for r in t["rows"] if not any("XXXL" in c for c in r[:2])]
    header, sel = pick({"header": t["header"], "rows": rows}, ["#", "slepé místo", "stav", "měření (držený `v3k7`)"])
    if not header:
        header, sel = t["header"], rows
    return "#### Známá slepá místa (registr po kroku 7)\n\n" + md_table(header, sel)


def section_xxxl_perf(root: Path) -> str:
    impl7 = read_text(root, K7_IMPL)
    if impl7 is None:
        return ""
    t = find_table(parse_tables(impl7), "Registr slepých míst po kroku 7")
    if not t:
        return ""
    for r in t["rows"]:
        if any("XXXL" in c for c in r[:2]):
            return f"- Výkon sítí XXXL (G4, držené seedy): {r[2]}, práh {r[3]}, {r[4]}."
    return ""


def section_long_run(report_path: Path) -> str:
    if not report_path.is_file():
        return ""
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    out = []
    days = data.get("virtual_hours", 0) / 24.0
    violations = sum(data.get("invariant_violations", {}).values()) if isinstance(
        data.get("invariant_violations"), dict) else 0
    out.append("#### Dlouhý běh (soak, závěrečný report)\n")
    out.append(f"- Simulovaných sítí: {data.get('networks', 0):,}".replace(",", " ")
               + f", virtuálních síť-dnů: {days:,.0f}".replace(",", " ")
               + f", cyklů: {data.get('cycles', 0):,}".replace(",", " "))
    out.append(f"- Porušené invarianty: {violations}, paniky: {data.get('panics', 0)}")
    fp = data.get("fp_noise")
    if fp is not None and days > 0:
        out.append(f"- Falešné poplachy bez přiřaditelné příčiny: {fp:,}".replace(",", " ")
                   + f" ({cz(fp / days, 0)} na síť-den; interní měřicí metrika, nejde o zobrazené položky)")
    xxxl = data.get("segments", {}).get("size|XXXL (>6000)")
    if xxxl and xxxl.get("attacks"):
        out.append(f"- Sítě XXXL (> 6000 zařízení): {xxxl['networks']} sítí, "
                   f"detekce {fmt_interval(xxxl['detected_any'], xxxl['attacks'])}"
                   f" z {xxxl['attacks']} útoků")
    fams = {k: v for k, v in data.get("families", {}).items() if "__" not in k and v.get("truth", 0) > 0}
    if fams:
        rows = []
        for name in sorted(fams):
            f = fams[name]
            rows.append([name, str(f["truth"]), fmt_interval(f["detected_any"], f["truth"]),
                         fmt_interval(f["detected_typed"], f["truth"])])
        out.append("")
        out.append(md_table(["rodina", "útoků", "detekováno (jakýkoli nález)", "správný typ nálezu"], rows))
    return "\n".join(out)


# ---------------------------------------------------------------- sestavení


def build_block(root: Path, tests: Optional[int], final_report: Optional[Path]) -> str:
    parts = [
        "_Tento blok generuje `tools/readme_status.py` z dokumentů v `docs/diplomka/eval/` a z gitu. "
        "Ručně se neupravuje._",
        section_meta(root, tests),
        section_xxxl_perf(root),
        section_thresholds(root),
        section_k7(root),
        section_k8(root),
        section_long_run(final_report) if final_report else "",
        section_blind_spots(root),
    ]
    text = "\n\n".join(p for p in parts if p and p.strip())
    return text.strip() + "\n"


def replace_block(readme: str, block: str) -> str:
    b = readme.find(BEGIN)
    e = readme.find(END)
    if b < 0 or e < 0 or e < b:
        raise ValueError(f"README neobsahuje značky {BEGIN} a {END}")
    nl = "\r\n" if "\r\n" in readme else "\n"
    body = block.replace("\r\n", "\n").replace("\n", nl)
    return readme[: b + len(BEGIN)] + nl + body + readme[e:]


def main(argv: Optional[list] = None, root: Path = ROOT) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="nic nezapisovat, vrátit 1 při zastaralém bloku")
    ap.add_argument("--print", dest="show", action="store_true", help="vypsat vygenerovaný blok")
    ap.add_argument("--readme", default=None, help="cesta k README (výchozí README.md v kořeni)")
    ap.add_argument("--no-cargo", action="store_true", help="nespouštět cargo, počet testů vynechat")
    ap.add_argument("--tests", type=int, default=None, help="počet testů zadaný ručně (přeskočí cargo)")
    ap.add_argument("--final-report", default=None, help="cesta k final-report.json")
    args = ap.parse_args(argv)

    readme_path = Path(args.readme) if args.readme else root / "README.md"
    tests = args.tests
    if tests is None and not args.no_cargo:
        tests = count_tests(root)
    fr = Path(args.final_report or os.environ.get("BAKULA_FINAL_REPORT") or DEFAULT_FINAL_REPORT)

    block = build_block(root, tests, fr)
    if args.show:
        sys.stdout.write(block)
    readme = readme_path.read_text(encoding="utf-8")
    try:
        new = replace_block(readme, block)
    except ValueError as exc:
        print(f"chyba: {exc}", file=sys.stderr)
        return 2
    if new == readme:
        if not args.show:
            print("README je aktuální.")
        return 0
    if args.check:
        print("README.md: blok Aktuální stav je zastaralý, spusťte python tools/readme_status.py",
              file=sys.stderr)
        return 1
    readme_path.write_text(new, encoding="utf-8", newline="")
    print("README.md: blok Aktuální stav přepsán.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
