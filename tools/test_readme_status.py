"""Testy pro tools/readme_status.py (spuštění: python -m unittest tools.test_readme_status
nebo python tools/test_readme_status.py). Cargo se nespouští."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import readme_status as rs  # noqa: E402

HELD = """## Krok 7, držené seedy 1 a 2 (svět k7)

| rameno | sítí | útoků | detekce mikro | FP/síť-den | zobrazeno/síť-den | zavřeno omylem (G3) |
|---|---:|---:|---:|---:|---:|---:|
| v3k7 | 80 | 100 | 80,0 (70,0 až 90,0) | 29,9 | 183,7 | 1,4 % |

### Rodiny

| rodina | n | v3k7 |
|---|---:|---:|
| c2_beacon | 10 | 70,0 % (40,0 až 90,0) |
"""

IMPL7 = """**Prahy B6:**

| práh | hodnota | výsledek |
|---|---|---|
| K6 | 1,4 % | **splněno** |
| L1 | 1,195 | **nesplněno** (> 1,15) |

### Registr slepých míst po kroku 7

| # | slepé místo | stav | měření (držený `v3k7`) |
|---|---|---|---|
| 1 | Kontext | **zadrženo** | 1,4 % |
| 15 | Výkon XXXL (G4) | p99 cyklu 1,08 s | < 3 s | splněno |
"""

README = "# X\n\ntext\n\n" + rs.BEGIN + "\nstarý obsah\n" + rs.END + "\n\npaticka\n"


def make_root(tmp: Path, held=True, impl=True) -> Path:
    if held:
        (tmp / "docs/diplomka/eval/k7").mkdir(parents=True)
        (tmp / rs.K7_HELD).write_text(HELD, encoding="utf-8")
    if impl:
        (tmp / "docs/diplomka/eval").mkdir(parents=True, exist_ok=True)
        (tmp / rs.K7_IMPL).write_text(IMPL7, encoding="utf-8")
    (tmp / "README.md").write_text(README, encoding="utf-8")
    return tmp


class WilsonTest(unittest.TestCase):
    def test_known_value(self):
        p, lo, hi = rs.wilson(50, 100)
        self.assertAlmostEqual(p, 50.0)
        self.assertAlmostEqual(lo, 40.38, places=1)
        self.assertAlmostEqual(hi, 59.62, places=1)

    def test_zero_total(self):
        self.assertIsNone(rs.wilson(0, 0))
        self.assertEqual(rs.fmt_interval(0, 0), "–")

    def test_bounds(self):
        _, lo, hi = rs.wilson(0, 10)
        self.assertEqual(lo, 0.0)
        self.assertLess(hi, 100.0)


class BlockTest(unittest.TestCase):
    def test_sections_and_missing_sources(self):
        with tempfile.TemporaryDirectory() as d:
            root = make_root(Path(d))
            block = rs.build_block(root, 42, Path(d) / "není.json")
            self.assertIn("c2_beacon", block)
            self.assertIn("splněno 1 z 2; nesplněno: L1", block)
            self.assertIn("p99 cyklu 1,08 s", block)
            self.assertNotIn("Krok 8", block)  # zdroj chybí, sekce se přeskočí
            self.assertNotIn("Dlouhý běh", block)

    def test_long_run(self):
        with tempfile.TemporaryDirectory() as d:
            fr = Path(d) / "final-report.json"
            fr.write_text(json.dumps({
                "networks": 2, "cycles": 10, "virtual_hours": 48.0, "panics": 0,
                "invariant_violations": {}, "fp_noise": 100,
                "families": {"a": {"truth": 100, "detected_any": 50, "detected_typed": 40},
                             "a__ranked": {"truth": 5, "detected_any": 1, "detected_typed": 1}},
                "segments": {"size|XXXL (>6000)": {"networks": 1, "attacks": 10, "detected_any": 5}},
            }), encoding="utf-8")
            out = rs.section_long_run(fr)
            self.assertIn("50,0 % (40,4 až 59,6)", out)
            self.assertNotIn("a__ranked", out)
            self.assertIn("virtuálních síť-dnů: 2", out)


class UpdateTest(unittest.TestCase):
    def test_idempotent_and_check(self):
        with tempfile.TemporaryDirectory() as d:
            root = make_root(Path(d))
            args = ["--no-cargo", "--final-report", str(Path(d) / "x.json")]
            self.assertEqual(rs.main(args + ["--check"], root=root), 1)  # zastaralé
            self.assertEqual(rs.main(args, root=root), 0)  # přepíše
            first = (root / "README.md").read_text(encoding="utf-8")
            self.assertEqual(rs.main(args, root=root), 0)  # podruhé beze změny
            self.assertEqual(first, (root / "README.md").read_text(encoding="utf-8"))
            self.assertEqual(rs.main(args + ["--check"], root=root), 0)
            self.assertTrue(first.startswith("# X\n\ntext"))
            self.assertTrue(first.rstrip().endswith("paticka"))
            self.assertNotIn("starý obsah", first)

    def test_missing_markers(self):
        with tempfile.TemporaryDirectory() as d:
            root = make_root(Path(d))
            (root / "README.md").write_text("bez značek\n", encoding="utf-8")
            self.assertEqual(rs.main(["--no-cargo"], root=root), 2)

    def test_count_tests_parses_list(self):
        class R:
            returncode = 0
            stdout = "a::b: test\nc::d: test\n\n2 tests, 0 benchmarks\n"

        self.assertEqual(rs.count_tests(Path("."), runner=lambda cmd, cwd: R()), 2)


if __name__ == "__main__":
    unittest.main()
