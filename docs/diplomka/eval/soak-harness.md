# Soak harness

`salticus-program soak run --out <dir> --wall-hours 80 --threads 18` spusti dlouhy beh nad simulovanymi sitemi.
Zadny skutecny sitovy provoz, nmap ani nft; vsechno bezi v pameti a v docasnych SQLite souborech.

## Princip

- Seed site = `derive(run_seed, network_id)`; blok siti je atomicka jednotka checkpointu.
- Jeden cyklus = 30 virtualnich minut, epizoda 24/48/72/96 virtualnich hodin.
- Behaji produkcni funkce: detekce, Suricata parser, fuze, korelace, report, nalezy, rozhodnuti, identita, hypotezy, planovac, vykonani overeni, `ops.rs`.
- Ground truth: 11 rodin utoku, 5 benignich lookalike udalosti, vypadky telemetrie. Pripsani nalezu utoku podle klicovych IP v okne utoku +2 cykly. Intervaly jsou Wilsonovy 95 %.
- Doplnkove nohy: CTU-13/IoT-23 kotva (kazda pruchod musi dat stejna cisla), ops stress s kontrolou auditniho retezu, Redis broker (`SALTICUS_SOAK_REDIS`).

## Vystupy

`state.json`, `blocks.jsonl` (otisk bloku), `timeseries.csv`, `status.md`, `final-report.md/json`.
`soak verify --out <dir> --samples N` znovu prehraje nahodne bloky a porovna otisky bit po bitu. `--resume` navaze; soubor `STOP` v `--out` beh korektne ukonci.

## Znamá omezeni

- Zeek parser drzi jen toky s cilem v rozsahu, odchozi (egress) provoz je neviditelny; report to uvadi zvlast.
- Cisla jsou z modelu, ne z realneho provozu; reali drzi kotva a Docker laby.
- Multi-host H5 (sdileny backend) neni zmeren, platform.rs je SQLite-only.
