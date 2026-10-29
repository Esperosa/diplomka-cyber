# Dataset registry

Registr datových zdrojů pro `src/eval/` (replay a baseline měření korelačního enginu). Formát polí podle `docs/diplomka/BAKULA_kompletni_technicky_navrh_diplomova_prace.md`, sekce 7.1. Zdroje se nabalují po vlnách (sekce "Dataset" v plánu diplomky) — vlna 0 je ověření frameworku na jednom zdroji, další vlny přidávají další `ScenarioSource` implementace bez zásahu do `dataset_replay.rs`.

## Vlna 0 — IoT-23

| Pole | Hodnota |
|---|---|
| `dataset_id` | `iot23` |
| `source` | Stratosphere IPS / CTU (ČVUT) |
| `url` | https://www.stratosphereips.org/datasets-iot23 |
| `license` | CC BY-NC-SA 4.0, pro výzkum |
| `modalities` | Zeek `conn.log.labeled` (per-flow metadata, ne raw PCAP) |
| `label_schema` | `label` ∈ {Benign, Malicious} (case se liší scénář od scénáře), `detailed-label` ∈ {C&C, C&C-FileDownload, DDoS, PartOfAHorizontalPortScan, ...} |
| `known_leakage_risks` | Žádný per-flow label se nesmí dostat do `correlate_events`/`rank_finding`/`score_services` — zajištěno strukturně (parallel `Vec<ConnectionObservation>`/`Vec<GroundTruthLabel>` v `LabeledDataset`, viz `src/eval/ground_truth.rs`). Malé stažené scénáře nemusí reprezentovat celou škálu provozu v plném IoT-23 korpusu. |
| `wave` | 0 |

### Stažené scénáře (committed, malé labelované výřezy)

| Scénář | Cesta v repu | Velikost | SHA-256 | Flows | Malicious | Benign |
|---|---|---|---|---|---|---|
| CTU-IoT-Malware-Capture-44-1 | `labs/datasets/iot23/CTU-IoT-Malware-Capture-44-1/conn.log.labeled` | 31 179 B | `12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f` | 237 | 26 (C&C, C&C-FileDownload, DDoS) | 211 |
| CTU-Honeypot-Capture-7-1 / Somfy-01 | `labs/datasets/iot23/CTU-Honeypot-Capture-7-1-Somfy-01/conn.log.labeled` | 18 024 B | `fb37fb38393c48b064d3afd373b075ffe31063d4924a2df1c5d13fc490b830cc` | 130 | 0 | 130 |

**Zdroj souborů:** staženo přímo z mirroru `mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/` (odkaz z homepage datasetu výše), konkrétně `.../CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled` a `.../CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled`, dne 29. 10. 2026.

**Proč committed, ne `.gitignore`:** jde o malé (desítky KB) labelované výřezy, ne o celý korpus — licence CC BY-NC-SA 4.0 pro výzkum to umožňuje a reprodukovatelnost testu na čistém klonu to vyžaduje (`src/eval/sources/iot23.rs` i `src/eval/dataset_replay.rs` mají `#[cfg(test)]` testy, které tyto soubory čtou). Pokud se v další vlně přidají větší scénáře/datasety, ty už patří mimo git (stahovací skript + hash v registru, ne commit).

## Vlna 1 — CTU-13

| Pole | Hodnota |
|---|---|
| `dataset_id` | `ctu13` |
| `source` | Stratosphere IPS / CTU (ČVUT) |
| `url` | https://www.stratosphereips.org/datasets-ctu13 |
| `license` | CC BY-NC-SA 4.0, pro výzkum |
| `modalities` | NetFlow-style bidirekční flow CSV (`binetflow`) — **jiná modalita než IoT-23's Zeek conn.log**, vlastní parser (`src/eval/sources/ctu13.rs`), žádné sdílení s `passive::zeek` |
| `label_schema` | `Label` pole `flow=From-Botnet-...`/`flow=Background`/`flow=Normal-...` — 3 kategorie, normalizováno na `Malicious`/`Benign`/**`Unknown`** (ne binárně — oprava 29.10.2026, `Background` = neověřený provoz, `is_unknown()` v `ground_truth.rs`, vyřazeno z confusion matrix, ne počítáno jako Benign) |
| `known_leakage_risks` | Stejná strukturní záruka jako IoT-23 (paralelní `Vec`). Navíc: `State` pole je NetFlow notace ("FPA_FPA", "CON"), ne Zeek `conn_state` slovník ("S0", "REJ") — heuristiky v `passive::anomaly`/`correlation_v2` laděné na Zeek vokabulář na CTU-13 nefungují stejně (změřeno, viz níže) |
| `wave` | 1 |

**Stažený výřez (NE committed — 30 MB, nad limit pro git, viz `.gitignore`):**

| Scénář | Cesta (lokální, gitignored) | Velikost | SHA-256 | Flows | Malicious |
|---|---|---|---|---|---|
| CTU-Malware-Capture-Botnet-54 (Virut), prvních 30 MB | `labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv` | 31 457 281 B | `e53331ede25cb047e65ed814b7e34dd49f3926e8585d4ea6294aba4cccf336b6` | 229 653 | 6 185 |

**Oprava 29.10.2026:** všechny tři SHA-256 hashe v této tabulce byly dřív useknuté o 1 hex znak (63 místo 64) — chyba při přepisu z `sha256sum` výstupu, odhalená nezávislou kontrolou (Opus Plan agent). Opraveno zde na skutečné hashe.

**Reprodukce stažení** (HTTP Range request — "reprezentativní výřez", ne bezhlavé stažení celého 251MB souboru, per návrh sekce 7):
```
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow" -o labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv
```

## Budoucí vlny (naplánováno, ne implementováno)

- **Vlna 1 (zbytek):** CICIDS2017/2018, CICIoT2023, UNSW-NB15 — každý jako nová `ScenarioSource` implementace v `src/eval/sources/`.
- **Vlna 2:** threat intel enrichment (NVD/KEV/EPSS, URLhaus, ThreatFox, OTX).
- **Vlna 3:** Mininet/Containerlab generátor syntetických scénářů — zdroj prakticky neomezeného objemu kontrolovaných scénářů (DHCP/NAT churn, vlastní firewall/DNS/IPS politiky), včetně identity-churn scénářů, které IoT-23 ani CTU-13 nepokrývají.
