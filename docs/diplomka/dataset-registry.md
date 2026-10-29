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
| CTU-IoT-Malware-Capture-44-1 | `labs/datasets/iot23/CTU-IoT-Malware-Capture-44-1/conn.log.labeled` | 31 179 B | `12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71` | 237 | 26 (C&C, C&C-FileDownload, DDoS) | 211 |
| CTU-Honeypot-Capture-7-1 / Somfy-01 | `labs/datasets/iot23/CTU-Honeypot-Capture-7-1-Somfy-01/conn.log.labeled` | 18 024 B | `fb37fb38393c48b064d3afd373b075ffe31063d4924a2df1c5d13fc490b830c` | 130 | 0 | 130 |

**Zdroj souborů:** staženo přímo z mirroru `mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/` (odkaz z homepage datasetu výše), konkrétně `.../CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled` a `.../CTU-Honeypot-Capture-7-1/Somfy-01/bro/conn.log.labeled`, dne 29. 10. 2026.

**Proč committed, ne `.gitignore`:** jde o malé (desítky KB) labelované výřezy, ne o celý korpus — licence CC BY-NC-SA 4.0 pro výzkum to umožňuje a reprodukovatelnost testu na čistém klonu to vyžaduje (`src/eval/sources/iot23.rs` i `src/eval/dataset_replay.rs` mají `#[cfg(test)]` testy, které tyto soubory čtou). Pokud se v další vlně přidají větší scénáře/datasety, ty už patří mimo git (stahovací skript + hash v registru, ne commit).

## Budoucí vlny (naplánováno, ne implementováno)

- **Vlna 1:** CTU-13 (C2/multi-stage), CICIDS2017/2018, CICIoT2023, UNSW-NB15 — každý jako nová `ScenarioSource` implementace v `src/eval/sources/`.
- **Vlna 2:** threat intel enrichment (NVD/KEV/EPSS, URLhaus, ThreatFox, OTX).
- **Vlna 3:** Mininet/Containerlab generátor syntetických scénářů — zdroj prakticky neomezeného objemu kontrolovaných scénářů (DHCP/NAT churn, vlastní firewall/DNS/IPS politiky), včetně identity-churn scénářů, které IoT-23 ani CTU-13 nepokrývají.
