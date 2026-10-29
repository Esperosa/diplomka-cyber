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

**Stažený výřez (NE committed — 30 MB/scénář, nad limit pro git, viz `.gitignore`):**

| Scénář | Rodina (ověřeno přímo na `mcfp.felk.cvut.cz`) | Cesta (lokální, gitignored) | Velikost | SHA-256 | Flows (ve výřezu) | Malicious |
|---|---|---|---|---|---|---|
| CTU-Malware-Capture-Botnet-54, scénář 13, prvních 30 MB | Virut | `labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv` | 31 457 281 B | `e53331ede25cb047e65ed814b7e34dd49f3926e8585d4ea6294aba4cccf336b6` | 229 653 | 6 185 |
| CTU-Malware-Capture-Botnet-51, scénář 10, prvních 30 MB | Rbot | `labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv` | 31 457 281 B | `c27b7443884c68c4b4ae49ce1404bf897a5dd7a430122a21121e4d135bfbca32` | 228 760 | 81 |
| CTU-Malware-Capture-Botnet-42, scénář 1, 30 MB od offsetu 150 000 000 B | Neris | `labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv` | 31 457 312 B | `2b78111d5eefae6ea24d58bb7cf54f6958a6c2cbb9b843e8693d5075f8bb8710` | 229 501 | 2 614 |

**Deliverable 18 (29.10.2026) — rozšíření ze 1 na 3 scénáře, 2 další malware rodiny.** Důvod offsetu u Botnet-42: první 30 MB (chronologický začátek 6,15h capture) obsahovalo 0 Botnet-labelovaných flows — malware aktivita v téhle capture začíná později. Ověřeno přímo (`curl` sondy na 150MB/250MB offsetu), ne odhadnuto. Výřez proto sestaven jako: hlavičkový řádek z bytu 0 (CSV header, nutný pro `src/eval/sources/ctu13.rs::column()` lookup podle jména) + 30 MB dat od bytu 150 000 000, první (potenciálně useknutý) řádek dat zahozen. **Honestní poznámka k Botnet-51**: tahle scénář má v adresáři i druhý soubor (`capture20110818.binetflow.labeled`, jiné jméno sloupců `Label(Normal:CC:Background)` + extra `CCDetector` sloupec) — NEpoužitý, protože nemá stejné schéma jako ostatní 2 scénáře; ověřeno přímo (`curl -r 0-500`), ne předpokládáno ze jména souboru.

**Oprava 29.10.2026:** všechny tři SHA-256 hashe v této tabulce byly dřív useknuté o 1 hex znak (63 místo 64) — chyba při přepisu z `sha256sum` výstupu, odhalená nezávislou kontrolou (Opus Plan agent). Opraveno zde na skutečné hashe.

**Reprodukce stažení** (HTTP Range request — "reprezentativní výřez", ne bezhlavé stažení celého souboru, per návrh sekce 7):
```
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-54/detailed-bidirectional-flow-labels/capture20110815-3.binetflow" -o labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-51/detailed-bidirectional-flow-labels/capture20110818.binetflow" -o labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv
# Botnet-42: header z bytu 0 + data od offsetu 150 000 000 (viz vysvetleni vyse)
curl -s -r 0-200 "$URL42" | head -1 > header.tmp
curl -s -r 150000000-181457280 "$URL42" | tail -n +2 > body.tmp
cat header.tmp body.tmp > labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv
```

## Budoucí vlny (naplánováno, ne implementováno)

- **Vlna 1 (zbytek):** CICIDS2017/2018, CICIoT2023, UNSW-NB15 — každý jako nová `ScenarioSource` implementace v `src/eval/sources/`.
- **Vlna 2:** threat intel enrichment (NVD/KEV/EPSS, URLhaus, ThreatFox, OTX).
- **Vlna 3:** Mininet/Containerlab generátor syntetických scénářů — zdroj prakticky neomezeného objemu kontrolovaných scénářů (DHCP/NAT churn, vlastní firewall/DNS/IPS politiky), včetně identity-churn scénářů, které IoT-23 ani CTU-13 nepokrývají.
