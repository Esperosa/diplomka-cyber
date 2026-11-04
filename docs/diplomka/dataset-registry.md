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

### Rozšíření 30.10.2026 — 7 dalších scénářů (committed) + 1 velký (gitignored)

**Impuls**: stejný jako u CTU-13 výše — N=2 (jen 1 malware rodina) bylo uživatelem odmítnuto jako nedostatečné. IoT-23 má 20 individuálních scénářů na mirroru; doplněno 7 malých (pod 3 MB, committed) + zaznamenán 1 větší (24 MB, gitignored, zatím nezapojený do testu).

**Reálný bug nalezený při rozšíření**: `CTU-IoT-Malware-Capture-34-1` má `tunnel_parents`/`label`/`det_label` jako **3 řádně oddělené tab-pole** (novější verze CTU labelovacího skriptu), ne smáčknutý kombinovaný formát jako 44-1/Somfy-01. Bez opravy `extract_label` (`src/eval/sources/iot23.rs`) by se každý řádek tiše vyhodnotil jako "Unknown" (fail-safe z dřívější N9 opravy) — celý scénář by tiše změřil 0 known klíčů, ne viditelně selhal. Opraveno: `extract_label` teď nejdřív zkusí přesný klíč `"label"` (nový formát), až pak fallback na kombinované pole (starý formát). Ověřeno rozbij→spadne→vrať→projde (2 nové testy, oba spadly se `0 malicious`/`"Unknown" != "Benign"` před oprava).

| Scénář | Velikost | SHA-256 | Flows | Malicious | Rodina/technika |
|---|---|---|---|---|---|
| CTU-Honeypot-Capture-4-1 | 61 653 B | `aebe40ea0e03b120265a5c7bc140dd9b0d3fe2fce65559e84776b7dd5360e71e` | 452 | 0 | benigní honeypot |
| CTU-Honeypot-Capture-5-1 | 182 147 B | `f36db06e7d6ba7364e932a5b003f75835e004b320d70019e8a2f0ba8685d9262` | 1374 | 0 | benigní honeypot |
| CTU-IoT-Malware-Capture-8-1 | 1 431 000 B | `4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a` | 10403 | 8222 | C&C |
| CTU-IoT-Malware-Capture-20-1 | 419 604 B | `ef48ad72f65efd13d517223e61e4d877ba53a082ddb8159324b18d3f310d0711` | 3209 | 16 | C&C-Torii |
| CTU-IoT-Malware-Capture-21-1 | 428 943 B | `b63db259aead078f50fc150aa97ace4d1f69576e1245334962759d978ce437eb` | 3286 | 14 | C&C-Torii |
| CTU-IoT-Malware-Capture-34-1 | 2 926 718 B | `d69e49b2aae8c1bd33286936531658202dec47d989f0439bad3f8be180467a6e` | 23145 | 21222 | C&C, DDoS, PartOfAHorizontalPortScan |
| CTU-IoT-Malware-Capture-42-1 | 585 829 B | `269fa1b22d9a37e159cf41b81a213a0032d21306f5d39b4c20cb0d211b04e8aa` | 4426 | 6 | C&C-FileDownload, FileDownload |

**Pozn. k přesnosti počtu flows:** počty výše = `grep -v "^#" conn.log.labeled | wc -l` (ověřeno bez prázdných řádků), tedy přesně to, co spočítá i produkční parser `src/passive/zeek.rs::parse_zeek_log` (přeskakuje jen řádky začínající `#` nebo prázdné). Dřívější odhad v této tabulce byl o 1 nižší na všech 7 scénářích (chyba v ručním odhadu, ne v datech) — opraveno na přesné počty.

**Gitignored (zaznamenáno, zatím nezapojeno do testu — viz `.gitignore`):**

| Scénář | Velikost | SHA-256 | Poznámka |
|---|---|---|---|
| CTU-IoT-Malware-Capture-3-1 | 24 383 537 B | `9851009bbca03e15089fa1a356dd4b5eee4a98161a51703626058a0b507f50d0` | 151 567 malicious / 156 103 flows (Attack, C&C, PartOfAHorizontalPortScan) — stejná velikostní kategorie jako CTU-13 výřezy, vědomě odloženo mimo tento krok |

**Vědomě vynechaný scénář (zjištěno/zdokumentováno 31.10.2026):** `CTU-IoT-Malware-Capture-43-1` (Mirai) vrací 404 na standardní cestě `bro/conn.log.labeled`, protože tenhle konkrétní scénář má `conn.log.labeled` ve VLASTNÍM adresáři `labeled/`, ne v `bro/` jako všechny ostatní dosud použité scénáře (`bro/` obsahuje jen `conn.log`/`dns.log`/`http.log`/... bez labelu). Ověřeno přímo (`curl` directory listing). Samotný soubor `labeled/conn.log.labeled` má navíc **9,36 GB** (`Content-Length` ověřen přímo HTTP HEAD požadavkem) — o 2 řády víc než ostatní committed IoT-23 scénáře, vyžadovalo by stejnou offset-based výřezovou techniku jako u CTU-13 velkých souborů. Vědomě nezapojeno do téhle vlny rozšíření (klesající návratnost — N=9/4 rodiny už poskytuje statisticky testovatelný vzorek, viz `baseline-iot23.md` dodatek s Wilcoxon testem) — zaznamenáno jako known gap, ne jako ztracený/zapomenutý scénář.

**Reprodukce stažení:**
```
base="https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios"
curl -s "$base/CTU-Honeypot-Capture-4-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-Honeypot-Capture-4-1/conn.log.labeled
curl -s "$base/CTU-Honeypot-Capture-5-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-Honeypot-Capture-5-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-8-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-20-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-20-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-21-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-21-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-34-1/conn.log.labeled
curl -s "$base/CTU-IoT-Malware-Capture-42-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-42-1/conn.log.labeled
# gitignored, vetsi:
curl -s "$base/CTU-IoT-Malware-Capture-3-1/bro/conn.log.labeled" -o labs/datasets/iot23/CTU-IoT-Malware-Capture-3-1/conn.log.labeled
```

**Souhrn po rozšíření: 9 scénářů committed (2 benigní + 44-1 + Somfy-01... pozn. Somfy-01 je taky benigní, takže 3 benigní + 6 malware), 4 rodiny/techniky** (C&C, C&C-Torii, DDoS, FileDownload, PartOfAHorizontalPortScan), **+ 1 scénář zaznamenaný mimo git**. Nová sdílená `IOT23_COMMITTED_SCENARIOS` konstanta v `src/eval/dataset_replay.rs`, nový `iot23_nine_scenarios_four_families_dataset_sufficiency_check` test — BEZ `#[ignore]`, běží normálně v CI (všechny soubory committed).

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

### Rozšíření 30.10.2026 — zbývajících 10 scénářů, plná sada 13/13

**Impuls**: uživatel výslovně odmítl N=3 jako statisticky/datově průkazné ("dataset testů je stále moc malý"). CTU-13 (akademický paper "An empirical comparison of botnet detection methods", mcfp.weebly.com) má přesně 13 scénářů — tahle session doplnila zbývajících 10, čímž je **poprvé pokryta celá, standardní, publikovaná CTU-13 sada, ne jen výběr 3**.

**Rodina u každého scénáře ověřena PŘÍMO na `mcfp.felk.cvut.cz`** (jméno exe vzorku a/nebo capture název v adresáři scénáře), **ne odhadnuta ze zapamatované mapovací tabulky** — stejná disciplína, co tento projekt už jednou vynutila opravu (Virut/RBot mix-up, viz historie výše v tomto dokumentu). Dva scénáře se od často citované "scénář 6 = Menti, scénář 8 = Murlo" tabulky skutečně liší: přímo zjištěno **Donbot** (Botnet-47) a **Qvod** (Botnet-49), ne Menti/Murlo. Dva scénáře (Botnet-46, Botnet-53) nemají u zdroje jednoznačné jméno rodiny (jen capture technika "fast-flux" / generické "bot") — zapsáno honestně jako neoznačené, ne domyšlené.

Tři scénáře (Botnet-46/48/52) mají celý soubor pod 30 MB — stažen celý (ne výřez). U tří scénářů (Botnet-43/44/45) byla raná část capture (prvních 30 MB) málo nebo vůbec zastoupená malware provozem — ověřeno přímo sondami na více offsetech (stejná disciplína jako u Botnet-42 výše), výřez sestaven z hustší oblasti. Zbývající čtyři (Botnet-47/49/50/53) mají dost malware provozu už v prvních 30 MB.

| Scénář | Rodina (ověřeno přímo) | Cesta (lokální, gitignored) | Velikost | SHA-256 | Flows | Malicious |
|---|---|---|---|---|---|---|
| CTU-Malware-Capture-Botnet-43, scénář 2, 30 MB od offsetu 60 000 000 B | Neris | `labs/datasets/ctu13/Botnet-43/capture20110811.binetflow.excerpt.csv` | 31 457 330 B | `72aff359dfdd7e4534fe6033771324f1094a7d44a98ca81ad91f14b4529a0d80` | 229 265 | 10 263 |
| CTU-Malware-Capture-Botnet-44, scénář 3, 30 MB od offsetu 475 000 000 B | Rbot | `labs/datasets/ctu13/Botnet-44/capture20110812.binetflow.excerpt.csv` | 31 457 370 B | `23c323a23484fef6e8fce57c2c578e6d7ef6ce6ec4aa67ba89ae67f75cfd01e0` | 231 592 | 4 757 |
| CTU-Malware-Capture-Botnet-45, scénář 4, 30 MB od offsetu 58 000 000 B | Rbot (DoS varianta) | `labs/datasets/ctu13/Botnet-45/capture20110815.binetflow.excerpt.csv` | 31 457 365 B | `726a30ca60915cd304949dbc43a54b496f328db7de1c42a716979acdd1cceca2` | 229 288 | 469 |
| CTU-Malware-Capture-Botnet-46, scénář 5, celý soubor | "fast-flux" (rodina neoznačena u zdroje) | `labs/datasets/ctu13/Botnet-46/capture20110815-2.binetflow.full.csv` | 17 766 203 B | `ef5c9ed6895d4ca5aec723449dae30054ccd1f6b091713a52ffcb681ff78a02c` | 129 832 | 901 |
| CTU-Malware-Capture-Botnet-47, scénář 6, prvních 30 MB | Donbot (NE "Menti" — ověřeno přímo, mapovací tabulka se mýlí) | `labs/datasets/ctu13/Botnet-47/capture20110816.binetflow.excerpt.csv` | 31 457 281 B | `107a93bc1923a50a2a8c15e1b9ad785011dcf028f470df99691d157914521482` | 228 608 | 1 552 |
| CTU-Malware-Capture-Botnet-48, scénář 7, celý soubor | Sogou | `labs/datasets/ctu13/Botnet-48/capture20110816-2.binetflow.full.csv` | 15 630 512 B | `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680` | 114 077 | 63 |
| CTU-Malware-Capture-Botnet-49, scénář 8, prvních 30 MB | Qvod (NE "Murlo" — ověřeno přímo, mapovací tabulka se mýlí) | `labs/datasets/ctu13/Botnet-49/capture20110816-3.binetflow.excerpt.csv` | 31 457 281 B | `72935df0e450755278550c0289b363f93b2e8d6175d96339462f1da376bc050f` | 228 413 | 381 |
| CTU-Malware-Capture-Botnet-50, scénář 9, prvních 30 MB | Neris | `labs/datasets/ctu13/Botnet-50/capture20110817.binetflow.excerpt.csv` | 31 457 281 B | `dc49523e0f11c6bb418784d4cc0703c6bbdbfe340fbf7d98583b963d44255e43` | 229 364 | 50 |
| CTU-Malware-Capture-Botnet-52, scénář 11, celý soubor | Rbot | `labs/datasets/ctu13/Botnet-52/capture20110818-2.binetflow.full.csv` | 14 596 615 B | `cee542d4b5efe4fa1cd59b87ece5aaea9a13d8f0abe56cd07cee31590736428c` | 107 251 | 8 164 |
| CTU-Malware-Capture-Botnet-53, scénář 12, prvních 30 MB | rodina neoznačena u zdroje ("bot") | `labs/datasets/ctu13/Botnet-53/capture20110819.binetflow.excerpt.csv` | 31 457 281 B | `8a7d096e2aa40c8da267cf50987a6775dccfdeb8d3b0dd9f9d551c0ad8bd745e` | 228 811 | 1 720 |

**Souhrn po rozšíření: 13/13 standardních CTU-13 scénářů, ~2,64 milionu flows celkem, ~27 000 malicious flows, 7 odlišných rodin/technik** (Neris×3, Rbot×4, Virut×1, "fast-flux"×1, Donbot×1, Sogou×1, Qvod×1, neoznačeno×1) — proti dřívějšímu N=3 (3 rodiny, ~688 000 flows). Použito v `src/eval/dataset_replay.rs`'s sdílené `CTU13_ALL_SCENARIOS` konstantě, nahrazující 6 dříve nezávisle hardcoded N=3 seznamů.

**Reprodukce stažení zbývajících 10** (stejný vzor jako výše; offsety u Botnet-43/44/45 zjištěny sondováním více bodů v souboru, ne odhadem):
```
# Cele soubory (<30MB)
curl -s "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/detailed-bidirectional-flow-labels/capture20110815-2.binetflow" -o labs/datasets/ctu13/Botnet-46/capture20110815-2.binetflow.full.csv
curl -s "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/capture20110816-2.binetflow" -o labs/datasets/ctu13/Botnet-48/capture20110816-2.binetflow.full.csv
curl -s "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/detailed-bidirectional-flow-labels/capture20110818-2.binetflow" -o labs/datasets/ctu13/Botnet-52/capture20110818-2.binetflow.full.csv

# Prvnich 30MB (dost malware provozu uz na zacatku)
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/detailed-bidirectional-flow-labels/capture20110816.binetflow" -o labs/datasets/ctu13/Botnet-47/capture20110816.binetflow.excerpt.csv
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-49/detailed-bidirectional-flow-labels/capture20110816-3.binetflow" -o labs/datasets/ctu13/Botnet-49/capture20110816-3.binetflow.excerpt.csv
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/detailed-bidirectional-flow-labels/capture20110817.binetflow" -o labs/datasets/ctu13/Botnet-50/capture20110817.binetflow.excerpt.csv
curl -s -r 0-31457280 "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-53/detailed-bidirectional-flow-labels/capture20110819.binetflow" -o labs/datasets/ctu13/Botnet-53/capture20110819.binetflow.excerpt.csv

# Offset-based (rana cast capture ma malo/zadny malware provoz, ověřeno sondou)
curl -s -r 0-200 "$URL43" | head -1 > h.tmp; curl -s -r 60000000-91457279 "$URL43" | tail -n +2 > b.tmp; cat h.tmp b.tmp > labs/datasets/ctu13/Botnet-43/capture20110811.binetflow.excerpt.csv
curl -s -r 0-200 "$URL44" | head -1 > h.tmp; curl -s -r 475000000-506457279 "$URL44" | tail -n +2 > b.tmp; cat h.tmp b.tmp > labs/datasets/ctu13/Botnet-44/capture20110812.binetflow.excerpt.csv
curl -s -r 0-200 "$URL45" | head -1 > h.tmp; curl -s -r 58000000-89457279 "$URL45" | tail -n +2 > b.tmp; cat h.tmp b.tmp > labs/datasets/ctu13/Botnet-45/capture20110815.binetflow.excerpt.csv
```

## Vlna 1 (krok 5, 2026-11-04): CIC-IDS2017 a UNSW-NB15

Obě sady jsou mimo git v `F:\bakula-datasets\` (proměnná `BAKULA_EXTERNAL_DATASETS`). Do repa jde jen kód zdroje, skripty výřezu (`tools/datasets/`) a hashe níže. Rozdělení na vývojovou a zamčenou testovací část je v `docs/diplomka/eval/anchor-split.txt` (`[dev-k5]`, `[test-k5]`, SHA-256 testovací části `b1dbb1ca…`), pravidla jsou v `impl-krok5.md`, A9.

### CIC-IDS2017 (přegenerovaná verze Engelen a kol.)

| Pole | Hodnota |
|---|---|
| `dataset_id` | `cicids2017` |
| `source` | Canadian Institute for Cybersecurity (UNB), záznam 3. až 7. 7. 2017; toky a štítky přegenerovali Engelen, Rimmer, Joosen (KU Leuven, WTMC 2021) opraveným CICFlowMeterem |
| `url` | https://www.unb.ca/cic/datasets/ids-2017.html (originál), https://intrusion-detection.distrinet-research.be/WTMC2021/ (použitá verze, `Dataset/dataset.zip`, 333 841 436 B, ověřeno HTTP Range 2026-11-04) |
| `license` | Ani originál, ani přegenerovaná verze nemají výslovnou licenci. Obě stránky žádají citaci: Sharafaldin, Lashkari, Ghorbani, ICISSP 2018, a Engelen a kol., IEEE SPW/WTMC 2021. Ověřeno na oficiálních stránkách 2026-11-04. |
| proč ne originál | Stažení z UNB vyžaduje formulář se jménem, e-mailem a organizací. Pravidla práce zakazují posílat osobní údaje externím službám, proto je použita veřejně stažitelná přegenerovaná verze téhož záznamu. Opravuje i známé chyby originálu: konstrukci toků, ignorované RST, chybné příznaky a přes 20 % přeznačených toků. |
| `modalities` | Toky CICFlowMeteru. Výřez má jen sloupce Src/Dst IP a port, Protocol, Timestamp, Flow Duration (µs), počty paketů a délky payloadu v obou směrech, FIN/SYN/RST a Label. |
| `label_schema` | `BENIGN` nebo název útoku, u pokusů bez payloadu přípona `- Attempted`. Obojí se počítá jako Malicious. |
| osobní údaje | Testbed, provoz 25 simulovaných uživatelů (B-Profile). Žádní skuteční uživatelé. |
| `known_leakage_risks` | Toky nemají Zeek `conn_state`: zdroj ho odvozuje přibližně (bez paketů zpět = S0, RST = RSTO, jinak SF). Časy jsou o +5 h posunuté proti místnímu času testbedu (přegenerovaná verze), relativní pořadí sedí. Útočník je za NAT jako 172.16.0.1, mimo rozsah 192.168.10.0/24. |
| `wave` | 1 |

Staženo po dnech přes HTTP Range ze `dataset.zip` (komprimovaně: pondělí 64,8 MB, úterý 54,9 MB, středa 87,0 MB, čtvrtek 53,1 MB, pátek 74,0 MB). Plná data se neukládala. Výřezy podle A9 jsou okno [první tok skupiny štítků − 30 min, poslední + 30 min], nejvýš 3 h. Neškodné pondělní výřezy jsou hodina 1 až 2 a 5 až 6 od začátku dne.

| Výřez | Část | Okno (čas souboru) | Toků | Škodlivých | Velikost | SHA-256 |
|---|---|---|---:|---:|---:|---|
| `tue-ftp-patator` | dev | 04.07. 13:47:52 až 15:50:13 | 102 995 | 3 984 | 10 137 032 B | `5b95badc02325b80166d4f904421c447727fee9b5abe8dda7aea7fd7b7c5a628` |
| `wed-dos-slow` | dev | 05.07. 13:31:00 až 15:40:36 | 95 251 | 10 843 | 9 470 140 B | `df91914427c2be10f5d6d2cace59819faf2377154fa2d69283b091f890e25212` |
| `fri-botnet` | dev | 07.07. 14:04:13 až 17:04:13 | 135 702 | 1 509 | 13 309 039 B | `31e515f92154af22a9cb3db1b2b98be5c2e98a3580bd1e46eece4e08c4d88b22` |
| `mon-benign-am` | dev | 03.07. 14:55:58 až 15:55:58 | 59 849 | 0 | 5 905 339 B | `b3d1993cc6cc4489cc986d4dcc7c7c772b667e67b19660b5c9d75a2bc42d9dab` |
| `tue-ssh-patator` | test | 04.07. 18:39:01 až 21:34:15 | 122 372 | 2 988 | 12 053 674 B | `36db1cdcd235e7383c2d714d27f13ae6d536668b707d2043c7a859240a1976d3` |
| `wed-dos-hulk-goldeneye` | test | 05.07. 15:40:36 až 16:49:49 | 211 284 | 166 709 | 21 103 295 B | `e1631a242d09aaed6ad8e7ebd49d93c1063a75687c87b35270450ec9b92d2ad6` |
| `thu-web` | test | 06.07. 13:45:54 až 16:12:50 | 86 752 | 2 056 | 8 564 709 B | `5e822969eb69ab17c30fa0e255a66c9bdb5a5743cc25811d62ab98913b16efa6` |
| `thu-infiltration` | test | 06.07. 18:49:02 až 21:14:24 | 174 824 | 48 | 16 691 017 B | `7f83aeceeed6569c75bc93f636b9abe36705cc411133dd7e953e26b49b833cde` |
| `fri-portscan` | test | 07.07. 17:07:57 až 20:07:57 | 225 719 | 139 741 | 21 286 911 B | `e091f5127881d036807bce0ab17eb4c83be637308ad9b72e0b548f70fe7d5e03` |
| `fri-ddos` | test | 07.07. 20:26:31 až 21:46:10 | 143 780 | 95 123 | 13 919 184 B | `9740f79b940e5a329f8053160bfa8cb41dc16e8e10ba39e5eefcddc5ff6ef993` |
| `mon-benign-pm` | test | 03.07. 18:55:58 až 19:55:58 | 35 878 | 0 | 3 517 788 B | `046f23600c4900f4ecf268954b6dcd1fc54427f9db9df4a63b4e35cb089119a3` |

Odchylka od A9, zjištěná před během jakéhokoli detektoru: okna `wed-dos-slow` a `wed-dos-hulk-goldeneye` se podle pravidla překrývala (15:13 až 16:07), takže vývojová a testovací část by sdílely toky. Hranice je proto v polovině mezery mezi posledním tokem pomalé skupiny (15:37:49) a prvním tokem Hulk (15:43:23), tedy 15:40:36 (`tools/datasets/cic_recut_wed.py`). Heartbleed (11 toků, večer) není v žádném výřezu. Ve výřezu `fri-portscan` jsou i pozdní pokusy botnetu (`Bot - Attempted` do 17:59).

### UNSW-NB15

| Pole | Hodnota |
|---|---|
| `dataset_id` | `unsw-nb15` |
| `source` | UNSW Canberra, Cyber Range Lab, nástroj IXIA PerfectStorm (Moustafa a Slay, MilCIS 2015) |
| `url` | https://research.unsw.edu.au/projects/unsw-nb15-dataset (oficiální sdílená složka UNSW; anonymní odkaz z oficiální stránky, bez přihlášení) |
| `license` | „Free use of the UNSW-NB15 dataset for academic research purposes is hereby granted in perpetuity. Use for commercial purposes should be agreed by the authors.“ Citovat pět článků z oficiální stránky. Ověřeno 2026-11-04. |
| `modalities` | Argus a Bro toky, `UNSW-NB15_4.csv` (97 588 754 B, 440 044 řádků, 49 sloupců podle `NUSW-NB15_features.csv`). Výřez má `stime, srcip, sport, dstip, dsport, proto, state, dur, sbytes, dbytes, spkts, dpkts, attack_cat, label`. |
| `label_schema` | `label` 0/1, `attack_cat` ∈ {Fuzzers, Analysis, Backdoor, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms} |
| osobní údaje | Syntetický provoz testbedu, žádní skuteční uživatelé |
| `known_leakage_risks` | Argus stavy jsou převedené přibližně (INT/REQ = S0, RST = RSTO, FIN/CON/CLO/ACC = SF). Útočníci 175.45.176.0/24 jsou mimo rozsah 59.166.0.0/24 + 149.171.126.0/24. „Generic“ tvoří dvě třetiny škodlivých toků. |
| `wave` | 1 |

| Výřez | Část | Okno (Unix čas) | Toků | Škodlivých | Velikost | SHA-256 |
|---|---|---|---:|---:|---:|---|
| `unsw-h0` | dev | 1424249984 až +3600 s | 138 993 | 30 525 | 11 469 722 B | `58489ca79c3c32e0958678d7c5e35d7a1366972e399d4c05404ca2d3f1ed2123` |
| `unsw-h2` | test | 1424257184 až +3600 s | 132 138 | 29 411 | 10 921 712 B | `335d8b55900afb4393056f251ea57661a61ecf834226270aee6feb46218c2f42` |

Odchylka od A9: kategorie útoků se v UNSW-NB15 v čase prolínají, takže rozdělení „Reconnaissance a Exploits do vývojové části“ by šlo provést jen vyřazením toků z provozu. Místo něj se dělí po čase: první hodina souboru je vývojová, třetí hodina testovací a mezi nimi je hodina odstupu. Rozhodnuto před během jakéhokoli detektoru. Obě části mají všech 9 kategorií.

## Budoucí vlny (naplánováno, ne implementováno)

- **Vlna 1 (zbytek):** CSE-CIC-IDS2018, CICIoT2023 — každý jako nová `ScenarioSource` implementace v `src/eval/sources/`. CIC sady vyžadují registrační formulář s osobními údaji, takže jen přes veřejné přegenerované verze (Engelen a kol., CNS 2022), nebo po rozhodnutí uživatele.
- **Vlna 2:** threat intel enrichment (NVD/KEV/EPSS, URLhaus, ThreatFox, OTX).
- **Vlna 3:** Mininet/Containerlab generátor syntetických scénářů — zdroj prakticky neomezeného objemu kontrolovaných scénářů (DHCP/NAT churn, vlastní firewall/DNS/IPS politiky), včetně identity-churn scénářů, které IoT-23 ani CTU-13 nepokrývají.
