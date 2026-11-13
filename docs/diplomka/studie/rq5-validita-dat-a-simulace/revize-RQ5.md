# Revize RQ5 po nezávislé kontrole

Datum: 2026-10-31. Podklad: `kontrola-RQ5.md` (verdikt VRÁTIT K PŘEPRACOVÁNÍ, věcná chybovost 6 / 51 = 11,8 %). Revidovány byly `extrakce.csv` a `studie.md`. `neovereno.md` se neměnil (důvod v části 6).

## 1. Postup

- Všechny zdroje, o které se opravy opírají, jsem 2026-10-31 stáhl znovu (curl) do nového adresáře `<pracovní adresář>/rq5rev\` a převedl přes `pdftotext`, a to dvakrát: s `-layout` a bez něj. Surový text bez `-layout` zachovává pořadí hodnot ve sloupcích tabulek, takže z něj šlo ověřit přiřazení řádků v tabulkách, které se v layoutu rozpadají (Engelen Tab. II, Wang Tab. 3, Majorczyk slajd 21/27, Layeghy Tab. 4, TESSERACT Tab. 1). Starší texty z `rq5pdf` jsem nepoužil.
- Venue jsem ověřoval přes Crossref API (Engelen, NetDiffusion, Goldschmidt) a podle hlavičky PDF (Wolf, Anjum).
- Kód soaku jsem četl čerstvě v pracovní kopii (`src/soak/traffic.rs`, `netmodel.rs`, `episode.rs`, `runner.rs`) včetně `git diff` necommitnutých změn.
- Hodnoty z kontroly jsem nepřebíral. Každou jsem znovu našel ve zdroji. Kde se kontrolor mýlí nebo kde je nález neúplný, je to uvedeno v části 3.

## 2. Opravy v extrakci (audit trail: původní → nová hodnota)

Typ: V = věcná chyba podle kontroly, D = drobná chyba podle kontroly, N = nově nalezeno při revizi (řádek kontrola nekontrolovala nebo chybu neuvedla).

| id | typ | co bylo špatně (původní hodnota) | nová hodnota | jak ověřeno |
|---|---|---|---|---|
| RQ5-001 až 005 | D | venue „IEEE S&P Workshops (DLS)“ | „IEEE Security and Privacy Workshops (SPW) 2021, workshop WTMC; DOI 10.1109/SPW53761.2021.00009“ | Crossref: container-title „2021 IEEE Security and Privacy Workshops (SPW)“; ref. [10] článku odkazuje na `downloads.distrinet-research.be/WTMC2021`. „DLS“ ve zdroji není. |
| RQ5-004 | V | „SQL 0,18 -> 0,79, Infiltration 0,11 -> 0,00, Brute Force 0,77 -> 0,93“; „Tab. II, s. 4“ | XSS 0,18 → 0,25 → 0,79; SQL 0,11 → 0,00 → 0,00; Infiltration 0,81 → 0,66 → 0,91; Web Brute Force 0,77 → 0,78 → 0,95 (0,93 je Heartbleed); Tab. II, s. 5 | Surový text Tab. II vypisuje 15 názvů tříd a pak 15 trojic Pr/Re/F1 ve stejném pořadí. 10. trojice (XSS) = „0.52 0.11 0.18“, 11. (SQL) = „0.33 0.07 0.11“, 12. (Infiltration) = „0.96 0.70 0.81“. Layout posunul popisky o řádek. Potvrzuje to text Sekce IV-B: „Web Attack - SQL Injection ends up with 12 traces in total, and all 3 test traces are mispredicted as Benign“ (SQL v Intermediate = 0,00). Strana podle `pdftotext -f 5 -l 5`. **Souhlas s kontrolou.** |
| RQ5-005 | D | „F1 0,99 beze změny“ | F1 0,98 → 0,98 → 0,99 | Tab. II, 6. trojice (DoS Slowhttptest): Original „0.98 0.99 0.98“, Intermediate „0.97 0.99 0.98“, Final „0.99 0.99 0.99“. Souhlas. |
| RQ5-012 | N | umístění „Sekce 5.1“ | Sekce 5.2 (odstavec „Mislabelled“) | Citace je na s. 11, za nadpisem „5.2. Automated Analysis“ (s. 10). Hodnota přibližně 20 % sedí. |
| RQ5-019 | D | citace „Abstrakt: …“ | Sekce I (Úvod) | Abstrakt čísla neobsahuje. Věta „about 78% and 75% of the records are duplicated“ je v Úvodu, hodnoty 93,32 / 78,05 / 88,26 / 75,15 % v tabulkách statistik. Souhlas. |
| RQ5-020 | D + N | citace „Abstrakt“; metoda „21 klasifikátorů“ | Sekce I; „21 naučených modelů (7 algoritmů, každý 3× na jiné trénovací sadě)“ | Zdroj: „21 learned machines (7 learners, each trained 3 times with different train sets)“. |
| RQ5-023 | V | „0,52 (N&T) vs 0,24 (vlastní) vs 0,23 (Flash)“, host 201, „víc než dvojnásobek“ | GAE: klient 201 0,52 vs 0,24; klient 501 opačně 0,38 vs 0,60; klient 051 0,14 vs 0,13. Hodnota 0,23 patří detektoru Flash (klient 051, štítky Flash). | Slajd 21/27 (s. 25 PDF): řádky GAE 201 „0.46 0.59 0.52“ / „0.14 0.67 0.24“, GAE 501 „0.23 1.0 0.38“ / „0.43 0.99 0.60“; řádek Flash 051 se štítky Flash „0.13 0.95 0.23“. Souhlas. |
| RQ5-032 | V | „0,96 (trénink i test 90 % mw) vs 0,32 (10 % mw)“; poznámka „Poměr tříd v testu sám o sobě ztrojnásobí F1“ | Celá mřížka ALG2: trénink 10 % → test 10 % 0,32 / test 90 % 0,33; trénink 90 % → 0,30 / 0,96. ALG1: 0,58 / 0,62 a 0,45 / 0,94. Efekt testovacího poměru závisí na tréninku. | Tab. 1, poslední řádek (realistic): „0.58 0.45 0.32 0.30 0.62 0.94 0.33 0.96“, sloupce v pořadí [test 10 %: ALG1 tr10, tr90, ALG2 tr10, tr90 \| test 90 %: totéž]. Souhlas, s doplněním v části 3. |
| RQ5-035 | D + N | citace „abstrakt: generalisability 'highly asymmetric'“; poznámka o rekonstrukci z matice | Abstrakt: „the generalisability has a high degree of asymmetry“; „highly asymmetrical“ je v Sekci 5.1. Hodnoty z čitelné Tab. 4. | Tab. 4 (Extra Tree): cíl BoT-IoT ze zdrojů CIC/ToN/UNSW „0.14% 24.42% 94.83%“, cíl UNSW z BoT/CIC/ToN „4.90% 0.57% 0.00%“; Tab. 2 „99.82% 84.62% 77.63% 91.73%“. Souhlas. Nově: minimum F1 mimo doménu je 0,00 % (ToN → UNSW), ne 0,14 % (oprava ve `studie.md`, tabulka b). |
| RQ5-037 | V | „accuracy -25,63 % průměrně, AUROC -27,13 %“ | AUROC průměrně −30,45 % (OC-SVM −17,85 % až autoenkodér −37,49 %); accuracy −25,63 %; −27,13 % platí jen pro PCA | Sekce 5.2: „on average the AUROC decreased by 30.45%. In the best case, only a decrease of 17.85% … 37.49% in the worst case“; Sekce 4.1 (PCA): „average decrease of 27.13% in AUROC“. Souhlas. |
| RQ5-040 | D | „top venues 2017-2022“ | sborníky 2017–2021 (9 konferencí) | Sekce 4: „we investigated the proceedings from 2017 to 2021“. Souhlas. |
| RQ5-041 | D (poznámka) | – | doplněno: 90 % při n = 12 není celé číslo | Sekce 5.3: „Most practitioners (90%) agree …“, Sekce 3: „12 practitioners“. Souhlas. |
| RQ5-043 | D | dataset „GCUT, WWT“, hodnota bez rozlišení | AR 1,00 na GCUT (DG také 1,00); na WWT AR 0,80 = DG 0,80 | Tab. 5 (sloupce DG, AR, RNN, HMM, Naive GAN): GCUT „1.00 1.00 1.00 0.01 0.90“, WWT „0.80 0.80 0.20 -0.60 -0.60“. Souhlas. |
| RQ5-046, 047 | N (venue) | „ACM POMACS / SIGMETRICS“ | ACM SIGMETRICS 2024 (DOI 10.1145/3652963.3655071 dle Crossref) | Crossref; časopisecké vydání v POMACS jsem nedohledal. |
| RQ5-047 | D | „26-73 procentních bodů“ | 26–72 p. b. (26,2 a 71,6) | Tab. 4: „0.738 (DT) 0.262 (DT)“ vs real/real „1.00 (SVM) 0.978 (SVM)“. Souhlas. |
| RQ5-049 | D | „o 41-76 % lepší“ bez výjimky | kromě REaLTabFormer | Sekce 7.2: „Compared to baselines except REaLTabFormer, CascadeNet achieves 41%~76% improvement“. Souhlas. |
| RQ5-050 | D | venue „arXiv preprint“, recenzováno „ne“ | workshop ML for CyberSecurity @ ECML PKDD 2024; „ano (workshop)“ | Hlavička PDF: „Preprint; Accepted at Machine Learning for CyberSecurity @ … (ECML PKDD) 2024“. Souhlas. |
| RQ5-051 | N | umístění „Sekce VII“; per krok „0,05 % až 17 %“ bez rozlišení | Sekce VI-B (Discussion); 0,05–10 % bez uživatelů, až 17 % s uživateli; 1 % jen u agenta trénovaného se šumem | Text s. 11 pod „B. Modeling Improvements“ před „VII. CONCLUSION“: „had an observation probability of 10%, even without users, whereas "attemptRead" had a rate 0.05%. With users … 17%“. |
| RQ5-052 | N | umístění „Sekce VI“ | Sekce V (konec, analýza výnosů) | Citace je na s. 9 nad nadpisem „VI. DISCUSSION“. Hodnoty −80 / −101 / −109 % a −5 / −11 / −14 % sedí. |
| RQ5-053 | V | „učené modely AUROC 0,868-0,997 při AP <= 0,062“ (bez omezení na dataset) | Trace 0,868–0,997 při AP ≤ 0,062; FiveDirections 0,666–0,943 při AP ≈ 0; Theia: Magic 0,976 / AP 0,088, ale Theseus 0,994 / AP 0,551 | Sekce V-A1: „On Trace, AUROC ranges from 0.868 to 0.997, yet AP remains at or below 0.062“; „On FiveDirections, all learned systems have near-zero AP … AUROC values ranging from 0.666 to 0.943“; V-A3: „Magic reaches an AUROC of 0.976, but its AP is 0.088“; Tab. IV „Theseus 0.551 ± 0.150 0.994 ± 0.002“. Souhlas, s doplněním. |
| RQ5-054 | V | „OilRig AUC 0,951 při precision 0,048“ přiřazeno ARGUS | ARGUS OilRig AUC 0,942, FPR 0,115, P 0,030; EULER AUC 0,951, FPR 0,070, P 0,048 | Surový text Tab. 3 vypisuje sloupce postupně. FPR: „0.176 0.115 0.070 0.065 0.002“ + „0.006“ pro OilRig v pořadí ARGUS_ft, ARGUS, EULER, VGRNN, PIKACHU, Anomal-E. P: „0.021 0.030 0.048 0.051 0.649 0.264“, AUC: „0.918 0.942 0.951 0.951 0.999 0.934“. Souhlas. |
| RQ5-057, 058 | N (venue) | „Computers & Security“ bez dokladu (čtená verze je „Preprint submitted to Computers & Security“) | Computers & Security 2025, DOI 10.1016/j.cose.2025.104510 | Crossref (publikováno 2025-09). Umístění 057 zpřesněno na Sekci 5.5.2. |
| RQ5-060 | D | ToN-IoT „duplicitní toky s různými štítky“; „bez kvantifikace“ | duplicity se týkají NF-ToN-IoT; filtrace 21 978 630 → 18 902 360 toků (přibližně 14 %); Bot-IoT 99,99 % jen ilustrační | Sekce 2.1: „in NF-ToN-IoT a number of flows are duplicated and labeled as corresponding to different attacks“; Tab. 1 „Total Size 21'978'630 18'902'360“. Souhlas. |

Počet opravených řádků v extrakci: **26**, z toho:
- 6 s věcnou chybou (004, 023, 032, 037, 053, 054),
- 12 s drobnou chybou nebo poznámkou z kontroly (001, 005, 019, 020, 035, 040, 041, 043, 047, 049, 050, 060),
- 2 jako důsledek opravy venue u 001 (002, 003),
- 6 s drobnou chybou nově nalezenou při revizi (012, 046, 051, 052, 057, 058).

U 020 a 035 revize navíc doplnila nové údaje. Mezi 12 dříve nekontrolovanými řádky revize nenašla žádnou věcnou chybu. Drobné chyby měly 012, 051, 052 (umístění) a 057, 058 (doklad venue). Řádky 008, 009, 011, 021, 033, 048 a 061 byly bez chyby.

## 3. Kde je nález kontroly neúplný nebo kde nesouhlasím

1. **S1, „nejde o 12 pevných adres (generují se náhodně na síť)“.** Částečně nesouhlasím. `netmodel.rs:825` `let externals: Vec<String> = (0..12)` leží uvnitř `NetworkModel::generate(run_seed, id)` (`netmodel.rs:678`). Každá síť tedy dostane právě 12 adres a ty se během epizody nemění. Formulace „12 pevných adres na síť“ je správná, chybělo jen „na síť“. Pro artefakt je podstatné právě to, že benigní egress po celou epizodu opakovaně míří na stejných 12 cílů. Útočné externí cíle se losují nově z `public_ip()` a útoky `externals` nikdy nepoužívají (`grep externals`: jen `traffic.rs:997, 1119, 2253`, všechno benigní generátory).
2. **S1, „oddělení platí jen pro benigní odchozí provoz“.** Souhlasím a doplňuji. Pool `public_ip()` sdílí i část benigního *odchozího* provozu: cíle lookalike událostí software_update (`traffic.rs:1815–1819`, `target_external` z `traffic.rs:902`), patch_window (`traffic.rs:2301–2302`) a ntp_fanout (`traffic.rs:1846`). Oddělení tedy platí pro *běžný* benigní egress, ne pro veškerý. Příchozí směr (weboví klienti `traffic.rs:1095`, flash crowd `traffic.rs:1794`) sdílí pool s útočníky, jak uvádí kontrola.
3. **RQ5-032.** Kontrolor má pravdu, že skok 0,32 → 0,96 mění poměr v tréninku i testu. Tvrzení „poměr v testu sám F1 nemění“ by ale bylo také neúplné. Při tréninku s 90 % malwaru změna testu z 10 na 90 % zvedne F1 z 0,30 na 0,96 (ALG2) a z 0,45 na 0,94 (ALG1), při tréninku s 10 % jen z 0,32 na 0,33 a z 0,58 na 0,62. Doslovně z Tab. 1: „0.58 0.45 0.32 0.30 0.62 0.94 0.33 0.96“. Závěr Z-6b je formulovaný podmíněně.
4. **RQ5-053.** Kontrola uvádí jen Trace. Rozpor AUROC a AP je ve zdroji doložen i na FiveDirections a u modelu Magic na Theia (citace v části 2), protipříklad je Theseus na Theia. Doplnil jsem to do Z-7, aby závěr nestál na jednom datasetu, ale ani nezobecňoval.
5. **RQ5-054.** Souhlas. Doplňuji nekonzistenci ve zdroji: textové počty (528 detekovaných vs 1 529 202 falešných událostí, ARGUS Sandworm) dávají precision přibližně 0,0003, kdežto Tab. 3 uvádí P = 0,010. Zdroj vztah nevysvětluje, uvádím počty jako události z textu.
6. **S2.** Souhlas s nálezem k řádku 2593 (testovací fixture `Kind::Attack(Family::SshBrute)`, ne benigní pravda). Doplňuji: jediné benigní řádky v `out.alerts` vytváří `log_corruption` (`traffic.rs:2391–2399`) a jsou záměrně poškozené (`{"event_type":"alert","src_ip":null,"dest_ip":12345}` a podobně). Platné alerty tedy z benigních událostí nevznikají.

## 4. Změny ve `studie.md`

| sekce | původně | nově | důvod |
|---|---|---|---|
| hlavička | Verze 1.0 | Verze 1.1, odkaz na kontrolu a revizi | protokol §9 |
| Abstrakt 1 | „Bot z 0,60 na 0,99, Infiltration z 0,11 na 0,00“ | Bot 0,60 → 0,99, XSS 0,18 → 0,79, SQL 0,11 → 0,00 (3 testovací vzorky) | RQ5-004 |
| Abstrakt 3 | accuracy −25,6 % | accuracy −25,6 % a AUROC −30,5 % | RQ5-037 |
| Abstrakt 4 | 26–73 p. b. | 26–72 p. b. | RQ5-047 |
| Abstrakt 5 | „Nerealistický poměr tříd v testu ztrojnásobí F1 z 0,32 na 0,96“ | base rate 1 : 100 (RQ5-030) + podmíněný efekt poměru tříd (0,30 → 0,96 jen při tréninku s 90 %) | RQ5-032 |
| Abstrakt 6 | „Útočníci a benigní cíle mají oddělené rozsahy veřejných IP“; „Suricata alerty vznikají jen z útoků“ | oddělení jen u běžného odchozího provozu (12 `externals` na síť), příchozí směr sdílený; „platné“ alerty jen z útoků | S1, S2 |
| Metodika | – | odstavec o nezávislé kontrole a revizi; poznámka, že `mentions_ip` je jen v pracovní kopii a běh v2 mohl počítat starší atribucí; poznámka o rozpadlých tabulkách | protokol §9, bod 4 |
| (a) CICIDS2017 | „Bot 0,60 → 0,99, Infiltration 0,11 → 0,00“ | Bot, XSS, Infiltration 0,81 → 0,91, SQL 0,11 → 0,00 | RQ5-004 |
| (a) ToN-IoT | duplicity u ToN-IoT, „kvalitativně“ | duplicity u NF-ToN-IoT; filtrace přibližně 14 % toků | RQ5-060 |
| (a) OpTC | F1 GAE 0,52 vs 0,24 | + „klient 201; u 501 opačně 0,38 vs 0,60“ | RQ5-023 |
| (b) Layeghy | F1 77–100 %, cross od 0,14 % | 77,6–99,8 % (Extra Tree), cross od 0,00 % | RQ5-035 |
| (b) Verkerken | AUROC až 0,94; AUROC −27,1 % | AUROC 0,85–0,98; AUROC −30,5 % (−17,9 až −37,5 %) | RQ5-037 |
| (b) medián | „medián přibližně 30–33 % (Verkerken 25,6 %, BRIDGE 33 %)“ | 5 hodnot: 20 / 30,5 / 32,8 / 69 / 72 % → medián 33 % (BRIDGE), nezávisle na volbě metriky u Verkerkena | přepočet, RQ5-037 |
| (c) DoppelGANger | „AR téměř perfektní rank korelace“ | AR 1,00 na GCUT, na WWT 0,80 jako DG | RQ5-043 |
| (c) CascadeNet | „o 41–76 % lepší“ | kromě REaLTabFormer | RQ5-049 |
| (c) Nyberg | −80 až −109 % | + jen proti „Guided“, proti „Exploratory“ −5 až −14 % | RQ5-052 |
| (e) base rate | „F1 0,32 → 0,96 jen změnou poměru“ | podmíněná formulace | RQ5-032 |
| (e) metrika | „AUROC 0,868–0,997 při AP ≤ 0,062“ | po datasetech + protipříklad Theia | RQ5-053 |
| (e) CI, štítky, replikace | – | 90 % z 12; klient 201; „události“ místo FP/TP | RQ5-041, 023, 054 |
| Soak S1, S2 | viz část 5 | viz část 5 | kontrola kódu |
| Soak S5, S10 | – | čísla řádků, poznámka k necommitnuté změně; `runner.rs:69` výchozí seed vs seed v2 ze `status.md` | kontrola kódu |
| Co odpovídá číslům | Nyberg bez omezení | + „jen proti Guided“; podíly lookalike z v2 mohly vzniknout s oknem +2 | RQ5-052, `git diff episode.rs` |
| Syntéza | „FP 2 896× vyšší než TP“ | „2 896× víc falešně pozitivních událostí než detekovaných útočných (preprint)“ | RQ5-054 |
| Závěry | viz část 7 | viz část 7 | |
| Překlad do praxe 1a, 2, 4 | „externí IP z útočného poolu“; „Sdílený pool externích IP“; „z Z-6“ | baseline „odchozí spojení mimo `externals`“; sdílet generátor odchozích cílů; „z Z-6a“ | S1, Z-6 |
| H-1 | viz část 5 | viz část 5 | S1 |
| H-3 | „(RQ5-032, mechanismus poměru tříd)“ | + „Z-6b, nízká jistota, odhad autora“ | RQ5-032 |
| Hrozby validity | – | chybovost kontroly a vzorec chyb; druhá kontrola není nezávislá; preprinty a Z-7; stav kódu soaku | |

## 5. Zkreslení soak harnessu: S1, S2 a H-1

**S1 (přepsáno).** Doklad z kódu (pracovní kopie 2026-10-31):
- `traffic.rs:392–400` `public_ip()`: první oktet z {45, 61, 77, 91, 103, 154, 178, 193, 198}.
- Útočné užití: externí útočník (`traffic.rs:661`), externí cíl útoku (`traffic.rs:741–752`, rodiny C2Beacon, Exfil, DnsTunnel, Cryptomining, InsiderHoarding, FleetBeacon, ApChain, Ransomware), zdroje DDoS (`traffic.rs:1523`) a credential stuffingu (`traffic.rs:1880`).
- Benigní užití: weboví klienti v každém cyklu (`traffic.rs:1095`), flash crowd (`traffic.rs:1794`), cíl software_update (`traffic.rs:1819` / `902`), cíle ntp_fanout (`traffic.rs:1846`), cíl patch_window (`traffic.rs:902` → `2302`).
- Běžný benigní egress: `model.externals` (`traffic.rs:997` stanice → 443, `1119` NTP z brány, `2253` retry storm), 12 adres na síť z oktetů {13, 34, 52, 104, 142, 185, 203} (`netmodel.rs:825–833`). Sady oktetů jsou disjunktní.
- Důsledek: artefakt existuje jen v odchozím směru. V běžném provozu je každý odchozí kontakt na adresu mimo 12 `externals` útočný, výjimkou jsou jen řídké lookalike události. V příchozím směru artefakt podle oktetu není.

**S2 (přepsáno).** Doklad: uzávěr `alert` uvnitř `emit_truth` (`traffic.rs:1232`, `1249–1260`), 13 volání, všechna pod `if truth.ids_visible` (`traffic.rs:1329–2186`). Benigní pravdy mají `ids_visible: false` (`traffic.rs:903`). Řádek 2593 jsem vyřadil, je to testovací fixture útoku. Benigní `log_corruption` přidává jen neplatné řádky (`traffic.rs:2391–2399`).

**H-1 (přepsáno).** Původně: „sdílený pool externích IP, pokles detekce c2_beacon, exfiltration, credential_stuffing, web_exploit o 5–30 %“. Credential stuffing a web exploit jsou ale příchozí rodiny, kterých se artefakt netýká (útočník i benigní klient mají adresu z téhož poolu). Nová H-1:
- Změna: část běžného benigního egressu (p, výchozí 0,2 = odhad autora) míří na nové adresy z `public_ip()`.
- Primární efekt: FP/síť-den odchozích typů nálezů vzroste aspoň 1,5×, precision klesne.
- Sekundární efekt: detekce 8 rodin s externím cílem klesne o 0–20 % relativně, pokud engine staví na novosti cíle.
- Negativní kontrola: příchozí rodiny (ssh_bruteforce, credential_stuffing, web_exploit, ddos_volume) se změní o méně než 2 p. b.
- Kritérium zamítnutí: CI poměru FP obsahuje 1 nebo je pod 1,1 a pokles detekce je pod 2 p. b. u všech 8 rodin.
- Velikosti efektu jsou odhad autora, literatura je pro korelační engine nedává.

**Další nálezy z kódu.**
- `mentions_ip` (přesná shoda IP, `episode.rs:164`) a zkrácení okna lookalike atribuce na `cycle <= truth.end_cycle` jsou jen v necommitnuté pracovní kopii (`git diff src/soak/episode.rs`). `episode.rs` byl naposledy změněn 2026-10-31 22:43 SEČ, běh v2 začal 17:57 UTC (18:57 SEČ, `status.md` ř. 4) a status uvádí commit `unknown`. Kterou verzí atribuce v2 počítá, nelze ověřit. Ve studii je to uvedeno v Metodice, u S5 a v Hrozbách validity.
- S10: `runner.rs:69` má výchozí `run_seed: 20_260_131`. Seed 20261031 uvádí `status.md` ř. 3, takže byl zadán při spuštění. Tím je poznámka kontrolora potvrzena.
- S3, S5, S6, S11 kontrolor ověřil jako SEDÍ. Čísla řádků jsem znovu ověřil (`netmodel.rs:878–881`, `episode.rs:52, 710–711`, `traffic.rs:1189, 1194, 1206, 2449`, `episode.rs:1101`) a beze změny platí. S4, S7–S9 jsem znovu neověřoval.

## 6. Neověřitelné zdroje a V2

- Kontrola i revize otevřely všechny zdroje (0 neověřitelných), takže do `neovereno.md` nic nepřibylo.
- V2 řádky: 048 (abstrakt FloCon 2023 na stránce SEI, ověřen), 062 a 063. Závěr vysoké jistoty Z-1 je cituje jen jako kvalitativní doplněk. Ve `studie.md` jsem to vyznačil („V2, jen abstrakt; jistota na nich nestojí“). Jádro Z-1 stojí na V3 řádcích 001, 002, 019, 022 a 060. Přeznačení ani snížení jistoty nebylo potřeba.

## 7. Změny jistoty závěrů

| Z-id | stará → nová | co se změnilo |
|---|---|---|
| Z-1 | vysoká → vysoká | formulace rozdělena podle jednotek (toky, stopy, záznamy, procesy, události); V2 řádky označeny jako doplněk |
| Z-3 | střední → střední | medián přepočten (33 %), rozsah 20–72 % beze změny |
| Z-5 | střední → střední | 73 → 72 p. b.; rank korelace jen na GCUT; střet zájmů i u 049 |
| Z-6 | vysoká → rozděleno: **Z-6a vysoká**, **Z-6b nízká** | Z-6a: base rate (030, 055, analytické, recenzované). Z-6b: efekt poměru tříd podmíněný tréninkem, jediná studie mimo NIDS |
| Z-7 | vysoká → **střední** | omezeno na doložená nastavení, přidán protipříklad Theia; 054 jen nepřímo; všechny zdroje jsou preprinty |
| Z-9 | střední → střední | poznámka k 90 % z 12 |
| Z-10 | nízká → nízká | výnosy −80 až −109 % jen proti „Guided“ |
| Z-2, Z-4, Z-8, Z-11, Z-12 | beze změny | – |

## 8. Druhá kontrola po revizi (vlastní, ne nezávislá)

- **Vzorek:** 47 z 63 řádků (75 %): 001–005, 008, 009, 011, 012, 013, 016, 017, 019–027, 030–035, 037, 038, 040, 043, 045, 047–061. Zahrnuje všechny řádky s věcnou opravou a všechny s opravenou hodnotou nebo umístěním (mimo ně zůstaly jen 041 a 046, kde se měnila poznámka nebo venue), všech 12 dříve nekontrolovaných (008, 009, 011, 012, 021, 033, 048, 051, 052, 057, 058, 061) a 22 řádků, které revize neměnila.
- **Postup:** Proti čerstvě staženým textům zdrojů (`<pracovní adresář>/rq5rev\`) jsem pro každý řádek ověřil, že hodnoty a citace z revidované `extrakce.csv` jsou ve zdroji doslova. Kontrolu dělá skript `<pracovní adresář>/rq5scripts\second_check.py`, který hledá 1–11 řetězců na řádek: čísla, celé řádky tabulek v pořadí sloupců a doslovné citace. Přiřazení hodnot k řádkům a sloupcům v rozpadlých tabulkách jsem ověřil ručně (Engelen Tab. II, TESSERACT Tab. 1, Layeghy Tab. 4, DoppelGANger Tab. 5, Wang Tab. 3, Majorczyk slajd 21, Larroche Tab. 5 a 6, Jacobs Tab. 5), postup popisuje část 2.
- **Výsledek:** všech 47 řádků OK. Věcná chybovost **0 / 47 = 0 %** (cíl ≤ 5 % splněn). Drobné chyby v kontrolovaných polích: 0.
- **Omezení:** Při 0 chybách z 47 je horní mez 95% Wilsonova intervalu 7,6 %, takže vzorek sám nevylučuje chybovost těsně nad 5 %. Kontrolu dělal autor revize, takže není nezávislá ve smyslu protokolu §9. Mimo vzorek zůstalo 16 řádků: 006, 007, 010, 014, 015, 018, 028, 029, 036, 039, 041, 042, 044, 046, 062, 063. Všechny je kontrola-RQ5 označila jako OK (041 s poznámkou, kterou revize zapracovala). Při revizi jsem z nich mimo skript namátkou ověřil 006, 007, 014, 015, 018, 028, 036, 039 a 042 a byly v pořádku.

## 9. Co zůstává nevyřešené

- Nová nezávislá kontrola podle §9: druhá kontrola zde je vlastní. Pro formální splnění protokolu je potřeba, aby vzorek znovu prošel jiný kontrolor.
- RQ5-016: verze RAID 2003 není srovnána s technickou zprávou CS-2003-02.
- RQ5-034 (Cantone) a 035 (Layeghy): časopisecká verze nejasná, venue nechávám s „nejasné“ nebo „souvisí s“.
- RQ5-046/047: vydání v POMACS nepotvrzeno, ověřeno jen SIGMETRICS 2024 přes Crossref.
- RQ5-054: nesoulad mezi počty událostí v textu a precision v Tab. 3 zdroj nevysvětluje.
- RQ5-041: 90 % při n = 12 je ve zdroji vnitřně nekonzistentní.
- Soak: kterou verzí atribuce (podřetězec nebo přesná shoda) počítá běh v2, nejde ověřit (commit `unknown`). Čísla v sekci „Co z literatury odpovídá našim číslům“ je po commitu změny potřeba přepočítat. S4 a S7–S9 nebyly při revizi znovu ověřeny proti kódu.
- H-1: podíl p nových benigních cílů a velikosti efektu jsou odhad autora. Před během je potřeba p změřit na CTU-13 background.
