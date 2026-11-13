# Druhá nezávislá kontrola RQ5 po revizi (protokol §9)

Datum: 2026-10-31. Předmět kontroly: `extrakce.csv` a `studie.md` ve verzi 1.1, tedy po revizi popsané v `revize-RQ5.md`. Soubory `extrakce.csv` ani `studie.md` jsem neměnil. `kontrola-RQ5.md` a `revize-RQ5.md` jsem četl jen kvůli tomu, abych věděl, co se mělo opravit. Hodnoty jsem z nich nepřebíral.

## Verdikt: PŘIJATO S OPRAVAMI

- **Věcná chybovost je 5 / 59 = 8,5 %** (95% Wilsonův interval 3,7–18,4 %), tedy nad limitem 5 %. Verdikt PŘIJATO proto nelze dát.
- Žádné z pěti chybných čísel neleží v poli `hodnota`. Chyby jsou v podmínkách (konfigurace a n), v poznámkách a v metadatech (venue a recenzovanost).
- Žádná věcná chyba nepadá na řádek, o který se opírá závěr s vysokou jistotou (Z-1, Z-2, Z-6a).
- Všech pět věcných chyb je v řádcích, které revize měnila. U dvou z nich (041, 023) revize chybu sama zanesla.
- Ve 33 kontrolovaných řádcích, které revize neměnila, není žádná věcná chyba. Z toho 7 řádků nikdo dřív nekontroloval, zbylých 26 tvoří doplněk vzorku.

Proč „s opravami“, a ne „vrátit“: opravy jsou lokální a znám jejich přesné znění (viz níže). Nová extrakce celé RQ by podle výsledku tohoto vzorku nic dalšího nepřinesla.

Tvrzení revize, že její vlastní druhá kontrola našla 0 / 47 věcných chyb, neplatí. Čtyři z pěti chyb nalezených zde jsou v řádcích jejího vzorku: 023, 041, 047 a 053. Pátá chyba (052) patří k řádkům, které revize měnila.

## Vzorek a postup

- **Kontrolováno 59 z 63 řádků (94 %).** Mimo vzorek zůstaly 010, 029, 056 a 059.
- **Povinná část A: všech 26 řádků změněných revizí.** 001, 002, 003, 004, 005, 012, 019, 020, 023, 032, 035, 037, 040, 041, 043, 046, 047, 049, 050, 051, 052, 053, 054, 057, 058 a 060.
- **Povinná část B: všech 12 dříve nekontrolovaných řádků.** 008, 009, 011, 012, 021, 033, 048, 051, 052, 057, 058 a 061. Řádky 012, 051, 052, 057 a 058 jsou zároveň v části A.
- **Povinná část C: všechny řádky závěrů s vysokou a střední jistotou.** Jde o závěry Z-1, Z-2, Z-3, Z-5, Z-6a, Z-7, Z-8, Z-9 a Z-12. Mimo části A a B do této skupiny patří řádky 006, 007, 013, 014, 015, 016, 018, 022, 024, 025, 026, 027, 028, 030, 031, 034, 036, 038, 039, 042, 044, 045, 055, 062 a 063.
- **Přírůstek nad části A a B je 26 řádků.** Cílem bylo aspoň 10.
- **Postup.** Pět paralelních průchodů (skupiny A–E) stáhlo zdroje 2026-10-31 znovu, a to curl nebo přímé načtení stránky do nového adresáře `<pracovní adresář>/rq5v2\`. Texty jsme převedli přes `pdftotext` s `-layout` i bez něj. Rozpadlé tabulky jsme ověřili obrazově (`pdftoppm` a kontrola PNG): Majorczyk slajd 21/27, TESSERACT Tab. 1, Larroche Tab. 5 a 6, Layeghy Tab. 2 a 4, DoppelGANger Tab. 5, NetDiffusion Tab. 1, 3 a 4 a Wang Tab. 3. Venue jsme ověřili přes Crossref API.
- **Nezávislost.** Texty v `rq5pdf` ani v `rq5rev` jsme nepoužili. Kontroloři zdrojů nečetli `kontrola-RQ5.md`, `revize-RQ5.md` ani `studie.md`. Pět věcných nálezů jsem pak sám ověřil u zdroje: obrázek slajdu 21, obrázek NetDiffusion Tab. 4, text SoK Appendix B.3, patička Guerra v4 a Nyberg Sekce V-C. DOI NetDiffusion a OpTC jsem ověřil v Crossrefu.

## Tabulka kontrolovaných řádků

| id | výsledek | poznámka (opravená hodnota a umístění) |
|---|---|---|
| RQ5-001 | OK | Úvod a Sekce III-A doslovně (25,9 %). Crossref potvrzuje venue „2021 IEEE Security and Privacy Workshops (SPW)“, s. 7–12. |
| RQ5-002 | OK | Abstrakt doslovně. |
| RQ5-003 | OK | Tab. II: Bot F1 0,60 / 0,53 / 0,99, vážený průměr 0,99 ve všech verzích. „Jediný split“ je inference, ne výrok autorů (text zmiňuje „random seeds“). |
| RQ5-004 | DROBNÁ | Všech pět trojic F1 je správně: XSS 0,18 → 0,25 → 0,79, SQL 0,11 → 0,00 → 0,00, Infiltration 0,81 → 0,66 → 0,91, Web Brute Force 0,77 → 0,78 → 0,95, Heartbleed → 0,93. Ověřeno ze surového textu Tab. II. Nepřesnosti: (1) hvězdička „Test sets … extremely small“ označuje Heartbleed, XSS, SQL a Infiltration, ne Web Brute Force; (2) „3 vzorky SQL“ platí pro Intermediate a Final, Original má 21 toků SQL; (3) s. 5 je strana PDF, ve sborníku je to s. 11. |
| RQ5-005 | OK | Tab. I: 5 499 / 5 109 / 1 742 toků. Tab. II: F1 0,98 / 0,98 / 0,99. Citace IV-B doslovně. |
| RQ5-006 | DROBNÁ | 98 % doslovně v Sekci 3.2. Zdroj ale neříká, jakým klasifikátorem výsledku dosáhl, takže „jednoduchý klasifikátor“ je inference. Pole limity cituje Sekci 5.2, která se týká heuristických měr, ne tohoto výsledku. |
| RQ5-007 | OK | Tab. 2: LUCID 0,997, BL 0,997, BL (C) 1,000; citace doslovně. |
| RQ5-008 | DROBNÁ | 6 % → 1,5 % doslovně v Sekci 3.3 (Tab. 4: ADA 0,8804 → 0,8350, Base 0,82). Limit „jen jedna konfigurace“ autoři neuvádějí. |
| RQ5-009 | OK | Sekce 5.1 doslovně (0,00013 %). |
| RQ5-011 | OK | Sekce 5.1: 97,8 % „related to“ nmap scan; ToN-IoT 55 % a 28 % DNS. |
| RQ5-012 | OK | Sekce 5.2 (Mislabelled) doslovně, přibližně 20 %. |
| RQ5-013 | OK | Tab. 5: 0,722 / 0,000 / 0,130, průměr 0,282; 1 344 / 1 366 / 1 337 toků; ACM CCS '22. |
| RQ5-014 | DROBNÁ | Hodnoty jsou správně (Tab. 4: 1,000 → 0,000). Citace je ale z textu Sekce 7.3, ne z Tab. 4. |
| RQ5-015 | OK | Sekce 7.4 doslovně (F1 0,990). |
| RQ5-016 | OK | Sekce 3: 79 / 177 (45 %), 43 FA. |
| RQ5-017 | OK | Sekce 6.2: 76 / 18 / 32 / 25 při 100 FA. |
| RQ5-018 | DROBNÁ | Tab. 12: 7/36 (S), 1/2 (C) sedí. Chybí podmínka „at 100 false alarms“. 81 % (29/36) je výpočet extraktora, ne údaj autorů. URL vede na TR CS-2003-02 (verze RAID 2003 nebyla porovnána). |
| RQ5-019 | DROBNÁ | Hodnoty jsou správně (Tab. I: 78,05 / 93,32 %; Tab. II: 75,15 / 88,26 %). Umístění tabulek bez čísla a sekce, správně „Sekce IV-A, Tab. I a II“. |
| RQ5-020 | OK | Úvod doslovně: „21 learned machines (7 learners, each trained 3 times …)“, 98 % a 86 %. |
| RQ5-021 | OK | Sekce 4.3 doslovně; Sekce 4.1: 292 367 z 17 433 324 390 událostí. |
| RQ5-022 | DROBNÁ | Slajd 9/27 sedí (40 %, 4,22 %, 28,24 %, 1,6 %). Metadata jsou neúplná: jde o recenzovaný článek CSET '25, ve sborníku 2025 ACSAC Workshops, s. 551–561, DOI 10.1109/ACSACW69556.2025.00064 (Crossref). Plný text je na HAL (hal-05474126), automatické stažení blokuje ochrana proti botům. Opravit pole recenzovano („ano“) a venue. |
| RQ5-023 | **VĚCNÁ** | Hodnoty GAE sedí (obraz slajdu 21/27): klient 201 0,52 / 0,24, klient 501 0,38 / 0,60, klient 051 0,14 / 0,13. Chybná je poznámka, kterou přidala revize. F1 0,23 patří detektoru Flash u **klienta 201** se štítky Flash, ne u klienta 051. Flash u klienta 051 se štítky Flash má F1 **0,24**. Pole metoda „GAE, 3 sady štítků“ je také chybně: GAE je vyhodnocen jen se 2 sadami (Nikulshin & Tahli, Ours), tři sady má jen Flash. |
| RQ5-024 | OK | Tab. 5 (obraz): Pikachu AUC 78,28 ± 0,43 (rep. 94), Euler AP 0,02 (rep. 5,23), Argus AP 0,09 ± 0,04 (rep. 32,27). |
| RQ5-025 | OK | Tab. 6 (obraz): Argus AUC 43,23 ± 3,05 / 79,75, AP 0,01 / 3,36, publikováno 99,7 / 80,74. |
| RQ5-026 | OK | Tab. 2: AUC 0,9300, AP 0,0240; citace doslovně. |
| RQ5-027 | OK | Sekce 3: 90 % a 73 %; alfa 0,832; 22 %; 4 NIDS práce. |
| RQ5-028 | OK | Tab. 5: 0,968 / 0,882 vs 0,998 / 0,996. |
| RQ5-030 | OK | P8 doslovně. |
| RQ5-031 | OK | Tab. 1 (obraz): 10-fold 0,91 / 0,83, realistic 0,58 / 0,32. |
| RQ5-032 | DROBNÁ | Všech 8 hodnot a jejich mapování na sloupce ověřeno obrazem. Mapování v hodnotě i poznámce je správné. Umístění „s. 4“ neodpovídá, v arXiv verzi je Tab. 1 na s. 5. |
| RQ5-033 | OK | Popisek Obr. 5 a Sekce 4.4: ALG1 0,58, ALG2 0,32, DL 0,64. |
| RQ5-034 | OK | Sekce 4.1: 94,63 / 29,35 / 10,83 / 40,24 %, 9 z 16. |
| RQ5-035 | OK | Tab. 2 a Tab. 4, Extra Tree (obraz): 84,62; 0,14; 0,57; 91,73; 94,83; minimum 0,00 (ToN → UNSW). Abstrakt „high degree of asymmetry“. |
| RQ5-036 | OK | Sekce VII (ve zdroji středník místo čárky), F1 99,1 %, 38 %, obnovení na 99 %. |
| RQ5-037 | DROBNÁ | −25,63 % accuracy, −30,45 % AUROC a −27,13 % pro PCA sedí. Hodnoty −17,85 % a −37,49 % ale nejsou průměry modelů. Jde o nejlepší a nejhorší jednotlivý běh, oba s tréninkem na CIC-2018 (Sekce 5.2). Průměry modelů jsou OC-SVM −25,89 % (Sekce 4.4) a autoenkodér −35,84 % (Sekce 4.3). Ve `studie.md` (b) je proto formulace „−17,9 až −37,5 % podle modelu“ nepřesná. |
| RQ5-038 | OK | Sekce 5.8 a 5.9: −0,0093; 0,5577 vs 0,8296. |
| RQ5-039 | OK | Abstrakt doslovně (96× až 435×). |
| RQ5-040 | DROBNÁ | Citace doslovně (Sekce 5.2), roky 2017–2021 sedí. Pole limity_autoru „malý vzorek praktiků“ není limita uvedená autory. |
| RQ5-041 | **VĚCNÁ** | 90 % i citace v Sekci 5.3 sedí, Tab. 3 uvádí „Stat. Sign. 0 % 10 % 90 %“. Podmínka „n = 12“ je ale chybná a poznámka o „vnitřní nekonzistenci zdroje“ je nepravdivá. Appendix B.3: „two respondents skipped the "Stat. Sign." question in P3“, takže n = 10 a 90 % = 9/10. Tuto poznámku zanesla revize a propsala se do `studie.md` (Z-9 a tabulka (e)). |
| RQ5-042 | OK | Sekce 5.2 doslovně (43 %, 80 %). |
| RQ5-043 | OK | Tab. 5 (obraz): GCUT DG 1,00, AR 1,00; WWT DG 0,80, AR 0,80. |
| RQ5-044 | DROBNÁ | Citace ze Sekce 6.2 sedí. „Downstream metrics“ ale odkazují na předchozí práci [35], autoři je pod DP sami neměřili. |
| RQ5-045 | OK | Tab. 3 (0,0001–0,0004) a Tab. 4 (14,08 / 0,07 / 99,77 / 92,57); citace pod Tab. 4. |
| RQ5-046 | DROBNÁ | Hodnoty sedí (obraz Tab. 1 a 3: 0,396 / 0,140 vs 0,86 / 0,648; JSD 0,16). DOI 10.1145/3652963.3655071 je ale podle Crossrefu jen dvoustránkový abstrakt (SIGMETRICS 2024, s. 85–86). Plný článek je POMACS 8(1), s. 1–32, DOI 10.1145/3639037 (ověřeno v Crossrefu). Totéž platí pro 047. |
| RQ5-047 | **VĚCNÁ** | Hodnoty 0,738 (DT) a 0,262 (DT) patří v Tab. 4 (obraz, s. 15) řádku Synthetic/Real, NetDiffusion, post-gen. heuristika **„Not Used“**. Řádek **„Used“** má 0,676 (DT) a 0,222 (DT). Podmínka „s post-gen. heuristikou“ a umístění „řádek NetDiffusion (Used)“ jsou proto chybné. Oprava: podmínka „bez post-gen. heuristiky“. S heuristikou je pokles 32,4 a 75,6 p. b. Údaj „26–72 p. b. i u nejlepší konfigurace“ ve studii zůstává platný. Real/real 1,00 a 0,978 (SVM) sedí. |
| RQ5-048 | DROBNÁ | Citace na stránce SEI existuje doslovně, ale jde o prezentaci z FloCon 2023 (6. 2. 2023), ne o abstrakt SIGCOMM. Recenzovaný je článek SIGCOMM 2022, s. 458–472, DOI 10.1145/3544216.3544251. Plný text je podle OpenAlex hybrid OA, „nedostupný“ tedy platí jen pro curl. |
| RQ5-049 | OK | Sekce 2.2 a 7.2 doslovně, včetně výjimky REaLTabFormer. |
| RQ5-050 | OK | Abstrakt a hlavička „Accepted at Machine Learning for CyberSecurity @ ECML PKDD 2024“. Uvnitř řádku drobný rozpor: `riziko_zkreseni` stále uvádí „preprint“. |
| RQ5-051 | DROBNÁ | Čísla i citace v Sekci VI-B sedí. „Per krok 0,05 % až 10 %“ ale podává jako rozpětí dva příklady (attemptRead 0,05 %, attemptConnectToApplications 10 %). Zdroj minimum ani maximum neuvádí. Totéž platí pro „0,05–17 %“ ve `studie.md` (c) a Z-10. Šum 1 % v simulátoru je současně FP i FN rate. |
| RQ5-052 | **VĚCNÁ** | Hodnoty −80 / −101 / −109 % (Guided) a −5 / −11 / −14 % (Exploratory) sedí (Sekce V-C). Poznámka „Benigní uživatelé dominují výsledku víc než útočník“ ale zdroji přímo odporuje: „The choice of Lore's policy, being either "Guided" or "Exploratory" was the most significant variable affecting the returns of all agents.“ Vliv uživatelů nebyl významný pro (Heuristic, Exploratory) ani pro (Vejde w/ Noise, Exploratory). Chybná interpretace se propsala do `studie.md`, sekce „Co z literatury odpovídá našim číslům“ („benigní aktivita dominuje nákladům“). |
| RQ5-053 | **VĚCNÁ** | Hodnoty jsou správně: Trace AUROC 0,868–0,997 při AP ≤ 0,062; FiveDirections 0,666–0,943 při AP 0,002–0,007; Theia Magic 0,976 / 0,088, Theseus 0,994 / 0,551; allowlist nejlepší F1 a MCC na všech 4 datasetech. Metadata jsou ale chybně. arXiv v4 (12. 10. 2026) má na první straně „Network and Distributed System Security (NDSS) Symposium 2027 … doi 10.14722/ndss.2027.230448“. Venue má být NDSS 2027 a recenzovano „ano“, ne „arXiv preprint / ne“. Tím padá zdůvodnění Z-7 „všechny zdroje jsou nerecenzované preprinty“ a 053 je třeba vyřadit ze seznamu preprintů v Hrozbách validity. Chyba je konzervativní, jistotu nenadsazuje. |
| RQ5-054 | DROBNÁ | Obrazově sedí: OilRig ARGUS 0,942 / FPR 0,115 / P 0,030, EULER 0,951 / 0,070 / 0,048; Sandworm ARGUS P 0,010; 528 vs 1 529 202. Citace „despite a high TPR …“ je ale v Sekci 4, ne v Sekci 5 (Related Work). Tvrzení „zdroj vztah nevysvětluje“ je přísné: Sekce 4 definuje TP a FP na úrovni hran, kdežto 528 a 1 529 202 jsou počty událostí. |
| RQ5-055 | OK | Sekce 5.3: 66 % při FPR řádu 1 × 10⁻⁵ a 58 % při detekci 0,7. |
| RQ5-057 | OK | Crossref: Computers & Security 156, 104510 (2025), titul a autoři sedí. Sekce 5.5.2: 17 %, 19 %, 13,7 %, 71 %. |
| RQ5-058 | OK | Sekce 5.4 doslovně (29 %). |
| RQ5-060 | DROBNÁ | 21 978 630 → 18 902 360 (14,0 %) a duplicity u NF-ToN-IoT sedí. Rozsah „všechny verze“ u provozu s routerem a DNS (192.168.1.1) ale zdroj neuvádí. „In all datasets“ se týká provozu mířícího mimo testovací síť. Bot-IoT autoři nezkoumali, je jen zmíněn v úvodu. |
| RQ5-061 | OK | Abstrakt (15 vlastností, 5 kategorií), Sekce VII doslovně, 34 datasetů. 10-fold CV „makes only limited sense“ (poznámka to zjednodušuje na „nevhodné“). |
| RQ5-062 | OK | V2 je pravdivé, abstrakt (HAL, Semantic Scholar) bez čísel, CRiSIS 2022, LNCS 13857. Plný text je na HAL (hal-03775466, CC-BY), blokuje jen automatické stažení. Přes prohlížeč lze řádek zpřesnit. |
| RQ5-063 | OK | V2 je pravdivé, abstrakt sedí, IEEE CNS 2022, s. 254–262. Volný plný text nenalezen. |

## Chybovost

- Ověřeno 59 řádků, NEOVĚŘITELNÉ 0 (0 %).
- OK 38, DROBNÁ CHYBA 16, VĚCNÁ CHYBA 5 (023, 041, 047, 052, 053).
- **Věcná chybovost 5 / 59 = 8,5 %** (95% Wilsonův interval 3,7–18,4 %).
- **Podle typu pole:** chybné číslo v poli `hodnota` 0 / 59. Chybná konfigurace nebo n v podmínkách 2 (041, 047). Chybné tvrzení v poznámce nebo metodě 2 (023, 052). Chybná venue nebo recenzovanost 1 (053).
- **Podle skupiny:**
  - 26 řádků změněných revizí: 5 věcných chyb (19 %),
  - 7 řádků, které dřív nikdo nekontroloval a revize je neměnila (008, 009, 011, 021, 033, 048, 061): 0 věcných,
  - 26 ostatních řádků: 0 věcných.
- **Vzorec chyb:** po revizi už nejsou chyby v číslech. Zbývají v textu kolem čísel: v podmínkách, poznámkách a metadatech. Z toho dvě chyby (023, 041) do textu zanesla sama revize.

## Kontrola přepsaných závěrů Z-6a, Z-6b, Z-7 a H-1

- **Z-6a (vysoká). OK.** Opírá se o řádky 030 a 055, oba jsem ověřil (P8 doslovně, Axelsson Sekce 5.3). Tvrzení je aritmetické a jistota „vysoká“ odpovídá důkazům.
- **Z-6b (nízká). OK.** Čísla ALG2 0,30 → 0,96 a 0,32 → 0,33 a rozdíl 0,33–0,51 jsem ověřil obrazem Tab. 1. Podmíněná formulace odpovídá zdroji a nízká jistota je přiměřená.
- **Z-7 (střední). Čísla jsou správně, zdůvodnění je chybné.** „Všechny zdroje jsou nerecenzované preprinty“ neplatí, protože 053 je NDSS 2027. Jistota „střední“ může zůstat kvůli nekonzistenci (protipříklad Theia) a jedné skupině zdrojů. Opravit sloupec „důvody snížení“ a Hrozby validity. Formulace „054 jen nepřímo: precision 0,03–0,05“ sedí (ARGUS 0,030, EULER 0,048).
- **H-1. Odpovídá kódu, viz S1 níže.** Výběr osmi rodin s externím cílem odpovídá `traffic.rs:741–752`. Negativní kontrola (ssh_bruteforce, credential_stuffing, web_exploit, ddos_volume) je správně: SshBrute nemá interního útočníka (`traffic.rs:632–641`), takže útočník je vždy externí z `public_ip()`. DDoS a credential stuffing berou zdroje z `public_ip()` (`traffic.rs:1523`, `1880`). Velikosti efektu jsou správně označené jako odhad autora. Výhrady nemám.

## Kód soaku: S1, S2 a sporný bod „12 pevných adres“

Kontrolováno proti `src/soak/` v HEAD (`a293d2b`). Pracovní kopie `src/soak` je čistá (`git status` beze změn).

| # | výsledek | nález |
|---|---|---|
| S1, „12 pevných adres na síť“ | **SEDÍ** | `netmodel.rs:825–835`: `externals` = 12 adres z oktetů {34, 52, 104, 142, 185, 203, 13}, generované uvnitř `NetworkModel::generate` (`netmodel.rs:678`). Episode volá `generate` jednou na síť (`episode.rs:240`) a `externals` se nikde nemění: v `src/soak` je jen čtení na `traffic.rs:997, 1119, 2253`. `Rng::range` je včetně horní meze (`rng.rs:39–45`), takže se vybírá ze všech 12. Adresy se losují s opakováním, takže je jich nejvýš 12, což je zanedbatelné. Formulace „12 pevných adres na síť“ je správná a výtka první kontroly („generují se náhodně“) platila jen napůl. |
| S1, které benigní události používají `public_ip()` | **SEDÍ, úplný výčet** | Příchozí: weboví klienti v každém cyklu (`traffic.rs:1095`) a flash crowd (`1794`). Odchozí: software_update (`1816–1819`, cíl z `target_external` = `public_ip()` z `902`), ntp_fanout (`1846`) a patch_window (`2302`, cíl z `902`). Ostatní benigní události (`902` sice nastaví `target_external` všem benigním pravdám, ale nepoužijí ho) jsou čistě interní: backup, authorized_scanner, onboarding, batch_job, collector_replay. Retry storm používá `externals`. Pevné řetězce IP jsou v `traffic.rs` jen v testech (2564–2664). Běžný provoz: 18 % toků každého neserverového zařízení míří na `externals:443` (`995–1001`). DNS jde na interní DNS (`1054–1081`), externí resolver v kódu není. Studie i abstrakt bod 6 to popisují správně. Drobnost: „stanice na 443“ ve skutečnosti znamená všechna neserverová zařízení, nejen workstation. |
| S1, útočné užití | SEDÍ | `public_ip()` pro externího útočníka (`661`), externí cíl osmi rodin (`741–752`), DDoS (`1523`) a credential stuffing (`1880`). Útoky `externals` nepoužívají. Sady oktetů jsou disjunktní. |
| S2 | **SEDÍ** | Uzávěr `alert` (`traffic.rs:1249–1260`) je jediné místo s `out.alerts.push(eve_line(…))`. Všech 13 volání je pod `if truth.ids_visible` (1329, 1373, 1454, 1501, 1545, 1674, 1897, 1938, 1973, 2047, 2087, 2126, 2184). Benigní pravdy mají `ids_visible: false` (`903`). Jediný další zápis do `alerts` je `log_corruption` (`2391–2399`) s neplatnými řádky. Řádek 2593 je testovací fixture útoku a ze studie byl správně vyřazen. |
| S5, stav kódu | **ZASTARALÉ ve studii** | Studie (Metodika, S5, Hrozby validity) i revize uvádějí, že `mentions_ip` a zkrácené okno lookalike událostí jsou „jen v necommitnuté pracovní kopii“. Změna je ale commitnutá v `a293d2b` (2026-10-31 23:40 +0100, „fix(soak): presne porovnani IP … okno provoznich udalosti“) a ve stejném commitu je i tato verze `studie.md`. Běh v2 začal v 18:57 SEČ (`status.md`) a byl postaven před tímto commitem. Formulaci je třeba aktualizovat: změna je v `a293d2b`, běh v2 ji s velkou pravděpodobností nemá (spuštěn přes 4 h před commitem, status má commit `unknown`). Čísla lookalike podílů z v2 proto patří ke staré atribuci. Řádky `episode.rs:52, 164, 187, 710–711, 1101` sedí. |

## Kontrola 5 náhodných tvrzení z tabulky Závěry

Vybrány Z-1, Z-5, Z-7, Z-9 a Z-10.

- **Z-1 (vysoká).** Odpovídá řádkům 001, 002, 019, 022 a 060. Rozdělení podle jednotek je správně. U 060 se „odfiltrované toky (ToN-IoT přibližně 14 %)“ týkají filtrace provozu mimo síť i chybně štítkovaného provozu, v pořádku. 022 je recenzovaný článek (ACSAC Workshops 2025), takže důkaz je silnější, než studie uvádí. Bez přesazení.
- **Z-5 (střední).** „TSTR ztrácí 20–72 p. b.“: dolní mez 20 pochází z DoppelGANger („80 % of the real data accuracy“), což je relativní pokles, ne procentní body. Abstrakt správně uvádí 26–72 p. b. (047). Sjednotit na „26–72 p. b. (NetDiffusion) a 20 % relativně (DoppelGANger)“. Rank korelace „AR 1,00 na GCUT“ sedí. Bez přesazení.
- **Z-7 (střední).** Čísla sedí, zdůvodnění „nerecenzované preprinty“ je chybné (053 = NDSS 2027). Je to podhodnocení, ne přesazení.
- **Z-9 (střední).** Tvrzení „uvedených 90 % neodpovídá celému počtu“ je nepravdivé (n = 10, 9/10). Odstranit také v tabulce (e). Jistota může zůstat střední.
- **Z-10 (nízká).** „Falešné alerty nerovnoměrné (0,05–17 %)“ podává dva příklady jako rozpětí. Navazující text v sekci „Co z literatury odpovídá našim číslům“ („benigní aktivita dominuje nákladům“) přesahuje zdroj: podle ANOVA je hlavním faktorem politika útočníka. Jistota „nízká“ je přiměřená, přesazená je jen formulace mimo tabulku Závěry.

Přesazení jistoty (jistota vyšší než důkaz) jsem v tabulce Závěry nenašel. Našel jsem jedno podhodnocení (Z-7) a dvě nepřesné formulace (Z-5, Z-9).

## Nutné opravy

**Extrakce (`extrakce.csv`)**

1. **RQ5-023.** Poznámka: „Hodnota 0,23 patří detektoru Flash u klienta 201 se štítky Flash; Flash u klienta 051 se štítky Flash má 0,24.“ Metoda: „GAE se 2 sadami štítků (Nikulshin & Tahli, vlastní); Flash se 3“.
2. **RQ5-041.** Podmínky: „n = 10 (2 z 12 respondentů otázku vynechali, App. B.3)“. Poznámku o nekonzistenci odstranit, 90 % = 9/10.
3. **RQ5-047.** Podmínky: „bez post-gen. heuristiky (Not Used)“. Umístění: „Tab. 4, Synthetic/Real, NetDiffusion, Not Used“. Volitelně doplnit: s heuristikou (Used) 0,676 a 0,222 (pokles 32,4 a 75,6 p. b.). Venue jako u 046.
4. **RQ5-052.** Poznámku nahradit: „Uživatelé snížili výnosy všech agentů, hlavním faktorem však byla politika útočníka (ANOVA, Sekce V-C); proti Exploratory nebyl vliv uživatelů vždy významný.“
5. **RQ5-053.** Venue: „NDSS 2027 (DOI 10.14722/ndss.2027.230448; čten arXiv v4)“. Recenzovano: „ano“.
6. **Drobné opravy:**
   - 004: hvězdička jen u Heartbleed, XSS, SQL a Infiltration; SQL Original 21 toků.
   - 006: klasifikátor neuveden; limity.
   - 008: limity.
   - 014: umístění Sekce 7.3 + Tab. 4.
   - 018: „při 100 FA“; 81 % je odhad autora.
   - 019: umístění Tab. I a II, Sekce IV-A.
   - 022: venue ACSAC Workshops 2025, DOI 10.1109/ACSACW69556.2025.00064, recenzovano „ano“.
   - 032: Tab. 1 na s. 5.
   - 037: −17,85 % a −37,49 % jsou jednotlivé běhy (trénink na CIC-2018); průměry modelů jsou OC-SVM −25,89 % a AE −35,84 %.
   - 040: limity.
   - 044: „downstream metriky z předchozí práce [35]“.
   - 046 a 047: DOI plného článku 10.1145/3639037 (POMACS 8(1)).
   - 048: zdroj citace je prezentace FloCon 2023; článek SIGCOMM 2022, DOI 10.1145/3544216.3544251.
   - 050: `riziko_zkreseni` bez „preprint“.
   - 051: 0,05 % a 10 % jsou příklady, ne rozpětí.
   - 054: citace je ze Sekce 4.
   - 060: „všechny verze“ jen u provozu mimo síť.

**Studie (`studie.md`)**

7. Z-7, sloupec důvody: „zdroje jsou preprinty kromě 053 (NDSS 2027)“. Hrozby validity, Preprinty: vyřadit 053.
8. Z-9 a tabulka (e): odstranit „90 % neodpovídá celému počtu“, nahradit „90 % z 10 odpovídajících“.
9. Sekce „Co z literatury odpovídá našim číslům“, bod Provozní události: nahradit „benigní aktivita dominuje nákladům“ formulací podle opravy 052.
10. Tabulka (b), Verkerken: „−17,9 až −37,5 % (nejlepší a nejhorší jednotlivý běh); průměry modelů −25,9 až −35,8 %“.
11. Z-5: „TSTR ztrácí 26–72 p. b. (NetDiffusion), DoppelGANger 20 % relativně“.
12. Tabulka (c) a Z-10, Nyberg: „např. 0,05 % až 10 % (bez uživatelů) a 17 % (s uživateli) u jednotlivých kroků“.
13. Metodika, S5 a Hrozby validity: změna atribuce je commitnutá v `a293d2b` (23:40), běh v2 (start 18:57) ji s velkou pravděpodobností nemá.
14. Volitelně: u 022 a 062 doplnit, že plný text existuje na HAL (ruční stažení), a zpřesnit.

## Pět nejzávažnějších zjištění

1. **RQ5-041.** n = 10, ne 12. „Vnitřní nekonzistence zdroje“ neexistuje. Chybu zanesla revize (na podnět první kontroly) a propsala se do Z-9 a tabulky (e).
2. **RQ5-053** je recenzovaný článek NDSS 2027, ne preprint. Zdůvodnění Z-7 a seznam preprintů v Hrozbách validity jsou chybné. Chyba je konzervativní.
3. **RQ5-047.** Hodnoty 0,738 a 0,262 patří konfiguraci bez post-gen. heuristiky, ne s ní. Závěr „26–72 p. b. i u nejlepší konfigurace“ přesto platí.
4. **RQ5-052.** Poznámka „uživatelé dominují víc než útočník“ odporuje zdroji (hlavní faktor je politika útočníka) a propsala se do sekce o soaku.
5. **Vlastní kontrola revize (0 / 47) chyby nezachytila.** Čtyři z pěti věcných chyb jsou v řádcích jejího vzorku. Opravná poznámka u 023 přiřazuje hodnotu 0,23 špatnému klientovi. Poznámka studie, že atribuce je „necommitnutá“, je zastaralá: změna je v `a293d2b`.

Kód soaku: S1 (včetně „12 pevných adres na síť“ a úplného výčtu benigních užití `public_ip()`), S2 a H-1 odpovídají kódu.
