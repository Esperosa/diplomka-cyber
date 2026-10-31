# Studie 04: syntéza dat, datová intuice a dedukce/abdukce ve Skákavce

Stav: 2026-10-31. Autor: výzkumná studie (bez zásahu do kódu). Čísla o Skákavce pocházejí z `docs/diplomka/eval/soak-findings.md` (soak v1, 15 664 sítí) a z průběžného `F:\bakula-soak\run-v2-72h\status.md` (566 sítí, 3,5 h, čteno jen pro čtení). Jsou to výsledky simulace, ne měření živých sítí.
Hranice: o kódu, rešerši FP a pokrytí útoků píší jiné studie ve stejném adresáři; tady je jen odkazuji (viz kapitola Odkazy na ostatní studie).
Poctivost zdrojů: u každého tvrzení je URL a rok. Co jsem nečetl celé (jen abstrakt/výsledek vyhledávání), je označeno „nečteno celé“. Co je moje úvaha bez zdroje, je označeno „odhad“ nebo „úvaha“.

---

## Shrnutí (15 řádků)

1. Největší problém Skákavky v datech soaku není slabý model, ale (a) 211 až 1 108 falešných nálezů na síť-den, (b) provozní události (patch, pád senzoru, záloha, replay kolektoru) jsou pro engine „útok“ (v2: patch_window 99 %, collector_replay 97 %, log_corruption 95 %, sensor_crash 93 % s falešným nálezem) a (c) špatná kalibrace.
2. Největší páka je proto DEDUKCE/ABDUKCE nad kontextem („vysvětli pozorování nejlepší benigní hypotézou dřív, než ji vydáš jako útok“), ne nový generativní model. Je to levné, bez GPU, vysvětlitelné a v Rustu hotové (crate `ascent`).
3. Druhá páka je kalibrace pravděpodobností (isotonická regrese + konformální práh) učená na simulaci a korigovaná na malé reálné kotvě. Přínos je spolehlivý, ale jen tak poctivý, jak poctivá je kotva.
4. Třetí páka jsou peer-group baseline podle typu zařízení (`classifyHost` / role v simulaci). Fakt „zařízení stejného typu se chovají podobně“ je v literatuře o MUD profilech dobře podložen (nepřímo, viz 2.2), a řeší cold-start.
5. Generativní modely provozu (NetShare, DoppelGANger, NetDiffusion) a síťové foundation modely (ET-BERT, netFound, YaTC) NEDOPORUČUJI v první vlně: vyžadují GPU, jsou vyvíjeny pro jiné úlohy (klasifikace šifrovaného provozu, generování hlaviček), mají doložené slabiny (periodicita, mód kolaps, bez payloadu) a hlavně by přidaly další vrstvu cirkularity.
6. Cirkularita (testuji detektor na datech, která jsem napsal) je největší metodické riziko studie. Z literatury: modely NIDS se po přenosu mezi datasety často hroutí k náhodě (Layeghy 2022, Cantone 2024), takže i výsledek „na simulátoru skvělé“ nic nedokazuje. Opatření: held-out rodiny, nezávislý druhý generátor, slepý test, kotva CTU-13/IoT-23, předregistrace.
7. LLM je vhodný jako triážní sumarizátor a navrhovatel dalších kontrol, ne jako zdroj pravdy; benchmarky ukazují, že agenti minou ≥ 40 % útočných alertů (Alert-Bench, 2026, nečteno celé). V designu musí být za strukturovaným výstupem a ověřením nástrojem.
8. Doporučená 3 (pořadí): (1) abdukční/dedukční vrstva „benigní vysvětlení + nesmysl detektory“ v `ascent`, (2) kalibrace (isotonic + conformal) s reálnou kotvou, (3) peer-group baseline + soft priors (KEV/EPSS, ATT&CK) pro cold-start.
9. Nedoporučená 3: (1) vlastní GAN/difuzní generátor provozu, (2) předtrénovaný síťový transformer (netFound/ET-BERT) jako detektor, (3) plná Markov Logic / ProbLog inference v produkčním jádru a LLM jako rozhodčí.
10. Odhady přínosu (označené „odhad“, žádné nejsou změřené): z reportu v2 plyne, že jen asi 7 % behaviorálních FP (385 711 z 5 302 629) je přiřaditelných benigním událostem, takže abdukce událostí sama sníží celkové FP jen o jednotky procent; hlavní FP (`unexpected_traffic`, `inductive_volume_anomaly`) vznikají z prahů a baseline, kam míří peer-group a kalibrace. Peer-group pomůže C2/rogue jen okrajově (telemetrie je neukáže).
11. Pozor: C2 beacon 4,7 % a rogue device 0,2 % jsou převážně problém pokrytí a signálu, ne usuzování. Dedukce umí „rogue = zařízení, které není v inventáři, ale mluví“, což je přesně přístup logický, ne statistický (viz 3.5).
12. Ověření: vše v soak harnessu párově na stejných semenech (A/B s a bez vrstvy), s Wilsonovými intervaly, předem zmrazenými pravidly a held-out rodinami.
13. Nejistoty: nejsou veřejně srovnatelná čísla pro „abdukci v NIDS“; většina odkazů je z let 2014 až 2016 (forenzní BN) a modernější důkaz chybí. Vlastní odhady přínosu proto nesou velkou nejistotu.
14. Doporučení k diplomce: napsat to jako experiment s předregistrovaným plánem a negativním výsledkem jako přijatelným výstupem.
15. Žádný kód nebyl změněn.

---

## 0. Východisko: co z dat soaku plyne (a co ne)

| Pozorování | Zdroj | Co to naznačuje o řešení |
|---|---|---|
| 210,7 FP/síť-den (v1), 1 108 (v2, 20 síť-dnů bez útoku v bloku) | soak-findings, status v2 | Potřebujeme filtr „je to vysvětlitelné benigně?“ |
| FP podle typu: `unexpected_traffic` 2,46 M, `inductive_volume_anomaly` 1,94 M, `packet_rate_spike` 0,53 M | status v2 | Objemové detektory bez kontextu |
| Benigní lookalike s FP: batch_job 86 %, backup_burst 75 %, flash_crowd 80 %, authorized_scanner 44 %, patch_window 99 %, service_crash 92 %, sensor_crash 93 %, collector_replay 97 %, log_corruption 95 % | status v2 | Abdukce s kontextem události |
| retry_storm 0 %, software_update 0 %, onboarding 1,6 % | status v2 | Co už engine umí (nesahat) |
| Kalibrace: p ≥ 0,6 podkonfidentní (0,75 → 0,996), p 0,1 až 0,5 překonfidentní (0,43 → 0,21) | soak-findings | Monotónní přemapování (isotonic) |
| C2 4,7 % (v1), 12,5 % (v2), rogue 0,2 % → 7,4 % | oba | Signál/pokrytí; dedukce pomůže jen u rogue |
| exploit_attempt: nikdy správný typ (typ `suricata_alert` se nevydává) | soak-findings | Chyba typování, ne usuzování (mapování Suricata SID → ATT&CK) |
| Rozpočet kontrol: 68 % plánů mimo rozpočet | soak-findings | EVOI musí upřednostnit kontroly s vysokou informační hodnotou |
| Identita: falešné rozdělení 8,7 % při churn | soak-findings | Konzistenční kontroly identity (kap. 3) |
| Case Memory: Brier 0,0107 vs. 0,25 naivně | soak-findings | Silný, ale na simulátoru (viz kap. 1.5) |

Důležité: Brier 0,0107 je na označených datech, která generuje stejný simulátor, a podstatná část hypotéz je téměř deterministická (ddos, dns_tunnel ~100 %). Číslo nelze číst jako „model je dobrý“ (úvaha; k tomu viz Arp 2022, kap. 1.5).

---

## 1. Syntetická data

### 1.1 Co to je a co říká literatura

Simulace s ground truth je v zásadě „generátor označených dat“. Literatura rozlišuje tři způsoby: (a) mechanistická simulace (to je `src/soak`), (b) učené generátory provozu (GAN, difuze, transformer), (c) augmentace reálných dat.

**Učené generátory provozu.**
- NetShare (SIGCOMM 2022): GAN pro hlavičky paketů/toky, rozdělení trasy na časové bloky, kódování IP bitově a portů přes IP2Vec; autoři hlásí o 46 % přesnější distribuční metriky než baseline. Nezahrnuje payload. Zdroj: https://par.nsf.gov/servlets/purl/10406016 (2022) a shrnutí na https://github.com/annuszulfiqar2021/NetShare (repo).
- Kritika: práce CascadeNet (NSDI 2026) uvádí, že NetShare se učí periodický vzor, který odporuje realitě v časovém chování rychlosti paketů; autoři CascadeNet hlásí 41 až 76 % zlepšení v časových metrikách při srovnatelné statistické věrnosti. To je tvrzení autorů konkurenčního modelu, ověřit nezávisle. Zdroj: https://www.usenix.org/system/files/nsdi26_slides-lu-runwei.pdf (2026, jen slidy).
- NetDiffusion (Jiang et al., SIGMETRICS 2024): řízená varianta Stable Diffusion s doladěním protokolové shody po generování. Zdroj: https://ar5iv.labs.arxiv.org/html/2310.08543 (2023/2024). NetDiffus (jiná práce, 2023) převádí časové řady na obrázky: https://arxiv.org/abs/2310.04429.
- Přehled omezení: mód kolaps, dlouhé časové závislosti, chybějící payload, ignorování shody s protokolem; empiricky smíšené (GAN typu CTGAN vs. Bayesovské sítě). Zdroje: https://arxiv.org/pdf/2507.01976 (přehled, 2025) a https://arxiv.org/html/2410.16326v2 (srovnání, 2024); obojí jsem četl jen v souhrnu.
- DoppelGANger (IMC 2020, Lin et al.) je předchůdce NetShare pro časové řady s metadaty; neověřoval jsem jeho URL v této rešerši (arXiv 1909.13403 podle mé paměti; nečteno).

**Sim-to-real.** Teorie domain randomization (Chen et al., ICLR 2022) formalizuje mezeru simulace–realita a ukazuje, že potřebné je, aby randomizované prostředí „pokrývalo“ realitu; v praxi vyžaduje expertní nastavení rozsahů a několik desítek reálných epizod výrazně zlepší výsledek (podle nalezeného souhrnu, nečteno celé). Zdroje: https://arxiv.org/abs/2110.03239 (2021/2022), https://research.nu.edu.kz/ru/publications/efficient-sim-to-real-transfer-in-reinforcement-learning-through-/ (nečteno celé). Pro kybernetickou oblast jsem v rešerši nenašel přímo aplikovaný zdroj; tvrzení o přenosu do NIDS přebírám jen jako analogii (úvaha).

**Přenos mezi datasety v NIDS (hlavní varování).**
- Layeghy & Portmann (2022): žádný ze sedmi modelů negeneralizoval přes všechny čtyři benchmarky, asymetrie mezi směry přenosu. https://arxiv.org/abs/2205.04112
- Cantone et al. (2024): při křížovém testu mezi CIC-IDS-2017, CSE-CIC-IDS2018 a LycoS je přesnost ve většině kombinací blízká náhodě. https://katalog.lib.cas.cz/KNAV/EdsRecord/edsarx,edsarx.2402.10974 (zprostředkováno katalogem; nečteno celé)
- Arp et al. (USENIX Security 2022): katalog 10 záludností ML v bezpečnosti (např. sampling bias, data snooping, spurious correlations, label inaccuracy, test na nerealistickém prostředí). https://arxiv.org/pdf/2010.09470
- Přehled 2026 o NetFlow IDS: benchmarkové výsledky bývají nafouknuté (normalizace přes train/test, náhodné dělení); nový benchmark MAWIFlow z reálného provozu 2011–2021. https://arxiv.org/pdf/2602.05594 (nečteno celé)

### 1.2 Přínos a rizika pro Skákavku

Simulátor `src/soak` už je mechanistický generátor s ground truth, takže „syntéza“ je ve Skákavce de facto řešena pro vyhodnocení; zbývá otázka, zda ho smíme používat i k učení (kalibrace, priory).

| Použití | Přínos | Riziko |
|---|---|---|
| Kalibrace pravděpodobností (isotonic) z `soak` | Vysoký (kalibrace je prokazatelně špatná, oprava je levná) | Kalibrace se naučí vlastnosti simulátoru; v reálu může být posunutá |
| Ladění prahů (objemová anomálie) na benigních lookalike | Vysoký | Overfit na „mé“ benigní události (batch_job, backup_burst jsou kódovány mnou) |
| Trénink klasifikátoru typu nálezu | Střední | Leakage: simulátor má artefakty (např. přesné intervaly beaconu) |
| What-if vzácných útoků | Střední | Útok je modelován tak, jak ho chápu já; nevyzkouším neznámé |
| Učený generátor provozu | Nízký–střední | Cena, GPU, a ověření „věrnosti“ by stejně potřebovalo reálná data |

### 1.3 Jak poznat, že simulace „klame“ (kontrola věrnosti)

Konkrétní postup (úvaha, standardní techniky dvouvýběrového testu; žádný jediný zdroj):

1. Ze simulace vyexportovat toky ve formátu stejném jako CTU-13 / IoT-23 (Zeek conn.log: doba trvání, orig/resp bytes, pakety, stav spojení, port, protokol).
2. Pro každou vlastnost (log bytes, trvání, inter-arrival, entropie portů, počet cílů na zdroj za okno) spočítat KS a Wasserstein vzdálenost mezi simulací (benigní podmnožina odpovídajícího typu zařízení) a reálnými benigními toky.
3. Klasifikátor-dvouvýběrový test (C2ST): natrénovat jednoduchý gradient boosting / logistickou regresi, aby rozlišil sim vs. real. AUC blízko 0,5 = nerozlišitelné; AUC 0,95 = simulátor klame. Stačí CPU a malá data. Výsledek je diagnostika, ne důkaz.
4. Tabulka „které vlastnosti rozlišují nejvíc“ (feature importance C2ST) jde přímo jako TODO pro `traffic.rs`.
5. Stejný test provést na „útočných“ tocích (c2_beacon vs. CTU-13 botnet scénáře) a hlásit zvlášť.

Čeho se vyvarovat: dataset CTU-13 pochází z roku 2011 (García et al.; neověřeno v této rešerši) a IoT-23 z let 2018–2019 – je to starší provoz; shoda s nimi neznamená shodu s dnešní sítí (TLS 1.3, QUIC, cloud). Úvaha.

### 1.4 What-if generování a augmentace vzácných útoků

- Pro rekall slabých rodin (C2, cryptomining, rogue) je syntéza užitečná k testu „vidí to detektor, kdybych útok pomalu zavěsil“, tj. parametrické zkoušky (perioda beaconu, jitter, velikost, noc/den). Tohle už simulátor umí; potřeba je systematický sweep parametrů (např. jitter 0 až 50 %, perioda 30 s až 6 h) a křivka detekce vs. parametr.
- Přínos: ukáže, kde je „práh slepoty“, ne že ho zvýší. Zvýšení vyžaduje nový signál (např. periodicita přes týdny, JA3/SNI, DNS).
- Riziko: pokud se rekall zvyšuje ladění na stejné parametry, které simulátor generuje, je to cirkulární (viz 1.6).

### 1.5 Kalibrace a prahy na syntetických datech

- Isotonická regrese: neparametrické monotónní přemapování pravděpodobnosti → empirická frekvence; opravuje právě tvar, který Case Memory vykazuje (podkonfidentní nad 0,6, překonfidentní 0,1–0,5). Standard (Zadrozny & Elkan 2002, Niculescu-Mizil & Caruana 2005; ze znalosti, bez ověření URL).
- Konformální přístup: split conformal dává práh s garancí pokrytí při výměnitelnosti. Při posunu rozdělení (simulace → realita) je potřeba vážení věrohodnostním poměrem: Tibshirani, Barber, Candès, Ramdas, „Conformal Prediction Under Covariate Shift“ (NeurIPS 2019), https://arxiv.org/abs/1904.06019. Pro klasifikaci s driftem posteriorů: Wang & Qiao (AISTATS 2025), https://arxiv.org/pdf/2502.17744. V kontextu IDS: preprint o robustní konformální detekci (2026, nečteno celé, metodicky nezaručeno) https://arxiv.org/pdf/2609.19241 uvádí, že kalibrace na čistém provozu přestane pokrývat při posunu, a vážená varianta bývá nestabilní při silném posunu.
- Moje doporučení (úvaha): dvoustupňová kalibrace. Stupeň 1 isotonic na simulaci po rodinách (včetně held-out), stupeň 2 korekce (posun/šířka) odhadnutá z malé reálné kotvy (CTU-13 + IoT-23 + vlastní reálný provoz správce). Hlásit ECE a reliability diagram zvlášť pro sim a real. Pokud se ECE na real zhorší oproti sim o víc než daná mez, kalibrace se nepoužije.
- Pozor: Case Memory aktualizuje Beta posteriory z výsledků ověřování; kalibrační vrstva by měla být nad ním (post-processing), aby neposouvala ochranu proti otrávení (`case_memory.rs`).

### 1.6 Rizika: leakage, overfitting na simulátor, cirkularita

| Riziko | Příklad ve Skákavce | Mitigace |
|---|---|---|
| Cirkularita | Detektor ladím na rodinách a lookalike, které píše stejný kód | Held-out rodiny, druhý generátor psaný od zadání jiným autorem, slepé skórování |
| Leakage přes semeno/síť | Sítě z jednoho archetypu v train i test | Dělit po sítích a po archetypech, ne po cyklech (Arp 2022: data snooping) |
| Artefakty simulátoru | Přesný interval beaconu, konstantní velikost | C2ST audit (1.3), randomizace s hodnotami z reálných dat |
| Label leakage | `host_key` útočníka se objeví v textu nálezu | Atribuce je už v harnessu popsána; zakázat feature z textu nálezu |
| Kalibrace na stejných sítích jako metrika | ECE se počítá z dat, ze kterých se učila isotonic | Cross-fitting po sítích (K-fold po sítích) |
| „Nadějný“ Brier | 0,0107 vs 0,25 baseline při triviálních rodinách | Reportovat Brier po rodinách a jen na netriviálních (p ∈ [0,1; 0,9]) |

Nezávislý generátor (doporučení): druhý, odlišný zdroj provozu, který Skákavka nezná: (i) přehrání reálných PCAP/CSV z CTU-13 a IoT-23 přes Suricata + Zeek, (ii) jednoduchý druhý simulátor psaný z textového popisu technik ATT&CK jiným autorem (nebo jiným modelem, který nevidí kód detektoru), (iii) červený tým: člověk (nebo agent bez přístupu k pravidlům detektoru) navrhuje evasion scénáře a spouští je v harnessu.

### 1.7 Co je realistické v Rustu bez GPU

| Technika | Bez GPU | Poznámka |
|---|---|---|
| Parametrické sweepy simulátoru | ano | už funguje (`soak`) |
| Isotonic, Platt, konformální práh | ano, triviální | stovky řádků Rustu |
| Bayesovské/Copula generátory tabulkových toků | ano, CPU | v literatuře obstojí vůči GAN (viz 2024 srovnání výše, nečteno celé) |
| Gradient boosting (C2ST, klasifikace) | ano | `linfa`/`smartcore`, nebo trénink v Pythonu a export; nutno ověřit |
| GAN/difuze/transformer trénink | ne prakticky | GPU, týdny ladění; inference malého modelu v `candle`/`ort` je možná, ale trénink ne |

---

## 2. Datová intuice

### 2.1 Naučené reprezentace a foundation modely

- ET-BERT (WWW 2022): předtrénování transformeru na neoznačených datagramech, úlohy Masked BURST a Same-origin BURST; po doladění zlepšení 0,2 až 10 % proti předchozím pracím na pěti úlohách klasifikace šifrovaného provozu. https://arxiv.org/pdf/2202.06335 (2022)
- netFound (2023, v4 leden 2025): hierarchický transformer s protokolově uvědomělou tokenizací, předtrénovaný na telemetrii; autoři uvádějí lepší výsledky než čtyři SOTA metody na pěti úlohách a odolnost vůči šumu v označení a „shortcutům“; kritika, že ET-BERT/YaTC chovají provoz jako text/obrázek a nezachycují specifika sítí, je autorský rámec, ne nezávislé hodnocení. https://arxiv.org/abs/2310.17025
- YaTC (AAAI 2023): masked autoencoder nad obrázkovou reprezentací toku; nehledal jsem primární zdroj (jen zmínka v netFound), nečteno.
- Pozor, jejich úlohy jsou klasifikace aplikací a malwaru v šifrovaném provozu s označenými daty; Skákavka řeší detekci anomálií a ověřování hypotéz nad agregovanými toky a Suricatou. Přenositelnost je nejistá (úvaha).

Reálný přínos vs. cena (odhad): pro Skákavku nízký–střední přínos, vysoká cena (trénink, data o objemu, GPU, MLOps, vysvětlitelnost slabá), a zvyšuje cirkularitu, pokud se předtrénuje na simulaci.

### 2.2 Peer-group baseline (podobná zařízení se chovají podobně)

- Základ je podložen MUD profily (RFC 8520): zařízení stejného typu mívají úzký, předvídatelný komunikační vzor, z něhož se generují profily a baseline pro detekci anomálií; hybrid „statický MUD + ML“ snižuje FP oproti samotnému ML. Zdroje: https://arxiv.org/pdf/1902.02484 (2019), https://arxiv.org/pdf/2304.04987 (2023), https://www2.ee.unsw.edu.au/~hhabibi/pubs/conf/22wowmom.pdf (2022). Rešerše nenašla práci přímo o „peer-group“ (kohortní baseline sdílená mezi zařízeními stejného typu); to je moje extrapolace.
- Využití pro Skákavku: `classifyHost` (ui-src/devices.ts) dává typ + `confidence` + `reasons` z portů, produktů, jmen, výrobce a assetů. Soak má vlastní role (19 typů: ws 68 706, mobile 37 054, voip 29 027, iot 13 468, printer 11 414, cam 11 249, plc 2 426, medical 4 479...), takže ground truth role je k dispozici.
- Konkrétní návrh: pro každý (typ zařízení, kontext sítě) udržovat kompaktní profil: množina povolených cílových portů/protokolů, kvantily bytes/h, počet unikátních cílů/h, denní profil. Skóre odchylky zařízení = vzdálenost od profilu peer-skupiny (po odstranění sebe sama), ne od vlastní krátké historie. Jednoduché, vysvětlitelné („tato kamera mluví na 3 cíle, ostatní kamery na 1“).
- Rizika: (a) chyba klasifikace typu se propíše (použít `confidence` jako váhu, ne tvrdé přiřazení); (b) neznámá zařízení (`unknown`) nemají skupinu; (c) skupina poškozená jednou zhackovanou skupinou (otrava: robustní statistiky, medián/MAD; viz ochrana v `case_memory.rs`); (d) v malých sítích (Soho 14 zařízení) jsou skupiny malé: použít hierarchický (empirický Bayes) shrinkage k celosvětovému typovému priorovi.
- Přínos (odhad): střední pro FP u IoT/tiskáren/kamer; malý pro C2/rogue.

### 2.3 Transfer mezi sítěmi, federované priory, cold-start

- Federované učení pro IDS: přehledy ukazují hlavní překážky: non-IID data, FedAvg špatně konverguje v heterogenním prostředí, poisoning/inference útoky, chybějící standardní benchmarky. Zdroje: https://arxiv.org/pdf/2509.17836v1 (2025), https://arxiv.org/pdf/2509.21389v2 (2025). Cold-start a few-shot jsem v rešerši konkrétně nenašel (mezera).
- Pro Skákavku je federace předčasná (produkt nemá flotilu sítí; úvaha). Realistická verze je „sdílené anonymizované statistiky“: ručně kurátorované priory (např. hierarchické Beta priory per (typ nálezu, archetyp sítě)) dodané s produktem a aktualizované centrálně z dobrovolně sdílených agregátů. Soak dává možnost „předtrénovat“ je na simulaci a zeslabit hodnotou pseudopozorování (např. efektivní velikost vzorku 10–20, aby je reálná data brzy přebila). Toto je v souladu se současnou Beta-konstrukcí Case Memory (úvaha).
- Cold-start (první dny bez historie): (1) typové priory (peer-group), (2) pravidla z veřejných znalostí (2.4), (3) vyšší práh vydání nálezu a nižší důvěra v objemové detektory po dobu učení (např. první 3–7 dní), (4) explicitní stav „učím se“ v UI. Tohle snižuje FP právě na začátku, kdy jsou největší.
- Few-shot adaptace: bayesovská aktualizace priorů s malým počtem označení správce (schválí/odmítne nález); tuto zpětnou vazbu Case Memory už přijímá (zdroj `CaseSource`).

### 2.4 „Soft priors“ z veřejných znalostí

- EPSS v4 (FIRST, 17. 3. 2025): pravděpodobnost zneužití CVE během 30 dní, gradient boosting; užitečné jako prior pro `State` nejistotu (je zranitelnost reálně zneužívána?). Zdroje: https://en.wikipedia.org/wiki/Exploit_Prediction_Scoring_System (sekundární), primární stránka https://www.first.org/epss (neověřena v této rešerši); srovnání EPSS vs. CISA KEV: https://arxiv.org/html/2411.02618v1 (2024).
- CISA KEV: seznam zneužívaných CVE jako tvrdý signál (prior blízko 1 pro „aktivně zneužíváno“); vydavatel a katalog veřejný (https://www.cisa.gov/known-exploited-vulnerabilities-catalog, neověřeno v rešerši).
- MITRE ATT&CK jako ontologie pro typování nálezů a pro řetězení (taktika → technika). Řeší konkrétní slabinu `exploit_attempt` (správný typ 0 %): mapování Suricata SID/classtype → ATT&CK technika. Tohle je dedukce nad veřejnou znalostí, ne učení.
- Známé porty/protokoly (IANA, Nmap services) jako prior očekávané role portu: většinu už dělá `PORT_RULES` v `classifyHost`.
- Riziko: statické tabulky stárnou (EPSS denně), nutno verzovat a logovat verzi priorů u každého rozhodnutí (reprodukovatelnost a audit).

---

## 3. Dedukce a abdukce

### 3.1 Formalizace stavu sítě jako znalostní báze

Fakta (příklady, názvy jsou návrh):
- `device(id, role, subnet, conf)`, `service(dev, port, proto, product)`, `identity_alias(dev, ip, from, to)`
- `flow(src, dst, port, bytes, t0, t1)`, `alert(sid, src, dst, t, sev)`, `finding(id, type, host, t, p)`
- `sensor_up(sensor, t)`, `sensor_gap(sensor, t0, t1)`, `scheduled(job, src, dst, window)`, `maint_window(subnet, t0, t1)`, `change_event(dev, kind, t)`
- Odvozená: `benign_explains(finding, cause, strength)`, `inconsistent(f1, f2, why)`, `artifact(finding, why)`.

Čas jako první třída (intervaly), vztahy `before`, `overlaps`, `within(window)`. Tohle odpovídá tomu, co `hypothesis.rs` už má (typované nejistoty `Aleatoric`, `Epistemic`, `Identity`, `Observation`, `State`, `Interpretation`); dedukční vrstva by plnila zejména `Interpretation` a `Observation`, které zdrojový komentář označuje jako „v tomto kroku nepočítané“ a „vyžaduje historickou baseline, navazující krok“ (viz `src/hypothesis.rs`, definice `UncertaintyKind`).

### 3.2 Pravidlové odvozování v Rustu

- `ascent`: Datalog-like makro v Rustu, relace nad libovolnými typy (Clone+Eq+Hash), `ascent_run!` s lokálními proměnnými, paralelní varianty; verze 0.8.0 (k datu rešerše). https://docs.rs/ascent (docs.rs, neuvedeno datum) a https://docs.rs/crate/ascent/latest/source/README.MD
- Crepe a Datafrog jsem v rešerši neověřil (výsledek jen ascent); znám je jen z paměti jako alternativy, tak je bereme jako nepotvrzené.
- Výhoda pro nás: deterministické, bez GPU, vyhodnocení pod milisekundy až desítky ms na okno (odhad; souvisí s cyklem p50 70 ms, `hypothesis_plan_exec` 33 ms v1). Pravidla jsou čitelná správci a lze je auditovat – „proč systém něco tvrdí“ je odvozovací strom.
- Omezení: Datalog je monotónní; negace („není v kalendáři záloha“) vyžaduje stratifikaci, která se v ascent podporuje (negace nad uzavřenými relacemi), ale nemám ověřeno detailně. Čas jako intervaly je třeba řešit diskretizací do cyklů (30 virt. minut v harnessu).

### 3.3 Pravděpodobnostní logika: kdy a jaká

| Přístup | Co dává | Cena | Doporučení |
|---|---|---|---|
| Noisy-OR / log-odds sčítání důkazů s explaining-away | „A i B podporují hypotézu; benigní příčina C vysvětlí A, tedy hypotézu zeslabí“ | Velmi nízká | ANO, ručně implementovat |
| Naivní Bayes / malá Bayesovská síť (diskrétní, ≤ 20 uzlů na hypotézu) | Posterior hypotézy z kontextu | Nízká–střední | ANO, pro jádro abdukce |
| ProbLog / DeepProbLog (https://arxiv.org/pdf/1805.10872, 2018) | Pravděpodobnostní fakta + logika, neuronové vstupy | Střední–vysoká; Python/Prolog, exaktní inference může být exponenciální | NE do produkčního jádra; vhodné jen jako akademický prototyp |
| Markov Logic Network | Měkká pravidla s vahami | Vysoká, učení vah drahé | NE (v rešerši jsem nenašel aplikaci na IDS korelaci) |
| Faktorové grafy / loopy BP | Obecná, přibližná | Střední | Možné později; složitost proti přínosu je nejistá |

Historické důkazy o užitečnosti: Bayesovské sítě pro důkazy v síťové forenzice počítají pravděpodobnost útočné cesty a míru FP, a postupně ji aktualizují s novým důkazem (IFIP 2016, https://dl.ifip.org/IFIP-AICT-484/hal-01758685; WOSIS 2014 přes https://scitepress.org/Papers/2014/49803/pdf/index.html); abduktivní a induktivní uvažování v Prologu pro kauzalitu důkazů (2014, tamtéž); MulVAL (Datalog) pro útočné grafy (zmíněno v těchto zdrojích). Korelace alertů logickým modelem: Zhou, Heckman, Reynolds, Carlson, Bishop (TISSEC 2007) https://nob.cs.ucdavis.edu/bishop/papers/2007-tissec; pravděpodobnostní korelace: Valdes & Skinner (RAID 2001; podle výsledku vyhledávání jen patentový popis). Důkaz je tedy starší (2001–2016) a bez moderních srovnání s detektory; neznám veřejné číslo, o kolik tyto metody snižují FP v produkčním NIDS (nejistota).

### 3.4 Abdukce = nejlepší vysvětlení

Pro každý surový nález/událost sestavit množinu kandidátních vysvětlení H = {útok_k, benigní_j, artefakt_m} s prior (peer-group, KEV/EPSS, ATT&CK) a věrohodností P(pozorování | H) z kontextu, a vydat posterior. Příklad z zadání: nárůst provozu 02:00, zdroj je NAS, cíl úložiště, v kalendáři záloha → `backup` posterior vysoký, nález se degraduje (ne maže): „nevydán jako útok; zaznamenán s vysvětlením; zkontroluj, jen když se změní cíl/objem/čas“.

Pravidla odvozená z dat soaku (konkrétní, testovatelná):

| Benigní lookalike | Abduktivní důkaz (co zkontrolovat) | Co se musí stát, aby se vysvětlení zamítlo |
|---|---|---|
| patch_window, service_crash | Zařízení bylo mimo provoz / restart v inventáři; nálezy po restartu = reconnect storm | Nový cíl mimo dosavadní množinu nebo exfiltrační objem |
| sensor_crash, log_corruption, collector_replay | `sensor_gap` překrývá okno nálezu; duplicitní tok id/časové razítko mimo pořadí; neplatné řádky | Nález potvrzen druhým nezávislým zdrojem (Suricata + toky) |
| backup_burst, batch_job | Pravidelné okno (cron, týdenní vzorec), role zdroj ∈ {files, db, NAS}, cíl ∈ {files, db, cloud storage} | Změna cílové třídy (nový externí cíl) |
| flash_crowd | Mnoho různých klientů → jeden webový server; legitimní poměr odpovědí | Jeden zdroj, žádná odezva, SYN bez ACK |
| authorized_scanner | Zdroj v seznamu schválených skenerů / okno | Skener mimo okno nebo mimo seznam |
| device_decommission, onboarding | `change_event` v inventáři | Zařízení, které nemá change_event, ale mění adresu |

Kritické: „benigní vysvětlení“ je také cesta útočníka (útočník se maskuje jako záloha). Proto musí degradace mít strop a kontrolní podmínky (viz „co musí nastat“): stropem je limit, že dedukce nikdy nesmí sama potlačit nález s IDS shodou na kritickou signaturu nebo s novým cílem/rolí; degradovat jen na nižší prioritu a logovat (doporučení, úvaha).

Odhad přínosu (odhad, není změřen): pokrývá lookalike s FP ≥ 75 % v tabulce výše (batch, backup, patch, crash, collector, log, flash); jejich nálezy tvoří významnou část 5,3 M FP, přesný podíl neznám bez rozpadu nálezů podle příčin. Hrubě 30 až 70 % snížení FP odvozených od provozních událostí, ale je třeba změřit v harnessu (atribuce „nálezy přiřaditelné jen jim“ už je v reportu: 97 171 collector_replay, 78 979 log_corruption, 67 268 patch_window, 42 834 sensor_crash, 36 357 service_crash, 17 540 authorized_scanner, 17 020 batch_job, 17 009 flash_crowd, 11 533 backup_burst; dohromady 385 711 z 5 302 629 = 7,3 %). Důležité: tato atribuční čísla ukazují, že jen asi 7 % FP je přiřaditelné čistě benigním událostem; velká většina (1,9 M `inductive_volume_anomaly`, 2,5 M `unexpected_traffic`) vzniká bez události, tedy z prahů/baseline. Abdukce nad událostmi sama tedy FP o řád nesníží. To je nejdůležitější korekce mého původního odhadu: ve výsledku se přínos mění na „odhad 5 až 10 % všech FP“ z událostí, plus neznámý díl z `unexpected_traffic`, pokud lze benigní příčinu odvodit z kontextu (peer-group). Hlavní vliv na FP/síť-den proto musí přijít z baseline a prahů (peer-group, kalibrace), ne z abdukce.

### 3.5 Konzistenční kontroly a „nesmysl“ detektory

Logické/fyzikální nemožnosti, které lze evaluovat deterministicky a levně:

- tok s bytes větším než kapacita linky × trvání; pakety × min. velikost > bytes; trvání záporné;
- tok z doby, kdy zařízení nebylo v síti / bylo vypnuté (`device out of service`);
- tok před navázáním spojení (ACK bez SYN) jen v asymetrickém směru; ověřit s pokrytím senzoru;
- stejný `flow_id` / 5-tice s časem mimo pořadí (replay kolektoru);
- dva nálezy si odporují: „zařízení je offline (sensor_gap/patch)“ vs. „zařízení spustilo exfiltraci“ → `inconsistent` → pravděpodobně chyba senzoru nebo identity, ne útok; rozhodnout podle věrohodnosti zdrojů;
- identita: jedno MAC na dvou IP současně / IP, která přeskočí mezi MAC s nemožnou rychlostí → řešení falešného rozdělení (8,7 %) a falešného sloučení (1,7 %).

Tohle míří přímo na sensor_crash, log_corruption, collector_replay (až 93–97 % FP) a je to čistě logické, takže nejnižší riziko vůči cirkularitě (pravidla vycházejí z fyziky a protokolu, ne z parametrů simulátoru).
Rogue device: dedukce `mluví(ip) ∧ ¬v_inventáři(ip) ∧ ¬dhcp_lease(ip)` je kandidát na lepší detektor než statistika. Rogue je nyní 0,2 % (v1) až 7,4 % (v2); to je ale především otázka, zda telemetrie takové zařízení vidí (slepé podsítě senzoru v2). Dedukce nezvýší viditelnost.

### 3.6 Kauzální graf a omezení

Plné do-calculus bez experimentů nelze. Realistické jsou kauzální omezení pořadí (časová souslednost), která zakazují nemožné vysvětlení:
- příčina předchází následek (exfiltrace po sběru dat; lateral movement po kompromitaci zdroje);
- řetězec ATT&CK taktik (recon → initial access → ... → exfiltration) jako prior pro korelaci nálezů do kampaně (`apt_chain` už dosahuje 99,5 %);
- „zásah“ jako experiment: aktivní ověření Skákavky (`verification_planner`) je přirozená intervence. EVOI už vybírá kontrolu s nejvyšší očekávanou informací; kauzální formulace dovoluje říct „zkoušel jsem X a výsledek rozlišil H1 od H2“. Důkaz z intervence je silnější než z pozorování (úvaha).

### 3.7 Vysvětlitelnost pro správce

Výstup nálezu: (1) tvrzení, (2) hlavní důkazy (fakta s časovými značkami), (3) zvažovaná benigní vysvětlení a proč byla odmítnuta nebo přijata (odvozovací strom z pravidel), (4) co by ho změnilo (jaká kontrola), (5) verze pravidel a priorů. Odvozovací stopa z Datalogu je přirozený audit trail (sedí s existujícím auditním řetězcem v `ops.sqlite`, pokud se tam zapisuje).

---

## 4. LLM / agentní usuzování s pojistkami

### 4.1 Kde pomáhá a kde ne

Pomáhá (Pásmo B podle pravidel uživatele: výsledek vždy s lidskou kontrolou):
- sumarizace důkazů do srozumitelného jazyka, překlad technické stopy do češtiny pro správce;
- navržení dalšího kroku ověření z konečné množiny povolených kontrol (výběr, ne vymýšlení);
- seskupení nálezů do příběhu (kampaň) jako návrh, který potvrdí dedukční vrstva (ATT&CK pořadí).

Nepomáhá / nesmí:
- rozhodovat o blokaci či potlačení nálezu;
- být jediný zdroj faktu (kdo je zařízení, jaký je CVE).
Důkazy o rizicích: Alert-Bench (NeurIPS 2026, zdroj https://neurips.cc/virtual/2026/168137, nečteno celé) hlásí, že každá konfigurace LLM agentů mine ≥ 40,4 % útokových alertů, více výpočtu nezlepší triáž a dotazy bez nalezených záznamů vedou častěji k zamítnutí (nebezpečný „absence of evidence“ efekt). Elastic (vendor, https://www.elastic.co/security-labs/llm-benchmarking-agentic-soc) zdůrazňuje hodnocení stop volání nástrojů a riziko, že model vypráví výsledek nástroje místo jeho zavolání. Oslo/FFI studie o orchestraci (jen sekundární zpráva, https://letsdatascience.com/news/researchers-show-structured-llm-workflows-improve-alert-tria-5b13951e, ověřit primárně). SecAlertBench (8 322 alertů, GitHub, nerecenzováno): https://github.com/Dxsssu/SecAlertBench.

### 4.2 Pojistky (architektura)

1. LLM vidí jen strukturovaný, předfiltrovaný souhrn (ne surové logy s osobními údaji).
2. Výstup jen JSON se schématem (enum akcí, id důkazů, které existují); validace schématem; odkazy na důkazy ověřit proti úložišti (neexistující id = zahodit).
3. Každé tvrzení „z faktů“ musí nést id faktu; dedukce přepočítá, zda fakt skutečně platí.
4. LLM nikdy nemění pravděpodobnost ani stav; může jen navrhnout ověření z whitelistu, a to proběhne přes `verification_planner` (rozpočet, schválení, scope; v soaku 0 porušení).
5. Negativní výsledek („nic nenalezeno“) se nesmí interpretovat jako vyvrácení (viz Alert-Bench) – to hlídá explicitní typ nejistoty `Epistemic`/`Observation` (pokrytí).
6. Logování každého volání (prompt hash, verze modelu, výstup, validace) do auditního řetězce; deterministický režim (teplota 0) pro reprodukovatelnost.
7. Selhání LLM = degradace na šablonový text; produkt nesmí být na LLM závislý.

### 4.3 Lokální modely vs. API a ochrana dat

- Data o síti (IP, jména hostů, topologie) jsou citlivá; podle uživatelských pravidel žádné osobní údaje v repozitáři. API varianta vyžaduje minimalizaci a pseudonymizaci (nahrazení IP tokeny), smlouvu o zpracování (GDPR, mimo rozsah studie).
- Lokální modely bez GPU (malé kvantované modely) zvládnou sumarizaci krátkého strukturovaného vstupu; kvalita u češtiny nejistá (odhad, neměřeno). Doporučení: šablony pro první vydání; LLM jako volitelný plugin s pseudonymizací.
- Evidence AI použití: výstupy Pásma B, které jdou ven, se zapisují do ai-disclosure.md projektu (pravidlo uživatele).

---

## 5. Návrh pro Skákavku

### 5.1 Vrstvy

```
[1 Syntéza]  soak simulátor (hlavní) + druhý nezávislý generátor + replay CTU-13/IoT-23
      |  pouze pro: kalibraci, ladění prahů, ověření (ne trénink černé skříňky)
[2 Priory]   typové/peer-group profily, hierarchická Beta (shrinkage), ATT&CK/KEV/EPSS, cold-start režim
      |
[3 Pravděpodobnostní jádro]  existující hypotézy + typované nejistoty + Case Memory (Beta)
      |      + noisy-OR / malá Bayesovská síť pro posterior hypotézy včetně benigních vysvětlení
      |      + kalibrace (isotonic) + konformální práh vydání
[4 Dedukce]  ascent: kontext událostí, nesmysl detektory, konzistence, identita, kauzální pořadí
      |      výstup: degradace/eskalace s odvozovací stopou
[5 Ověřování] EVOI plánovač; kontroly vybrané tak, aby rozlišily H_útok vs. H_benigní
      |      volitelný LLM: sumarizace a návrh z whitelistu, nikdy rozhodnutí
```

Jak vrstvy spolupracují: dedukce (4) generuje benigní/artefakt hypotézy a jejich prior; jádro (3) vypočítá posterior; plánovač (5) použije rozdíl posteriorů jako hodnotu informace („ověření backupu je levné a rozliší H“). Dnes EVOI pracuje jen s hypotézou útoku; rozšíření na soutěžní hypotézy je hlavní změna (návrh; ke kódu se vyjadřují jiné studie).

### 5.2 Tabulka přínos / složitost / riziko / pořadí

Všechny přínosy jsou ODHADY, nikoli měření.

| # | Krok | Odhad přínosu | Složitost | Riziko | Pozn. |
|---|---|---|---|---|---|
| 1 | Nesmysl detektory + konzistenční kontroly (senzor, replay, log, identita) v `ascent` | FP z provozních událostí (sensor/log/collector): velký relativní pokles těchto kategorií (odhad 60–90 % z jejich 0,22 M), celkově malý; zpřesní identitu | nízká (dny až 1–2 týdny) | nízké (pravidla z fyziky) | začít zde |
| 2 | Abdukce benigních událostí (backup, batch, patch, flash crowd, scanner) s kontrolními podmínkami | odhad 5–10 % všech FP; zvýší důvěru správce v nálezy (vysvětlení) | střední (2–4 týdny) | střední (maskování útoku) | po 1 |
| 3 | Kalibrace isotonic + konformální práh, cross-fitting po sítích, korekce na kotvě | ECE a Brier po rodinách výrazně lepší (odhad); FP o málo, ale správné zobrazení pravděpodobností | nízká–střední | střední (posun sim→real) | nezávislé na 1–2 |
| 4 | Peer-group baseline podle role + hierarchický shrinkage, cold-start režim | největší potenciál na `unexpected_traffic` a `inductive_volume_anomaly` (4,4 M FP v v2), odhad 20–50 % těchto FP; nejistota vysoká | střední–vysoká | střední (chyba typu zařízení, otrava) | největší potenciální dopad na FP |
| 5 | Soft priors: ATT&CK mapování Suricata (oprava exploit_attempt typu), KEV/EPSS jako State prior | oprava typování exploit_attempt z 0 % (jde o typ, ne detekci); KEV/EPSS střední | nízká–střední | nízké | rychlé |
| 6 | Druhý nezávislý generátor + C2ST audit věrnosti | neovlivňuje detekci, zvyšuje důvěryhodnost výsledků | střední | nízké | nutné pro obhajitelnost |
| 7 | LLM sumarizátor s pojistkami | přínos pro UX, ne pro přesnost | střední | střední (halucinace, data) | volitelné, až na konec |
| 8 | Učený generátor/foundation model | nejisté | vysoká (GPU) | vysoké | nedoporučeno |

Pořadí zavedení: 1 → 3 → 4 → 2 → 5 → 6 (průběžně od začátku jako ověřovací infrastruktura) → 7. Pozn.: bod 6 musí vzniknout před zavedením 3 a 4, aby se vyhnulo ladění na vlastním simulátoru; proto ho doporučuji paralelně s krokem 1.

### 5.3 Tři nejslibnější

1. Dedukční vrstva v `ascent` (nesmysl detektory, konzistence, kontext událostí). Důvod: deterministická, vysvětlitelná, bez GPU, míří na nejhlasitější a metodicky nejčistší FP (artefakty), nízké riziko cirkularity, protože vychází z protokolu a fyziky.
2. Kalibrace s kotvou (isotonic + konformální práh, cross-fitting po sítích). Důvod: konkrétně naměřená vada (podkonfidentní nad 0,6, překonfidentní 0,1–0,5), levná oprava, a kalibraci lze nezávisle ověřit na CTU-13/IoT-23.
3. Peer-group baseline + cold-start priory. Důvod: míří na největší typ FP (objemové a „unexpected_traffic“), využívá `classifyHost`/role a podporu v literatuře o MUD; hierarchický shrinkage řeší malé sítě. Vyžaduje opatrnost kvůli typovým chybám.

### 5.4 Tři nedoporučené

1. Vlastní generativní model provozu (GAN/difuze). Důvod: GPU, doložené slabiny (periodicita NetShare dle CascadeNet 2026, mód kolaps, bez payloadu, shoda s protokolem), nic nezlepšuje to, co už simulátor má (ground truth), a přidává další vrstvu, jejíž věrnost bychom opět museli ověřovat reálnými daty, které nemáme v množství.
2. Předtrénovaný síťový transformer (netFound/ET-BERT/YaTC) jako detektor. Důvod: navrženo pro klasifikaci šifrovaného provozu, slabá vysvětlitelnost, vysoká cena, nejisté přenositelnost (cross-dataset kolaps v NIDS, Layeghy 2022, Cantone 2024) a riziko leakage při předtrénování na simulaci.
3. Plná pravděpodobnostní logika (ProbLog/Markov Logic) v produkčním jádru a LLM jako rozhodčí. Důvod: exaktní inference může růst exponenciálně, učení vah je drahé, v rešerši nenalezen důkaz pro IDS; LLM jako rozhodčí je v rozporu s požadavkem „nikdy jediný zdroj pravdy“ (Alert-Bench). Stejný efekt dává noisy-OR + malá Bayesovská síť v ruční implementaci.

---

## 6. Jak to ověřit bez cirkularity

Předregistrace (do repozitáře před spuštěním, s hashem): seznam hypotéz H1–H4, metriky, cutoffs, rozdělení rodin a sítí. Cokoli mimo plán se označí „exploratorní“.

**Rozdělení dat (v soak harnessu):**
- Rodiny útoků: 19 rodin rozdělit na „vývojové“ (např. 12; smí se vidět při návrhu pravidel/priorů) a „držené“ (7; nikdo je nevidí). Držené rodiny vybrat losem s pevným semenem a zamknout. Kandidáti na držené: rodiny, které nejsou hlavním cílem ladění (např. ransomware, insider_hoarding, fleet_beacon, ics_attack, cryptomining, web_exploit, credential_stuffing) – návrh, finální výběr losem.
- Benigní události: totéž – nové benigní lookalike (např. nová událost „migrace VM“, „audit skener“, „tiskový špičkový provoz“), kterou autor pravidel nezná; implementovat jiný člověk/agent.
- Sítě: dělení po sítích a archetypech (např. leave-one-archetype-out), ne po cyklech.

**Nezávislé zdroje:**
1. Replay reálných datasetů přes stejný pipeline Suricata/Zeek → Skákavka: CTU-13 (23 scénářů už v harnessu, 3 průchody bez nedeterminismu), IoT-23. Primární metriky: FP/hodina na benigním provozu a recall na malicious scénářích; porovnat s „triviální baseline“ (dnes: A porazí baseline jen v 6 z 20 scénářů; cílem je zvýšit toto číslo, ne dosáhnout vysokého absolutního).
2. Druhý generátor „B“: psaný z textového zadání (ATT&CK technika, parametrické rozsahy) nikým, kdo nevidí detektor; používán jen k závěrečnému hodnocení, nikdy k ladění.
3. Červený tým: scénáře evaze (maskování za zálohu, pomalý beacon pod prahem jitteru) navržené bez přístupu k pravidlům; každé zjištěné selhání → záznam, ne ladění na místě.

**Ablace a statistika:**
- Párové A/B na stejných semenech: baseline (dnešní engine) vs. +vrstva; stejné sítě, stejné útoky.
- Metriky: recall (Wilson 95 %), správný typ, FP/síť-den (s intervalem přes bootstrap po sítích), ECE a Brier po rodinách a na netriviálním pásmu p ∈ [0,1; 0,9], latence, počet degradovaných nálezů, které byly skutečné útoky („potlačené TP“, hlavní bezpečnostní metrika abdukce).
- Kritérium přijetí: FP klesne a potlačené TP nepřekročí předem danou mez (např. ≤ 1 % recallu držených rodin) a výsledek se drží na B generátoru i na reálných datasetech. Pokud na B/real zisk zmizí, pravidlo se označí jako overfit.
- Citlivostní analýza: změnit parametry simulátoru (jitter, frekvence událostí) o ±50 %; ukázat, že zisk nezávisí na přesné hodnotě.
- Kontrola leakage: zakázat feature odvozené z textu nálezu nebo `host_key` útočníka; test „permutace štítků“ musí dát zisk ≈ 0.
- Tichá kontrola: C2ST audit (1.3) před i po; pokud se simulace stává rozlišitelnější od reality, výsledky se hlásí s varováním.

**Slepý test:** člověk (nebo oddělený agent) připraví 20 až 30 sítí/epizod s utajenými útoky a benigními událostmi; autor vrstvy je spustí a vyhodnocení provede jiná osoba. Menší vzorek, ale chrání před nevědomým laděním.

---

## 7. Co zůstává nejisté

- Žádná čísla přínosu ve studii nejsou změřena. Všechny odhady jsou řádové a musí je potvrdit harness; nejhorší nejistota je u peer-group (odhad 20–50 % u objemových FP).
- Z atribuce v reportu v2 plyne, že pouze zhruba 7 % behaviorálních FP je přiřaditelných benigním událostem; zbytek jsou prahy a baseline. Pokud je to správně, abdukce událostí nebude hlavní řešení FP (viz 3.4); ověřit rozpad FP podle příčin, než se zaváže kapacita.
- Literatura o abdukci a logice pro NIDS je převážně 2001–2016, bez moderních srovnávacích dat; ProbLog/MLN na IDS jsem nenašel.
- Generativní modely: různé zdroje se rozcházejí (GAN dobré na tabulkových, kritika časové věrnosti); CascadeNet výsledky pocházejí od konkurenčního autora.
- Alert-Bench, preprint 2609.19241 a přehled 2602.05594 jsem četl jen ve shrnutích vyhledávače; čísla je nutno ověřit v originále před citací v diplomce. Platí i pro Cantone 2024 (přes katalog).
- Primární URL pro DoppelGANger, YaTC, FIRST EPSS, CISA KEV, RFC 8520, Crepe a Datafrog nebyly v této rešerši ověřeny.
- Zda je C2 beacon 4,7 % (v1) / 12,5 % (v2) problém signálu, pokrytí senzoru, nebo prahu, tato studie nerozhoduje; řeší ji studie o pokrytí útoků.
- Přenos ze simulace na reálné sítě nelze s dostupnými daty zaručit; CTU-13 (2011) a IoT-23 (2018–2019) jsou zastaralé a malé. Konformální záruky při posunu jsou slabé (preprint 2609.19241).
- Kvalita lokálních LLM v češtině a cena jejich provozu bez GPU nebyly měřeny.

## Odkazy na ostatní studie

Studie o kódu, rešerši FP redukce a pokrytí útoků píší jiní agenti do `docs/diplomka/studie/`; tato studie se na ně odkazuje a jejich obsah nekopíruje. Doporučuji po dokončení doplnit přesné názvy souborů (v době psaní tu byl adresář prázdný).

## Seznam zdrojů (URL, rok)

- NetShare (SIGCOMM 2022): https://par.nsf.gov/servlets/purl/10406016 ; https://github.com/annuszulfiqar2021/NetShare
- CascadeNet (NSDI 2026, slidy): https://www.usenix.org/system/files/nsdi26_slides-lu-runwei.pdf
- NetDiffusion (2023/2024): https://ar5iv.labs.arxiv.org/html/2310.08543 ; NetDiffus (2023): https://arxiv.org/abs/2310.04429
- Přehled syntézy provozu (2025): https://arxiv.org/pdf/2507.01976 ; srovnání generátorů (2024): https://arxiv.org/html/2410.16326v2
- Domain randomization (2021/2022): https://arxiv.org/abs/2110.03239
- Dos and Don'ts of ML in Computer Security (USENIX Sec 2022): https://arxiv.org/pdf/2010.09470
- Layeghy & Portmann (2022): https://arxiv.org/abs/2205.04112 ; Cantone et al. (2024): https://katalog.lib.cas.cz/KNAV/EdsRecord/edsarx,edsarx.2402.10974
- NetFlow DL IDS přehled (2026): https://arxiv.org/pdf/2602.05594
- ET-BERT (2022): https://arxiv.org/pdf/2202.06335 ; netFound (2023–2025): https://arxiv.org/abs/2310.17025
- Conformal covariate shift (2019): https://arxiv.org/abs/1904.06019 ; Wang & Qiao (2025): https://arxiv.org/pdf/2502.17744 ; konformální IDS (2026): https://arxiv.org/pdf/2609.19241
- MUD profily (2019, 2022, 2023): https://arxiv.org/pdf/1902.02484 ; https://www2.ee.unsw.edu.au/~hhabibi/pubs/conf/22wowmom.pdf ; https://arxiv.org/pdf/2304.04987
- FL pro IDS (2025): https://arxiv.org/pdf/2509.17836v1 ; https://arxiv.org/pdf/2509.21389v2
- EPSS vs KEV (2024): https://arxiv.org/html/2411.02618v1
- Ascent (Datalog v Rustu): https://docs.rs/ascent
- DeepProbLog (2018): https://arxiv.org/pdf/1805.10872
- Korelace alertů (2007): https://nob.cs.ucdavis.edu/bishop/papers/2007-tissec ; BN forenzní model (2016): https://dl.ifip.org/IFIP-AICT-484/hal-01758685 ; důkazy z bezpečnostních událostí (2014): https://scitepress.org/Papers/2014/49803/pdf/index.html
- LLM triáž: Alert-Bench (2026) https://neurips.cc/virtual/2026/168137 ; Elastic https://www.elastic.co/security-labs/llm-benchmarking-agentic-soc ; SecAlertBench https://github.com/Dxsssu/SecAlertBench
