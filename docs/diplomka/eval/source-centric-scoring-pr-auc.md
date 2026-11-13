# Jádro: proč ablace A ztrácí, a jak ji reálně zlepšit (Deliverable 28)

**Status: naměřeno (29. 10. 2026).** Reakce na zjištění: negativní výsledek ("ablace A prohrává s triviálním baseline na všech 3 scénářích", Deliverable 18/20) se nemá jen honestně zdokumentovat — má se zjistit, **jestli a jak se dá reálně zlepšit**. Tohle je ta diagnóza a první konkrétní, měřený krok ke zlepšení.

## Diagnostická otázka

Je slabý výsledek způsoben **špatně zvoleným prahem** (score≥3.2 byl odhad z Deliverable 3, nikdy netrénovaný), nebo **samotný signál nemá rozlišovací silu** na tomhle datasetu? To jsou dvě zcela odlišné diagnózy s odlišnou léčbou — první řeší kalibrace/lepší práh, druhá vyžaduje lepší detektor.

## Nástroj: PR-AUC (`src/eval/stats.rs::pr_auc`)

Plocha pod precision-recall křivkou, počítaná ze (skóre, label) dvojic **bez vazby na konkrétní práh** — měří, jestli skóre má užitečnou informaci, nezávisle na tom, kde se later nastaví hranice rozhodnutí. Náhodný/konstantní klasifikátor má PR-AUC = prevalence (podíl pozitivních) — to je správný "nulový" baseline, analogicky 0.5 u ROC-AUC. Ověřeno na ručně spočítaném referenčním příkladu (shoda se standardním scikit-learn `average_precision_score` dokumentačním příkladem, AP=5/6).

## Naměřeno — první diagnóza (existující destinace-centrické skóre)

```
Botnet-54: PR-AUC=0.5784 prevalence=0.7670 rozdil=-0.1886
Botnet-51: PR-AUC=0.1957 prevalence=0.1791 rozdil=+0.0165
Botnet-42: PR-AUC=0.3844 prevalence=0.5086 rozdil=-0.1242
```

**Diagnóza: na 2 ze 3 scénářů je PR-AUC POD prevalencí — signál je hůř než náhodný, ne jen špatně prahovaný.** Žádná kalibrace ani jiný práh tohle nemůže opravit — problém je v tom, CO se měří, ne KDE se škáluje.

## Hypotéza: špatná jednotka analýzy

`score_connection_keys` agreguje podle **CÍLE** `(dst_ip, proto, port)` — odpovídá otázce "je tahle SLUŽBA anomální". CTU-13 ground truth je ale definovaná podle **ZDROJE** — bot je infikovaný HOST, ne anomální služba. To je fundamentálně jiná jednotka analýzy, a destinace-centrické skóre na ni ani nemůže dobře odpovídat.

## Nový nástroj: `score_source_hosts` (`src/passive/anomaly.rs`)

Stejná robust z-score logika, ale agregovaná podle `src_ip`, plus nový rys: **počet distinktních cílů** (typický indikátor C2/scanning chování infikovaného hosta, který destinace-centrické skóre vůbec nezachycuje).

## Naměřeno — srovnání

```
Botnet-54: DESTINACE PR-AUC=0.5784 prevalence=0.7670 LIFT=0.75x | ZDROJ PR-AUC=0.0093 prevalence=0.0004 LIFT=24.21x
Botnet-51: DESTINACE PR-AUC=0.1957 prevalence=0.1791 LIFT=1.09x | ZDROJ PR-AUC=0.0128 prevalence=0.0041 LIFT=3.09x
Botnet-42: DESTINACE PR-AUC=0.3844 prevalence=0.5086 LIFT=0.76x | ZDROJ PR-AUC=0.0323 prevalence=0.0004 LIFT=89.97x
```

**Klíčové: LIFT (PR-AUC / prevalence) je jediná korektní srovnávací metrika mezi dvěma jednotkami analýzy s úplně jinou základní sazbou** — zdrojová prevalence je o 2-3 řády nižší (pár botů mezi tisíci hostů), takže raw PR-AUC čísla samotná nejsou přímo srovnatelná; LIFT je scale-invariant.

| Scénář | Destinace-centrický LIFT | Zdroj-centrický LIFT |
|---|---|---|
| Botnet-54 | 0.75× (hůř než náhoda) | **24.21×** |
| Botnet-51 | 1.09× (téměř náhoda) | **3.09×** |
| Botnet-42 | 0.76× (hůř než náhoda) | **89.97×** |

## Interpretace

**Přesun z "je tahle služba anomální" na "je tenhle host anomální" dramaticky a konzistentně zlepšuje rozlišovací silu na všech 3 reálných scénářích/2 rodinách.** To je reálná, měřená cesta ke zlepšení — ne naděje, že se to časem spraví. Destinace-centrické skóre (dosavadní `score_connection_keys`, jádro ablace A) je skutečně slabé, protože měří špatnou věc pro tento typ hrozby (botnet C2), ne protože je implementace chybná.

## Naměřeno — krok 2: překládá se lepší ranking do lepší klasifikace? (NE naivně)

Otázka z omezení výše ("PR-AUC lift neznamená automaticky lepší klasifikaci při nějakém prahu") je teď změřená, ne jen vyslovená. Použit stejný práh `3.2`, který je dnes natvrdo zapojený do destinace-centrické ablace A (Deliverable 3) — **beze změny, ne přeladěný na zdrojová data**, aby srovnání nebylo cirkulární.

```
Botnet-54: ZDROJ klasifikace pri prahu 3.2: TP=1 FP=2086 FN=0 TN=528 precision=0.000 recall=1.000 f1=0.001 | trivialni baseline precision=0.000 f1=0.001
Botnet-51: ZDROJ klasifikace pri prahu 3.2: TP=10 FP=1886 FN=0 TN=520 precision=0.005 recall=1.000 f1=0.010 | trivialni baseline precision=0.004 f1=0.008
Botnet-42: ZDROJ klasifikace pri prahu 3.2: TP=1 FP=2370 FN=0 TN=418 precision=0.000 recall=1.000 f1=0.001 | trivialni baseline precision=0.000 f1=0.001
```

**Výsledek: NE, naivní přenesení prahu nefunguje.** Na všech 3 scénářích práh 3.2 klasifikuje téměř všechny zdroje jako malicious (recall=1.0, ale FP v tisících) — prakticky identické s triviálním "vše=bot" baseline. To NENÍ v rozporu s naměřeným LIFT 24–90× výše — je to důkaz, že **práh a skóre jsou dvě different věci**: `score_source_hosts` používá jinou agregaci (jiné rysy, jiné měřítko robust z-score) než destinace-centrické skóre, pro které byl 3.2 kdysi odhadnutý (Deliverable 3, nikdy natrénovaný). Přenos konstanty z jedné domény do druhé nemá důvod fungovat — a nefunguje.

**Co s tím NEdělat**: hledat nový "magický" práh proladěním přímo na tomhle eval-setu by byl přesně ten cirkulární overfitting, který si tenhle projekt opakovaně zakazuje (stejná disciplína jako u 3.2 samotného). Hand-picked konstanta pro novou doménu skóre by byla jen o stupeň sofistikovanější verze stejné chyby.

**Co to skutečně ukazuje**: tohle je přímý, měřený argument PRO existující kalibrační vrstvu (Deliverable 19, `src/eval/calibration.rs::IsotonicCalibrator`, LOSO-validovaná na destinace-centrickém skóre) místo hand-picked prahů obecně — problém není "najít lepší magické číslo pro zdroj", je "přestat používat magická čísla a kalibrovat skóre na pravděpodobnost nezávisle pro každou doménu agregace". Zdroj-centrické skóre potřebuje svou vlastní izotonickou kalibraci (stejná metoda, nová doména) — to je přesně následující, bounded krok, ne nový koncept.

## Naměřeno — krok 3: LOSO izotonická kalibrace na zdroj-centrickém skóre (druhý, ještě poučnější negativní výsledek)

Kalibrátor (Deliverable 19, nezměněná implementace) natrénovaný LOSO na zdroj-centrických bodech:

```
Botnet-54 held-out (n=2615): naive(3.2) brier=0.7977 f1=0.0010 | kalibrovane(0.5) brier=0.0004 f1=0.0000 | trivialni baseline f1=0.0008
Botnet-51 held-out (n=2416): naive(3.2) brier=0.7806 f1=0.0105 | kalibrovane(0.5) brier=0.0042 f1=0.0000 | trivialni baseline f1=0.0082
Botnet-42 held-out (n=2789): naive(3.2) brier=0.8498 f1=0.0008 | kalibrovane(0.5) brier=0.0004 f1=0.0000 | trivialni baseline f1=0.0007
```

**Brier skóre se zlepšilo dramaticky (0.78–0.85 → 0.0004–0.0042) — ale F1 při standardním prahu 0.5 na kalibrované pravděpodobnosti spadl na 0.0000, HŮŘ než naivní práh 3.2 i hůř než triviální baseline.** Důvod: při extrémně nízké prevalenci (0.04–0.41 % zdrojů je bot) izotonická regrese správně nikdy nevytvoří pool s průměrem nad 0.5 — i pool obsahující VŠECHNY pozitivní body dohromady má průměrnou pravděpodobnost hluboko pod 0.5, protože pozitiv je v absolutních číslech málo. Model tím pádem u prahu 0.5 nikdy nic neoznačí jako malicious.

**To NENÍ chyba kalibrátoru — je to přesně to, co dobrá kalibrace má dělat** (vrátit realistickou P(malicious), ne nafouknutou). Je to ale důkaz, že **"práh 0.5" je u vzácných jevů (rare-event classification) neplatný koncept** — nízký Brier zde vzniká hlavně tím, že model správně predikuje "téměř nikdy", což je u tak nízké prevalence skoro vždy numericky správné, ne tím, že by uměl rozlišit bota od nebota. Klasický a dobře známý rare-event pitfall, teď přímo změřený na vlastních datech projektu, ne jen citovaný z literatury.

**Co by bylo špatně**: hledat jiný, nižší práh (např. 0.01) proladěním přímo na tomhle eval-setu — znovu stejný cirkulární overfitting problém jako u 3.2.

**Co z toho plyne správně**: u vzácných jevů se práh nemá hledat jako jedno pevné číslo vůbec — patří sem přesně to, co diplomka od začátku identifikuje jako svůj skutečný cíl (VOI/typovaná nejistota ve `verification_planner.rs`/`hypothesis.rs`, ne binární klasifikace s jedním prahem). Tohle je konkrétní, měřený argument PRO tenhle směr, ne proti kalibraci — kalibrace (Brier) funguje přesně podle očekávání, jen ukazuje, že navazující rozhodovací krok nesmí být fixní prah.

## Naměřeno — krok 4: nekruhový LOSO F1-optimální práh (třetí a definitivní pokus)

Námitka proti krokům 2–3 výše: oba použily prah zvolený mimo trénovací data (3.2 z jiné domény, 0.5 z učebnice) — co kdyby se prah zvolil správnou, nekruhovou metodikou — maximalizací F1 **jen na trénovacích foldech** (LOSO, stejná disciplína jako `IsotonicCalibrator::fit(&train)`), a tenhle zmrazený práh pak aplikoval na held-out scénář? To je přesně to, co dělá standardní PR-křivka threshold selection, a NENÍ to cirkulární — held-out scénář nikdy neovlivní, jaký práh se vybere.

```
Botnet-54 held-out: LOSO F1-optimalni prah (z treninku)=494020.518 -> test precision=0.0038 recall=1.0000 f1=0.0077 | naivni (3.2) f1=0.0010 | trivialni baseline f1=0.0008
Botnet-51 held-out: LOSO F1-optimalni prah (z treninku)=704664.166 -> test precision=0.0000 recall=0.0000 f1=0.0000 | naivni (3.2) f1=0.0105 | trivialni baseline f1=0.0082
Botnet-42 held-out: LOSO F1-optimalni prah (z treninku)=77435.366  -> test precision=0.0008 recall=1.0000 f1=0.0015 | naivni (3.2) f1=0.0008 | trivialni baseline f1=0.0007
```

**Výsledek: ani tohle nefunguje — a způsob, jak nefunguje, je sám o sobě informativní.** Vybrané prahy jsou absurdně vysoké (desítky až stovky tisíc) — F1-optimalizace na tréninku najde jediný extrémní odlehlý bod, který v trénovacích datech náhodou perfektně odděluje tu hrstku pozitiv, a zvolí ho jako "optimální" práh. Na Botnet-51 je tenhle přemrštěný práh tak vysoký, že na held-out datech nezachytí NIC (recall=0.0) — naprosté selhání generalizace. To NENÍ chyba implementace F1-optimalizace, je to přímý důsledek **příliš málo trénovacích scénářů (jen 2 v LOSO) vůči extrémní vzácnosti pozitiv** — jeden šťastný bod v tréninku stačí k tomu, aby "optimální" práh byl ve skutečnosti degenerovaný artefakt, ne stabilní hranice.

**Definitivní závěr ze 3 po sobě jdoucích pokusů (naivní přenos → kalibrace+0.5 → nekruhová LOSO F1-optimalizace):** u tohoto skóre, na téhle vzorkové velikosti a téhle míře vzácnosti jevu, **žádná podoba jediného skalárního prahu není spolehlivý způsob, jak z LIFT/PR-AUC zlepšení (prokazatelně reálného) udělat klasifikaci**. To nevyvrací hodnotu zdroj-centrického skóre — LIFT 24–90× zůstává naměřený, reprodukovatelný a konzistentní přes všechny 3 scénáře. Vyvrací to konkrétně **binární prah jako rozhodovací mechanismus** pro tenhle typ vzácného jevu. To je přesně ten typ zjištění, který návrhový dokument diplomky od začátku předjímá jako důvod pro VOI/typovanou nejistotu (`verification_planner.rs`, `hypothesis.rs`) místo pevných prahů — teď s konkrétním, měřeným, trojnásobně potvrzeným argumentem proč, ne jen teoretickým zdůvodněním.

## Co z tohoto plyne — konkrétní další krok

1. **Toto je zatím diagnostický nástroj, ne zapojený detektor.** `score_source_hosts` běží jen v testu, ne v `detect_connection_anomalies`/produkčním rozhodování — a na základě kroku 4 výše by zapojení přes jediný pevný práh bylo vědomě špatné rozhodnutí, ne jen nedodělané.
2. **Čtyři zjištění dohromady**: (a) ranking (PR-AUC/LIFT) je prokazatelně silný, (b) naivní threshold-transfer mezi doménami agregace nefunguje, (c) kalibrovaná pravděpodobnost s "učebnicovým" prahem 0.5 nefunguje u tak vzácného jevu, (d) ani nekruhová LOSO F1-optimalizace prahu nefunguje (degeneruje na přeučení na 1 odlehlý bod při jen 2 trénovacích scénářích). F1 jako metrika "porazilo/neporazilo triviální baseline" je u zdroj-centrické klasifikace **špatně položená otázka při jakékoliv podobě fixního prahu** — ne jen při naivní. Správná metrika zůstává LIFT/PR-AUC (threshold-independent); správný další krok není pátý pokus o práh, ale přechod rozhodovací logiky na VOI/typovanou nejistotu.
3. **Ground truth na úrovni zdroje vyžaduje jinou definici "known evidence"** — aktuální `GroundTruthLabel`/confusion matrix logika je psaná pro destinace-centrické klíče; přepis na zdroj-centrické vyžaduje paralelní, ne nahrazující, evaluační cestu (žádná regrese v existujících ablacích A-D).

## Honestní omezení

- **PR-AUC lift neznamená automaticky, že výsledná klasifikace (při nějakém prahu) porazí triviální baseline** — jen že RANKING skóre je mnohem lepší než náhodný. Krok 2 výše je nutný k ověření skutečného zlepšení F1.
- **"Počet distinktních cílů" je 1 nový rys** přidaný ad-hoc na základě domény (typický botnet indikátor) — nebyl systematicky srovnáván proti jiným možným rysům (velikost paketů, periodicita, entropie portů), takže zbývá prostor pro další zlepšení.
- ~~3 scénáře, 2 rodiny — stejné omezení jako u všech ostatních CTU-13 měření v tomhle projektu.~~ **Vyřešeno níže (30.10.2026) — rozšířeno na 13 scénářů/7 rodin.**

## Dodatek (30.10.2026): rozšíření na N=13 odhalilo skutečný reálný protipříklad + opraven skrytý nedeterminismus v `pr_auc`

**Důvod rozšíření**: N=3 není statisticky ani datově průkazné. CTU-13 dataset registry rozšířen na všech 13 standardních scénářů (7 různých rodin/technik — viz `dataset-registry.md`).

**Vážnější nález před samotným rozšířením čísel**: `src/eval/stats.rs::pr_auc` zpracovávalo vzorky se **shodným skóre jednotlivě, ne jako skupinu** — u vázaných hodnot pak výsledek závisel na **relativním pořadí vstupu**, které u volajících se skóre uloženým v `HashMap` (`score_source_hosts`, `score_connection_keys`) **není mezi běhy procesu stabilní** (Rust `HashMap` používá per-proces náhodný hash seed). Přímo změřeno: 3 po sobě jdoucí běhy stejného testu na stejných datech daly **8/13, 9/13 a 11/13** scénářů splňujících "lift ≥ 2×" a medián zdroj-centrického liftu se lišil mezi 3.09× a 5.40× — číslo, které se mění mezi spuštěními na identických datech, **nelze nazvat statisticky průkazným**, bez ohledu na velikost N. Opraveno: vázané skóre se teď zpracovává jako jedna skupina (TP/FP připočteny najednou, bod na PR křivce spočítaný jednou za skupinu) — výsledek pak závisí jen na multisetu (skóre, label) dvojic, ne na jejich pořadí. Ověřeno: 4 opakované běhy po opravě dávají bajtově identický výstup. Regresní test (`pr_auc_is_independent_of_input_order_within_tied_scores`) i analogický test pro `IsotonicCalibrator::fit` (`fit_is_independent_of_input_order_within_tied_scores`) — oba ověřeny rozbij→spadne→vrať→projde.

**Po opravě, na N=13**: medián zdroj-centrický lift = **3.09×**, medián destinace-centrický lift = **1.00×** (medián stále potvrzuje hlavní zjištění). ALE **"lift ≥ 2× na KAŽDÉM scénáři" (tvrzení z N=3) už neplatí univerzálně — jen na 8 z 13 scénářů.** Konkrétní, reálný protipříklad: **Botnet-44 (Rbot)** má destinace-centrický lift **6.08×**, zdroj-centrický jen **2.17×** — DESTINACE-centrické skóre je tu lepší. Regresní test (`ctu13_source_centric_scoring_vs_destination_centric_pr_auc_comparison`) byl opraven z "assert na každém jednotlivém scénáři" na "assert na agregátu (medián)" — honestní zúžení tvrzení, ne tiché schování protipříkladu (Botnet-44 je v testovacím výstupu vypsaný stejně jako ostatní).

**Co to znamená**: hlavní zjištění (zdroj-centrické skóre je v průměru/mediánu silnější) **přežilo** rozšíření na 7× větší a rozmanitější vzorek — to zvyšuje důvěru v hlavní závěr. Ale síla tvrzení se musela honestně snížit z "univerzálně platí" na "platí v agregátu, s dokumentovanou výjimkou". To je přesně ten druh korekce, kterou větší dataset má provádět — a je to zapsáno jako nalezení, ne jako něco co se má schovat.

## Dodatek (31.10.2026): formální statistická signifikance potvrzuje "agregátně platí"

"Medián je vyšší" ještě není "statisticky průkazně vyšší". `src/eval/stats.rs::wilcoxon_signed_rank_test` (párový Wilcoxonův znaménkový pořadový test, exaktní p-hodnota) aplikován na `zdroj_lift[i] - destinace_lift[i]` přes všech 13 scénářů: **n_effective=13, W=11.0, p=0.013428**.

Statisticky významné na běžné hladině α=0.05, i přes zdokumentovaný protipříklad Botnet-44. To formálně potvrzuje, že "zdroj-centrický lift je v agregátu vyšší" není artefakt výběru mediánu nebo náhody na malém vzorku — je to měřitelný, signifikantní efekt přes celou dostupnou sadu. Reprodukce: `cargo test --lib ctu13_source_centric_scoring_vs_destination_centric_pr_auc_comparison -- --ignored --nocapture`.
