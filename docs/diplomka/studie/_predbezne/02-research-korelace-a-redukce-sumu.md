# Research: korelační engine s minimem falešných nálezů a sekvenční ověřování

Stav: rešerše z 2026-10-31. Zdroje dohledány přes webové vyhledávání; většina tvrzení vychází ze shrnutí výsledků vyhledávání a abstraktů, plné texty byly čteny jen výjimečně. Proto je u každého tématu uvedena míra důvěry. Čísla jsou citována jen tam, kde je u nich zdroj. Vzorce označené "učebnicový" jsou standardní statistika, kterou tato rešerše nepotvrzovala konkrétním odkazem. Návrhy označené "Návrh (vlastní)" jsou moje inženýrské doporučení, ne tvrzení literatury.

Kontext (z `docs/diplomka/eval/soak-findings.md`, jde o simulaci, ne živé sítě): 210,7 falešných nálezů na síť a den, z toho 75 % `inductive_volume_anomaly` a 22 % `packet_rate_spike`; c2_beacon detekován z 4,7 %, rogue_device 0,2 %; exploit_attempt správný typ 0,0 % (IDS viděl 2 301 z 5 061); lateral_movement správný typ 12,5 %; kalibrace Case Memory podkonfidentní pro p >= 0,6 a překonfidentní pro p 0,1 až 0,5, izotonická kalibrace zatím není zapojena; 68 % plánů ověření je mimo rozpočet.

---

## Shrnutí (nejdůležitější závěry)

1. Reálné SOC mají extrémní poměr šumu: ve studii NCSA (USENIX Security 2024) jen asi 0,01 % ze 24 tis. až 134 tis. alertů denně souviselo se skutečnými útoky a téměř polovina alertů byla "benign trigger", tedy správně zasažené pravidlo s legitimním vysvětlením. Cílem tedy není "méně falešných detekcí" jako takových, ale rozlišit "správně vyvolané, ale neškodné" od "škodlivé". Naše 211 nálezů/den je v tomto světle očekávaný výsledek holých prahů.
2. Nejlépe doložená praxe redukce je risk-based alerting (RBA): jednotlivé slabé signály se nezveřejňují, jen se sčítají do rizika entity (hostu) v časovém okně a alert vzniká až po překročení prahu. Splunk uvádí (vendor claim) snížení objemu o 50 až 90 %. Pro nás: "nález" vzniká z entity, ne z události.
3. Vectra, Splunk i akademické práce se shodují: skórovat entity (hosty), ne jednotlivé detekce, a váhy brát z progrese útoku (kill chain), rychlosti, šíře a důležitosti entity. Vendorská čísla (80 až 85 % snížení šumu) jsou marketing, nepoužívat jako cíl.
4. Provozní události (pád serveru, patch, výpadek senzoru) jsou nejlevněji řešitelné explicitním "kontextovým potlačením": změna, kterou lze vysvětlit známou událostí (výpadek senzoru, údržbové okno, hromadná změna u celé peer-group), se neřeší prahem, ale kontextovým modelem. Peer-group srovnání (zvedla se celá skupina) je robustnější než absolutní práh.
5. Pro objemové anomálie nahradit pevný/průměrový práh robustním baseline se sezónností (týdenní a denní profil, medián a MAD, případně S-H-ESD z Twitteru, 2017) a požadovat trvání (CUSUM/EWMA). Statistika je učebnicová, vhodná pro Rust bez ML.
6. Při tisících hostů je každý host testem; bez korekce multiplicity vznikne šum čistě statisticky. Benjamini-Hochberg (FDR) je standardní filtr, Benjamini-Yekutieli pro závislé hosty, online varianty (SAFFRON, alpha-investing) pro proud alertů. Konformní kalibrace dává práh s garancí FP míry, ale předpokládá výměnnost, kterou síťový provoz porušuje; použít opatrně a po režimech.
7. Sekvenční ověřování ("proklepávání") má pevný teoretický základ: Waldův SPRT (rozhodne při překročení prahů dle zadaných chyb alfa a beta, minimalizuje očekávaný počet pozorování) a bayesovská varianta s log-likelihood ratio. Předpoklad nezávislosti pozorování v praxi neplatí, proto nezávislost vynutit návrhem kontrol (každá kontrola jiný zdroj) a LR pro korelované kontroly snižovat.
8. Pro volbu další kontroly je v literatuře doložen přístup "active learning nad HMM" (KTH, CNS 2022: výběr podle očekávaného snížení entropie víry, až 50 % nižší chyba víry oproti statickým strategiím) a omezená optimalizace výběru alertů (Shah et al., 2019). To odpovídá našemu EVOI; potřebuje ale cenu kontroly a rozpočet.
9. Beaconing: RITA kombinuje skóre intervalů (šikmost Bowleyho, rozptyl přes MAD, počet spojení) a skóre velikostí dat. Reimplementace RITA v5 uvádí váhy 0,45/0,35/0,20 (interval/velikost/trvání) a minimálně 10 pozorování na pár. Naše 4,7 % detekce souvisí pravděpodobně s tím, že jitter a nízká četnost spojení potřebují delší okno (hodiny až dny), ne s prahy.
10. DNS tunelování: praktické signály jsou entropie subdomény, délka dotazu, poměr NXDOMAIN a objem unikátních subdomén na doménu; prahy v blozích (entropie 3,5 až 4,0 bitu/znak, label > 50 znaků) nejsou validované a nutně se ladí na vlastní baseline.
11. Laterální pohyb: nejsilnější nízkonákladový signál je nová hrana v grafu připojení (first-seen pair) pro dvojici (zdroj, služba/port) s váhou podle vzácnosti, kombinovaná s autentizačními logy. Na LANL vyšlo Bowman et al. (RAID 2020) 85 % TPR při 0,9 % FPR s embeddingy, ale pozdější kritika ukazuje nadhodnocení kvůli NTLM filtru. Nové hrany jsou běžné (přes 5 000 nových hran za období v LANL, Jbeil), takže samotná novost nestačí.
12. Datasety: CICIDS2017 má doložené chyby v generování provozu, tvorbě toků, extrakci příznaků i značkování; Engelen et al. (2021) po opravě mění přes 20 % stop. Platí obecně: veřejné datasety jsou vhodné k regresním testům detektorů, ne k odhadu FP na provozu reálné sítě. Skládat test z (a) čistého reálného pozadí, (b) vložených útoků se známým ground truth, (c) provozních událostí.
13. Dempster-Shafer pro nás nedoporučuji jako jádro: předpokládá stejně spolehlivé zdroje a při silném konfliktu dává kontraintuitivní výsledky (Zadehův paradox). Pro bezpečnost je lepší bayesovský log-odds model s explicitní korelační korekcí a "noisy-OR" pro více příčin; DS lze použít jen pro vizualizaci "neznámého" (typovaná nejistota je už v produktu).
14. Spojení zdrojů je nejlevnější zdroj přesnosti: Suricata flow_id/community_id propojí alert se Zeek conn.log; ale community_id se může mezi sensory lišit (hlášený případ ve fóru Suricata), proto vždy ověřit a mít záložní join 5-tice + čas.
15. Největší očekávaný zisk na naši situaci (návrh vlastní): (1) entitní risk skóre s trváním, (2) robustní sezónní baseline s peer-group, (3) kontextové potlačení provozních událostí, (4) FDR/rozpočet alertů na síť, (5) SPRT-smyčka ověřování s pravidly zastavení, (6) teprve potom specializované detektory (beacon, lateral, rogue) a kalibrace.

---

## 1. Alert fatigue a redukce falešných poplachů

### Co říká literatura a praxe

**Měřený poměr šumu v reálném SOC.** Yang et al., "True Attacks, Attack Attempts, or Benign Triggers? An Empirical Measurement of Network Alerts in a Security Operations Center", USENIX Security 2024. Data: 115 617 526 alertů z NCSA SOC za 4 roky (2018 až 2022), 227 ověřených incidentních hlášení. Zjištění: 24 tis. až 134 tis. alertů denně, jen 0,01 % souvisí se skutečnými útoky; 27 % jsou "attack attempts" (útok bez kompromitace); asi 48,9 % důvodů spuštění tvoří "benign triggers" (správně zasažený signál, ale s obchodním vysvětlením, údaj ze slajdů autorů). Většinu skutečných útoků SOC odhalí ve stejný den, ale následné vyšetřování trvá v průměru 53 dnů. URL: https://www.usenix.org/conference/usenixsecurity24/presentation/yang-limin , slajdy https://usenix.org/system/files/usenixsecurity24_slides-yang-limin.pdf . Poznámka: stránka IBM uvádí tutéž práci chybně s ICML; věřit USENIX. Důvěra: střední až vysoká (z abstraktu a slajdů, plný text nečten).

**Starší průzkum SOC.** IDC/FireEye (průzkum podzim 2020, zveřejněn 2021): analytici tráví téměř polovinu času false positives; respondenti odhadovali 45 % alertů jako FP, MSSP 53 %. Jde o subjektivní odhad respondentů, ne měření. URL: https://www.cybersecuritydive.com/news/security-alert-analyst-SOC-idc-fireeye/595111/ (2021). Důvěra: nízká jako kvantitativní zdroj. Totéž platí pro často citovaných "83 %" (Vectra, 2023, jen sekundární zdroj): nebrat jako měřený poměr.

**Risk-based alerting (Splunk ES).** Mechanismus: pozorování se zapisují jako "risk attributions" k objektu (uživatel, systém), neotvírají se jako alert. Agregované skóre = součet rizik objektu v časovém okně; alert vzniká po překročení prahu (příklad z Splunk solution guide: 100 bodů za 24 hodin). Vestavěná pravidla navíc spouští při událostech z více sourcetype za 3 dny a při více taktikách MITRE ATT&CK za 7 dní. Skóre se snižuje podle atributů (známý obchodní provoz), běžný start je jednotná hodnota 10. Splunk v komunitní FAQ uvádí snížení objemu alertů o 50 až 90 % (vendor claim, neověřeno nezávisle). URL: https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Implementing_risk-based_alerting , https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.1/mission-control/analyze-risk-with-risk-based-alerting-in-splunk-enterprise-security , https://community.splunk.com/t5/Splunk-Enterprise-Security/Risk-Based-Alerting-FAQs/td-p/668170 (2023 až 2025). Důvěra: vysoká na mechanismus, nízká na číslo.

**NDR entitní skórování (Vectra).** Dokumentace popisuje jediné "Urgency score" vážené z behaviorálního důkazu, progrese útoku, rychlosti, závažnosti, vzácnosti, šíře a důležitosti entity; starší model byl Threat x Certainty. Vendor uvádí snížení šumu 80 až 85 % (marketing). URL: https://docs.vectra.ai/reference/ai-driven-priortization-faq , https://www.vectra.ai/blog/how-vectra-ai-scoring-helps-security-teams-focus-on-what-matters-first (2023 až 2025). Důvěra: střední na strukturu skóre, nízká na čísla.

**Sigma korelační pravidla.** Specifikace korelací definuje `event_count` (počet shod v okně, group-by), `value_count` (počet unikátních hodnot pole), `temporal` a `temporal_ordered` (více pravidel v okně, volitelně v pořadí); operátory gt/gte/lt/lte/eq/neq. Existuje Rust implementace (crate `rsigma-eval`) držící stav po oknech. Poznámka: nepodařilo se mi dohledat oficiální specifikaci, jen vendor dokumentaci (Sekoia) a crate. URL: https://docs.sekoia.io/xdr/features/detect/sigma , https://docs.rs/crate/rsigma-eval/0.9.0/source/src/correlation/window.rs . Důvěra: střední.

**Korelace do incidentů a ATT&CK seskupování.** Práce: Muñoz-Calle et al. (J. Universal Computer Science, září 2024): víceúrovňová korelace alertů na jeden alert za útok; Ferazza et al. (Int. J. Information Security): bezdozorový rámec meta-alertů s ATT&CK, snížení objemu triáže bez ztráty kritických hrozeb; arXiv 2101.02573 (2021): sloučení alertů stejného kroku, propojení podle taktik, rozdělení grafu na incidenty, testováno na DARPA 2000. Většina je ověřena na laboratorních/cvičných datech, ne produkční SOC; praktici upozorňují, že pravidlová korelace závislá na jednotném ATT&CK tagování je křehká. URL: https://doaj.org/article/44fbb4987ec04872b55b15a25b0ce328 , https://arxiv.org/pdf/2101.02573.pdf . Důvěra: nízká až střední.

**Obecný kontext ML v IDS.** Sommer a Paxson, "Outside the Closed World", IEEE S&P 2010: ML v detekci je těžší než jinde kvůli ceně chyb, nedostatku trénovacích dat, rozmanitosti provozu a "semantic gap" (výsledek nejde interpretovat provozně). Závěr: nutné rozumět tomu, co systém umí a neumí odhalit, ne black box. URL: https://www1.icsi.berkeley.edu/pubs/networking/outsidethe10.pdf (2010, klasika). Důvěra: vysoká.

### Konkrétní metoda
Risk skóre entity E v okně W: `R(E,W) = sum_i w_i * s_i * decay(t - t_i)`, kde s_i je skóre signálu, w_i váha podle typu a spolehlivosti zdroje. Alert se vydá při `R >= theta` nebo při pokrytí >= k různých taktik/kategorií. Deduplikace: klíč (entita, kategorie, okno), opakované signály téhož pravidla se počítají s klesající váhou (např. `s * 1/(1+log n)`), aby jedno hlasité pravidlo nepřebilo ostatní. (Návrh vlastní; Splunk dokumentuje součet, ne konkrétní útlum.)

### Vhodnost pro naše omezení
Velmi vhodné: žádné ML, plná vysvětlitelnost (seznam příspěvků k skóre), levný stav na entitu. Riziko: ruční váhy; řešit kalibrací z Case Memory (verdikty) místo ručního ladění.

### Míra důvěry
Mechanismus RBA vysoká; kvantitativní přínosy nízká (vendor). Doporučuji měřit vlastní přínos na soak v2 a necitovat vendor procenta jako cíl.

---

## 2. Statistické základy

### Adaptivní prahy a baseline
- **Robustní z-skóre (MAD):** `z = 0,6745 * (x - median) / MAD` (učebnicový vzorec; konstanta 0,6745 převádí MAD na směrodatnou odchylku normálního rozdělení). Odolné proti odlehlým hodnotám v baseline, na rozdíl od průměr/směrodatná odchylka. Práh typicky 3,5 (Iglewicz-Hoaglin, učebnicově; nepotvrzeno zdrojem v této rešerši).
- **Sezónní dekompozice:** Twitter S-H-ESD (Hochenbaum, Vallis, Kejariwal, 2017, "Automatic Anomaly Detection in the Cloud Via Statistical Learning"): dekompozice na sezónní složku a trend, následně Generalized ESD test na reziduích; "hybrid" varianta používá robustní statistiky kvůli produkčním datům s větším podílem anomálií. URL: https://alphaxiv.org/abs/1704.07706 (2017). Potvrzeno z popisu, detail MAD ve zdrojích nepotvrzen. Důvěra: střední.
- **EWMA a CUSUM** (učebnicově, SPC): EWMA `z_t = lambda*x_t + (1-lambda)*z_{t-1}`, typicky lambda 0,05 až 0,3; CUSUM `S_t = max(0, S_{t-1} + (x_t - mu0 - k))`, alarm při `S_t > h`, kde k přibližně polovina posunu, který chceme zachytit. Výhoda CUSUM: detekuje trvalý malý posun, nereaguje na izolovaný špičkový bod, což přímo cílí na naše `packet_rate_spike` (22 % FP). Nezdrojováno v této rešerši.
- **Peer-group baseline:** porovnat hosta s jeho skupinou (role, VLAN, typ zařízení) ve stejném čase. Pokud se zvedne celá skupina, jde o provozní/kontextovou událost (patch, update, flash crowd), ne o anomálii hosta. Návrh vlastní, zdrojem opřený jen nepřímo (princip peer-group analytiky u NDR).
- **Změnové body:** pro detekci trvalé změny režimu (nová role serveru, přesun služby) použít CUSUM/PELT; po detekci změny baseline přeučit, nevydávat anomálie dlouhodobě. Nezdrojováno zde.

### Multiple testing (FDR)
Z tisíců hostů každý interval vznikají tisíce testů. Přehled: Bonferroni a podobné řízení FWER je příliš konzervativní pro detekci; FDR odpovídá provozní otázce "jaký podíl alertů je falešný". BH je konzervativní při obecné závislosti, Benjamini-Yekutieli je korekce; pro proud alertů existují online procedury (Javanmard-Montanari, SAFFRON). Pozor: BH má nízkou sílu u konformních p-hodnot (arXiv 2312.01969). Existuje Rust crate s BH (`anomalyx-detect`) jako referenční implementace. URL: https://arxiv.org/pdf/2605.13642 , https://arxiv.org/pdf/2009.03117 , https://arxiv.org/pdf/2112.03196 , https://ar5iv.labs.arxiv.org/html/2312.01969 , https://docs.rs/crate/anomalyx-detect/1.0.0/source/src/fdr.rs (2020 až 2026, část preprinty). Důvěra: střední (zdroje obecné, ne bezpečnostní benchmark; benchmark pro infrastrukturní hosty jsem nenašel).

BH postup (učebnicový): seřadit p-hodnoty p(1) <= ... <= p(m), najít největší k, kde `p(k) <= (k/m) * q`, zamítnout (= alertovat) prvních k. Vyžaduje skutečné p-hodnoty z baseline (tail pravděpodobnost z empirického rozdělení), ne libovolná skóre.

### Kalibrace a konformní predikce
- Fisch et al., "Conformal Prediction Sets with Limited False Positives" (ICML 2022): omezuje počet falešně pozitivních prvků v predikční množině. https://arxiv.org/abs/2202.07650 . 
- IDS-specifické práce jsou nové a většinou preprinty: CALIBURN (2026, konformní řízení rizika pro streamovací NIDS, rozpočet alertů alfa mapuje na práh s omezenou FP, výkon silně závisí na prevalenci útoků; testováno na LITNET-2020, CICIDS2017, UNSW-NB15), kovariančně vědomý konformní detektor pro O-RAN (ICML 2026). URL: https://www.alphaxiv.org/abs/2605.24696 , https://icml.cc/virtual/2026/78428 . Důvěra: nízká (preprinty, nepřezkoumáno).
- Zásadní omezení: garance předpokládá výměnnost (exchangeability), kterou síťový provoz (sezónnost, drift) porušuje. Praktické řešení: kalibrovat po režimech (hodina/den v týdnu, role) na čistém okně.
- **Kalibrace pravděpodobností:** izotonická regrese (neparametrická, potřebuje stovky vzorků) nebo Platt (logistická, málo dat). Naše Case Memory má už 48,4 M predikcí a systematickou chybu kalibrace (soak): izotonickou kalibraci zapojit je levná oprava. Důvěra v metodu vysoká (učebnicová), v konkrétní zisk nutno změřit.

### Bayesovské kombinování důkazů
- **Naive Bayes v log-odds tvaru:** `log O(H|e1..en) = log O(H) + sum_i log LR_i`. Přidává důkazy snadno a je vysvětlitelné (každé LR je příspěvek), ale při korelovaných důkazech (několik signálů z téhož toku) počítá dvakrát a je překonfidentní. Obecně známý problém; v tomto vyhledávání jsem pro bezpečnostní kontext nenašel zdroj, který to kvantifikuje. 
- **Noisy-OR:** model více nezávislých příčin jedné události, `P(y=1) = 1 - (1-leak) * prod(1 - p_i)`. Dobré pro "alespoň jedna z N nezávislých indikací je skutečná". Ve vyhledávání jsem nenašel bezpečnostní zdroj výslovně k noisy-OR (jen obecné bayesovské sítě).
- **Bayesovské sítě:** Zhai, Ning, Iyer, Reeves (NC State, ACSAC 2004 / TR-2004-25) oddělují důkaz událostní (IDS alerty) a stavový (efekty na systému, vulnerability scan) a spojují je v Bayesovské síti; tvrdí, že doplňková pozorování snižují míru falešných alertů. URL: https://repository.lib.ncsu.edu/items/00821713-d7e8-4dc0-b200-25c649d901a7 , https://techrep.csc.ncsu.edu/2004/TR-2004-25.pdf (2004, starší). Důvěra: střední (stará, ale princip platí).
- **Praktická korekce korelace (Návrh vlastní):** skupiny důkazů ze stejného zdroje/toku sloučit do jedné skupiny a do součtu započítat jen max (nebo max + 0,3 * ostatní) LR skupiny. Cap na celkový log-LR z jedné nezávislé skupiny.

### Dempster-Shafer
Kritika v IDS literatuře: pravidlo kombinace předpokládá stejnou důvěryhodnost zdrojů, nezahrnuje spolehlivost zdroje, při silném konfliktu dává kontraintuitivní výsledky (Zadehův paradox); navrženy váhované úpravy (např. rozšířená DS pro fúzi alertů, DSmT). Studie s DS na KDD99/DARPA jsou stará data a malé. URL: https://arxiv.org/pdf/2103.08585 , https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/AlertFusion-ACMSE2005.pdf , https://arxiv.org/pdf/math/0404371 . Důvěra: střední. Doporučení: nepoužívat jako jádro.

### Vhodnost pro naše omezení
Vše je výpočetně triviální (kvantily, součty), vhodné pro Rust a vysvětlitelné. Největší zisk: MAD + sezónnost + CUSUM + peer-group (cílí na 75 % + 22 % FP), potom BH/rozpočet alertů.

### Míra důvěry
Metody vysoká (učebnicové); jejich konkrétní přínos na našich datech nutno změřit; konformní kalibrace nízká (preprinty).

---

## 3. Sekvenční ověřování ("proklepávání")

### Co říká literatura
- **SPRT (Wald):** online test, který po každém pozorování aktualizuje poměr věrohodností a zastaví, když překročí práh; uživatel předem zadá míry chyb (falešný alarm alfa, zmeškání beta) a menší chyby vyžadují víc pozorování; Waldovo optimum: mezi testy se stejnými chybami minimalizuje očekávaný počet pozorování. Použito v detekci kompromitovaných počítačů (patentová rodina), kombinace autoenkodéru a SPRT pro IoT (arXiv 2404.13690, 2024), produktová implementace Oracle MSET-SPRT. Předpoklady: nezávislá pozorování a známá rozdělení; v reálných proudech alertů to neplatí (korelace, shluky), proto se garance chyb musí chápat jako přibližné. Pro omezenou dobu rozhodnutí existují zkrácené SPRT. URL: https://arxiv.org/pdf/2404.13690 , https://docs.oracle.com/en/database/oracle/machine-learning/oml4sql/21/dmcon/mset-sprt.html . Důvěra: vysoká na teorii, střední na bezpečnostní použití.
- **Výběr alertu/kontroly podle informace:** Kim, Dán et al. (KTH), "Active learning for alert prioritization", CNS 2022: alerty modelovány přes skrytý Markovův model, politiky vybírají alert s největším očekávaným snížením entropie víry; až 50 % nižší chyba víry oproti statickým strategiím, robustní vůči vysoké míře falešných alertů a chybám šetření. URL: https://people.kth.se/~gyuri/Pub/KimD_ActiveLearningAlertPrio_CNS2022.pdf (2022). Důvěra: střední.
- **Omezená optimalizace výběru:** Shah et al., "A Two-Step Approach to Optimal Selection of Alerts for Investigation in a CSOC", IEEE TIFS 2019: složené riziko alertu + optimalizace výběru při omezených zdrojích analytiků. Důvěra: střední (z abstraktu).
- **POMDP pro obranu:** arXiv 2507.15163 (2025): adaptivní bezpečnostní politiky přes agregaci víry a rollout, IDS alerty jako pozorování; POMDP politika přirozeně používá VoI. Bandit formulace pro triáž alertů ve vyhledávání nenalezena. Důvěra: nízká až střední.
- **SOC triage ladder a SOAR:** praxe obohacení (threat intel, passive DNS, JA3/JA4, reputace, WHOIS stáří domény) před eskalací na člověka; v této rešerši nenalezen recenzovaný zdroj s měřeným dopadem, jen produktové popisy. Nelze citovat čísla.

### Konkrétní návrh sekvenčního ověřování (Návrh vlastní, postavený na SPRT a EVOI)
Stav hypotézy h: log-odds `L_h`. Počáteční `L_0 = log(prior/(1-prior))` z kalibrovaného skóre z kroku 1 a 2.

1. **Kandidát:** nález se nevydává uživateli, vzniká hypotéza se stavem "otevřená".
2. **Žebříček kontrol** seřazený podle `EVOI_c / cost_c` (očekávané snížení entropie nebo nákladů rozhodnutí děleno cenou kontroly), s rozpočtem na síť a čas. Cenu tvoří: aktivita proti síti (nmap vs. pasivní dotaz), latence, riziko rušení. Pasivní/levné kontroly první (obohacení z již uložených dat, passive DNS, JA4, reputace, historie hostu), aktivní (nmap, nuclei) až když LR levných nestačí.
3. Po každé kontrole `L_h += log LR_c`, kde `LR_c = P(výsledek|H1)/P(výsledek|H0)` je z kalibrované tabulky kontroly (z Case Memory, dělená podle typu hypotézy). U kontrol, jejichž výsledky nejsou nezávislé (stejný zdroj dat), použít snížení LR (viz téma 2).
4. **Pravidla zastavení (Wald):** `A = (1-beta)/alfa`, `B = beta/(1-alfa)` (učebnicový tvar). Práh potvrzení `L_h >= log A`, práh vyvrácení `L_h <= log B`. Příklad: alfa 0,01 a beta 0,1 dává log A přibližně 4,5 a log B přibližně -2,3 (výpočet vlastní). Mezi prahy pokračovat.
5. **Další pravidla zastavení:** (a) rozpočet kontrol vyčerpán nebo EVOI/cost pod min. hodnotou, výsledek "nerozhodnuto" s typovanou nejistotou (ne tiše zahodit, ne vydat); (b) maximální počet kroků (zkrácený SPRT) a maximální doba (u kontinuálního jevu sledovat dál pasivně); (c) při nesouladu kontrol (silný konflikt) eskalovat na člověka; (d) zásah (blokace IP) jen při potvrzení nad prahem a po schválení.
6. **Pivoting:** hypotéza na hostu A smí vytvořit potomky (hosté, se kterými A nově komunikuje), ale s tlumením: `prior_child = prior_parent * propagace` (např. 0,3 až 0,5, volit z dat) a hloubkou omezit (např. 2 až 3). Cíl: poskakovat jen po hranách s nově vzniklou nebo vzácnou komunikací. Zabraňuje explozi fronty.
7. **Dvojí brána vydání:** uživatel vidí nález při `L_h >= log A` (potvrzeno) nebo jako "nerozhodnuto, doporučená akce" při velké důležitosti entity; samotné slabé skóre se agreguje do rizika entity (téma 1), nikdy není nález.
8. **Učení:** každý uzavřený případ upraví tabulky LR_c (s ochranou před otrávením, kterou už máme, 99,4 % zachyceno v soak). Kalibrovat LR izotonicky.

### Vhodnost
Plně slučitelné s naším EVOI a hypotézami. Hlavní riziko: zdroje LR_c jsou v počátku slabé (málo dat); začít s ručními konzervativními LR a nechat Case Memory je nahradit. Měřit stejně jako v soak: počet kontrol na nález, podíl rozhodnutých, časy.

### Míra důvěry
Teorie vysoká, konkrétní nastavení parametrů je hypotéza k ověření.

---

## 4. Detekce pomalých a skrytých jevů

### Beaconing
- RITA: skóre složeno ze skóre intervalů a velikostí dat; skóre intervalů průměruje šikmost (Bowley), rozptyl (median absolute deviation) a skóre počtu spojení; malá velikost dat zvyšuje pravděpodobnost beaconu; reimplementace RITA v5 (crate flowscope) váží ts 0,45, ds 0,35, trvání 0,20, vyžaduje alespoň 10 pozorování na pár a nereprodukuje histogramovou/modální složku; RITA při nedostatku spojení vrací skóre 0 místo nejistoty (hodnocení 2026). Jitter oslabuje metriky rozptylu; Active Countermeasures doporučuje dívat se na signál ve velkých časových blocích, což jitter normalizuje. URL: https://docs.rs/crate/flowscope/0.22.0/source/src/detect/patterns/rita_beacon.rs , https://www.activecountermeasures.com/detecting-beacons-with-jitter/ , https://activecm.github.io/threat-hunting-labs/beacons , https://arxiv.org/pdf/2609.19091 . Důvěra: střední (sekundární; primární kód je `analysis/beacons.go` v repozitáři activecm/rita, nečten).
- Zkušenost z naší simulace (4,7 % detekce, medián latence 60 min) ukazuje: detektor potřebuje agregaci přes dlouhé okno na pár (zdroj, cíl, port) a zpracování stavu mezi cykly. Doporučení (vlastní): držet pro každý pár streamovaný sketch (počet, součty intervalů, histogram intervalů s log kontejnery, medián/MAD odhad), bez ukládání všech toků. Frekvenční analýza (DFT na binovaných počtech) pomáhá u jitteru; zdroj: popisy "hunting for beaconing with frequency analysis" jsou nekvalitní agregátory, nebrat jako zdroj. 
- Falešné nálezy beaconu: legitimní periodika (NTP, aktualizace, monitoring, cloud agenti) vyřadit allowlistem podle cíle/JA4/role a peer-group frekvence (periodika, která vidí mnoho hostů, nejsou beacon). Nový periodický pár u jediného hosta je silnější.

### DNS tunelování
Praktické příznaky: entropie subdomény (3,5 až 4,0 bitu na znak), délka labelu > 50 znaků, poměr NXDOMAIN, počet unikátních subdomén na doménu; vstup Zeek dns.log. Vendor (Infoblox) hlásí 99,9 % přesnost kombinace CNN autoenkodéru a statistik, nevalidováno nezávisle. Prahy v praktických návodech nejsou validované, ladit na vlastní baseline. NXDOMAIN je sekundární (vzniká i u DGA a překlepů). URL: https://www.infoblox.com/blog/?p=12885 , https://cyberdefenders.org/blog/dns-tunneling-detection/ (neuvedeno datum, hodnotit nízce). Důvěra: nízká až střední. V naší simulaci je dns_tunnel již 99,8 %; nesoustředit tu úsilí.

### Exfiltrace
Signály: asymetrie odesláno/přijato, objem oproti baseline hosta a peer-group, nový cíl, čas mimo běžnou dobu. Soak zjistil, že produkční parser zahazuje toky mimo scope, takže exfiltrace je v produkci slepá (0,0 % pořadí zdroje, 42,1 % s egress): oprava telemetrie je důležitější než nový detektor. (Vlastní zdroj: soak-findings.) Zdroj z literatury k prahům jsem nenašel.

### Laterální pohyb
Viz téma 5 (graf). Dodatek: kombinovat first-seen pair (zdroj, cíl, port/služba) s autentizačním logem (Kerberos, NTLM, SMB, RDP). LANL kritika: lateral movement v LANL koinciduje s NTLM událostmi, takže filtr jen na NTLM nadhodnocuje výkon (arXiv 2504.13527).

### Reverse shell
Příznaky: dlouhé interaktivní spojení, odchozí na neobvyklý port, malé pakety oběma směry s nepravidelným časem (lidská interaktivita), spojení z hosta, který běžně neiniciuje outbound. V rešerši jsem nenašel recenzovaný zdroj s validovanými prahy; to je zbývající nejistota. Návrh: poměr malých paketů obousměrně a doba bez přerušení nad medián hostu, jako slabý signál vstupující do risk skóre, ne jako samostatný nález.

### Rogue device
Doložené techniky (patent US 8000698 a rodina): asociace, MAC test, ARP test, test replay, korelace a DHCP fingerprinting (typ zařízení z DHCP požadavků a porovnání s povolenými typy); databáze známých zařízení se buduje z ARP požadavků a MAC adres. Autoři přiznávají, že jednoduché přístupy mají false positives i negatives. Praktický vzor: "neautorizované" není "rogue", dokud není ověřeno (vendor). URL: https://patents.justia.com/patent/8000698 , https://www.manageengine.com/eu/products/oputils/rogue-detection-tool.html (patent starší, vendor marketing). Důvěra: nízká až střední. Naše 0,2 % detekce rogue je pravděpodobně chyba pokrytí zdrojů (DHCP/ARP) a identity (8,7 % falešného rozdělení identit při churnu), ne chybějící algoritmus. Hypotéza k ověření: nové zařízení, které se na síti poprvé objeví a nemá DHCP/ARP historii, vstupuje do žebříčku ověřování (SPRT) místo přímého nálezu.

### Vhodnost a důvěra
Všechny zmíněné metody jsou implementovatelné ve streamovacím režimu s malým stavem v Rustu. Důvěra: beaconing střední, ostatní nízká až střední (málo recenzovaných zdrojů s prahy).

---

## 5. Graf a entitní přístup

### Literatura
- **Bowman et al., "Detecting Lateral Movement in Enterprise Computer Networks with Unsupervised Graph AI" (RAID 2020)** a související patent US 11856013: autentizační logy jako graf, bezdozorové embeddingy uzlů, link predictor označuje nepravděpodobné nové autentizační hrany; na LANL (58 dní, přes 12 000 uživatelů, 17 000 počítačů) uvádějí 85 % TPR při 0,9 % FPR. URL: https://www2.seas.gwu.edu/~howie/publications/CyberGraph-RAID20.pdf (poznámka: tento název v odkazu je "CyberGraph RAID20"; shoda autorů a názvu nepotvrzena z textu) a https://patents.google.com/patent/US11856013 . Důvěra: střední.
- **Kritika vyhodnocení LANL:** arXiv 2504.13527 (2025, "Designing a reliable lateral movement detector using a graph foundation model"): dřívější LANL výsledky nadhodnoceny kvůli tomu, že laterální pohyb koinciduje s NTLM událostmi. arXiv 2208.13524 (2022, Lateral Movement Detection Using User Behavioral Analysis). Jbeil (LANL temporální): počet nových hran v dnech 39 až 57 v průměru 5 196,1, tedy novost hrany je častá. LMDetect: heterogenní multigrafy a časové podgrafy (LANL, CERT). URL: https://arxiv.org/pdf/2504.13527 , https://arxiv.org/pdf/2208.13524 . Důvěra: střední.
- Log2vec, ATLAS: v tomto vyhledávání jsem k nim neověřil zdroje; neuvádím tvrzení.

### Realisticky implementovatelné bez ML infrastruktury (Návrh vlastní)
1. **Hranový graf (src, dst, port/služba, protokol)** s počítadly a časem prvního/posledního výskytu. Skóre "novosti" `-log P(hrana)`, kde P z frekvence ve stejné peer-group (hrana, kterou vidí mnoho hostů jako normální, není vzácná).
2. **Fan-out a fan-in:** počet unikátních cílů hosta v okně oproti jeho baseline (MAD) – skenování a laterální pohyb.
3. **Řetězení:** nová hrana A->B krátce po nové příchozí hraně X->A (a pak B->C) naznačuje pivot; to je přesně typ, který chceme sekvenčně ověřovat. Používat jako seeding potomků hypotézy.
4. **Komunity:** označení komunit (např. propagace štítků nebo Louvain na týdenním grafu) a alert na hranu mezi komunitami, které spolu nemluvily. Cena: O(E) a týdenní přepočet, bez GPU.
5. **PageRank-like:** personalizovaný PageRank z podezřelého hosta pro výběr dalších hostů k ověření (pivot ranking). Vhodné pro seřazení fronty, ne pro samostatné alerty.
6. Embeddingy a GNN odložit (potřebují trénink, ztrácí vysvětlitelnost).

### Míra důvěry
Doložené: princip nové hrany a omezení datasetu. Konkrétní implementace jsou návrh, bez benchmarku v našich podmínkách.

---

## 6. Datasety a benchmarky

| Dataset | Validita a známé problémy | Doporučené použití |
|---|---|---|
| CICIDS2017 | Engelen, Rimmer, Joosen (IEEE S&P Workshops 2021): chyby v generování provozu, tvorbě toků, extrakci příznaků i značkování; po opravě je více než 20 % stop přestavěno nebo přeznačeno; autoři vydali upravený CICFlowMeter (TCP tok končí po vzájemné výměně FIN, RST také ukončuje tok). URL: https://lirias.kuleuven.be/retrieve/713070 , https://dblp.uni-trier.de/rec/conf/sp/EngelenRJ21.html | Jen opravená verze (Engelen), jako zdroj útoků, ne pozadí. Nepoužívat k odhadu FP |
| CICIDS2018 | Stejný původ (CIC); dědí metodické slabiny CICFlowMeter. Konkrétní studii ověřující jsem nenašel | Jen pomocně |
| UNSW-NB15 | Chybí šifrované APT a IoT protokoly (IEEE DataPort shrnutí), starší (2015) a laboratorní | Jen regresní test příznaků |
| CTU-13 | Reálný botnet provoz v captures; v tomto vyhledávání jsem nenašel studii o kvalitě štítků | Součást naší kotvy (už používáme); zdroj botnetů a C2 |
| IoT-23 | K jeho nedostatkům jsem zdroj nenašel | Součást naší kotvy; IoT pozadí a malware |
| LANL cyber | Autentizační logy, skutečná data, ale kritika NTLM nadhodnocení (arXiv 2504.13527) | Test laterálního pohybu (celá autentizace, ne jen NTLM) |
| DARPA OpTC, MAWI | V této rešerši nebyla ověřena | Neuvádět tvrzení; OpTC je hostový provoz, MAWI páteřní bez štítků (obecná znalost, nepotvrzeno zdroji) |

Přehledy: Network Intrusion Datasets: A Survey, Limitations, and Recommendations (arXiv 2502.06688, 2025), COMIDDS průběžný přehled 48 datasetů (arXiv 2408.02521, 2024), NetFlow datasety pro ML NIDS (arXiv 2011.09144): příznaky z jednoho datasetu nelze přenést na jiný kvůli rozdílným polím. URL: https://arxiv.org/pdf/2502.06688 , https://arxiv.org/pdf/2408.02521 , https://arxiv.org/pdf/2011.09144 .

**Jak skládat realistický test (Návrh vlastní):**
1. Pozadí: dlouhé čisté reálné nebo realisticky simulované pozadí s denními/týdenními cykly (naše soak v2) pro měření FP/sit-den.
2. Útoky: vkládat reálné captures (CTU-13, IoT-23, opravený CICIDS2017) do pozadí s přepsanými IP, se ground truth na úrovni toku a času.
3. Provozní události jako negativní testy (pád serveru, patch, výpadek senzoru, zpožděná data) s cílem FP míry blízké 0 %.
4. Metriky: FP na sít-den, míra detekce podle rodin (Wilson 95 %), čas do detekce, správný typ, počet kontrol na nález; uvádět zvlášť "nález s ověřením" a "bez ověření".
5. Nepodstatné je ladit na stejných datech, na kterých se hodnotí (rozdělit seedy/scénáře).

Důvěra: vysoká na CICIDS2017 (primární zdroj), střední na LANL, nízká na ostatní.

---

## 7. Praktické kombinace nástrojů a telemetrie

- **community_id** je standardizovaný hash toku, umožňuje pivot mezi Zeek, Suricata, Security Onion, Arkime porovnáním řetězců; specifikace github.com/corelight/community-id-spec. Zeek log `suricata_corelight` nese community_id a uid/id na conn.log. Pozor: forum Suricata hlásí případ, kdy stejná relace měla v Zeek a Suricata různé community_id (Zeek 3.0.5, Suricata 5.0.2, příčina nejasná); praktikové upozorňují na selhání při částečném zachycení, NAT přes obě strany a nekonzistentní směrovosti. Proto join: primárně community_id, záložně 5-tice + čas (tolerance jednotky sekund) a směr normalizovat. URL: https://docs.securityonion.net/en/3/main/community-id/ , https://forum.suricata.io/t/community-flow-id-inconsistency/189 , https://corelight.com/hubfs/resources/zeek-cheatsheets/corelight-cheatsheet-poster.pdf . Důvěra: střední.
- **Suricata EVE JSON:** `flow_id` svazuje alert s flow, fileinfo, http a anomaly záznamy; alert nese `signature_id` a `signature`. Tentýž logging běží bez alertu. URL: https://docs.suricata.io/en/suricata-7.0.15/output/eve/eve-json-format.html . Řízení šumu ET Open (threshold/suppress): zdroj jsem nenašel, zbývá doplnit z dokumentace Suricata.
- **Co které zdroje přidají (Návrh vlastní, opřený o předchozí témata):**
  - Zeek conn.log/NetFlow: objem, periodicita, grafové hrany (základ detektorů 4 a 5).
  - Zeek dns.log: DNS tunelování, DGA, kontext názvu pro IP (passive DNS vlastní).
  - Zeek ssl/x509 + JA3/JA4: identita klienta nezávislá na IP; JA4 je nástupce JA3 se stabilní řazenou extenzí a funguje i pro QUIC; JA4 (klient) je BSD-3, ostatní JA4+ jsou pod FoxIO License 1.1, před vložením do produktu prověřit licenci (právní otázka). Databáze ja4db.com. URL: https://github.com/FoxIO-LLC/ja4 , https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637 (2023). Důvěra: střední (detaily specifikace nečteny).
  - Suricata: signaturní důkaz (exploit_attempt); v soaku IDS viděl 2 301 z 5 061, ale typ `suricata_alert` se nikdy nevydá, tedy chyba mapování alert -> hypotéza, ne chybějící telemetrie.
  - DHCP/ARP: identita zařízení, rogue device, změna MAC/IP (churn 8,7 % falešného rozdělení).
  - Auth logy/Sysmon/EDR: pro laterální pohyb nejsilnější vrstva, ale pro malé sítě často nedostupná; návrh rozlišit "pokrytí zdrojů" v nálezu (nelze vydat "čistý" verdikt při slepém místě).
- **Kontrola kvality telemetrie jako vstup korelace (Návrh vlastní):** sledovat zdraví senzoru (zpoždění, pokles objemu, slepé podsítě); při výpadku senzoru potlačit nálezy "pokles aktivity" a "nový host" a označit okna jako neúplná. To přímo cílí na naší 82 až 100 % FP míru u provozních událostí.

Důvěra: střední.

---

## Srovnávací tabulka přístupů

| Přístup | Přínos (cílí na) | Složitost | Riziko | Poznámka |
|---|---|---|---|---|
| Entitní risk skóre s oknem (RBA) | Velký: dedup + agregace slabých signálů | Nízká | Ruční váhy; skrytí pomalého útoku pod prahem | Základ; váhy z Case Memory |
| Robustní baseline (MAD) + sezónnost + CUSUM | Velký: 75 % + 22 % FP z objemu | Nízká | Chybné sezóny po změně režimu | Přetrénování po změnových bodech |
| Peer-group srovnání | Velký: hromadné provozní události | Nízká až střední | Špatné přiřazení rolí | Navázat na identitu zařízení |
| Kontextové potlačení (údržba, výpadek senzoru, patch) | Velký: provozní FP | Střední | Útočník ve vysvětleném okně | Potlačit kategorie, ne vše |
| FDR (BH/BY) a rozpočet alertů | Střední: stabilizace počtu | Nízká | Nutné skutečné p-hodnoty; ztráta síly | Po zavedení baseline |
| Izotonická kalibrace Case Memory | Střední: správné prahy | Nízká | Málo dat v tříšti | Už chybí podle soaku |
| Konformní řízení FP | Potenciálně velký | Střední | Porušená výměnnost; zdroje jsou preprinty | Po režimech, odložit |
| SPRT-smyčka ověřování | Velký: potvrzení/vyvrácení | Střední | Závislé LR, slabé počáteční tabulky | Hlavní odlišnost produktu |
| EVOI s cenou kontroly | Střední: rozpočet (68 % mimo rozpočet) | Střední | Špatně odhadnuté ceny | Již částečně existuje |
| Beacon sketch na pár (RITA-like) | Velký pro c2 (4,7 %) | Střední | Legitimní periodika; jitter | Allowlist a peer-group |
| Nová hrana v grafu + řetězení | Střední až velký pro lateral | Střední | Běžný churn nových hran | Vážit vzácností |
| Komunity, PageRank pro pořadí pivotů | Malý až střední | Střední | Přepočet grafu | Pro řazení, ne alerty |
| Embeddingy/GNN | Nejasný | Vysoká | Bez vysvětlitelnosti, vyžaduje trénink | Odložit |
| Dempster-Shafer | Malý | Střední | Paradoxy při konfliktu | Nedoporučeno jako jádro |
| Oprava mapování alert -> typ (exploit) | Velký pro 0,0 % typ | Nízká | Žádné | Chyba, ne metoda |

---

## Doporučené pořadí zavedení (Návrh vlastní)

0. **Opravy chyb měření** bez nových metod: mapování `suricata_alert` -> typ exploit_attempt, scope filtr Zeek parseru pro odchozí toky (exfiltrace), churn identity. Nízká cena, jasný efekt.
1. **Agregace do entitního rizika** s deduplikací a okny; nález = překročení prahu nebo pokrytí kategorií (téma 1).
2. **Robustní baseline** pro objemové detektory (MAD, sezónnost, CUSUM, požadavek trvání) a peer-group (téma 2).
3. **Kontextové potlačení** provozních událostí a zdraví senzoru.
4. **Izotonická kalibrace** pravděpodobností z Case Memory; rozpočet alertů na síť přes BH (téma 2).
5. **SPRT-smyčka ověřování** s pravidly zastavení a tlumeným pivotováním (téma 3). Teprve s kalibrací kroku 4.
6. **Specializované detektory:** beacon sketch, nová hrana a řetězení, rogue přes DHCP/ARP jako hypotéza k ověření (témata 4 a 5).
7. **Hodnocení** na složeném testu (téma 6) s cílem FP/sít-den, správný typ, kontrol na nález; teprve poté konformní kalibrace a případné grafové embeddingy.

Zdůvodnění: kroky 0 až 3 odstraňují největší zdroj šumu bez nových dat; krok 5 potřebuje kalibrované LR, jinak SPRT potvrzuje chybně.

---

## Co zůstává nejisté

- Žádný dohledaný zdroj neměří FP poměr NDR produktů (Corelight, Vectra, ExtraHop, Darktrace) nezávisle; veřejná čísla jsou vendorská. Darktrace a ExtraHop jsem nehledal.
- SPRT a závislost důkazů: chybí studie kvantifikující, jak moc korelace alertů porušuje garance chyb v bezpečnostním kontextu; naše korekce (cap na skupinu) je heuristika.
- Konformní řízení FP v NIDS: jen preprinty 2026; praktický přínos při driftu neznámý.
- Prahy pro DNS tunel, reverse shell a exfiltraci nejsou validovány recenzovanými zdroji; ladit na vlastních datech.
- Log2vec, ATLAS, CyberGraph: tvrzení z původních prací neověřena (jen RAID 2020 přes sekundární záznam).
- CTU-13 a IoT-23: nenašel jsem studii o kvalitě štítků ani realismu; DARPA OpTC a MAWI neověřeny.
- Nenalezeno: studie ET Open (kvalita pravidel, doporučení threshold/suppress), bandit formulace triáže, studie o SOAR playbooků s měřeným dopadem, validovaná pravidla "Zeek BeaconDetection".
- Všechny číselné parametry v návrzích (útlum, propagace 0,3 až 0,5, alfa/beta, lambda) jsou výchozí hypotézy, ne doložené hodnoty; nutné vyladit na soak v2 a regresní sadě.
- Jedna formální poznámka: odkazy z vyhledávání jsem nestahoval v plném znění; před citací v diplomové práci ověřit každý odkaz a rok z primárního zdroje.
