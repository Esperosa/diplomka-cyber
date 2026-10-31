# RQ5: Validita benchmarků, syntetických a simulovaných dat a testování bez cirkularity

Verze 1.0, 2026-10-31. Postup podle `../00-protokol.md`. Extrakce je v `extrakce.csv` (63 řádků: 60 V3, 3 V2), dotazy v `hledani.csv`, nepřečtené zdroje v `neovereno.md`. Návrhy z `_predbezne/` nebyly použity jako důkaz.

## Abstrakt

Otázka: jak moc se dá věřit číslům naměřeným na veřejných NIDS datasetech a na syntetických či simulovaných datech, a jak testovat tak, aby autor simulátoru nepotvrzoval sám sebe. Prošli jsme 41 prací v plném textu nebo oficiálním abstraktu. Hlavní zjištění:

1. **Veřejné datasety mají měřené vady, ale oprava výkon nemusí snížit.** V CICIDS2017 je 25,9 % toků artefaktem nástroje CICFlowMeter a přes 20 % stop bylo nutné rekonstruovat nebo přeštítkovat (RQ5-001, 002). Agregované F1 zůstalo po opravě 0,99, ale F1 jednotlivých tříd se měnilo v obou směrech: Bot z 0,60 na 0,99, Infiltration z 0,11 na 0,00 (RQ5-003, 004). Představa, že po opravě „zmizí X % výkonu“, je zjednodušená. Mění se hlavně to, co model skutečně detekuje.
2. **Artefakty dovolí triviálním pravidlům dosáhnout špičkových výsledků.** Na DARPA 1999 detektor jednoho bajtu zachytil 45 % útoků (RQ5-016). Na UNSW-NB15 oddělí třídy s 98% přesností dva příznaky, protokol a TTL (RQ5-006). Na CIC-IDS-2017 rozhodují bity TTL (RQ5-013). Jakmile se do simulace přimíchá reálný provoz, zmizí 58–76 % detekcí PHAD (RQ5-017).
3. **Přenos mezi datasety selhává soustavně.** Průměrné MCC (Matthewsův korelační koeficient) klesá z 94,6 % uvnitř datasetu na 29,4 % mezi datasety (RQ5-034). Další naměřené propady: F1 z 0,83 na 0,56 při vynechání celého datasetu (RQ5-038), přesnost (accuracy) o 25,6 % u nesupervizovaných metod (RQ5-037), F1 z 0,999 na 0,28 při nasazení na reálnou kampusovou síť (RQ5-013). Jedna studie ukazuje, že časové rozdělení dat samo propad způsobit nemusí (−0,009 F1, RQ5-038).
4. **U syntetického provozu nestačí distribuční metriky.** Generátor s nejmenší vzdáleností marginálních rozdělení prošel doménovými testy jen v 0,07–14 % případů (RQ5-045). Model trénovaný na syntetice a testovaný na reálných datech ztratí 26–73 procentních bodů přesnosti i u nejlepšího generátoru (RQ5-046, 047). NetShare se naučil periodický vzor, který v reálných datech není (RQ5-049).
5. **Metodická rizika jsou častá a mají známou velikost.** Sampling bias je aspoň částečně přítomen v 90 % a data snooping v 73 % prací z top konferencí (RQ5-027). Statistickou významnost zmiňují 2 z 30 prací o ML-NIDS (RQ5-040). Nerealistický poměr tříd v testu ztrojnásobí F1 z 0,32 na 0,96 (RQ5-032). Přísné štítkování lateral movement srazí AUC metody Argus z 99,7 na 43,2 (RQ5-025).
6. **Soak harness má několik konkrétních zkreslení z této literatury.**
   - Útočníci a benigní cíle mají oddělené rozsahy veřejných IP, obdoba artefaktu TTL a zdrojových adres.
   - Suricata alerty vznikají jen z útoků.
   - Útočné toky se nevzorkují, benigní ano.
   - Šum je nastavený ručními konstantami.
   - Wilsonovy intervaly považují útoky za nezávislé, i když útoky ve stejné síti nezávislé nejsou.
   - Ladění a test nejsou oddělené žádnými drženými seedy.

   Tato zkreslení se dají změřit a navrhujeme pro ně hypotézy H-1 až H-8.

## Metodika a PRISMA

- **Vyhledávání.** 32 dotazů přes WebSearch (z toho 11 typu „proti“: negeneralizace, chyby, replikace, negativní výsledky) a 2 kola citačního řetězení. Klíčové práce (Engelen 2021, Flood 2024, Arp 2022, Larroche 2026, NetDiffusion) jsme řetězili dozadu i dopředu.
- **Čtení plných textů.** PDF jsme stahovali do izolovaného adresáře a převáděli přes `pdftotext`. Hodnoty jsme brali z tabulek a textu. Kde se tabulka při převodu rozpadla (Arp Tab. 1, Layeghy Obr. 1), vzali jsme jen textová tvrzení, nebo jsme pořadí ověřili proti jiné tabulce (u Layeghyho).
- **Kód soaku.** Kód (`src/soak/`, `src/eval/anchor.rs`, `src/eval/dataset_replay.rs`) jsme prošli pomocí read-only průzkumu. Klíčová místa jsme ručně ověřili. Jedno tvrzení průzkumu se ukázalo jako zastaralé: atribuce podle podřetězce už neplatí, protože `mentions_ip` v `episode.rs:164` porovnává IP přesně.

**PRISMA**

| krok | počet |
|---|---:|
| identifikováno (32 dotazů × 10 výsledků + 12 z řetězení) | 332 |
| po deduplikaci (odhad autora: stejné práce na arXiv, venue a agregátorech) | ≈ 210 |
| po screeningu názvů a abstraktů | 62 |
| plný text zkoušen | 49 |
| zahrnuto (přečteno, relevantní) | 41 |
| z toho V3 / V2 | 38 / 3 |
| zahrnuto do extrakce s číselnou hodnotou | 35 prací, 57 číselných řádků |

Důvody vyloučení po plném textu (8 prací): bez metriky a jen popisné (Brown 2009, Hicks 2026, El Mahdaouy 2026 a Catillo 2023 používáme jen kvalitativně), nedostupný plný text (MAWILab, Kenyon 2020, D'hooge 2020: V1) a čistě marketingové nebo agregátorové stránky (themoonlight.io, emergentmind). Tvrzení výrobců jsme v této RQ nenašli, takže tabulka „Tvrzení výrobců“ je prázdná.

## Výsledky podle podtémat

### (a) Kvalita a chyby veřejných datasetů

| dataset | popsaná vada | velikost | dopad na výsledky | id |
|---|---|---|---|---|
| CICIDS2017 | „TCP appendices“ (chyba CICFlowMeter), neúspěšné útoky („Attempted“) | 25,9 % toků jsou artefakty (u tříd až 50 %), přes 20 % stop opraveno | F1 třídy Bot 0,60 → 0,99, Infiltration 0,11 → 0,00, vážené F1 beze změny 0,99 | 001–005 |
| CICIDS2017 | zkratka TTL (útočníci mimo síť, Kali TTL 64, DDoS z Windows TTL 128) | TTL bity tvoří kořen rozhodovacího stromu | F1 0,999 → 0,282 na kampusové síti | 013 |
| CICIDS2017 Heartbleed | spojení se mezi heartbeaty nikdy nezavřelo | jediný vzor | F1 1,0 → 0,0 po zavření spojení | 014 |
| CICIDS2017 DoS | jediná napadená stránka (výchozí Apache) | 97 % hodnot bwd packet size ≈ 11 595 B ± 1 % | 3 příznaky stačí na F1 0,997 | 007 |
| CICIDS2017 / 2018 | chyby orchestrace, příznaků a štítkování, duplikace paketů | kvalitativně (V2) | – | 062, 063 |
| UNSW-NB15 | TTL a protokol jako artefakty testbedu, překryv tříd | 98 % accuracy jen z 2 příznaků, 40 % Shellcode/Recon shodné s Exploits | výhoda metody ADA 6 % → 1,5 % | 006, 008 |
| KDD99 / NSL-KDD | duplicity | 78 % train, 75 % test | 98 % trénovacích záznamů správně klasifikuje všech 21 modelů | 019, 020 |
| DARPA 1999 | TTL 253 a zdrojové adresy jako artefakt simulace | 29 ze 36 detekcí přes TTL nelegitimních | PHAD 76 → 18–32 detekcí po přimíchání reálného provozu | 016–018 |
| Bot-IoT | obrácená základní četnost, retransmise | 0,00013 % benign, retransmise přes 34 % (běžně do 3 %) | metriky přesnosti nesmyslné | 009, 010, 060 |
| ToN-IoT | DNS a router provoz označený jako útok, duplicitní toky s různými štítky | 55 % (DoS), 28 % (XSS) toků jsou DNS | kvalitativně | 011, 060 |
| CTU-13 | štítek „Botnet“ zahrnuje sken, aktualizace OS označené jako adware | sc. 5: 97,8 % škodlivých toků je nmap | – | 011, 012 |
| DARPA OpTC | chybné actor_id, nepřesné oficiální štítky | 40 % procesů a 4,22 % událostí chybných, škodlivé jen 0,0016 % | F1 GAE 0,52 vs 0,24 podle volby štítků | 021–023 |
| LANL | štítky jen podmnožina red teamu, filtrace NTLM a uživatelů | – | AUC Pikachu 94 → 78,3, AP Argus 32,3 → 0,09 | 024 |

Nenalezeno s plným textem: MAWI (štítky MAWILab vznikají kombinací detektorů, tedy hrozí cirkularita, ale jen V1), CIC-DDoS2019 (samostatný audit nenalezen) a IoT-23 (přímá kritika štítků nenalezena).

**Rozpor.** Opravy datasetů výkon nesnižují jednotně. U Engelena opravy výkon spíš zvyšují, protože odstraní matoucí artefakty (RQ5-003). U Mahoneyho a Larroche výkon klesá, protože se odstraní artefakty, na kterých detekce stála (RQ5-017, 024). Vysvětlení: záleží na tom, jestli artefakt pomáhal (třídy šly díky němu oddělit) nebo škodil (byl šumem v pozitivní třídě). Obecné procento „ztraceného výkonu po opravě“ se proto z literatury určit nedá.

### (b) Přenos mezi datasety (cross-dataset)

| studie | datasety | uvnitř datasetu | mezi datasety | id |
|---|---|---|---|---|
| Cantone 2024 | 4× CIC/LycoS | MCC 94,63 % | MCC 29,35 % (rozsah 10,8–40,2 %) | 034 |
| Layeghy 2022 | 4× NetFlow v2 | F1 77–100 % | F1 od 0,14 % do 94,8 %, silně asymetrické | 035 |
| Apruzzese (XeNIDS) 2022 | 6 datasetů | F1 99,1 % (CTU13) | −20 % na cizích botnetech, DoS 38 % | 036 |
| Verkerken 2022 | CIC17 ↔ CIC18 | AUROC až 0,94 | accuracy −25,6 %, AUROC −27,1 % | 037 |
| BRIDGE 2026 | 5 IoT botnet | F1 0,83 | LODO F1 0,56, časový split jen −0,009 | 038 |
| Jacobs (Trustee) 2022 | CIC17 → kampus UCSB | F1 0,999 | F1 0,282 | 013 |
| Hakim 2026 | 3 IIoT | – | nejvlivnější kategorie portu 96–435× častější ve zdroji | 039 |

Syntéza: 7 studií a 15 různých datasetů. Metriky (MCC, F1, accuracy, AUROC) ani podmínky nejsou srovnatelné, takže uvádíme jen rozsah. Relativní pokles hlavní metriky při přenosu (odhad autora z hodnot v tabulce):
- minimum 20 % (XeNIDS, botnety),
- medián přibližně 30–33 % (Verkerken 25,6 %, BRIDGE 33 %),
- maximum 69–72 % (Cantone, Trustee).

U jednotlivých dvojic datasetů klesá F1 až k nule (Layeghy). Heterogenita je vysoká. Společná příčina, kterou uvádějí čtyři studie (013, 035, 039 a částečně 034): model se opírá o příznaky, které jsou artefaktem konkrétního testbedu (porty, TTL, okna TCP, velikosti paketů).

### (c) Syntetická data a generátory provozu

| generátor | metrika věrnosti | výsledek | známé selhání | id |
|---|---|---|---|---|
| WGAN-GP varianty (Ring 2019) | Euklidovská vzdálenost marginál a 7 doménových testů | baseline z nezávislých marginál má nejmenší vzdálenost (0,0002) | baseline projde Testem 1 jen ve 14 % a Testem 6 v 0,07 % případů | 045 |
| DoppelGANger (Lin 2020) | TSTR (train on synthetic, test on real), rank korelace | 80 % reálné přesnosti, o 43 % lepší než AR | AR model má téměř perfektní rank korelaci i při nekvalitních vzorcích; DP rozbíjí autokorelaci | 042–044 |
| NetShare (Yin 2022) | distribuční metriky | o 46 % lepší než baseline (V2) | TSTR přesnost 0,396 / 0,140 proti 0,86 / 0,648 na reálných datech, přitom JSD 0,16 (měřila konkurence); periodický vzor v rozporu s realitou | 046, 048, 049 |
| NetDiffusion (Jiang 2024) | JSD, TVD, HD a TSTR | JSD 0,04 | TSTR 0,738 / 0,262 proti 1,00 / 0,978 na reálných datech | 047 |
| CascadeNet (Lu 2026) | časové metriky | o 41–76 % lepší | – (vlastní tvrzení autorů) | 049 |
| resampling / GAN augmentace (Wolf 2024) | MCC | většinou pokles | negativní výsledek | 050 |
| simulátor vs cyber range (Nyberg 2026) | míra falešných alertů | simulátor 1 % rovnoměrně, range 0,05–17 % podle kroku | výnosy agentů s benigními uživateli −80 až −109 % | 051, 052 |

Pro CyberBattleSim jsme nenašli žádné měření přenosu do emulace ani do reality. Autoři tento rámec sami označují za zjednodušený, ale to je jen sekundární tvrzení (V1).

### (d) Simulace, emulace a kritéria validity

- **Způsob vzniku datasetů.** Sharafaldin 2018 (CICIDS2017, 25 profilovaných uživatelů, B-Profile) uvádí F1 0,96–0,98 pro RF, ID3 a KNN (RQ5-056). Pozdější audity ukazují, že tato čísla stojí částečně na artefaktech (RQ5-001 až 015).
- **Ring et al. 2019.** Přehled 34 datasetů navrhuje 15 vlastností v 5 kategoriích. Doporučuje testovat na více datasetech, kombinovat emulovaná a reálná data a nepoužívat 10násobnou křížovou validaci, protože sken o tisících tocích se pak ocitne v tréninku i testu (RQ5-061).
- **Goldschmidt & Chudá 2025.** Z 89 datasetů jich má jen 17 % čistě reálný normální provoz a 19 % reálné útoky, od roku 2020 jen 13,7 % (RQ5-057). CIC-IDS2017 používá 29 % prací, většinou v původní chybné verzi (RQ5-058).
- **Mahoney & Chan 2003.** Navrhují přimíchat reálný provoz do simulace. Detekcí pak ubude, ale podíl legitimních detekcí vzroste, u SPADE ze 2/6 na 1/1 (RQ5-017, 018).

### (e) Metodická rizika a doporučení

| riziko | měřená velikost | doporučení | id |
|---|---|---|---|
| sampling bias | v 90 % prací; recall klesne o více než 10–15 % po odstranění | data z cílové distribuce, víc zdrojů | 027, 029 |
| data snooping / leakage | v 73 % prací; 329 článků v 17 oborech | časové oddělení, kalibrace jen na validaci | 027, 059, 053 |
| časová nekonzistence | F1 0,91 → 0,58 a 0,83 → 0,32 | omezení C1–C3, metrika AUT | 031, 033 |
| base rate / poměr tříd v testu | F1 0,32 → 0,96 jen změnou poměru; 99 % TPR při 1 % FPR = 100 FP na 99 TP | realistický poměr v testu, FP vztažené k základní četnosti | 030, 032, 055 |
| nevhodná metrika | AUROC 0,868–0,997 při AP ≤ 0,062; AUC 0,93 při AP 0,024 | AP/PR, MCC, recall při pevném FP | 026, 053 |
| chybějící jednoduchá baseline | boxplot ≥ Kitsune; allowlist ≥ učené PIDS; 3 příznaky = LUCID | vždy porovnat s triviální metodou | 007, 028, 053 |
| absence CI / seedů | statistická významnost ve 2 z 30 prací; 90 % praktiků to považuje za velmi problematické | více běhů, rozptyl, testy | 040, 041 |
| štítkování a předzpracování | změna pořadí metod; F1 0,52 vs 0,24 jen jiné štítky | zveřejnit logiku štítkování, hodnotit na úrovni událostí | 023, 025, 063 |
| replikace na reálném provozu | FP 2 896× vyšší než TP | test na nezávislých reálných datech | 054 |

**Cirkularita.** Literatura ji přímo neměří (viz Co nebylo nalezeno). Nejbližší důkazy jsou dva:
- Mahoney & Chan: simulátor a detektor sdílejí implicitní předpoklad, například o TTL nebo zdrojových adresách, a detektor se pak trefí do artefaktu simulace.
- Nyberg 2026: agent trénovaný v simulátoru s rovnoměrným šumem selže na nerovnoměrném šumu skutečného prostředí.

Obecný princip, který z obou plyne: test musí obsahovat data, která autor detektoru nevytvořil.

## Co z toho přímo platí pro soak harness

Fakta o kódu jsme ověřili v `src/soak/` (stav 2026-10-31). Čísla jsou z `F:\bakula-soak\run-v2-72h\status.md` (3,5 h, 566 sítí, 4 784 virtuálních síť-dnů) a z `docs/diplomka/eval/soak-findings.md`.

| # | zkreslení v soaku | doklad v kódu | obdoba v literatuře | jak změřit | jak odstranit |
|---|---|---|---|---|---|
| S1 | **Oddělené IP pooly.** Útočníci, C2 a exfil cíle mají první oktet z {45, 61, 77, 91, 103, 154, 178, 193, 198}. Benigní egress míří na 12 pevných externích adres s jiným prvním oktetem. | `traffic.rs:392` `public_ip()`; benigní externí cíle v `netmodel.rs` (dle průzkumu) | TTL a zdrojové adresy v DARPA 1999 a CIC17 (016–018, 013); UNSW TTL 98 % (006) | Detektor „1. oktet ∈ útočný pool“ jako triviální baseline; ablace se sdíleným poolem (H-1) | Jeden sdílený pool pro benigní i útočné externí adresy; část benigního egressu na „nové“ IP |
| S2 | **Suricata alerty jen z útoků.** Benigní události alert nevydají, takže každý nález `suricata_alert` je z konstrukce TP. Autorizovaný skener ani patch alert nevyvolají. | alerty jen v `emit_truth`, podmíněno `ids_visible`, benigní pravdy mají `ids_visible: false` (`traffic.rs:903, 2593`) | label leakage (Arp P3); Bad smell „labels leaked via features“ (Flood) | Podíl detekcí, které stojí jen na IDS alertu | Benigní alerty: falešné signatury, ET POLICY a INFO, skener → reálný počet alertů na síť-den |
| S3 | **Útočné toky se nevzorkují, benigní ano**, takže útok je ve velkých sítích relativně hlasitější. | `netmodel.rs:878–881` `flow_sampling()`, komentář „utoky se nevzorkuji“ | sampling bias (027); nerealistický poměr tříd (032) | Detekce podle velikosti sítě se stejným vzorkováním (H-3) | Stejné vzorkování pro útoky, nebo vzorkování až na úrovni senzoru |
| S4 | **Základní četnost.** Na síť-den připadá přibližně 2,66 pozorovatelného útoku (12 724 / 4 784) a útočné toky tvoří přibližně 9,2 % všech toků (36,8 M z 401,7 M). OpTC má škodlivé události s podílem 0,0016 %. | status.md, `plan_episode` (`attack_rate_per_day`) | base rate (030, 055); OpTC (021) | Precision a FP/síť-den přepočtené na realistickou četnost (odhad autora: 0,01–0,1 útoku/síť-den) | Scénáře s řídkými útoky, většina síť-dnů bez útoku (teď jen 20 síť-dnů bez útoku z 4 784) |
| S5 | **Benevolentní atribuce.** Za detekci se počítá jakýkoli nález na kterékoli klíčové IP v okně [start−2, konec+2] cyklů. U horizontálního skenu, ransomwaru a fleet beaconu tvoří klíčové IP stovky obětí. | `episode.rs:710–711`; `finding_mentions` (`episode.rs:187`, přesná shoda IP) | „alerting success vs investigation utility“ (053); LM only vs all (025) | „Placebo atribuce“: stejný postup na náhodném okně bez útoku dá míru náhodných zásahů (H-4) | Odečíst placebo míru, hlásit hlavně „správný typ“ a zdrojové pořadí |
| S6 | **„Pozorovatelný“ útok** = `flows_emitted > 0`. Počítadlo se ale zvyšuje dřív, než se tok zablokuje nebo ztratí při výpadku či `degrade`, takže do jmenovatele vstupují i útoky, které telemetrie nikdy neviděla. | `traffic.rs:1194–1216` (`push`), `degrade` až v `traffic.rs:1189` | label inaccuracy (027) | Porovnat jmenovatel s `flows_emitted − blokované − ztracené` | Počítadlo „doručeno do telemetrie“ za `degrade` |
| S7 | **Cirkularita typování.** Metrika „správný typ“ používá `expected_types()`, seznam toho, co engine podle autora umí. Rodiny i signatury navrhl tentýž autor jako detektor. | `traffic.rs:105` | Mahoney & Chan (sdílený předpoklad); Nyberg (rovnoměrný šum) | Nezávislá sada útoků (jiný autor nebo nástroj, pcap replay) | Držené rodiny (H-6); kotva na reálných datech jako primární metrika |
| S8 | **Ruční konstanty místo fitu na data.** Benigní rychlosti (lognormal, medián 18/h), velikosti, denní profil (schodová funkce 1,0 / 0,35 / 0,06) a jitter beaconu ±20 % od začátku cyklu nejsou odvozené z CTU-13, IoT-23 ani jiných dat. | dle průzkumu kódu (`netmodel.rs` a `traffic.rs`, `diurnal`) | marginály ≠ závislosti (045); periodické artefakty (049); rovnoměrný šum (051) | Doménové testy podle Ringa a porovnání rozdělení soak vs CTU-13 background (KS, JSD), autokorelace počtu toků (H-5) | Fit parametrů na reálný background a injekce útoků do reálného pozadí (hybrid podle Mahoneyho) |
| S9 | **Nezávislost v CI.** Wilsonův interval počítá útoky jako nezávislé pokusy, ale útoky v jedné síti sdílejí kvalitu telemetrie, topologii i velikost. | `stats.rs` (Wilson), `report.rs` `ci()` | absence variance a CI (040) | Clusterový bootstrap přes sítě; design effect = var_cluster / var_Wilson (H-7) | Intervaly z clusterového bootstrapu; přes sítě, ne přes útoky |
| S10 | **Žádné držené seedy ani rodiny.** Jeden seed (20261031 ve v2) slouží zároveň k ladění i k hlášení. | `runner.rs` (výchozí `run_seed`), `netmodel.rs` `derive(run_seed, network_id)` | data snooping (027), validation-only kalibrace (053), TESSERACT C1 (031) | Výsledek na nových seedech po ladění na starých (H-8) | Rozdělit seedy na ladicí a držené, předregistrace prahů |
| S11 | **Slabá kotva.** Anchor předává prázdné `known_services`, takže ablace A se blíží pravidlu „aspoň 3 toky na klíč“. F1 se počítá per klíč (dst_ip, proto, port). | `src/eval/dataset_replay.rs:137` | jednoduchá baseline (028, 053); úroveň hodnocení (Larroche, event-level) | Už teď: ablace A porazí triviální baseline jen v 6 z 20 scénářů | Dodat inventář služeb z pasivní fáze, hlásit i event-level a host-level metriky |

**Co z literatury odpovídá našim číslům:**

- **Typování lateral movement.** Soak v1 měl 12,5 % správného typu, v2 má 63,4 %. Larroche ukazuje, že lateral movement je při přísném štítkování těžký i pro nejlepší grafové metody (AUC 43–53, RQ5-025). Soak v2 tedy může být spíš optimistický.
- **C2 beacon.** Detekce 12,5 %, medián latence 360 min. Literatura k soaku nemá přímou obdobu. CascadeNet ale ukazuje, že generátory zkreslují časové vzory (RQ5-049). Náš beacon restartuje fázi na začátku každého cyklu, takže jeho periodicita je artefakt generátoru a nižší výsledek nemusí znamenat skutečnou slabinu detektoru.
- **Provozní události vypadají jako útok.** U patch_window má falešný nález 99,2 % výskytů, u collector_replay 97,3 % a u sensor_crash 93,0 %. To odpovídá Nybergovi (RQ5-052): benigní aktivita dominuje nákladům. Je to užitečná a realistická část soaku. Pro hodnocení ji ale chceme na data napojit, ne nastavovat ručně.
- **Kotva na reálných datech.** Ablace A porazí triviální baseline jen v 6 z 20 scénářů. Odpovídá to Arpovi (boxplot ≥ Kitsune) a Guerrovi (allowlist ≥ učené modely). Jako primární srovnání je proto potřeba hlásit triviální baseline.
- **Šum.** FP 1 108 / síť-den při 2,66 útoku / síť-den. Precision behaviorálních nálezů je přibližně 31 % (2 378 886 / (2 378 886 + 5 302 629), odhad autora). Při realistické základní četnosti by byla řádově nižší, viz Axelsson (RQ5-055).

## Syntéza

- **Velikost efektu vad.** Při přechodu z „čistého“ benchmarku do reálnějšího prostředí měřené výkony klesají v rozpětí:
  - 20–72 % relativně při přenosu mezi datasety (7 studií, heterogenní),
  - 58–76 % detekcí po přimíchání reálného provozu (1 studie, 3 sady),
  - na reálné podnikové nebo kampusové síti F1 0,999 → 0,28 (1 studie) a FP 2 896× vyšší než TP (1 studie).

  Studie se stejnou metrikou a srovnatelnými podmínkami jsou jen 2, takže je kvantitativně nesdružujeme.
- **Mechanismus** se shoduje ve všech podtématech. Model nebo pravidlo se opře o vlastnost generátoru dat (TTL, IP rozsahy, porty, pevné velikosti, periodicita, rovnoměrný šum), ne o mechanismus útoku. Uvádí to 9 studií (001, 006, 007, 013–015, 016–018, 039, 049, 051).
- **Rozpor ohledně časového rozdělení.** TESSERACT ukazuje velký vliv časové konzistence (malware), BRIDGE zanedbatelný (IoT botnet, −0,009). Vysvětlení: vliv závisí na tom, jak rychle se distribuce v čase mění. V emulovaných datasetech trvajících dny bývá změna malá, v datech sbíraných roky velká.
- **Rozpor u syntetiky.** Distribuční metriky (JSD, EMD) bývají dobré, a přitom úlohová užitečnost špatná (045, 046) a naopak (044). Věrnost proto nejde shrnout jedním číslem. Je potřeba kombinace: marginály, závislosti mezi poli (doménové testy), časová struktura a TSTR.

## Závěry

| Z-id | tvrzení | důkazy | jistota | důvody snížení | použitelnost | doporučená akce |
|---|---|---|---|---|---|---|
| Z-1 | Veřejné NIDS datasety obsahují měřené artefakty a chyby štítkování v řádu desítek procent toků (CIC17 25,9 %, KDD duplicity 75–78 %, OpTC 40 % procesů s chybou). | 001, 002, 019, 022, 060, 062, 063 | vysoká | – | ano | Kotvu CTU-13 a IoT-23 používat jen s vlastní kontrolou štítků (Background, sken v sc. 5), hlásit per scénář |
| Z-2 | Detektory na benchmarcích se často opírají o artefakty generátoru (TTL, adresy, porty, velikosti) a triviální pravidla na nich dosahují špičkových výsledků. | 006, 007, 013–016, 018, 039 | vysoká | – | ano | Pro soak: povinná baseline „artefaktový detektor“ (S1, S2) |
| Z-3 | Po přechodu na jiný dataset nebo reálný provoz klesá výkon typicky o 20–72 % relativně a v jednotlivých případech k nule. | 013, 034–038 | střední | nekonzistence (heterogenní metriky), nepřímost (ML klasifikátory, ne korelační engine) | s úpravou | Hlásit výsledky na kotvě odděleně od soaku, nikdy je nesčítat |
| Z-4 | Přimíchání reálného pozadí do simulace snižuje počet detekcí a zvyšuje podíl legitimních detekcí. | 017, 018 | nízká | jediná studie (2003), staré detektory | ano | Hybridní soak: útoky injektované do reálného pozadí CTU-13 (H-2) |
| Z-5 | Distribuční podobnost syntetického provozu nezaručuje úlohovou užitečnost ani časovou věrnost. TSTR ztrácí 20–73 p. b. | 042–047, 049 | střední | nepřímost (ne IDS úlohy), střet zájmů (046) | ano | Validovat soak doménovými testy a časovou strukturou, ne jen marginálami (H-5) |
| Z-6 | Nerealistický poměr tříd v testu a ignorování základní četnosti nafukují F1 a precision mnohonásobně (F1 0,32 → 0,96). | 030, 031, 032, 055 | vysoká | nepřímost (malware) u 031, 032 | ano | Hlásit precision a FP/den při realistické četnosti útoků (H-3, S4) |
| Z-7 | AUROC je při silné nevyváženosti zavádějící (AUROC 0,87–0,997 při AP ≤ 0,06). | 026, 053, 054 | vysoká | – | ano | V soaku a na kotvě hlásit AP a recall při pevném počtu FP za den |
| Z-8 | Volba štítkování a předzpracování mění absolutní výkon i pořadí metod. | 023, 024, 025 | střední | preprinty, jedna skupina (Larroche) | ano | Pevně definovat atribuci v soaku, hlásit placebo míru (H-4) |
| Z-9 | Statistická významnost, rozptyl a držené testovací sady v NIDS literatuře chybějí (2 z 30 prací). | 027, 040, 041 | střední | malé vzorky | ano | Clusterový bootstrap a držené seedy (H-7, H-8) |
| Z-10 | Simulátor s rovnoměrným šumem podhodnocuje dopad benigní aktivity. V emulaci byly falešné alerty nerovnoměrné (0,05–17 %) a výnosy agentů klesly o 80–109 %. | 051, 052 | nízká | jediná studie, preprint | ano | Kalibrovat šum soaku z reálných dat per typ zařízení (H-5) |
| Z-11 | Syntetická augmentace dat spolehlivě nezlepšuje klasifikaci NIDS. | 050 | nízká | preprint, jedna studie | s úpravou | Neučit prahy ze syntetiky bez kontroly na kotvě |
| Z-12 | Jednoduchá baseline často dorovná nebo překoná složitou metodu (boxplot ≥ Kitsune, allowlist ≥ PIDS). | 007, 028, 053 | střední | rozdílné úlohy | ano | Každá změna enginu proti triviální baseline na stejných seedech |

## Překlad do praxe (Skákavka a soak)

1. **Artefaktová baseline jako povinný řádek reportu** (z Z-2, Z-12). Do `report.rs` přidat tři triviální detektory se stejnou atribucí:
   - (a) „externí IP z útočného poolu“,
   - (b) „existuje Suricata alert“,
   - (c) „aspoň 3 toky na neznámou službu“.

   Engine musí každý z nich porazit per rodinu. Kde neporazí, je výsledek té rodiny podezřelý z artefaktu.
2. **Odstranit S1–S3 v generátoru.**
   - Sdílený pool externích IP.
   - Benigní Suricata alerty v realistickém množství. Hodnota za síť-den je extrapolace: v literatuře jsme ji nenašli, je potřeba ji změřit na vlastním senzoru nebo převzít z CTU-13 alert logů, pokud existují.
   - Stejné vzorkování útočných i benigních toků.
3. **Hybridní režim „reálné pozadí + injektovaný útok“** (z Z-4, Z-5): benigní toky z CTU-13 Background nebo IoT-23 benign (po kontrole štítků) a generované útoky vložené s odpovídajícím časem a adresami. Volba datasetu je extrapolace: CTU-13 je zachycení z univerzity z roku 2011 a nemusí odpovídat archetypům Hospital nebo Industrial.
4. **Metriky** (z Z-6, Z-7, Z-9):
   - recall při pevném FP/síť-den,
   - AP,
   - precision přepočtená na četnost 0,01–0,1 útoku/síť-den (odhad autora, protože pro malé sítě jsme v literatuře data nenašli; OpTC dává 0,0016 % škodlivých událostí, nepřímo),
   - intervaly z clusterového bootstrapu přes sítě (B = 2 000) místo Wilsonova intervalu přes útoky.
5. **Protokol bez cirkularity** (z Z-8, Z-9, TESSERACT C1–C3):
   - Seedy rozdělit na ladicí (L) a držené (H). Prahy a parametry fixovat a předregistrovat (commit hash) před během na H.
   - Aspoň dvě rodiny útoků držet úplně mimo ladění (např. fleet_beacon, ics_attack) a hlásit je odděleně.
   - Primární metrika pro tvrzení v diplomce je kotva (reálná data). Soak slouží jako test robustnosti a regrese, ne jako důkaz detekční schopnosti.
6. **Atribuce**:
   - zavést placebo okna, tedy náhodná okna bez útoku na stejných klíčových IP,
   - hlásit „detekováno − placebo“,
   - jmenovatel „pozorovatelný“ počítat až za `degrade` (S6).
7. **Věrnost generátoru** (z Z-5, Z-10):
   - doménové testy ve stylu Ringa 2019 (UDP bez TCP flagů, rozsahy velikostí, broadcast nikdy jako zdroj, porty podle role),
   - porovnání rozdělení počtu toků na hosta a hodinu a jejich autokorelace s CTU-13 background (KS statistika, JSD),
   - fit konstant z bodu S8 na tato data.

## Hypotézy k empirickému ověření (předregistrace)

Formát: změna → očekávaný efekt (z důkazů) → metrika → scénář/seedy → kritérium zamítnutí. Všechny A/B porovnání běží na stejných seedech. Ladicí seedy jsou 20261031–20261040, držené 20261101–20261110. Testují se jen rodiny s ≥ 100 pozorovatelnými útoky na rameno.

- **H-1 (artefakt IP poolu).** Změna: sdílený pool externích IP pro benigní i útočný provoz.
  - Očekávaný efekt: pokles detekce rodin s externím protějškem (c2_beacon, exfiltration, credential_stuffing, web_exploit) o 5–30 % relativně. Rozsah je odhad autora z RQ5-017 a RQ5-013 (tam 58–76 %, ale artefakt byl silnější).
  - Metrika: detekce a správný typ per rodina, rozdíl s clusterovým bootstrap CI.
  - Scénář: soak v2, 200 sítí, držené seedy.
  - Kritérium zamítnutí: horní mez 95% CI rozdílu je u všech čtyř rodin pod 2 p. b. Hypotéza „artefakt nadhodnocuje“ se tím zamítne a artefakt je neškodný.
- **H-2 (reálné pozadí).** Změna: hybridní režim s benigním provozem z CTU-13 Background.
  - Očekávaný efekt: FP/síť-den se změní aspoň o faktor 2 (směr neznámý). Detekce slow_scan a lateral_movement klesne o 10–60 % relativně (RQ5-017, 025).
  - Metrika: FP/síť-den, detekce per rodina, AP.
  - Scénář: 13 scénářů CTU-13 × injekce 19 rodin, 3 seedy.
  - Kritérium zamítnutí: FP/síť-den v intervalu 0,5–2× syntetického a detekce všech rodin v ±5 p. b. Syntetické pozadí je pak pro tento účel postačující.
- **H-3 (vzorkování a velikost sítě).** Změna: útočné toky vzorkovat stejně jako benigní.
  - Očekávaný efekt: pokles detekce ve vrstvách XL a XXL o ≥ 5 p. b. u objemově detekovaných rodin (ssh_bruteforce, ddos, credential_stuffing). Ve vrstvě S beze změny, protože vzorkování je tam 1,0 (RQ5-032, mechanismus poměru tříd).
  - Metrika: detekce podle velikostních vrstev.
  - Kritérium zamítnutí: rozdíl ve vrstvách XL a XXL < 2 p. b. (horní mez CI).
- **H-4 (placebo atribuce).** Změna: měřit atribuci na náhodných oknech bez útoku.
  - Očekávaný efekt: placebo „detekce“ ≥ 20 % u rodin s mnoha klíčovými IP (horizontální sken, ransomware, fleet_beacon, lateral_movement) a ≤ 5 % u rodin s jednou klíčovou IP. Opírá se o RQ5-053 a RQ5-025: alerting vs. investigace.
  - Metrika: placebo míra per rodina.
  - Kritérium zamítnutí: placebo míra < 5 % u všech rodin. Atribuce pak nenafukuje detekci.
- **H-5 (věrnost pozadí).** Změna: žádná, jen měření.
  - Očekávaný efekt: soak pozadí projde doménovými testy podle Ringa (≥ 99 %), ale rozdělení toků na hosta a hodinu se od CTU-13 background liší (KS D > 0,2) a autokorelace má jiný tvar (RQ5-045, 049, 051).
  - Kritérium zamítnutí: KS D ≤ 0,1 pro všechny archetypy srovnatelné s CTU-13 (Campus, Smb). Konstanty jsou pak dostatečně realistické.
- **H-6 (držené rodiny).** Změna: dvě rodiny (fleet_beacon, ics_attack) vyřadit z veškerého ladění a hlásit je odděleně.
  - Očekávaný efekt: po dalším kole ladění se detekce laděných rodin zlepší víc než detekce držených. Rozdíl ≥ 5 p. b. by naznačoval přeladění na soak (RQ5-031, 053).
  - Kritérium zamítnutí: zlepšení držených rodin je ≥ zlepšení laděných, nebo rozdíl < 2 p. b.
- **H-7 (design effect CI).** Změna: clusterový bootstrap přes sítě místo Wilsonova intervalu.
  - Očekávaný efekt: šířka intervalu vzroste aspoň 1,5× u rodin s mnoha útoky na síť (port_scan_vertical, ssh_bruteforce). Jde o odhad autora; v literatuře jsme pro NIDS nenašli číslo, jen nepřímo RQ5-040.
  - Metrika: poměr šířek.
  - Kritérium zamítnutí: poměr < 1,1 u všech rodin. Wilsonův interval pak stačí.
- **H-8 (přeladění na seed).** Změna: po ladění prahů na seedech L změřit stejnou konfiguraci na seedech H.
  - Očekávaný efekt: pokles detekce i FP v rámci CI. Pokles o > 3 p. b. by znamenal přeladění (RQ5-053, validation-only kalibrace).
  - Kritérium zamítnutí: pro úspěch (žádné přeladění) musí rozdíl L − H ležet v CI kolem nuly u ≥ 17 z 19 rodin.

Neúspěšné hypotézy se zveřejní stejně jako úspěšné (protokol §10).

## Hrozby validity

- **Výběr zdrojů.** Hledání přes jeden webový vyhledávač, bez přímého přístupu do IEEE Xplore a ACM DL. Několik klíčových prací (Lanvin, Liu, NetShare, MAWILab, D'hooge 2020) zůstalo bez plného textu. Engelenova skupina je zastoupena třikrát (001–005, 006–012, 063), Larroche dvakrát. Hrozí převaha jedné výzkumné linie.
- **Extrakce.** Tabulky v PDF se rozpadají. Layeghyho matici jsme rekonstruovali z rozložení a ověřili jen proti diagonále (střední riziko). Arpovu Tab. 1 jsme nepoužili. U Majorczyka máme jen slajdy.
- **Nepřímost.** Velká část důkazů se týká supervizovaných ML klasifikátorů, Android malwaru (TESSERACT, Arp 4.1) nebo nebezpečnostních časových řad (DoppelGANger). Skákavka je korelační a ověřovací engine, ne flow klasifikátor, takže přenos velikostí efektu je extrapolace.
- **Publikační zkreslení.** Kritické práce mají motivaci najít vady (audity) a generátorové práce hodnotí konkurenci (NetDiffusion → NetShare). Negativní výsledky jsou vzácnější, našli jsme jen Wolf 2024 a BRIDGE (časový split).
- **Preprinty.** RQ5-024, 025, 026, 038, 039, 050–054 nejsou recenzované, proto mají v Závěrech nižší jistotu.
- **Soak.** Analýza kódu je statická. Konkrétní dopad S1–S11 je nezměřený, odtud hypotézy. Status v2 je průběžný (3,5 h běhu) a obsahuje 3 paniky.

## Co NEBYLO nalezeno

- Žádná práce, která by **přímo měřila cirkularitu** (týž autor píše simulátor i detektor proti nezávislému autorovi útoků). Máme jen nepřímé doklady: Mahoney & Chan a Nyberg.
- **Kvantifikace dopadu oprav** u Lanvin 2022 a Liu 2022: plný text nebyl dostupný.
- **CIC-DDoS2019, MAWI a IoT-23**: samostatný audit štítků s čísly jsme nenašli. MAWILab (štítky z kombinace detektorů) je jen V1.
- **CyberBattleSim**: žádné měření přenosu do emulace nebo reality.
- **LLM generátory provozu**: nenašli jsme recenzovanou práci s TSTR na bezpečnostní úloze. Comparative studie (Ammara 2025) se týká tabulárních GAN a difuzních modelů na NSL-KDD a CIC-IDS2017.
- **Design effect** (vliv shlukování v síti na CI) u NIDS evaluací nemá v literatuře žádné číslo.
- **Realistická základní četnost útoků na síť-den pro malé a střední sítě** (SOHO, SMB) není v recenzované literatuře doložena.
- **Velikost úniku dat z náhodného dělení u flow datasetů**: číslo 0,24 macro-F1 (Moczkodan) je jen V1. Jediný přečtený přímý test (BRIDGE) našel efekt malý.
