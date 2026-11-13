# RQ5: Validita benchmarků, syntetických a simulovaných dat a testování bez cirkularity

Verze 1.2 (revize po druhé nezávislé kontrole), 2026-11-01. Postup podle `../00-protokol.md`. Extrakce je v `extrakce.csv` (63 řádků: 60 V3, 3 V2), dotazy v `hledani.csv`, nepřečtené zdroje v `neovereno.md`, první nezávislá kontrola v `kontrola-RQ5.md`, první revize v `revize-RQ5.md`, druhá nezávislá kontrola v `kontrola-RQ5-v2.md`, druhá revize v `revize-RQ5-v2.md`. Návrhy z `_predbezne/` nebyly použity jako důkaz.

## Abstrakt

Otázka: jak moc se dá věřit číslům naměřeným na veřejných NIDS datasetech a na syntetických či simulovaných datech, a jak testovat tak, aby autor simulátoru nepotvrzoval sám sebe. Prošli jsme 41 prací v plném textu nebo oficiálním abstraktu. Hlavní zjištění:

1. **Veřejné datasety mají měřené vady, ale oprava výkon nemusí snížit.** V CICIDS2017 je 25,9 % toků artefaktem nástroje CICFlowMeter a přes 20 % stop bylo nutné rekonstruovat nebo přeštítkovat (RQ5-001, 002). Agregované F1 zůstalo po opravě 0,99, ale F1 jednotlivých tříd se měnilo v obou směrech: Bot z 0,60 na 0,99, Web Attack XSS z 0,18 na 0,79, Web Attack SQL naopak z 0,11 na 0,00 (jen 3 testovací vzorky) (RQ5-003, 004). Představa, že po opravě „zmizí X % výkonu“, je zjednodušená. Mění se hlavně to, co model skutečně detekuje.
2. **Artefakty dovolí triviálním pravidlům dosáhnout špičkových výsledků.** Na DARPA 1999 detektor jednoho bajtu zachytil 45 % útoků (RQ5-016). Na UNSW-NB15 oddělí třídy s 98% přesností dva příznaky, protokol a TTL (RQ5-006). Na CIC-IDS-2017 rozhodují bity TTL (RQ5-013). Jakmile se do simulace přimíchá reálný provoz, zmizí 58–76 % detekcí PHAD (RQ5-017).
3. **Přenos mezi datasety selhává soustavně.** Průměrné MCC (Matthewsův korelační koeficient) klesá z 94,6 % uvnitř datasetu na 29,4 % mezi datasety (RQ5-034). Další naměřené propady: F1 z 0,83 na 0,56 při vynechání celého datasetu (RQ5-038), přesnost (accuracy) o 25,6 % a AUROC o 30,5 % v průměru u čtyř nesupervizovaných metod (RQ5-037), F1 z 0,999 na 0,28 při nasazení na reálnou kampusovou síť (RQ5-013). Jedna studie ukazuje, že časové rozdělení dat samo propad způsobit nemusí (−0,009 F1, RQ5-038).
4. **U syntetického provozu nestačí distribuční metriky.** Generátor s nejmenší vzdáleností marginálních rozdělení prošel doménovými testy jen v 0,07–14 % případů (RQ5-045). Model trénovaný na syntetice a testovaný na reálných datech ztratí u NetDiffusion 26–72 procentních bodů přesnosti i v nejlepší konfiguraci a u NetShare 46–51 p. b. (RQ5-046, 047). NetShare se naučil periodický vzor, který v reálných datech není (RQ5-049).
5. **Metodická rizika jsou častá a mají známou velikost.** Sampling bias je aspoň částečně přítomen v 90 % a data snooping v 73 % prací z top konferencí (RQ5-027). Statistickou významnost zmiňují 2 z 30 prací o ML-NIDS (RQ5-040). Při základní četnosti 1 : 100 dává 99 % TPR a 1 % FPR 100 falešných poplachů na 99 skutečných (RQ5-030). Poměr tříd v testu umí F1 mnohonásobně změnit, ale v jediné studii (Android malware) jen v kombinaci s poměrem v tréninku: při tréninku s 90 % malwaru zvedne změna testu z 10 na 90 % F1 z 0,30 na 0,96, při tréninku s 10 % jen z 0,32 na 0,33 (RQ5-032). Přísné štítkování lateral movement srazí AUC metody Argus z 99,7 na 43,2 (RQ5-025).
6. **Soak harness má několik konkrétních zkreslení z této literatury.**
   - Běžný benigní odchozí provoz míří jen na 12 pevných externích adres na síť s jinými prvními oktety, než mají útočné cíle (C2, exfiltrace, tunel). Obdoba artefaktu TTL a zdrojových adres. Příchozí směr oddělený není: benigní weboví klienti berou adresy ze stejného poolu jako útočníci.
   - Platné Suricata alerty vznikají jen z útoků (benigní události vytvářejí nanejvýš poškozené řádky logu).
   - Útočné toky se nevzorkují, benigní ano.
   - Šum je nastavený ručními konstantami.
   - Wilsonovy intervaly považují útoky za nezávislé, i když útoky ve stejné síti nezávislé nejsou.
   - Ladění a test nejsou oddělené žádnými drženými seedy.

   Tato zkreslení se dají změřit a navrhujeme pro ně hypotézy H-1 až H-8.

## Metodika a PRISMA

- **Vyhledávání.** 32 dotazů přes webové vyhledávání (z toho 11 typu „proti“: negeneralizace, chyby, replikace, negativní výsledky) a 2 kola citačního řetězení. Klíčové práce (Engelen 2021, Flood 2024, Arp 2022, Larroche 2026, NetDiffusion) jsme řetězili dozadu i dopředu.
- **Čtení plných textů.** PDF jsme stahovali do izolovaného adresáře a převáděli přes `pdftotext`. Hodnoty jsme brali z tabulek a textu. Kde se tabulka při převodu rozpadla (Arp Tab. 1, Layeghy Obr. 1), vzali jsme jen textová tvrzení, nebo jsme pořadí ověřili proti jiné tabulce (u Layeghyho Tab. 4). Rozpadlé tabulky byly hlavním zdrojem chyb, které kontrola našla (Engelen Tab. II, Wang Tab. 3, Majorczyk slajd 21). Při revizi jsme jejich pořadí ověřili ze surového textu sloupců (`pdftotext` bez `-layout`) a z doprovodného textu článku.
- **Kód soaku.** Kód (`src/soak/`, `src/eval/anchor.rs`, `src/eval/dataset_replay.rs`) jsme prošli pomocí read-only průzkumu. Klíčová místa jsme ručně ověřili. Jedno tvrzení průzkumu se ukázalo jako zastaralé: atribuce podle podřetězce už neplatí, protože `mentions_ip` v `episode.rs:164` porovnává IP přesně. Tato změna je commitnutá v `a293d2b` (2026-10-31 23:40 SEČ, „fix(soak): presne porovnani IP ...“). Běh v2 začal v 18:57 SEČ (17:57 UTC), tedy přes 4 hodiny před commitem, a status běhu uvádí commit `unknown`. Čísla z běhu v2 proto s velkou pravděpodobností vznikla ještě s atribucí podle podřetězce a s oknem lookalike událostí prodlouženým o 2 cykly. Ověřit to nejde.
- **Nezávislá kontrola a revize.** Kontrola podle protokolu §9 proběhla 2026-10-31 (`kontrola-RQ5.md`): vzorek 51 z 63 řádků, věcná chybovost nad limitem 5 %, verdikt „vrátit k přepracování“. Revize (`revize-RQ5.md`) znovu otevřela zdroje u všech označených řádků i u 12 dříve nekontrolovaných. Opravila hodnoty v 6 řádcích s věcnou chybou a drobné chyby (umístění citací, venue, rozsahy), přepočítala medián v (b), rozdělila závěr Z-6, snížila jistotu Z-7 na střední a podle čerstvé kontroly kódu přepsala S1, S2 a H-1. Druhá vlastní (ne nezávislá) kontrola 47 řádků po revizi hlásila věcnou chybovost 0 / 47 (podrobnosti a původní hodnoty v `revize-RQ5.md`). Tento údaj se ukázal jako nepravdivý: druhá nezávislá kontrola (`kontrola-RQ5-v2.md`, 2026-10-31) ověřila 59 z 63 řádků (včetně všech 26 řádků změněných první revizí a všech řádků opírajících závěry s vysokou a střední jistotou) a našla 5 věcných chyb (5 / 59 = 8,5 %, 95% Wilsonův interval 3,7–18,4 %) a 16 drobných; verdikt PŘIJATO S OPRAVAMI. Čtyři z pěti věcných chyb byly v řádcích vlastního vzorku první revize (023, 041, 047, 053), pátá (052) v řádku, který revize měnila; dvě (023, 041) revize sama zanesla. Žádná nebyla v poli `hodnota` ani v řádku opírajícím závěr s vysokou jistotou. Druhá revize (`revize-RQ5-v2.md`, 2026-11-01) opravila všech pět věcných i všech 16 drobných chyb, u každé znovu otevřela zdroj, a opravila souvisící místa v této studii. Ani druhou revizi nedělal nezávislý kontrolor, takže nezávislé ověření opravených řádků nemáme.

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
| CICIDS2017 | „TCP appendices“ (chyba CICFlowMeter), neúspěšné útoky („Attempted“) | 25,9 % toků jsou artefakty (u tříd až 50 %), přes 20 % stop opraveno | F1 tříd Bot 0,60 → 0,99, XSS 0,18 → 0,79, Infiltration 0,81 → 0,91, ale SQL 0,11 → 0,00 (3 testovací vzorky); vážené F1 beze změny 0,99 | 001–005 |
| CICIDS2017 | zkratka TTL (útočníci mimo síť, Kali TTL 64, DDoS z Windows TTL 128) | TTL bity tvoří kořen rozhodovacího stromu | F1 0,999 → 0,282 na kampusové síti | 013 |
| CICIDS2017 Heartbleed | spojení se mezi heartbeaty nikdy nezavřelo | jediný vzor | F1 1,0 → 0,0 po zavření spojení | 014 |
| CICIDS2017 DoS | jediná napadená stránka (výchozí Apache) | 97 % hodnot bwd packet size ≈ 11 595 B ± 1 % | 3 příznaky stačí na F1 0,997 | 007 |
| CICIDS2017 / 2018 | chyby orchestrace, příznaků a štítkování, duplikace paketů | kvalitativně (V2) | – | 062, 063 |
| UNSW-NB15 | TTL a protokol jako artefakty testbedu, překryv tříd | 98 % accuracy jen z 2 příznaků, 40 % Shellcode/Recon shodné s Exploits | výhoda metody ADA 6 % → 1,5 % | 006, 008 |
| KDD99 / NSL-KDD | duplicity | 78 % train, 75 % test | 98 % trénovacích záznamů správně klasifikuje všech 21 modelů | 019, 020 |
| DARPA 1999 | TTL 253 a zdrojové adresy jako artefakt simulace | 29 ze 36 detekcí přes TTL nelegitimních | PHAD 76 → 18–32 detekcí po přimíchání reálného provozu | 016–018 |
| Bot-IoT | obrácená základní četnost, retransmise | 0,00013 % benign, retransmise přes 34 % (běžně do 3 %) | metriky přesnosti nesmyslné | 009, 010, 060 |
| ToN-IoT, NF-ToN-IoT | DNS a router provoz označený jako útok; v NF-ToN-IoT duplicitní toky se štítky různých útoků | 55 % (DoS), 28 % (XSS) funkčních toků jsou DNS; filtrace odstranila přibližně 14 % toků plné verze | dopad na detekci nekvantifikován | 011, 060 |
| CTU-13 | štítek „Botnet“ zahrnuje sken, aktualizace OS označené jako adware | sc. 5: 97,8 % škodlivých toků je nmap | – | 011, 012 |
| DARPA OpTC | chybné actor_id, nepřesné oficiální štítky | 40 % procesů a 4,22 % událostí chybných, škodlivé jen 0,0016 % | F1 GAE 0,52 vs 0,24 podle volby štítků (klient 201; u klienta 501 opačně 0,38 vs 0,60) | 021–023 |
| LANL | štítky jen podmnožina red teamu, filtrace NTLM a uživatelů | – | AUC Pikachu 94 → 78,3, AP Argus 32,3 → 0,09 | 024 |

Nenalezeno s plným textem: MAWI (štítky MAWILab vznikají kombinací detektorů, tedy hrozí cirkularita, ale jen V1), CIC-DDoS2019 (samostatný audit nenalezen) a IoT-23 (přímá kritika štítků nenalezena).

**Rozpor.** Opravy datasetů výkon nesnižují jednotně. U Engelena opravy výkon spíš zvyšují, protože odstraní matoucí artefakty (RQ5-003). U Mahoneyho a Larroche výkon klesá, protože se odstraní artefakty, na kterých detekce stála (RQ5-017, 024). Vysvětlení: záleží na tom, jestli artefakt pomáhal (třídy šly díky němu oddělit) nebo škodil (byl šumem v pozitivní třídě). Obecné procento „ztraceného výkonu po opravě“ se proto z literatury určit nedá.

### (b) Přenos mezi datasety (cross-dataset)

| studie | datasety | uvnitř datasetu | mezi datasety | id |
|---|---|---|---|---|
| Cantone 2024 | 4× CIC/LycoS | MCC 94,63 % | MCC 29,35 % (rozsah 10,8–40,2 %) | 034 |
| Layeghy 2022 | 4× NetFlow v2 | F1 77,6–99,8 % (Extra Tree) | F1 od 0,00 % do 94,8 % (Extra Tree), silně asymetrické | 035 |
| Apruzzese (XeNIDS) 2022 | 6 datasetů | F1 99,1 % (CTU13) | −20 % na cizích botnetech, DoS 38 % | 036 |
| Verkerken 2022 | CIC17 ↔ CIC18 | AUROC 0,85–0,98 | AUROC −30,5 % průměrně přes 4 modely (nejlepší a nejhorší jednotlivý běh −17,9 a −37,5 %; průměry modelů −25,9 až −35,8 %), accuracy −25,6 % | 037 |
| BRIDGE 2026 | 5 IoT botnet | F1 0,83 | LODO F1 0,56, časový split jen −0,009 | 038 |
| Jacobs (Trustee) 2022 | CIC17 → kampus UCSB | F1 0,999 | F1 0,282 | 013 |
| Hakim 2026 | 3 IIoT | – | nejvlivnější kategorie portu 96–435× častější ve zdroji | 039 |

Syntéza: 7 studií a 15 různých datasetů. Metriky (MCC, F1, accuracy, AUROC) ani podmínky nejsou srovnatelné, takže uvádíme jen rozsah. Relativní pokles hlavní metriky při přenosu (odhad autora z hodnot v tabulce; 5 studií, které uvádějí jedno souhrnné číslo; Layeghy a Hakim souhrnné číslo nemají):
- minimum 20 % (XeNIDS, F1 na botnetech),
- Verkerken 30,5 % (AUROC, podle autorů hlavní metrika; accuracy 25,6 %),
- medián 33 % (BRIDGE, F1: 0,2719 / 0,8296),
- maximum 69–72 % (Cantone MCC: 1 − 29,35 / 94,63 = 69 %; Trustee F1: 1 − 0,282 / 0,999 = 72 %).

Medián je stejný, ať se za Verkerkena vezme AUROC, nebo accuracy.

U jednotlivých dvojic datasetů klesá F1 až k nule (Layeghy). Heterogenita je vysoká. Společná příčina, kterou uvádějí čtyři studie (013, 035, 039 a částečně 034): model se opírá o příznaky, které jsou artefaktem konkrétního testbedu (porty, TTL, okna TCP, velikosti paketů).

### (c) Syntetická data a generátory provozu

| generátor | metrika věrnosti | výsledek | známé selhání | id |
|---|---|---|---|---|
| WGAN-GP varianty (Ring 2019) | Euklidovská vzdálenost marginál a 7 doménových testů | baseline z nezávislých marginál má nejmenší vzdálenost (0,0002) | baseline projde Testem 1 jen ve 14 % a Testem 6 v 0,07 % případů | 045 |
| DoppelGANger (Lin 2020) | TSTR (train on synthetic, test on real), rank korelace | 80 % reálné přesnosti, o 43 % lepší než AR | AR model má na GCUT perfektní rank korelaci (1,00) i při nekvalitních vzorcích, na WWT 0,80 stejně jako DG; DP rozbíjí autokorelaci | 042–044 |
| NetShare (Yin 2022) | distribuční metriky | o 46 % lepší než baseline (V2) | TSTR přesnost 0,396 / 0,140 proti 0,86 / 0,648 na reálných datech, přitom JSD 0,16 (měřila konkurence); periodický vzor v rozporu s realitou | 046, 048, 049 |
| NetDiffusion (Jiang 2024) | JSD, TVD, HD a TSTR | JSD 0,04 | TSTR 0,738 / 0,262 bez post-gen. heuristiky (s ní 0,676 / 0,222) proti 1,00 / 0,978 na reálných datech | 047 |
| CascadeNet (Lu 2026) | časové metriky | o 41–76 % lepší než baseliny kromě REaLTabFormer | REaLTabFormer je podobně věrný, podle autorů díky memorizaci tréninkových dat (vlastní tvrzení autorů) | 049 |
| resampling / GAN augmentace (Wolf 2024) | MCC | většinou pokles | negativní výsledek | 050 |
| simulátor vs cyber range (Nyberg 2026) | míra falešných alertů | simulátor 1 % rovnoměrně, range nerovnoměrně (např. 0,05 % a 10 % u jednotlivých kroků bez uživatelů, 17 % s uživateli) | výnosy agentů s benigními uživateli −80 až −109 % proti útočníkovi „Guided“, proti „Exploratory“ jen −5 až −14 %; hlavním faktorem však byla politika útočníka | 051, 052 |

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
| base rate / poměr tříd v testu | 99 % TPR při 1 % FPR = 100 FP na 99 TP (poměr 1 : 100); F1 0,30 → 0,96 změnou poměru v testu, ale jen při tréninku s 90 % malwaru (při 10 % 0,32 → 0,33) | realistický poměr v testu i v tréninku, FP vztažené k základní četnosti | 030, 032, 055 |
| nevhodná metrika | Trace: AUROC 0,868–0,997 při AP ≤ 0,062; FiveDirections: AUROC 0,666–0,943 při AP ≈ 0; OpTC: AUC 0,93 při AP 0,024; protipříklad Theia: AUROC 0,994 při AP 0,551 | AP/PR, MCC, recall při pevném FP | 026, 053 |
| chybějící jednoduchá baseline | boxplot ≥ Kitsune; allowlist ≥ učené PIDS; 3 příznaky = LUCID | vždy porovnat s triviální metodou | 007, 028, 053 |
| absence CI / seedů | statistická významnost ve 2 z 30 prací; podle zdroje 90 % z 10 odpovídajících praktiků (9/10; 2 z 12 otázku vynechali) to považuje za velmi problematické | více běhů, rozptyl, testy | 040, 041 |
| štítkování a předzpracování | změna pořadí metod; F1 0,52 vs 0,24 jen jiné štítky (OpTC klient 201, u klienta 501 opačný směr) | zveřejnit logiku štítkování, hodnotit na úrovni událostí | 023, 025, 063 |
| replikace na reálném provozu | falešně pozitivních událostí 2 896× víc než detekovaných útočných (ARGUS, Sandworm) | test na nezávislých reálných datech | 054 |

**Cirkularita.** Literatura ji přímo neměří (viz Co nebylo nalezeno). Nejbližší důkazy jsou dva:
- Mahoney & Chan: simulátor a detektor sdílejí implicitní předpoklad, například o TTL nebo zdrojových adresách, a detektor se pak trefí do artefaktu simulace.
- Nyberg 2026: agent trénovaný v simulátoru s rovnoměrným šumem selže na nerovnoměrném šumu skutečného prostředí.

Obecný princip, který z obou plyne: test musí obsahovat data, která autor detektoru nevytvořil.

## Co z toho přímo platí pro soak harness

Fakta o kódu jsme ověřili v `src/soak/` (stav 2026-10-31). Čísla jsou z `F:\Projekty\bakula-soak\run-v2-72h\status.md` (3,5 h, 566 sítí, 4 784 virtuálních síť-dnů) a z `docs/diplomka/eval/soak-findings.md`.

| # | zkreslení v soaku | doklad v kódu | obdoba v literatuře | jak změřit | jak odstranit |
|---|---|---|---|---|---|
| S1 | **Oddělené externí cíle odchozího provozu.** `public_ip()` losuje první oktet z {45, 61, 77, 91, 103, 154, 178, 193, 198}. Z něj jsou externí útočníci, všechny externí cíle útoků (c2_beacon, exfiltration, dns_tunnel, cryptomining, insider_hoarding, fleet_beacon, apt_chain, ransomware) a zdroje DDoS a credential stuffingu. Běžný benigní odchozí provoz (stanice na 443, NTP z brány, retry storm) míří jen na `model.externals`: 12 adres na síť, losovaných jednou při generování sítě, s prvním oktetem z disjunktní sady {13, 34, 52, 104, 142, 185, 203}. Útoky `externals` nikdy nepoužívají. Pool `public_ip()` ale sdílí i benigní provoz: externí klienti webových serverů v každém cyklu, flash crowd a cíle tří lookalike událostí (software_update, patch_window, ntp_fanout). **Příchozí směr tedy podle oktetu oddělený není.** Artefakt se týká odchozích spojení: v běžném provozu je každá nová externí adresa cíle útočná, výjimkou jsou jen řídké lookalike události. | `traffic.rs:392–400` `public_ip()`; útočné užití `traffic.rs:661, 752, 1523, 1880`; benigní užití `traffic.rs:902, 1095, 1794, 1819, 1846`; `netmodel.rs:825–833` (`externals`, uvnitř `NetworkModel::generate`, `netmodel.rs:678`); benigní egress `traffic.rs:997, 1119, 2253` | TTL a zdrojové adresy v DARPA 1999 a CIC17 (016–018, 013); UNSW TTL 98 % (006) | Triviální baseline „odchozí spojení na externí adresu mimo `externals` sítě“ a „1. oktet cíle ∈ útočný pool“; ablace H-1 | Benigní odchozí provoz losovat ze stejného generátoru jako útočné cíle a s realistickým podílem nových cílů; nebo naopak útočné cíle losovat z benigního rozložení |
| S2 | **Platné Suricata alerty jen z útoků.** Alert vzniká jen v uzávěru `alert` uvnitř `emit_truth`. Všech 13 volání je podmíněno `truth.ids_visible`. Benigní pravdy mají vždy `ids_visible: false`, takže autorizovaný skener ani patch alert nevyvolají. Jediné „alerty“ z benigních událostí jsou poškozené řádky z `log_corruption` (např. `event_type: alert` se `src_ip: null`), které nejsou platné. Každý nález `suricata_alert` tak stojí na útoku z konstrukce. | `traffic.rs:1249–1260` (uzávěr `alert`, `eve_line`), volání `traffic.rs:1329–2186`; benigní pravdy `ids_visible: false` na `traffic.rs:903`; poškozené řádky `traffic.rs:2391–2399` | label leakage (Arp P3); Bad smell „labels leaked via features“ (Flood) | Podíl detekcí, které stojí jen na IDS alertu | Benigní alerty: falešné signatury, ET POLICY a INFO, skener → reálný počet alertů na síť-den |
| S3 | **Útočné toky se nevzorkují, benigní ano**, takže útok je ve velkých sítích relativně hlasitější. | `netmodel.rs:878–881` `flow_sampling()`, komentář „utoky se nevzorkuji“ | sampling bias (027); nerealistický poměr tříd (032) | Detekce podle velikosti sítě se stejným vzorkováním (H-3) | Stejné vzorkování pro útoky, nebo vzorkování až na úrovni senzoru |
| S4 | **Základní četnost.** Na síť-den připadá přibližně 2,66 pozorovatelného útoku (12 724 / 4 784) a útočné toky tvoří přibližně 9,2 % všech toků (36,8 M z 401,7 M). OpTC má škodlivé události s podílem 0,0016 %. | status.md, `plan_episode` (`attack_rate_per_day`) | base rate (030, 055); OpTC (021) | Precision a FP/síť-den přepočtené na realistickou četnost (odhad autora: 0,01–0,1 útoku/síť-den) | Scénáře s řídkými útoky, většina síť-dnů bez útoku (teď jen 20 síť-dnů bez útoku z 4 784) |
| S5 | **Benevolentní atribuce.** Za detekci se počítá jakýkoli nález na kterékoli klíčové IP v okně [start−2, konec+2] cyklů. U horizontálního skenu, ransomwaru a fleet beaconu tvoří klíčové IP stovky obětí. | `episode.rs:710–711` (`ATTRIBUTION_LATENCY = 2`, `episode.rs:52`); `finding_mentions` (`episode.rs:187`, přesná shoda IP přes `mentions_ip`, `episode.rs:164`). Přesná shoda a zkrácené okno lookalike událostí jsou commitnuté v `a293d2b` (2026-10-31 23:40 SEČ). Běh v2 (start 18:57 SEČ) je s velkou pravděpodobností ještě nemá a mohl počítat s podřetězcem (viz Metodika). | „alerting success vs investigation utility“ (053); LM only vs all (025) | „Placebo atribuce“: stejný postup na náhodném okně bez útoku dá míru náhodných zásahů (H-4) | Odečíst placebo míru, hlásit hlavně „správný typ“ a zdrojové pořadí |
| S6 | **„Pozorovatelný“ útok** = `flows_emitted > 0`. Počítadlo se ale zvyšuje dřív, než se tok zablokuje nebo ztratí při výpadku či `degrade`, takže do jmenovatele vstupují i útoky, které telemetrie nikdy neviděla. | `traffic.rs:1194–1216` (`push`), `degrade` až v `traffic.rs:1189` | label inaccuracy (027) | Porovnat jmenovatel s `flows_emitted − blokované − ztracené` | Počítadlo „doručeno do telemetrie“ za `degrade` |
| S7 | **Cirkularita typování.** Metrika „správný typ“ používá `expected_types()`, seznam toho, co engine podle autora umí. Rodiny i signatury navrhl tentýž autor jako detektor. | `traffic.rs:105` | Mahoney & Chan (sdílený předpoklad); Nyberg (rovnoměrný šum) | Nezávislá sada útoků (jiný autor nebo nástroj, pcap replay) | Držené rodiny (H-6); kotva na reálných datech jako primární metrika |
| S8 | **Ruční konstanty místo fitu na data.** Benigní rychlosti (lognormal, medián 18/h), velikosti, denní profil (schodová funkce 1,0 / 0,35 / 0,06) a jitter beaconu ±20 % od začátku cyklu nejsou odvozené z CTU-13, IoT-23 ani jiných dat. | dle průzkumu kódu (`netmodel.rs` a `traffic.rs`, `diurnal`) | marginály ≠ závislosti (045); periodické artefakty (049); rovnoměrný šum (051) | Doménové testy podle Ringa a porovnání rozdělení soak vs CTU-13 background (KS, JSD), autokorelace počtu toků (H-5) | Fit parametrů na reálný background a injekce útoků do reálného pozadí (hybrid podle Mahoneyho) |
| S9 | **Nezávislost v CI.** Wilsonův interval počítá útoky jako nezávislé pokusy, ale útoky v jedné síti sdílejí kvalitu telemetrie, topologii i velikost. | `stats.rs` (Wilson), `report.rs` `ci()` | absence variance a CI (040) | Clusterový bootstrap přes sítě; design effect = var_cluster / var_Wilson (H-7) | Intervaly z clusterového bootstrapu; přes sítě, ne přes útoky |
| S10 | **Žádné držené seedy ani rodiny.** Jeden seed (20261031 ve v2) slouží zároveň k ladění i k hlášení. | `runner.rs:69` (výchozí `run_seed` 20 260 131; seed 20261031 byl při spuštění v2 zadán zvenku, `status.md` ř. 3), `netmodel.rs` `derive(run_seed, network_id)` | data snooping (027), validation-only kalibrace (053), TESSERACT C1 (031) | Výsledek na nových seedech po ladění na starých (H-8) | Rozdělit seedy na ladicí a držené, předregistrace prahů |
| S11 | **Slabá kotva.** Anchor předává prázdné `known_services`, takže ablace A se blíží pravidlu „aspoň 3 toky na klíč“. F1 se počítá per klíč (dst_ip, proto, port). | `src/eval/dataset_replay.rs:137` | jednoduchá baseline (028, 053); úroveň hodnocení (Larroche, event-level) | Už teď: ablace A porazí triviální baseline jen v 6 z 20 scénářů | Dodat inventář služeb z pasivní fáze, hlásit i event-level a host-level metriky |

**Co z literatury odpovídá našim číslům:**

- **Typování lateral movement.** Soak v1 měl 12,5 % správného typu, v2 má 63,4 %. Larroche ukazuje, že lateral movement je při přísném štítkování těžký i pro nejlepší grafové metody (AUC 43–53, RQ5-025). Soak v2 tedy může být spíš optimistický.
- **C2 beacon.** Detekce 12,5 %, medián latence 360 min. Literatura k soaku nemá přímou obdobu. CascadeNet ale ukazuje, že generátory zkreslují časové vzory (RQ5-049). Náš beacon restartuje fázi na začátku každého cyklu, takže jeho periodicita je artefakt generátoru a nižší výsledek nemusí znamenat skutečnou slabinu detektoru.
- **Provozní události vypadají jako útok.** U patch_window má falešný nález 99,2 % výskytů, u collector_replay 97,3 % a u sensor_crash 93,0 %. Nyberg (RQ5-052) zjistil, že simulovaní benigní uživatelé snížili výnosy všech agentů, ale hlavním faktorem byla politika útočníka (ANOVA), a proti průzkumnému útočníkovi („Exploratory“) nebyl vliv uživatelů vždy významný. Benigní aktivita tedy v literatuře náklady zvyšuje, ale nedominuje jim; soak podíly falešných nálezů na provozních událostech samy o sobě nepotvrzují ani nevyvracejí. Podíly ze soaku v2 mohly vzniknout ještě s oknem lookalike událostí prodlouženým o 2 cykly (viz Metodika), po změně mohou být nižší. Je to užitečná a realistická část soaku. Pro hodnocení ji ale chceme na data napojit, ne nastavovat ručně.
- **Kotva na reálných datech.** Ablace A porazí triviální baseline jen v 6 z 20 scénářů. Odpovídá to Arpovi (boxplot ≥ Kitsune) a Guerrovi (allowlist ≥ učené modely). Jako primární srovnání je proto potřeba hlásit triviální baseline.
- **Šum.** FP 1 108 / síť-den při 2,66 útoku / síť-den. Precision behaviorálních nálezů je přibližně 31 % (2 378 886 / (2 378 886 + 5 302 629), odhad autora). Při realistické základní četnosti by byla řádově nižší, viz Axelsson (RQ5-055).

## Syntéza

- **Velikost efektu vad.** Při přechodu z „čistého“ benchmarku do reálnějšího prostředí měřené výkony klesají v rozpětí:
  - 20–72 % relativně při přenosu mezi datasety (7 studií, heterogenní),
  - 58–76 % detekcí po přimíchání reálného provozu (1 studie, 3 sady),
  - na reálné podnikové nebo kampusové síti F1 0,999 → 0,28 (1 studie) a 2 896× víc falešně pozitivních událostí než detekovaných útočných (1 studie, preprint).

  Studie se stejnou metrikou a srovnatelnými podmínkami jsou jen 2, takže je kvantitativně nesdružujeme.
- **Mechanismus** se shoduje ve všech podtématech. Model nebo pravidlo se opře o vlastnost generátoru dat (TTL, IP rozsahy, porty, pevné velikosti, periodicita, rovnoměrný šum), ne o mechanismus útoku. Uvádí to 9 studií (001, 006, 007, 013–015, 016–018, 039, 049, 051).
- **Rozpor ohledně časového rozdělení.** TESSERACT ukazuje velký vliv časové konzistence (malware), BRIDGE zanedbatelný (IoT botnet, −0,009). Vysvětlení: vliv závisí na tom, jak rychle se distribuce v čase mění. V emulovaných datasetech trvajících dny bývá změna malá, v datech sbíraných roky velká.
- **Rozpor u syntetiky.** Distribuční metriky (JSD, EMD) bývají dobré, a přitom úlohová užitečnost špatná (045, 046) a naopak (044). Věrnost proto nejde shrnout jedním číslem. Je potřeba kombinace: marginály, závislosti mezi poli (doménové testy), časová struktura a TSTR.

## Závěry

| Z-id | tvrzení | důkazy | jistota | důvody snížení | použitelnost | doporučená akce |
|---|---|---|---|---|---|---|
| Z-1 | Veřejné NIDS datasety obsahují měřené vady v řádu desítek procent dat, jednotky se ale liší: artefakty toků (CIC17 25,9 % toků), přeštítkované nebo rekonstruované stopy (CIC17 přes 20 %), duplicitní záznamy (KDD 78 % train, 75 % test; duplicita není chyba štítku), chybné procesy (OpTC 40 % procesů, 4,22 % událostí) a odfiltrované toky (ToN-IoT přibližně 14 %). Další chyby štítkování jsou doloženy jen kvalitativně (062, 063: V2, jen abstrakt; jistota na nich nestojí). | 001, 002, 019, 022, 060, 062, 063 | vysoká | – (jádro: měřené vady ve více nezávislých auditech; číslo nejde sdružit, protože jednotky jsou různé) | ano | Kotvu CTU-13 a IoT-23 používat jen s vlastní kontrolou štítků (Background, sken v sc. 5), hlásit per scénář |
| Z-2 | Detektory na benchmarcích se často opírají o artefakty generátoru (TTL, adresy, porty, velikosti) a triviální pravidla na nich dosahují špičkových výsledků. | 006, 007, 013–016, 018, 039 | vysoká | – | ano | Pro soak: povinná baseline „artefaktový detektor“ (S1, S2) |
| Z-3 | Po přechodu na jiný dataset nebo reálný provoz klesá výkon typicky o 20–72 % relativně a v jednotlivých případech k nule. | 013, 034–038 | střední | nekonzistence (heterogenní metriky), nepřímost (ML klasifikátory, ne korelační engine) | s úpravou | Hlásit výsledky na kotvě odděleně od soaku, nikdy je nesčítat |
| Z-4 | Přimíchání reálného pozadí do simulace snižuje počet detekcí a zvyšuje podíl legitimních detekcí. | 017, 018 | nízká | jediná studie (2003), staré detektory | ano | Hybridní soak: útoky injektované do reálného pozadí CTU-13 (H-2) |
| Z-5 | Distribuční podobnost syntetického provozu nezaručuje úlohovou užitečnost ani časovou věrnost. TSTR ztrácí 26–72 p. b. (NetDiffusion, 047) a u DoppelGANger 20 % relativně (042). Jediná metrika věrnosti může klamat (rank korelace AR 1,00 na GCUT při nekvalitních vzorcích). | 042–047, 049 | střední | nepřímost (ne IDS úlohy), střet zájmů (046, 049: autoři hodnotí konkurenci; 049 s výjimkou REaLTabFormer) | ano | Validovat soak doménovými testy a časovou strukturou, ne jen marginálami (H-5) |
| Z-6a | Při nízké základní četnosti útoků vede i malá FPR k více falešným poplachům než skutečným detekcím. Při poměru 1 : 100 dává 99 % TPR a 1 % FPR 100 FP na 99 TP. Bayesovská detekční míra 66 % vyžaduje FPR řádu 10⁻⁵ i při detekci 1,0. | 030, 055 | vysoká | – (analytický důsledek Bayesovy věty, dva recenzované zdroje; úroveň důkazu E5, ale tvrzení je aritmetické) | ano | Hlásit precision a FP/den při realistické četnosti útoků (S4) |
| Z-6b | Poměr tříd v testu může F1 mnohonásobně změnit, ale efekt závisí na poměru v tréninku. ALG2: při tréninku s 90 % malwaru zvedne změna testu z 10 na 90 % F1 z 0,30 na 0,96, při tréninku s 10 % jen z 0,32 na 0,33. Časová nekonzistence (10-fold CV) nadhodnotí F1 o 0,33–0,51. | 031, 032 | nízká | jediná studie a dataset, nepřímost (Android malware, ne NIDS), efekt podmíněný tréninkem | s úpravou | V soaku hlásit poměr útoků v trénovacích (ladicích) i testovacích datech a porovnat výsledky při realistickém poměru (H-3, S4) |
| Z-7 | AUROC může být při silné nevyváženosti zavádějící: vysoké AUROC současně s téměř nulovou AP je doloženo v několika nastaveních (Trace AUROC 0,868–0,997 při AP ≤ 0,062; FiveDirections 0,666–0,943 při AP ≈ 0; OpTC Argus 0,93 při AP 0,024). Neplatí to vždy (Theia: Theseus AUROC 0,994 při AP 0,551). | 026, 053 (054 jen nepřímo: vysoké AUC a precision 0,03–0,05) | střední | zdroje jsou preprinty kromě 053 (NDSS 2027); jedna skupina zdrojů; nekonzistence (protipříklad Theia); mechanismus podporují recenzované analytické zdroje (030, 055) | ano | V soaku a na kotvě hlásit AP a recall při pevném počtu FP za den |
| Z-8 | Volba štítkování a předzpracování mění absolutní výkon i pořadí metod. | 023, 024, 025 | střední | preprinty, jedna skupina (Larroche) | ano | Pevně definovat atribuci v soaku, hlásit placebo míru (H-4) |
| Z-9 | Statistická významnost, rozptyl a držené testovací sady v NIDS literatuře chybějí (2 z 30 prací). | 027, 040, 041 | střední | malé vzorky (041: 10 odpovídajících praktiků, 9/10 = 90 %) | ano | Clusterový bootstrap a držené seedy (H-7, H-8) |
| Z-10 | Simulátor s rovnoměrným šumem podhodnocuje dopad benigní aktivity. V emulaci byly falešné alerty nerovnoměrné (např. 0,05 % a 10 % u jednotlivých kroků bez uživatelů, 17 % s uživateli) a výnosy agentů klesly o 80–109 % proti cílenému útočníkovi (proti průzkumnému jen o 5–14 %), přičemž hlavním faktorem byla politika útočníka, ne uživatelé. | 051, 052 | nízká | jediná studie, preprint; tvrzení o „podhodnocení dopadu benigní aktivity“ je interpretace, ne přímý výsledek zdroje | ano | Kalibrovat šum soaku z reálných dat per typ zařízení (H-5) |
| Z-11 | Syntetická augmentace dat spolehlivě nezlepšuje klasifikaci NIDS. | 050 | nízká | workshopový článek, jedna studie | s úpravou | Neučit prahy ze syntetiky bez kontroly na kotvě |
| Z-12 | Jednoduchá baseline často dorovná nebo překoná složitou metodu (boxplot ≥ Kitsune, allowlist ≥ PIDS). | 007, 028, 053 | střední | rozdílné úlohy | ano | Každá změna enginu proti triviální baseline na stejných seedech |

## Překlad do praxe (Salticus a soak)

1. **Artefaktová baseline jako povinný řádek reportu** (z Z-2, Z-12). Do `report.rs` přidat tři triviální detektory se stejnou atribucí:
   - (a) „odchozí spojení na externí adresu, která není mezi 12 `externals` sítě“ (v současném generátoru ji mají jen útoky a tři řídké lookalike události, viz S1),
   - (b) „existuje Suricata alert“,
   - (c) „aspoň 3 toky na neznámou službu“.

   Engine musí každý z nich porazit per rodinu. Kde neporazí, je výsledek té rodiny podezřelý z artefaktu.
2. **Odstranit S1–S3 v generátoru.**
   - Benigní odchozí cíle losovat stejným generátorem jako útočné, s realistickým podílem dosud neviděných cílů. Příchozí směr už sdílený pool má. Podíl nových cílů je extrapolace: v literatuře jsme ho nenašli, je potřeba ho změřit na kotvě (CTU-13 background).
   - Benigní Suricata alerty v realistickém množství. Hodnota za síť-den je extrapolace: v literatuře jsme ji nenašli, je potřeba ji změřit na vlastním senzoru nebo převzít z CTU-13 alert logů, pokud existují.
   - Stejné vzorkování útočných i benigních toků.
3. **Hybridní režim „reálné pozadí + injektovaný útok“** (z Z-4, Z-5): benigní toky z CTU-13 Background nebo IoT-23 benign (po kontrole štítků) a generované útoky vložené s odpovídajícím časem a adresami. Volba datasetu je extrapolace: CTU-13 je zachycení z univerzity z roku 2011 a nemusí odpovídat archetypům Hospital nebo Industrial.
4. **Metriky** (z Z-6a, Z-7, Z-9):
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

- **H-1 (artefakt odchozích cílů).** Změna: běžný benigní odchozí provoz (stanice na 443, NTP z brány, retry storm) nemíří jen na 12 pevných `externals` sítě. Část toků (podíl p, výchozí volba p = 0,2 je odhad autora a má se nahradit hodnotou změřenou na CTU-13 background) míří na nové adresy z `public_ip()`. Útočné cíle zůstávají beze změny. Tím zmizí oddělení podle prvního oktetu i podle novosti cíle (S1). Příchozí směr se nemění, protože sdílený pool už má.
  - Očekávaný efekt: hlavně více falešných nálezů odchozího typu a nižší precision, ne nutně pokles detekce. FP/síť-den nálezů typu beacon, exfiltrace, tunel a „nový externí cíl“ vzroste aspoň 1,5×. Detekce rodin s externím cílem (c2_beacon, exfiltration, dns_tunnel, cryptomining, insider_hoarding, fleet_beacon, apt_chain, ransomware) klesne o 0–20 % relativně, pokud engine na novosti cíle staví. Obě čísla jsou odhad autora: literatura (RQ5-006, 013, 016–018) dokládá, že artefakt adres a TTL umí výsledky nafouknout, ale velikost efektu pro korelační engine neuvádí. Negativní kontrola: rodiny jen s příchozím externím zdrojem (ssh_bruteforce, credential_stuffing, web_exploit, ddos_volume) se změní o méně než 2 p. b. Pokud se změní víc, změna zasáhla i něco jiného než artefakt.
  - Metrika: FP/síť-den podle typu nálezu, precision nálezů, detekce a správný typ per rodina; rozdíl s clusterovým bootstrap CI (přes sítě).
  - Scénář: soak v2, 200 sítí, držené seedy, A/B na stejných seedech. Doplňkově triviální baseline „odchozí spojení mimo `externals`“ na obou ramenech: v rameni A by měla mít vysokou precision, v rameni B nízkou.
  - Kritérium zamítnutí: 95% CI poměru FP/síť-den (B/A) u odchozích typů nálezů obsahuje 1, nebo je jeho horní mez pod 1,1, a zároveň je horní mez 95% CI poklesu detekce pod 2 p. b. u všech osmi rodin s externím cílem. Hypotéza „artefakt nadhodnocuje výsledky“ se tím zamítne a artefakt je pro engine neškodný.
- **H-2 (reálné pozadí).** Změna: hybridní režim s benigním provozem z CTU-13 Background.
  - Očekávaný efekt: FP/síť-den se změní aspoň o faktor 2 (směr neznámý). Detekce slow_scan a lateral_movement klesne o 10–60 % relativně (RQ5-017, 025).
  - Metrika: FP/síť-den, detekce per rodina, AP.
  - Scénář: 13 scénářů CTU-13 × injekce 19 rodin, 3 seedy.
  - Kritérium zamítnutí: FP/síť-den v intervalu 0,5–2× syntetického a detekce všech rodin v ±5 p. b. Syntetické pozadí je pak pro tento účel postačující.
- **H-3 (vzorkování a velikost sítě).** Změna: útočné toky vzorkovat stejně jako benigní.
  - Očekávaný efekt: pokles detekce ve vrstvách XL a XXL o ≥ 5 p. b. u objemově detekovaných rodin (ssh_bruteforce, ddos, credential_stuffing). Ve vrstvě S beze změny, protože vzorkování je tam 1,0. Opírá se o mechanismus poměru tříd (RQ5-032, Z-6b, nízká jistota), takže rozsah je odhad autora.
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
- **Extrakce.** Tabulky v PDF se rozpadají. Nezávislá kontrola našla věcnou chybovost 11,8 % (6 z 51 řádků), převážně záměnu řádku nebo detektoru v rozpadlé tabulce a zobecnění hodnoty z jednoho datasetu. Po revizi jsme pořadí ve všech dotčených tabulkách ověřili ze surového textu sloupců a hodnoty u Layeghyho z čitelné Tab. 4. Druhou kontrolu po první revizi dělal tentýž autor, který revizi psal, a její výsledek 0 / 47 neplatil. Druhá nezávislá kontrola (59 z 63 řádků) našla věcnou chybovost 8,5 % (5 / 59), všechny chyby v podmínkách, poznámkách a metadatech, ne v polích `hodnota`; ty jsou opraveny druhou revizí, kterou opět psal tentýž autor jako extrakci, takže opravy samy nejsou nezávisle ověřeny. Arpovu Tab. 1 jsme nepoužili. U Majorczyka máme jen slajdy.
- **Nepřímost.** Velká část důkazů se týká supervizovaných ML klasifikátorů, Android malwaru (TESSERACT, Arp 4.1) nebo nebezpečnostních časových řad (DoppelGANger). Salticus je korelační a ověřovací engine, ne flow klasifikátor, takže přenos velikostí efektu je extrapolace.
- **Publikační zkreslení.** Kritické práce mají motivaci najít vady (audity) a generátorové práce hodnotí konkurenci (NetDiffusion → NetShare). Negativní výsledky jsou vzácnější, našli jsme jen Wolf 2024 a BRIDGE (časový split).
- **Preprinty.** RQ5-024, 025, 026, 038, 039, 051, 052 a 054 nejsou recenzované a RQ5-050 prošel jen workshopovým recenzním řízením, proto mají v Závěrech nižší jistotu. RQ5-053 byl původně veden jako preprint, ale je přijat na NDSS 2027, a RQ5-022 je recenzovaný (ACSAC Workshops 2025). Závěry, které stojí převážně na preprintech (Z-8, Z-10, Z-11, částečně Z-7, kde 053 je recenzovaný), mají nejvýš střední jistotu.
- **Soak a stav kódu.** Atribuce s přesnou shodou IP a zkrácené okno lookalike událostí jsou commitnuté v `a293d2b` (2026-10-31 23:40 SEČ). Běh v2 začal v 18:57 SEČ a status uvádí commit `unknown`, takže čísla z něj s velkou pravděpodobností vznikla se starší verzí atribuce.
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
