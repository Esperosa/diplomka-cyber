# 09 Poučení z veřejných open-source projektů a literatury

Datum: 2026-11-13
Stav: rešeršní podklad pro diplomovou práci (produkt Salticus, Rust), bez převzetí kódu a pravidel.

## 1. Úvod: rozsah a metoda

Cílem je zjistit, jak veřejné projekty a publikace řeší pět otázek: detekci, korelaci, tvorbu hypotéz, ověřování a měření pokrytí. Z projektů si berou poučení o postupu a o struktuře znalostí. Kód, pravidla ani datové sady se nepřebírají.

Metoda:

- Čtení pouze veřejných zdrojů: README a dokumentace projektů, licenční soubory v repozitářích, metadata repozitářů přes veřejné rozhraní GitHubu (jen čtení), stránky projektů MITRE, bibliografické záznamy článků.
- Licence jsou převzaty z licenčních souborů v repozitáři (stav k 2026-11-13). Kde je repozitář dvou nebo více licencí, je to uvedeno. Automatická detekce GitHubu u několika repozitářů vrací „neurčeno“, proto se vychází z textu souboru.
- Seznam ATT&CK technik je ověřen strojově proti publikovaným datům ATT&CK Enterprise (verze 20.1, změněno 2026-11-05, repozitář `mitre-attack/attack-stix-data`). Každé ID existuje, žádné není zrušené ani zastaralé. Názvy taktik odpovídají této verzi (např. `stealth` a `defense-impairment` místo dřívějšího `defense-evasion`).
- Co se z veřejných stránek nepodařilo potvrdit, je označeno „neověřeno“. Popisy projektů vycházejí jen z toho, co je na uvedených stránkách napsáno.
- Atomic Red Team a Caldera jsou zde jen katalog (název, účel, licence). Žádné příkazy, payloady ani exploit kódy nejsou uvedeny ani zkoumány.
- Nic se neodesílalo ven. Všechny přístupy byly čtení veřejných stránek.

Formát sekcí: co dělají, co si bereme, co ne, licence, odkaz.

## 2. Projekty a zdroje

### 2.1 Zeek (a balíčky)

Co dělají:
- Pasivně analyzuje provoz a vytváří strukturované protokolové logy (spojení, DNS, TLS a další). Výstup je metadata, ne obsah.
- Skriptovací jazyk a frameworky, např. Intelligence framework: načítá indikátory (IP, domény, e-maily) z textových souborů, hlásí pozorované hodnoty a při shodě vyvolá událost a zápis do `intel.log`. Výchozí hlášení pokrývá jen navázaná TCP spojení; pokrytí UDP a ICMP vyžaduje vlastní hlášení s vyšší zátěží (dokumentace Zeek).
- Správce balíčků a katalog komunitních rozšíření (packages.zeek.org). Konkrétní balíčky tato rešerše neposuzuje (neověřeno).

Co si bereme:
- Oddělení „co se stalo na drátě“ (metadata) od „co si o tom myslíme“ (skripty a notice).
- Jednotný záznam na spojení s identifikátorem, na který se vážou další protokolové záznamy; vhodný vzor pro korelaci.
- Explicitní přiznání mezí: výchozí pokrytí je jen TCP, další vyžaduje vědomé rozhodnutí.

Co ne:
- Skripty ani jejich logiku nepřebíráme. Zeek je závislost mimo Rust, Salticus vlastní metadata vyrábí sama.

Licence: BSD (text v souboru `COPYING`, Regents of the University of California / LBNL / ICSI).
Odkazy: https://github.com/zeek/zeek , https://docs.zeek.org/en/master/frameworks/intel.html , https://packages.zeek.org

### 2.2 RITA a AC-Hunter

Co dělají:
- RITA analyzuje logy Zeek (TSV nebo JSON) a hlásí beaconing (v obou směrech přes hranici sítě), dlouhá spojení, DNS tunelování a shody s threat intel (README projektu).
- Skóre beaconu je celé číslo, lze filtrovat (např. `beacon:>=90`) a je konfigurovatelné; metodu výpočtu README nepopisuje, proto ji zde neuvádíme (neověřeno).
- AC-Hunter je komerční produkt stejné firmy; v této rešerši nebyl zkoumán (neověřeno).

Co si bereme:
- Čtyři kategorie hledání jako přehled základních analytických otázek nad toky: pravidelnost, délka, DNS struktura, reputace.
- Prahové skóre jako uživatelsky nastavitelný filtr, ne rozhodnutí. Skóre je pomůcka k řazení případů.

Co ne:
- Neodvozujeme konkrétní skórovací vzorec z cizího kódu. Vlastní metodu musíme odvodit a změřit na vlastních datech.

Licence: GPL-3.0 (repozitář `activecm/rita`; starší větev `rita-legacy` také GPL-3.0). Kód se nepřebírá.
Odkaz: https://github.com/activecm/rita

### 2.3 Suricata a Snort (taxonomie pravidel, ET Open)

Co dělají:
- Suricata a Snort jsou síťové IDS/IPS založené na pravidlech nad pakety a aplikačními buffery. Suricata: licence GPL-2.0.
- Sada Emerging Threats Open dělí pravidla do souborů podle kategorií. Z veřejného adresáře (`rules.emergingthreats.net/open/suricata/rules/`) jsou k vidění např. `emerging-dns`, `emerging-scan`, `emerging-malware`, `emerging-ja3`, `emerging-policy`, `emerging-hunting`, `emerging-coinminer`, `emerging-exploit`, `emerging-web_server`, `emerging-user_agents`, `emerging-phishing`, `emerging-dos`, `emerging-icmp`, `emerging-smtp`, `emerging-snmp`, `emerging-tftp`, `emerging-scada`, `emerging-deleted`, `emerging-retired`; dále `botcc`, `compromised`, `tor`, `dshield`, `ciarmy` a soubor `classification.config`. Adresář obsahuje `BSD-License.txt` a `gpl-2.0.txt`.
- Měření pokrytí: tato rešerše nenašla ve zkoumaných stránkách standardizovaný postup měření pokrytí pravidel Suricaty proti ATT&CK (neověřeno).

Co si bereme:
- Taxonomie podle role pravidla: některé jsou „hunting“ (širší, více falešných poplachů), jiné „malware“ nebo „policy“. Rozlišení „indikace“ proti „politice“ je užitečné pro váhy důkazů.
- Oddělení retired a deleted: pravidla mají životní cyklus.
- Soubor s třídami (`classification.config`) jako příklad pevné, malé množiny kategorií.

Co ne:
- Nepřebíráme pravidla ani jejich texty. Kategorie slouží jako inspirace pro vlastní, stručnější taxonomii.

Licence: Suricata GPL-2.0 (GitHub API). Snort 3: GPL-2.0 (úvod souboru `COPYING` hovoří o GPL v2). ET Open: BSD a GPL-2.0 soubory v adresáři pravidel; přesné podmínky pro konkrétní použití neověřeno.
Odkazy: https://github.com/OISF/suricata , https://docs.suricata.io/en/latest/rules/intro.html , https://github.com/snort3/snort3 , https://rules.emergingthreats.net/

### 2.4 Security Onion

Co dělají:
- Distribuce pro monitorování sítě. Podle README obsahuje vlastní rozhraní pro alerty, dashboardy, hunting, PCAP, detekce a správu případů (Security Onion Console), a dále osquery, CyberChef, Elasticsearch, Logstash, Kibana, Suricata a Zeek. Metadata sítě pochází ze Zeek nebo Suricaty, plný záznam paketů přes Suricata PCAP.
- Postup analytika mezi alerty, huntem a případy README nepopisuje (neověřeno).

Co si bereme:
- Myšlenku jednoho prostředí, kde alert, metadata a surový záznam jsou přístupné z jednoho místa a případ je samostatný objekt.

Co ne:
- Neprovozujeme celé SIEM prostředí. Salticus zůstává malým produktem.

Licence: Elastic License 2.0 (soubor `LICENSE` v repozitáři). Komponenty uvnitř mají vlastní licence.
Odkazy: https://github.com/Security-Onion-Solutions/securityonion , https://docs.securityonion.net/

### 2.5 Malcolm

Co dělají:
- Sada kontejnerů pro analýzu síťového provozu. Vstup: PCAP, logy Zeek a alerty Suricaty (nahrání nebo přeposílání). Data se normalizují, obohacují a korelují; rozhraním jsou OpenSearch Dashboards a Arkime (malcolm.fyi).
- Podpora ICS protokolů je na stránce uvedena jako plánovaná; stav v aktuální verzi neověřen.

Co si bereme:
- Pořadí „normalizace, obohacení, korelace“ jako základní tok dat a explicitní oddělení těchto tří kroků.

Co ne:
- Nepřebíráme architekturu s mnoha službami.

Licence: Apache-2.0 (soubor `LICENSE.txt`, Battelle Energy Alliance).
Odkazy: https://github.com/cisagov/Malcolm , https://malcolm.fyi/

### 2.6 Arkime

Co dělají:
- Systém pro velkoobjemový záznam paketů, indexaci a ukládání metadat. Packety ukládá jako standardní PCAP, metadata relací indexuje do OpenSearch/Elasticsearch. Pohledy Sessions a SPI View. Volitelná komponenta WISE přidává threat intel k metadatům relací. Podle stránky má doplňovat IDS, ne je nahrazovat.

Co si bereme:
- Vazba „relace v metadatech vede na zdrojové pakety“ jako vzor pro vysvětlitelnost: každý závěr se má dát vystopovat k pozorování.

Co ne:
- Plný záznam paketů je mimo rozsah Salticus (soukromí, objem).

Licence: Apache-2.0 (GitHub API).
Odkazy: https://github.com/arkime/arkime , https://arkime.com/

### 2.7 Wazuh

Co dělají:
- Hostitelský i síťový bezpečnostní monitoring. Pravidlo se k technice ATT&CK váže blokem `<mitre>` s ID techniky; v alertu pak je ID techniky a příslušné taktiky. Rozhraní MITRE ATT&CK nabízí přehled (celkem událostí a alertů, nejčastějších 10 technik), rámec (pozorované taktiky a techniky), události a znalosti o skupinách a mitigacích (dokumentace Wazuh).
- Procento pokrytí dokumentace nepopisuje; rámec ukazuje jen pozorované techniky (neověřeno, zda existuje jiný výpočet).

Co si bereme:
- Rozlišení „co pravidlo deklaruje“ (mapování) a „co se skutečně pozorovalo“ (výskyt). To jsou dvě různé veličiny, pokrytí pravidel a pokrytí provozu.

Co ne:
- Mapování pravidla na techniku není důkaz, že pravidlo techniku zachytí.

Licence: dvojí: engine pod `src/engine/` je AGPL-3.0 nebo novější; sdílené knihovny jsou GPL-2.0 nebo AGPL-3.0 (soubor `LICENSE`). Zbylé části neověřeno z textu.
Odkazy: https://github.com/wazuh/wazuh , https://documentation.wazuh.com/current/user-manual/ruleset/mitre.html

### 2.8 Elastic detection-rules

Co dělají:
- Repozitář pravidel Elastic Security s nástrojem pro tvorbu, validaci a testy. Příkazy: `python -m detection_rules test` spouští jednotkové testy v `tests/`, `validate-all` validuje všechna pravidla proti schématu. Zmíněny jsou schémata ECS a Beats a odznak „ATT&CK navigator coverage“. Emulace technik pro ověření pravidel je v samostatném repozitáři Cortado (README).
- Jak přesně se pokrytí počítá, README nepopisuje (neověřeno).

Co si bereme:
- Pravidlo je artefakt s testy a schématem, ne jen text. Pokrytí se zobrazuje jako vrstva v ATT&CK Navigatoru.
- Oddělení emulace od detekce: „zkouška“ je samostatný repozitář.

Co ne:
- Žádný přenos pravidel ani jejich dotazů.

Licence: Elastic License 2.0 (soubor `LICENSE.txt`). Pravidla ELv2 není vhodné kopírovat do produktu bez právního posouzení.
Odkaz: https://github.com/elastic/detection-rules

### 2.9 Sigma

Co dělají:
- Obecný formát pravidel pro logy. Pole: `logsource` (category, product, service), `detection` s pojmenovanými výběry, `condition`, `level` (informational až critical), `status` (stable, test, experimental, deprecated, unsupported), `tags` s `attack.*`, `falsepositives`. Pole `falsepositives` konvertory ignorují. Konverze do dotazů cílových systémů: `sigma-cli` a pySigma s backendy a pipeline.

Co si bereme:
- Metadata pravidla (zralost, závažnost, známé falešné poplachy) jako povinná pole. U vlastní detekce Salticus to platí také.
- Princip logického zdroje: detekce deklaruje, jaká data potřebuje. Při chybějících datech je správný výsledek „nelze posoudit“, ne „čisto“.

Co ne:
- Nekonvertujeme pravidla Sigma. Síťových logů je v repozitáři málo a formát cílí na vyhledávání v logách.

Licence: specifikace a logo jsou public domain; pravidla v repozitáři SigmaHQ pod Detection Rule License (DRL) 1.1 (soubor `LICENSE`); pySigma LGPL-2.1.
Odkazy: https://github.com/SigmaHQ/sigma , https://sigmahq.io/docs/basics/rules.html , https://github.com/SigmaHQ/pySigma

### 2.10 Velociraptor

Co dělají:
- Nástroj pro hostitelskou viditelnost a forenzní sběr. Dotazovací jazyk VQL, artefakty (parametry, zdroje, předpoklady), komunitní Artifact Exchange, hunty a sběr ve velkém měřítku (offline kolekce, hromadné získání souborů) podle dokumentace. Síťové artefakty stránka nezmiňuje (neověřeno).

Co si bereme:
- Ověření hypotézy na hostu jako samostatný krok: síťové pozorování řekne „kdo s kým“, hostitelský dotaz řekne „který proces“. Salticus tento krok nedělá sama, ale má ho popsat jako doporučený postup.

Co ne:
- Nesbíráme data z hostů (viz studie 08, endpoint telemetrie).

Licence: AGPL-3.0 (soubor `LICENSE`).
Odkazy: https://github.com/Velocidex/velociraptor , https://docs.velociraptor.app/

### 2.11 osquery

Co dělají:
- Dotazování stavu operačního systému přes SQL tabulky. Zmiňované funkce: sady dotazů, plánované dotazy, výstup jen s rozdíly mezi během a tabulky pro procesy, otevřené sokety a naslouchající porty.

Co si bereme:
- Diferenční výstup (co se změnilo od posledního měření) jako návrhový vzor pro srovnání s baseline hosta a pro odhalení konfiguračního driftu.

Co ne:
- Neintegrujeme agenta.

Licence: Apache-2.0 nebo GPL-2.0-only dle volby uživatele (soubor `LICENSE`).
Odkazy: https://github.com/osquery/osquery , https://osquery.io/

### 2.12 MISP

Co dělají:
- Platforma pro sběr a sdílení indikátorů a informací o hrozbách. Taxonomie (klasifikační sady, např. odhadní jazyk), galaxie (komunitní znalostní klastry: ATT&CK, aktéři, ransomware), korelace souvisejících dat, synchronizace mezi instancemi, enrichment moduly v Pythonu, exporty do STIX a OpenIOC pro IDS/SIEM. Warninglisty jsou na stránce jen zmíněny v navigaci (neověřeno, co přesně dělají).

Co si bereme:
- Indikátor s kontextem (kdo, kdy, s jakou důvěrou) a se štítky z pevných taxonomií místo volného textu.
- Oddělení enrichmentu od jádra: modul rozšiřuje, ale nemění data.

Co ne:
- Nebudeme sdílet data mimo organizaci (viz zásada, že nic neodchází ven).

Licence: AGPL-3.0 (GitHub API).
Odkazy: https://github.com/MISP/MISP , https://www.misp-project.org/

### 2.13 OpenCTI

Co dělají:
- Platforma pro správu znalostí o hrozbách. Podrobnosti o datovém modelu nebyly zkoumány (neověřeno).

Co si bereme:
- Pouze odkaz, že existuje jako protějšek MISP; pro Salticus se nezkoumal.

Licence: Community Edition Apache-2.0, Enterprise Edition pod vlastní licencí Filigran (soubor `LICENSE`).
Odkazy: https://github.com/OpenCTI-Platform/opencti , https://docs.opencti.io/

### 2.14 TheHive a Cortex

Co dělají:
- TheHive spravuje případy a pozorování (observables). Cortex spouští analyzery nad pozorováními (IP, e-mail, URL, doména, soubor, hash); analyzery jsou v Pythonu a lze napsat další. Jeden analyzer může mít více variant (např. odeslat soubor, nebo vyzvednout existující zprávu). TheHive spouští analyzery ve velkém počtu pozorování na pár kliknutí a má šablony pro zobrazení výstupu (README Cortex). Role „responder“ je jen zmíněna (neověřeno).

Co si bereme:
- Enrichment jako samostatný, opakovatelný krok se záznamem výstupu u případu. To je základ pro „historii případu“ a pro opakované měření.
- Různé varianty téhož zdroje (levný dotaz proti drahému odeslání): u Salticus rozlišit enrichment lokální (bez odeslání) a ten, který by data odesílal ven.

Co ne:
- Odesílání dat třetím stranám je zakázáno; enrichment zůstává lokální.

Licence: Cortex AGPL-3.0, TheHive AGPL-3.0 (GitHub API, TheHive poslední změna 2025-07).
Odkazy: https://github.com/TheHive-Project/Cortex , https://github.com/TheHive-Project/TheHive , https://docs.strangebee.com/cortex/

### 2.15 MITRE ATT&CK

Co dělají:
- Znalostní báze taktik a technik protivníka. Data jsou ke stažení v STIX (repozitář `mitre-attack/attack-stix-data`), aktuálně verze 20.1.

Co si bereme:
- Pevný slovník pro mapování. Každá technika se klasifikuje podle viditelnosti (net, host, both), viz sekce 3.
- Verzovaný slovník: změny taktik (nově `stealth`, `defense-impairment`) vyžadují přepsání mapování při aktualizaci.

Co ne:
- Mapování na ATT&CK není měřítko kvality. Technika může být „pokryta“ jediným slabým pravidlem.

Licence: MITRE uděluje bezúplatnou nevýhradní licenci pro výzkum, vývoj i komerční využití při zachování označení autorských práv (soubor `LICENSE.txt` v repozitáři dat).
Odkazy: https://attack.mitre.org/ , https://github.com/mitre-attack/attack-stix-data

### 2.16 MITRE CAR

Co dělají:
- Repozitář analytik postavených na ATT&CK. Každá analytika má hypotézu, informační doménu (host, síť, proces, externí), odkazy na ATT&CK, glosář, pseudokód a jednotkový test (způsob, jak ji vyvolat). Dále datový model, senzory, implementace (např. Splunk, EQL) a vrstvu pokrytí v ATT&CK Navigatoru. BZAR (skripty Zeek pro SMB a RPC) je uveden jako samostatná sada implementací.

Co si bereme:
- Strukturu záznamu: hypotéza, doména, pseudokód, test. Přesně to je podoba, kterou potřebuje každé vlastní pravidlo Salticus.
- Povinný „test, který analytiku vyvolá“ jako podmínku zařazení.

Co ne:
- Počet analytik není měřítko hodnoty; repozitář nemá aktualizace po 2025-05 (GitHub API).

Licence: Apache-2.0.
Odkazy: https://car.mitre.org/ , https://github.com/mitre-attack/car

### 2.17 MITRE D3FEND

Co dělají:
- Znalostní graf obranných opatření (verze 1.6.0 na stránce). Taktiky: Model, Harden, Detect, Isolate, Deceive, Evict, Restore. Pod Detect jsou síťové techniky: Network Traffic Analysis, Administrative Network Activity Analysis, Application Protocol Command Analysis, Connection Attempt Analysis, DNS Traffic Analysis, Inbound Session Volume Analysis, IPC Traffic Analysis, Network Traffic Community Deviation, Network Traffic Signature Analysis, Per Host Download-Upload Ratio Analysis, Protocol Metadata Anomaly Detection, Relay Pattern Analysis, RPC Traffic Analysis. Stránka propojuje techniky s ATT&CK a digitálními artefakty; mechanismus mapování nepopisuje (neověřeno).

Co si bereme:
- Seznam obranných analytických technik nad sítí jako kontrolní soupis, zda Salticus pokrývá např. poměr stahování a odesílání na hosta, odchylku od komunity (peer srovnání), anomálie protokolových metadat.

Co ne:
- Nepřebíráme ontologii; používáme jen názvy.

Licence: MIT (repozitář `d3fend/d3fend-ontology`).
Odkazy: https://d3fend.mitre.org/ , https://github.com/d3fend/d3fend-ontology

### 2.18 Atomic Red Team a Caldera (jen katalog)

- Atomic Red Team: knihovna testů mapovaných na ATT&CK, spouštěných lokálně nebo přes framework (Invoke-Atomic). Licence MIT. https://github.com/redcanaryco/atomic-red-team
- Caldera: platforma pro automatizaci emulace protivníka, postavená na ATT&CK; jádro (C2 server s REST API) a pluginy (např. Atomic, Emu, Stockpile). Licence Apache-2.0 (repozitář `apache/caldera`, dříve `mitre/caldera`). https://github.com/apache/caldera
- Využití pro Salticus: pouze jako katalog názvů technik na úrovni ATT&CK pro plánování laboratorních scénářů a pro vazbu na doménový seznam v sekci 3. Testy ani abilities se nespouštějí a nezkoumají.

### 2.19 Akademické práce

NetFlow detekce:
- Sperotto a kol., „An Overview of IP Flow-Based Intrusion Detection“, IEEE Communications Surveys & Tutorials, 2010, DOI 10.1109/SURV.2010.032210.00054. Přehled detekce na tocích (obsah, tvrzení o kategoriích útoků a omezeních neověřeno do detailu). https://doi.org/10.1109/SURV.2010.032210.00054
- Sommer a Paxson, „Outside the Closed World: On Using Machine Learning for Network Intrusion Detection“, IEEE S&P 2010, DOI 10.1109/SP.2010.25. https://doi.org/10.1109/SP.2010.25 (obsah neověřován nad rámec bibliografických údajů).
- Arp a kol., „Dos and Don'ts of Machine Learning in Computer Security“, USENIX Security 2022. https://www.usenix.org/conference/usenixsecurity22/presentation/arp (obsah neověřován nad rámec bibliografických údajů).

Kitsune/KitNET:
- Mirsky, Doitshman, Elovici, Shabtai, „Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection“, NDSS 2018, arXiv 1802.09089. Podle abstraktu jde o plug-and-play NIDS učený bez dohledu přímo na lokální síti, online, s rámcem pro efektivní sledování vzorců každého síťového kanálu; jádro KitNET je soubor autoenkodérů; výkon srovnatelný s offline detektory a běh na Raspberry Pi. Licence kódu `Kitsune-py`: neověřeno. https://arxiv.org/abs/1802.09089
- Co si bereme: lokálně učená norma (baseline na místě), inkrementální statistiky na kanál. Co ne: skóre odchylky samo o sobě není vysvětlení, analytik potřebuje důvod.

CICFlowMeter a CIC-IDS2017:
- Sharafaldin, Lashkari, Ghorbani, „Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization“, ICISSP 2018, DOI 10.5220/0006639801080116 (datová sada CIC-IDS2017). https://doi.org/10.5220/0006639801080116 ; stránka sady https://www.unb.ca/cic/datasets/ids-2017.html ; nástroj https://github.com/ahlashkari/CICFlowMeter (licence neověřena).

Kvalita labelů:
- Engelen, Rimmer, Joosen, „Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study“, IEEE Security and Privacy Workshops 2021, s. 7 až 12, DOI 10.1109/SPW53761.2021.00009. Autoři popisují problémy při generování provozu, tvorbě toků, extrakci rysů a označování a překonstruovali či znovu označili více než 20 procent původních stop; opravy se týkaly nástroje CICFlowMeter (např. ukončení toku až po FIN z obou stran, RST jako ukončení). Kód a označování jsou zveřejněny v repozitáři autorů. https://dblp.uni-trier.de/rec/conf/sp/EngelenRJ21.html
- Lanvin, Gimenez, Han, Majorczyk, Mé, Totel, „Errors in the CICIDS2017 Dataset and the Significant Differences in Detection Performances It Makes“, CRiSIS 2022, LNCS 13857, s. 18 až 33, DOI 10.1007/978-3-031-31108-6_2. Autoři uvádějí chyby v označení a záznamu: přeházené pořadí paketů, duplikace paketů a provedené útoky bez správného označení, a posuzují vliv oprav na hodnocení supervizovaných metod. Existence ověřena přes HAL (hal-03775466) a stránku autora. https://hal.archives-ouvertes.fr/hal-03775466
- Poučení: výsledek jednoduchého detektoru na veřejné sadě závisí na kvalitě labelů a na nástroji pro tvorbu toků. Salticus proto nehlásí přesnost z jedné veřejné sady; sadu před použitím kontroluje (pořadí a duplicity paketů, shoda časů útoku s labely) a výsledky uvádí s intervalem nejistoty.


## 3. Síťově viditelné ATT&CK techniky

Seznam obsahuje 112 technik a podtechnik z ATT&CK Enterprise v20.1. Každé ID bylo strojově ověřeno proti publikovaným datům (existuje, není zrušené ani zastaralé). Názvy jsou převzaty z dat. Strojově čitelná podoba je v souboru `09-attack-technik.txt` (ID, taktika, název, viditelnost, oddělené tabulátorem).

Význam sloupce viditelnost:
- `net`: dá se pozorovat v tocích, DNS, TLS nebo v síťovém logu protokolu; hostitelský log zpřesní, ale není nutný.
- `both`: síťová stopa je jen část obrazu a rozhodující důkaz je v hostitelském, autentizačním nebo cloudovém logu.
- `host`: v síti téměř neviditelné; záměrně zařazeno jako negativní příklad, aby seznam nesliboval víc, než data umožní (T1040, T1049, T1091).

Sloupec „Proč“ popisuje, co lze v datech hledat, ne že jde o spolehlivý signál. Přiřazení je úsudek autora studie podle povahy techniky, ne tvrzení MITRE. Taktika je jedna (hlavní), i když technika může spadat do více taktik; u T1205, T1078, T1550 a několika dalších je zvolena taktika podle síťové role (ověřeno, že je mezi taktikami dané techniky).

Chybějící technika neznamená, že je neviditelná, jen že ji do seznamu nezařazujeme. Seznam netvrdí, že Salticus všechny tyto techniky detekuje.

| ID | Název | Taktika | Viditelnost | Proč je viditelná (nebo není) v tocích, DNS, TLS a logu |
|---|---|---|---|---|
| T1595.001 | Scanning IP Blocks | reconnaissance | net | sken rozsahů IP: jednosměrné SYN/ICMP spojení na mnoho cílů, krátké záznamy v conn.log |
| T1595.002 | Vulnerability Scanning | reconnaissance | net | skenery zranitelností: série HTTP požadavků s typickými cestami a user-agentem v http.log |
| T1595.003 | Wordlist Scanning | reconnaissance | net | slovníkové skenování URL: vysoký podíl odpovědí 404 z jednoho zdroje |
| T1190 | Exploit Public-Facing Application | initial-access | net | zneužití veřejné aplikace: neobvyklé požadavky a odpovědi na exponované službě, následné odchozí spojení |
| T1189 | Drive-by Compromise | initial-access | both | drive-by: přesměrování a načtení obsahu z nové domény (DNS, HTTP, TLS SNI); doplňuje záznam prohlížeče |
| T1566.001 | Spearphishing Attachment | initial-access | both | příloha e-mailu: SMTP/IMAP metadata a přenos souboru; doplňuje poštovní log |
| T1566.002 | Spearphishing Link | initial-access | both | odkaz v e-mailu: následný DNS dotaz a HTTP/TLS spojení na neznámou doménu |
| T1133 | External Remote Services | initial-access | net | externí vzdálené služby: přihlášení VPN/RDP/SSH z neobvyklého zdroje a času |
| T1078 | Valid Accounts | initial-access | both | platné účty: neobvyklý zdroj, čas nebo cíl přihlášení v tocích a v autentizačních logech |
| T1078.004 | Cloud Accounts | initial-access | both | cloudové účty: přihlášení ke cloudovým API z neobvyklých adres (TLS SNI, cloudové logy) |
| T1199 | Trusted Relationship | initial-access | net | důvěryhodný vztah: provoz z partnerské sítě mimo obvyklý vzor |
| T1200 | Hardware Additions | initial-access | net | nové zařízení v síti: nový MAC a DHCP požadavek, neznámý host v ARP a DHCP logu |
| T1659 | Content Injection | initial-access | net | vložení obsahu: změněné odpovědi HTTP, neočekávané přesměrování |
| T1205 | Traffic Signaling | command-and-control | net | signalizace provozu: sekvence paketů nebo speciální paket předchází otevření služby |
| T1205.001 | Port Knocking | command-and-control | net | port knocking: sekvence spojení na zavřené porty následovaná spojením na dříve zavřený port |
| T1505.003 | Web Shell | persistence | both | web shell: neobvyklé POST požadavky na jednu cestu, odchozí spojení z web serveru |
| T1071.001 | Web Protocols | command-and-control | net | webové protokoly jako C2: periodické HTTP(S) spojení, user-agent, velikosti, JA3/JA4 |
| T1071.002 | File Transfer Protocols | command-and-control | net | přenos souborů (FTP/SMB) jako C2: neobvyklé FTP/SMB relace směrem ven |
| T1071.003 | Mail Protocols | command-and-control | net | poštovní protokoly jako C2: SMTP/IMAP/POP3 z hostů, které poštu nepoužívají |
| T1071.004 | DNS | command-and-control | net | DNS jako C2: dlouhé nebo entropické názvy, vysoký počet unikátních subdomén, typy TXT/NULL |
| T1071.005 | Publish/Subscribe Protocols | command-and-control | net | publish/subscribe (např. MQTT): spojení na brokery z hostů, které je nepoužívají |
| T1090.001 | Internal Proxy | command-and-control | net | interní proxy: host předává provoz mezi interními stanicemi, spárované toky |
| T1090.002 | External Proxy | command-and-control | net | externí proxy: spojení na proxy a relay mimo organizaci |
| T1090.003 | Multi-hop Proxy | command-and-control | net | vícestupňová proxy: spojení do sítě Tor a podobných relay |
| T1090.004 | Domain Fronting | command-and-control | net | domain fronting: nesoulad mezi TLS SNI a hlavičkou Host |
| T1095 | Non-Application Layer Protocol | command-and-control | net | neaplikační protokol: ICMP, UDP nebo surové TCP s nestandardním obsahem |
| T1102.001 | Dead Drop Resolver | command-and-control | net | dead drop resolver: dotaz na veřejnou službu a následné spojení na získanou adresu |
| T1102.002 | Bidirectional Communication | command-and-control | net | obousměrná komunikace přes web službu: periodická spojení na legitimní službu |
| T1102.003 | One-Way Communication | command-and-control | net | jednosměrná komunikace přes web službu: periodické stahování z veřejné služby |
| T1105 | Ingress Tool Transfer | command-and-control | both | přenos nástrojů: stažení spustitelného souboru, nesoulad MIME a přípony (files.log) |
| T1132.001 | Standard Encoding | command-and-control | net | standardní kódování: base64 a podobně v URI, DNS nebo tělech požadavků |
| T1132.002 | Non-Standard Encoding | command-and-control | net | nestandardní kódování: vysoká entropie v polích protokolů |
| T1568.001 | Fast Flux DNS | command-and-control | net | fast flux: rychle se měnící A záznamy s nízkým TTL |
| T1568.002 | Domain Generation Algorithms | command-and-control | net | DGA: vysoký počet NXDOMAIN, algoritmicky vypadající názvy |
| T1568.003 | DNS Calculation | command-and-control | net | DNS Calculation: adresa nebo port odvozené z odpovědi DNS, následné spojení |
| T1572 | Protocol Tunneling | command-and-control | net | tunelování protokolu: protokol uvnitř jiného (DNS, HTTP, ICMP, SSH), nesoulad velikostí a časování |
| T1573.001 | Symmetric Cryptography | command-and-control | net | symetrická kryptografie: vlastní šifrovaný kanál bez TLS, vysoká entropie |
| T1573.002 | Asymmetric Cryptography | command-and-control | net | asymetrická kryptografie: TLS s neobvyklými JA3/JA4, samopodepsanými certifikáty |
| T1571 | Non-Standard Port | command-and-control | net | nestandardní port: protokol na jiném než obvyklém portu (rozpoznaná služba proti portu v conn.log) |
| T1008 | Fallback Channels | command-and-control | net | záložní kanály: přepnutí na jiný protokol nebo cíl po selhání prvního |
| T1219 | Remote Access Tools | command-and-control | both | nástroje vzdáleného přístupu: spojení na známé relay služby, SNI |
| T1001.001 | Junk Data | command-and-control | net | vložená nepotřebná data: nezvykle velké nebo vycpané zprávy stejné struktury |
| T1001.002 | Steganography | command-and-control | net | steganografie: obrázky s neobvyklou velikostí a četností; v tocích jen nepřímo |
| T1001.003 | Protocol or Service Impersonation | command-and-control | net | napodobení protokolu: provoz tvarem neodpovídá deklarovanému protokolu |
| T1104 | Multi-Stage Channels | command-and-control | net | vícestupňové kanály: sekvence spojení na různé servery s odlišnými rolemi |
| T1665 | Hide Infrastructure | command-and-control | net | skrytí infrastruktury: provoz přes zprostředkující vrstvy a CDN; jen nepřímo |
| T1030 | Data Transfer Size Limits | exfiltration | net | limity velikosti přenosu: opakované přenosy stejné velikosti |
| T1041 | Exfiltration Over C2 Channel | exfiltration | net | exfiltrace přes C2: nárůst odeslaných bajtů na již známém C2 kanálu |
| T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | exfiltration | net | exfiltrace přes symetricky šifrovaný protokol: vysoký poměr odesláno/staženo mimo TLS |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | exfiltration | net | exfiltrace přes asymetricky šifrovaný protokol: velké odchozí TLS/SSH toky na nový cíl |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | exfiltration | net | exfiltrace přes nešifrovaný protokol: FTP, HTTP, DNS, ICMP s velkým objemem dat |
| T1567.001 | Exfiltration to Code Repository | exfiltration | net | exfiltrace do repozitáře: velké odchozí TLS toky na hostingy kódu (SNI) |
| T1567.002 | Exfiltration to Cloud Storage | exfiltration | net | exfiltrace do cloudového úložiště: odchozí toky na úložné služby (SNI), nárůst objemu |
| T1567.003 | Exfiltration to Text Storage Sites | exfiltration | net | exfiltrace na textová úložiště: odchozí POST na paste služby |
| T1567.004 | Exfiltration Over Webhook | exfiltration | net | exfiltrace přes webhook: POST na webhook domény služeb |
| T1029 | Scheduled Transfer | exfiltration | net | plánovaný přenos: odchozí přenosy v pravidelných intervalech |
| T1020 | Automated Exfiltration | exfiltration | net | automatizovaná exfiltrace: opakované odchozí přenosy bez uživatelské aktivity |
| T1537 | Transfer Data to Cloud Account | exfiltration | both | přenos do cloudového účtu: odchozí toky na cloudové API, doplněno cloudovými logy |
| T1046 | Network Service Discovery | discovery | net | objevování síťových služeb: mnoho cílů a portů z jednoho zdroje, odmítnutá spojení |
| T1018 | Remote System Discovery | discovery | both | objevování vzdálených systémů: ARP, ICMP, NBNS, LDAP dotazy; doplněno hostitelským logem |
| T1040 | Network Sniffing | credential-access | host | odposlech sítě: z toků téměř neviditelný, jen nepřímé indicie (zrcadlení, promiskuitní režim) |
| T1049 | System Network Connections Discovery | discovery | host | spojení systému: výpis probíhá na hostu; v síti jen důsledky |
| T1135 | Network Share Discovery | discovery | both | objevování sdílených složek: SMB tree connect na mnoho hostů |
| T1087.002 | Domain Account | discovery | both | doménové účty: LDAP/SAMR dotazy s velkým počtem výsledků |
| T1069.002 | Domain Groups | discovery | both | doménové skupiny: LDAP/SAMR dotazy na skupiny |
| T1482 | Domain Trust Discovery | discovery | both | domain trust: LDAP/RPC dotazy na vztahy důvěry |
| T1016.001 | Internet Connection Discovery | discovery | both | kontrola internetového spojení: dotazy na známé konektivitní domény |
| T1110 | Brute Force | credential-access | net | hrubá síla: opakované pokusy o autentizaci, mnoho neúspěchů |
| T1110.001 | Password Guessing | credential-access | net | hádání hesel: mnoho pokusů proti jednomu účtu (SSH, RDP, SMB, HTTP) |
| T1110.003 | Password Spraying | credential-access | net | password spraying: málo pokusů na mnoho účtů z jednoho zdroje |
| T1110.004 | Credential Stuffing | credential-access | net | credential stuffing: mnoho různých účtů z jednoho zdroje na webové přihlášení |
| T1558.003 | Kerberoasting | credential-access | both | Kerberoasting: Kerberos TGS požadavky s šifrou RC4 na mnoho SPN |
| T1558.004 | AS-REP Roasting | credential-access | both | AS-REP Roasting: AS-REQ bez předautentizace |
| T1558.001 | Golden Ticket | credential-access | both | Golden Ticket: neobvyklé vlastnosti lístků a čas; vyžaduje Kerberos log |
| T1558.002 | Silver Ticket | credential-access | both | Silver Ticket: použití služby bez předchozího TGS požadavku |
| T1003.006 | DCSync | credential-access | net | DCSync: replikace adresáře (DRSUAPI) z hosta, který není řadič domény |
| T1187 | Forced Authentication | credential-access | net | vynucená autentizace: SMB/WebDAV spojení na externí nebo neznámý cíl |
| T1557 | Adversary-in-the-Middle | credential-access | both | útok prostředníka: nesoulad adres a MAC, neočekávané relay |
| T1557.001 | Name Resolution Poisoning and SMB Relay | credential-access | net | otrava rozlišování jmen a SMB relay: odpovědi LLMNR/NBT-NS z neobvyklých hostů |
| T1557.002 | ARP Cache Poisoning | credential-access | net | otrava ARP: konfliktní ARP odpovědi, změny vazby IP-MAC |
| T1557.003 | DHCP Spoofing | credential-access | net | podvržený DHCP: více DHCP serverů, neočekávané nabídky |
| T1528 | Steal Application Access Token | credential-access | both | krádež přístupového tokenu: použití tokenu z nové adresy; vyžaduje cloudový log |
| T1539 | Steal Web Session Cookie | credential-access | both | krádež session cookie: stejná relace z různých adres |
| T1552.005 | Cloud Instance Metadata API | credential-access | both | cloud metadata API: dotazy na 169.254.169.254 z neočekávaných procesů |
| T1021.001 | Remote Desktop Protocol | lateral-movement | net | RDP: nová RDP spojení mezi stanicemi, neobvyklé zdroje |
| T1021.002 | SMB/Windows Admin Shares | lateral-movement | net | SMB a admin sdílení: spojení na ADMIN$/C$, nové dvojice hostů |
| T1021.003 | Distributed Component Object Model | lateral-movement | net | DCOM: RPC/DCOM mezi stanicemi |
| T1021.004 | SSH | lateral-movement | net | SSH: nové dvojice hostů, interní SSH mimo správce |
| T1021.005 | VNC | lateral-movement | net | VNC: spojení na VNC porty a protokol RFB |
| T1021.006 | Windows Remote Management | lateral-movement | net | WinRM: spojení na 5985/5986 mezi stanicemi |
| T1550.002 | Pass the Hash | lateral-movement | both | pass the hash: NTLM autentizace bez souvisejícího přihlášení; vyžaduje auth log |
| T1550.003 | Pass the Ticket | lateral-movement | both | pass the ticket: Kerberos lístek použit z jiného hosta |
| T1210 | Exploitation of Remote Services | lateral-movement | net | zneužití vzdálených služeb: exploit-like provoz a následné nové spojení z cíle |
| T1570 | Lateral Tool Transfer | lateral-movement | net | přesun nástrojů mezi hosty: SMB/HTTP přenos spustitelných souborů uvnitř sítě |
| T1563.002 | RDP Hijacking | lateral-movement | both | RDP hijacking: přepnutí relace; v tocích jen nepřímo |
| T1039 | Data from Network Shared Drive | collection | net | data ze sdílených složek: velké SMB čtení z jedné stanice |
| T1074.002 | Remote Data Staging | collection | net | vzdálené shromažďování dat: velké zápisy SMB/FTP na pracovní server |
| T1114.002 | Remote Email Collection | collection | both | vzdálený e-mail: přístup ke schránce přes IMAP/EWS/API z neobvyklého zdroje |
| T1530 | Data from Cloud Storage | collection | both | data z cloudového úložiště: velké stažení z úložiště, cloudový přístupový log |
| T1213 | Data from Information Repositories | collection | both | data z repozitářů informací: hromadné stahování z wiki a repozitářů |
| T1602.001 | SNMP (MIB Dump) | collection | net | SNMP MIB dump: SNMP GetBulk z neobvyklého zdroje |
| T1602.002 | Network Device Configuration Dump | collection | both | výpis konfigurace zařízení: TFTP/SSH přenos konfigurace |
| T1498.001 | Direct Network Flood | impact | net | přímá záplava: prudký nárůst paketů a toků na cíl |
| T1498.002 | Reflection Amplification | impact | net | reflection amplification: asymetrické UDP odpovědi (DNS, NTP) větší než dotaz |
| T1499.001 | OS Exhaustion Flood | impact | net | vyčerpání OS: záplava SYN a polootevřených spojení |
| T1499.002 | Service Exhaustion Flood | impact | net | vyčerpání služby: záplava HTTP požadavků |
| T1496 | Resource Hijacking | impact | both | únos prostředků (těžba): spojení stratum, kryptoměnové domény |
| T1486 | Data Encrypted for Impact | impact | both | zašifrování dat: masivní SMB zápisy, přejmenování; doplněno hostitelským logem |
| T1600 | Weaken Encryption | defense-impairment | net | oslabení šifrování: downgrade verze TLS a slabé šifry v handshake |
| T1542.005 | TFTP Boot | stealth | net | TFTP boot: neočekávané TFTP přenosy obrazů |
| T1197 | BITS Jobs | execution | both | BITS jobs: HTTP(S) přenos službou BITS, charakteristický user-agent |
| T1091 | Replication Through Removable Media | lateral-movement | host | přenosná média: v síti neviditelné; zařazeno jako negativní příklad |

## 4. Souhrnná tabulka: znalosti, podle kterých se rozhodujeme

Sloupec „zdroj“ odkazuje na sekce této studie. Řádky označené (návrh) jsou odvozené z kombinace zdrojů a jsou pracovními hypotézami, které je třeba ověřit měřením, ne převzatými tvrzeními.

| Znalost | Zdroj | Důsledek pro Salticus |
|---|---|---|
| Při nejistotě nejdřív pivot na doplňková metadata téhož spojení: DNS dotaz před spojením, TLS SNI a JA3/JA4, časování a velikosti | 2.1 Zeek (jeden záznam na spojení s navázanými záznamy), 2.2 RITA (pravidelnost, DNS), 2.17 D3FEND (DNS Traffic Analysis, Protocol Metadata Anomaly Detection) | Případ drží vazby spojení, DNS, TLS a časování; hypotéza se potvrzuje jen z nezávislých signálů, jeden signál nestačí k eskalaci |
| Srovnání s baseline hosta a s peery | 2.17 D3FEND (Network Traffic Community Deviation, Per Host Download-Upload Ratio Analysis), 2.19 Kitsune (lokálně naučená norma) | Každé skóre nese odkaz na baseline hosta i skupiny podobných hostů; nový host bez historie se označí „málo dat“, ne „čisto“ |
| Enrichment je samostatný, opakovatelný krok se záznamem výstupu | 2.14 TheHive a Cortex, 2.12 MISP (enrichment moduly), 2.5 Malcolm (normalizace, obohacení, korelace) | Enrichment běží lokálně; výsledek, zdroj a čas se ukládají k případu; enrichment, který by odesílal data ven, je vypnutý |
| Konfigurační drift se zjišťuje diferencí oproti minulému stavu | 2.11 osquery (diferenční výstup) | Salticus porovnává nastavení a viditelné služby proti předchozímu snímku; změna bez zdůvodnění zvyšuje důkazní váhu jiných signálů (návrh) |
| Historie případu je součást důkazu | 2.14 TheHive (případ jako objekt), 2.4 Security Onion (správa případů) | Případ ukládá časovou osu pozorování, rozhodnutí analytika a verzi pravidel; stejný vstup a stejná verze dávají stejný výsledek |
| Opakované měření: jednorázový výskyt není vzor | 2.2 RITA (pravidelnost jako skóre), 2.1 Zeek | Perioda a rozptyl se hodnotí přes více oken; hlášení uvádí počet opakování a délku pozorování |
| Kdy eskalovat: nezávislé signály z různých domén, vysoká hodnota aktiva, trvání nebo opakování | 2.16 CAR (hypotéza a doména), 2.8 Elastic (závažnost pravidel), 2.9 Sigma (level) | Eskalační pravidlo je explicitní a testované; jeden signál nízké spolehlivosti nikdy sám neeskaluje (návrh) |
| Hypotéza je součástí pravidla: hypotéza, doména, odkaz na ATT&CK, pseudokód, test | 2.16 CAR | Každé pravidlo Salticus má povinná pole hypotéza, požadovaná data, falešné poplachy a test, který ho vyvolá |
| Pravidlo deklaruje požadovaná data; při jejich absenci je odpověď „nelze posoudit“ | 2.9 Sigma (logsource), 2.7 Wazuh | Výstup rozlišuje tři stavy: nalezeno, nenalezeno, nelze posoudit (chybí vstup); „nenalezeno“ bez dat je zakázáno |
| Mapování na ATT&CK není měřítko pokrytí | 2.7 Wazuh (mapování versus pozorování), 2.8 Elastic (Navigator), 2.15 ATT&CK | Pokrytí se vykazuje ve dvou vrstvách: techniky s pravidlem, a z nich techniky s testem, který projde na laboratorním provozu |
| Pokrytí se měří proti viditelnosti: jen techniky, které data umožňují | 3 (tabulka viditelnosti), 2.17 D3FEND | Jmenovatelem pokrytí je množina technik s viditelností net nebo both, ne celé ATT&CK; hostitelské techniky jsou uvedeny jako mimo rozsah |
| Pravidla mají životní cyklus: stav, zastarání, odstranění | 2.3 ET Open (retired, deleted), 2.9 Sigma (status) | Každé pravidlo má stav (experimentální, testované, stabilní, vyřazené) a datum posledního ověření |
| Kategorie podle role: indikace versus politika versus hunting | 2.3 ET Open (malware, policy, hunting) | Důkazy se váží podle role; hunting a policy samy o sobě nezvyšují závažnost |
| Měření pokrytí pravidel IDS není standardizované | 2.3 (nenalezeno ve zkoumaných zdrojích) | Metodu pokrytí si definujeme sami a popíšeme ji v práci |
| Dataset před použitím zkontrolovat: pořadí a duplicity paketů, shoda časů útoku s labely, nástroj pro tvorbu toků | 2.19 Engelen a kol. 2021, Lanvin a kol. 2022 | Kontroly kvality datové sady jsou povinný krok; výsledky se hlásí s uvedením verze sady a použité opravy |
| Chyby nástroje na tvorbu toků mění labely (konec toku, FIN a RST) | 2.19 Engelen a kol. 2021 (CICFlowMeter) | Salticus dokumentuje pravidla ukončení toku a časových limitů a testuje je na ručně sestavených případech |
| Vysoké hodnoty přesnosti na veřejných sadách nejsou důkaz | 2.19 Engelen, Lanvin, Arp (nad rámec bibliografických údajů neověřeno) | Žádné tvrzení o přesnosti bez intervalu nejistoty, popisu sady a oddělení trénovacích a testovacích dat |
| Učení bez dohledu na lokální síti | 2.19 Kitsune | Lokální baseline je přípustný vstup; skóre odchylky nikdy nenahrazuje vysvětlení v lidské řeči |
| Skóre je pomůcka k řazení, ne verdikt | 2.2 RITA | Skóre určuje pořadí ve frontě, o eskalaci rozhoduje pravidlo s důvody |
| Zdroje a licence: kód pod AGPL/GPL/ELv2 se nepřebírá | 2.2, 2.7, 2.8, 2.10, 2.12, 2.14 | Vlastní implementace; v práci se odkazuje na postupy, ne na kód |
| Cizí reference musí mít záznam zdroje | zásady repozitáře | Každá položka této studie je dohledatelná podle odkazu; co není ověřeno, je označeno |

## 5. Omezení této rešerše

- Popisy projektů vycházejí z úvodních stránek, README a licenčních souborů. Podrobná architektura jednotlivých projektů nebyla zkoumána.
- Licence jsou stavem k 2026-11-13. Před jakýmkoli použitím (nad rámec odkazu) je nutné je znovu ověřit; AGPL, GPL a ELv2 mají odlišné požadavky.
- Neověřeno: metoda skórování beaconů v RITA, funkce AC-Hunter, konkrétní balíčky Zeek, postup analytika v Security Onion, licence Kitsune-py a CICFlowMeter, datový model OpenCTI, podrobný obsah článků Sperotto, Sommer a Paxson, Arp.
- Tabulka viditelnosti technik je úsudek autora. Má se ověřit na laboratorních datech (UHK, vlastní laboratoř, veřejné sady) před jakýmkoli tvrzením o pokrytí.
- Dva z uvedených zdrojů (Engelen a kol., Lanvin a kol.) byly ověřeny podle bibliografických záznamů a abstraktů; číselné závěry z celých textů nejsou převzaty.
