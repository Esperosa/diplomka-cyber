# Skákavka: rešerše prior art a novost

Stav: rychlá rešerše (datum 2026-10-31). Jde o první průchod, ne o systematickou přehledovou studii.

Metoda: webové vyhledávání a přímé otevření zdrojů, 8 bodů projektu, u každého bodu 3 až 4 dotazy (akademické i praktické: arXiv, USENIX, ACM, IEEE, vendor dokumentace, patenty). Kandidáti otevřeni přes přímé načtení stránky. Většina zdrojů je ověřena jen na úrovni abstraktu nebo snippetu, plné texty jsou uvedeny explicitně.

Poznámka k úplnosti: „nenalezeno" v této tabulce znamená jen, že nic nenašlo těchto několik dotazů. Neznamená, že to neexistuje. Chybí IEEE Xplore, ACM DL a USENIX jako přímé prohledávání, GitHub code search a patentové databáze v plné šíři.

---

## 1. Shrnutí

1. Jednotlivé kousky existují: aktivní skenování plus pasivní monitoring (NOMS 2020, komerční Qualys/Radiflow), Zeek+Suricata korelace (Splunk app, Community ID) a LLM agenti pro triáž a pentest (AgentSOC, PentestGPT v2, SherAgent).
2. Hypotézy jako nositelé typované nejistoty (aleatorická vs. epistemická) se v nalezených zdrojích objevují jen obecně (Bayesovské autoenkodéry, Dempster-Shafer), ne jako typ nálezu.
3. Plánovač podle očekávané hodnoty informace pro bezpečnostní investigaci jsem nenašel. Nejbližší je klasická VOI v expertních systémech a aktivní učení pro IDS (Ziai 2019, Margineantu 2005), ale ne pro výběr investigační akce s cenou.
4. Pivoting s postupným ověřováním každého kroku je u LLM pentest agentů blízký (PentestGPT v2, cochise/Happe a Cito 2025), ale cílí na útok, ne na obranné ověřování podezření.
5. Case Memory z verdiktů analytika existuje (Stellar Cyber, AACT), ale nalezené zdroje neřeší otrávení učení. Beta posteriory podle typu nálezu jsem nenašel.
6. Identita zařízení přes MAC/DHCP/IP je běžná praxe v komerčních produktech (Juniper JSA, Stellar Cyber, Splunk). Pravidlo „MAC > NetBIOS > DNS > IP" a pravidlo na nestabilní IP mám ověřené z dokumentace Juniperu.
7. Blokace přes nftables se schválením a auditem existuje po částech (SOAR human-in-the-loop, hash-chain logy, nftables backendy). Kombinaci s hash-řetězem přímo u schválené blokace jsem nenašel.
8. Simulátor s ground truth v řádu milionů sítí jsem nenašel. Existují laboratorní testbedy (AIT, NGIDS) a generátory datasetů (ID2T, ConCap). Wilsonovy intervaly jsou standardní metoda, samy o sobě nejsou novinkou.
9. Nevyřešené zdá se: společný model, kde se nálezy s typovanou nejistotou, EVOI plánovač a investigace s pivotingem spojí do jednoho rozhodovacího smyčky s rozpočtem a schvalováním. V nalezených zdrojích jsem to v jednom místě nenašel.
10. Kritická korekce: dokument citovaný jako „PACT" (arXiv 2605.22324) je v v2 přejmenován na STRAL. Nepoužívá VOI definované v dostupném textu, jen „selective label acquisition". Nelze ho tedy brát jako důkaz VOI přístupu.

---

## 2. Tabulka po bodech 1 až 8

Blízkost: 0 = nesouvisí, 1 = obecná souvislost, 2 = stejný problém jiným způsobem, 3 = téměř totéž.
Ověření: PLNÝ TEXT, ABSTRAKT (abstrakt nebo oficiální stránka), SNIPPET (jen výsledek vyhledávání, nebyla otevřena stránka), NEOVĚŘENO.

### Bod 1: Korelace pasivní telemetrie (Zeek, Suricata) s aktivním inventářem (nmap, httpx, nuclei)

| Nejbližší práce/produkt | Rok | URL | Co dělá | Rozdíl od Skákavky | Ověřeno | Blízkost |
|---|---|---|---|---|---|---|
| Combining active and passive scanning: Nmap + NetFlow vs NVD (NOMS, Muni) | 2020 | https://is.muni.cz/publication/1605419/2020-NOMS-Network-Monitoring-Enumerating-Vulnerabilities-Large-Heterogeneous-Networks-paper.pdf | Porovnává aktivní (Nmap) a pasivní (NetFlow) skenování a koreluje s NVD | Žádný Zeek/Suricata, žádné hypotézy ani ověřovací plánovač | SNIPPET (fetch PDF vrátil prázdný obsah) | 2 |
| Qualys Passive Sensor (sloučení pasivních nálezů s aktivními a agentovými záznamy) | ? | https://docs.qualys.com/en/ps/latest/get_started/get_started.htm | Odhaluje zařízení pasivně a páruje je s existujícím inventářem | Komerční, bez hypotéz a EVOI | SNIPPET | 2 |
| Radiflow Active Scanner (hybridní režim, aktivní dotazy porovnané s inventářem) | ? | https://www.radiflow.com/products/active-scanner | OT: pasivní poslech plus aktivní dotazy | OT zaměření, bez ověřování hypotéz | SNIPPET | 2 |
| Splunk app: Suricata alert ↔ Zeek log podle spojení (IP, port, protokol) | ? | https://splunkbase.splunk.com/app/9818 | Páruje Suricata alerty se Zeek logy, ukazuje neshodu | Pasivní + pasivní, bez aktivního pohledu | SNIPPET | 2 |
| Community ID (sdílený hash toku pro Zeek i Suricatu) | – | (zmíněno v průvodci ITUOnline) | Mapuje stejný tok stejným hashem | Technika, ne produkt | SNIPPET | 1 |

Poznámka: Patenty (např. US7761918, „System and method for scanning a network") popisují aktivní i pasivní skenery s centrální korelací. Nebyly otevřeny.

### Bod 2: Nálezy jako hypotézy s typovanou nejistotou (identita, pozorování, stav, interpretace, aleatorická vs. epistemická)

| Nejbližší práce/produkt | Rok | URL | Co dělá | Rozdíl | Ověřeno | Blízkost |
|---|---|---|---|---|---|---|
| AgentSOC: A Multi-Layer Agentic AI Framework for Security Operations Automation (Roy, Singh) | 2026 (arXiv 2604.20134) | https://arxiv.org/abs/2604.20134 | Generuje hypotézy útoku, kontroluje strukturální proveditelnost, risk scoring | Hypotézy, ne typovaná nejistota; hodnocení je koncepční, bez kvantitativních výsledků | ABSTRAKT | 2 |
| Towards Agentic Investigation of Security Alerts (Eilertsen, Mavroeidis, Grov) | 2025/2026 (arXiv 2604.25846) | https://arxiv.org/abs/2604.25846 | LLM agenti nad Suricata logy (SQL, grep), vydávají verdikt alertu | Bez explicitních hypotéz a bez nejistoty; zaměření na verdikt, ne na typy nejistoty | ABSTRAKT | 2 |
| Bayesian autoencoder s aleatorickou a epistemickou nejistotou pro anomálie (Computers & Security 2024) | 2024 | (nebylo otevřeno, dohledáno přes synapsesocial/TUS) | Modeluje obě nejistoty u anomálních predikcí na UNSW-NB15, CIC-IDS-2017 | Nejistota je u predikce modelu, ne u typovaného nálezu o zařízení | SNIPPET | 1 |
| Dempster-Shafer pro SCADA a IDS (arXiv 2111.10484) | 2021 | https://arxiv.org/pdf/2111.10484 | Epistemická nejistota během kompromitace, Dempster-Shafer | Jiná doména (SCADA) | SNIPPET | 1 |
| Scanner.dev „High-Probability Hypothesis Framework" (LLM investigace alertů) | ? | (blog, nenalezen přímý odkaz v rešerši) | Praktický rámec hypotéz pro LLM | Blog, bez zdrojů | NEOVĚŘENO | 2 |

### Bod 3: Plánovač podle očekávané hodnoty informace (EVOI/VOI): nejlevnější a nejinformativnější další kontrola, rozpočet, schvalování, idempotence

| Nejbližší práce/produkt | Rok | URL | Co dělá | Rozdíl | Ověřeno | Blízkost |
|---|---|---|---|---|---|---|
| Ramirez-Loaiza, Culotta et al. (výběr instancí podle očekávaného snížení chyby a ceny) | 2013 | https://cs.tulane.edu/~aculotta/pubs/ramirez13towards.pdf | Výběr dotazů na štítky podle VOI vs. cena | Obecné strojové učení, ne bezpečnostní investigace; ověření blokováno (403) | SNIPPET | 2 |
| Margineantu, Active Cost-Sensitive Learning (IJCAI) | 2005 | https://mlanthology.org/ijcai/2005/margineantu2005ijcai-active | Aktivní učení s cenou štítků a nerovnými náklady na chyby (IDS jako příklad) | Učení modelu, ne plánování investigace | SNIPPET | 2 |
| Ziai, Active Learning for Network Intrusion Detection | 2019 | https://arxiv.org/abs/1904.01555 | Aktivní učení pro NIDS s cílem minimalizovat počet štítků | Výběr vzorků podle strategie, ne VOI a bez rozpočtu; předpokládá důvěryhodné štítky | ABSTRAKT | 1 |
| STRAL (dříve PACT), Ndichu et al. (arXiv 2605.22324) | 2026 | https://arxiv.org/abs/2605.22324 | Aktivní učení pro SOC screening s ADWIN, selektivním vyžádáním štítků a Frozen baseline | VOI nedefinováno ve viditelném textu; „selective label acquisition" bez specifikace kritéria | ABSTRAKT | 1 |
| Doak et al., Sandia: active learning vs. passive na reálných bezpečnostních alertech | 2013 | https://www.osti.gov/servlets/purl/1115032 | Uncertainty sampling na reálných alertech, méně štítků | Model triáže, ne plánovač kontrol | NEOVĚŘENO (fetch ECONNREFUSED, jen snippet) | 1 |
| AACT: Automated Alert Classification and Triage (Turcotte, Labrèche, Paquette) | 2025 (arXiv 2505.09843) | https://arxiv.org/abs/2505.09843 | Učí se z triáže analytiků, reálné SOC, snížení alertů o 61 % | Klasifikátor, ne VOI plánovač; metodika vlastní skrytá | ABSTRAKT | 1 |
| Klasická VOI pro expertní systémy (Gorry 1973, Heckerman 1990) | 1973/1990 | (citováno v rešerši, primární zdroj neotevřen) | Test provést, jen když VOI přesáhne cenu testu | Obecná teorie, ne bezpečnostní; zdroj je ze snippetu | SNIPPET | 2 |

### Bod 4: Pivoting agent: postupné poskakování po souvisejících zařízeních, ověřování podezření, eskalační žebřík

| Nejbližší práce/produkt | Rok | URL | Co dělá | Rozdíl | Ověřeno | Blízkost |
|---|---|---|---|---|---|---|
| What Makes a Good LLM Agent for Real-world Penetration Testing? (PentestGPT v2, Deng et al.) | 2026 (arXiv 2602.17622) | https://arxiv.org/abs/2602.17622 | Attack-tree search s hodnocením obtížnosti a pamětí, GOAD 4 z 5 hostů | Útočná perspektiva, ne obranné ověřování; nepadají výsledky proti false positive | PLNÝ TEXT (až do části přílohy C) | 2 |
| Can LLMs Hack Enterprise Networks? (Happe, Cito; cochise) | 2025 (arXiv 2502.04227) | https://arxiv.org/abs/2502.04227 | Autonomní assumed-breach v GOAD, LLM přes pentest nástroje | Útok, ne ověřování podezření; plný text nebyl viditelný | ABSTRAKT | 2 |
| SherAgent: iterativní query-filter backtracking nad provenance grafy (Li et al., Ji et al.) | 2026 (arXiv 2607.09176) | https://arxiv.org/abs/2607.09176 | Backtracking po grafu událostí, rozšiřování dotazů, výběr klíčových uzlů | Provenance grafy na hostu, ne síťové zařízení s postupným pivotingem | ABSTRAKT | 2 |
| Towards Agentic Investigation of Security Alerts (Eilertsen et al.) | 2026 | https://arxiv.org/abs/2604.25846 | Sekvence dotazů na Suricata logy s verdiktem | Bez pivotingu jako takového | ABSTRAKT | 2 |
| Horizon3 NodeZero (attack path verification, continuous hack-fix-verify) | 2026 | https://www.businesswire.com/news/home/20260729113126/en/ | Komerční autonomní pentest, ověřování oprav | Ofenzivní, ne pasivní korelace; tisková zpráva | SNIPPET (fetch 403) | 1 |
| Autonomous Adversary (LMA red-teaming, AD testbed) | ? | https://www.themoonlight.io/es/review/autonomous-adversary-red-teaming-in-the-age-of-llm | Multi-hop lateral movement LLM agentem | Útočná perspektiva | NEOVĚŘENO (jen recenze třetí stranou) | 2 |
| ARES, PR 29 (lateral movement modul, pivot suggestions) | 2026 | https://github.com/dreadnode/ares/pull/29 | Graf spojení hostů, návrhy pivotů | Popis funkcí, ne verifikační metoda | SNIPPET | 2 |

### Bod 5: Case Memory: učení z verdiktů analytika (Beta posteriory podle typu nálezu) s ochranou proti otrávení učení

| Nejbližší práce/produkt | Rok | URL | Co dělá | Rozdíl | Ověřeno | Blízkost |
|---|---|---|---|---|---|---|
| Stellar Cyber, „From influence to evidence" (analyst override reasons jako precedent) | 2026 | https://stellarcyber.ai/from-influence-to-evidence-teaching-the-soc-not-to-make-the-same-mistake-twice/ | Uloží důvod analytika a přenese ho na podobné alerty; 13 % → 52 % na 150 alertech (vlastní test) | Vendor, bez Beta posteriorů; bez ochrany proti otrávení; vlastní A/B test | PLNÝ TEXT (promo článek, vlastní čísla) | 2 |
| AACT (učení z triáže analytiků) | 2025 | https://arxiv.org/abs/2505.09843 | Predikuje triáž, uzavírá benigní alerty | Bez paměti případů a bez obrany | ABSTRAKT | 2 |
| CBR pro bezpečnostní alerty (US patent 11178037; IEEE 2012 o manipulaci; AutoGuard, Wollongong) | 2008–2012 | https://ro.uow.edu.au/articles/thesis/New_directions_in_computer_intrusion_detection/27652461 | Případy jako precedent; IEEE 2012 zmiňuje hraní systému | Staré a bez Beta posteriorů | SNIPPET | 2 |
| Membrane: Contrastive Safety Memory for LLM agents (EMNLP 2026) | 2026 (arXiv 2606.05743) | https://arxiv.org/pdf/2606.05743 | Paměť s páry blokování/povolení pro LLM agenty, zmínka o stabilitě vůči otravě | Guardrail pro jailbreak, ne SOC; otrávení v abstraktu nerozvedeno | ABSTRAKT | 1 |
| Adaptive Feature Poisoning (Ennaji et al.) | 2025 (arXiv 2512.13501) | https://arxiv.org/abs/2512.13501 | Obrana IDS proti černé skřínce útoku přes perturbace | Obrana modelu IDS, ne paměti analytika | ABSTRAKT | 1 |
| Robustní PCA proti otrávení (IMC 2009) | 2009 | https://ptolemy.berkeley.edu/projects/truststc/pubs/725/IMC.2009.pdf | Ukazuje otrávení trénovacích dat u PCA detektoru | Obecná teorie otravy, ne case memory | SNIPPET | 1 |

### Bod 6: Identita zařízení přes MAC/DHCP/NAT (stabilní asset ID napříč změnami IP)

| Nejbližší práce/produkt | Rok | URL | Co dělá | Rozdíl | Ověřeno | Blízkost |
|---|---|---|---|---|---|---|
| Juniper QRadar/JSA: asset profiler (MAC > NetBIOS > DNS > IP, pravidlo na nestabilní IP) | 2026 (verze 7.5) | https://networkingdocs.hpe.com/documentation//us/en/software/jsa7.5.0/jsa/topics/concept/concept-jsa-user-updates-to-asset-data.html | Priorita identitních údajů; IP s ≥3 MAC/hostname za 2 h na blacklistu | Komerční SIEM, bez asset ID z DHCP logů jako veřejné metody | PLNÝ TEXT (přes redirect, dokumentace) | 2 |
| Stellar Cyber: MAC-identified vs IP-identified assets, DHCP continuity, IPAM | 2026 (doc v6.6) | https://docs.stellarcyber.ai/6.6.x/Using/Investigate/Asset-Analytics-MAC-or-IP-Identified.htm | Stabilní asset ID podle MAC, sledování po změně IP přes DHCP a IPAM | Vendor; bez pravidel pro MAC randomizaci | PLNÝ TEXT (dokumentace) | 2 |
| Splunk ES: identity resolution z DHCP, DNS, VPN, AD | 2024+ | https://docs.splunk.com/Documentation/ES/7.0.1/BehavioralAnalytics/Identityresolution | DHCP IP→MAC mapování v databázi identit | Komerční, bez Skákavky-like ověřování | SNIPPET | 2 |
| Zeek dhcp.log jako zdroj vazby MAC↔IP (dokumentace), MCP asset map | 2026 | https://docs.zeek.org/en/lts/logs/dhcp.html ; https://glama.ai/mcp/servers/lidless-labs/zeek-mcp/tools/zeek_dhcp_asset_map | Log DORA výměn, mapa MAC→IP/hostname | Dokumentace a nástroj, ne asset ID | SNIPPET | 1 |
| IETF draft-ietf-dhc-anonymity-profile (DHCP identifikátory umožňují sledování) | 2015 (draft) | https://ietf.potaroo.net/all-ids/draft-ietf-dhc-anonymity-profile-02.txt | Ukazuje, že DHCP identifikátory prozrazují zařízení i při randomizaci MAC | Obecný problém soukromí, ne správa aktiv | SNIPPET | 1 |
| Vanhoef et al., Why MAC Address Randomization is not Enough (WiSec 2016) | 2016 | https://papers.mathyvanhoef.com/wisec2016.pdf | Útok na randomizaci MAC přes časování skenů a čísla sekvencí | Útočný pohled na Wi-Fi; PDF nebylo čitelné | NEOVĚŘENO (PDF binární, nečitelné) | 1 |

Poznámka: Patent US11265286 (Cisco, „Tracking of devices across MAC address updates") je zmíněn ve výsledcích, neotevřen.

### Bod 7: Schvalované zásahy (blokace IP přes nftables) s auditním hash-řetězem

| Nejbližší práce/produkt | Rok | URL | Co dělá | Rozdíl | Ověřeno | Blízkost |
|---|---|---|---|---|---|---|
| SOAR playbooky s human-in-the-loop schválením pro vysoce rizikové akce | 2024–2026 | https://www.fortinet.com/resources/articles/automate-security-operations-with-soar | Blokace IP automaticky, schválení pro rizikové kroky, audit | Vendor články, bez hash-řetězu a bez nftables specifik | SNIPPET | 2 |
| Rampart (audit trail s SHA-256 řetězem na nástrojová volání) | 2026 | https://www.mintlify.com/peg/rampart/features/audit-trail | Hash-řetěz JSONL logu s ověřením | Obecný agent log, ne schválené zásahy | SNIPPET | 2 |
| Bernstein (brána schválení, HMAC řetěz, Merkle seal) | 2026 | https://bernstein.readthedocs.io/en/latest/security/audit-log/ | Klasifikátor, ambiguita jde k člověku, odmítnutí sealu při rozbitém řetězu | Obecný agent, ne nftables | SNIPPET | 2 |
| nftables ban/unban backend (Perl; tabulka, sety, kontrola integrity) | ? | https://metacpan.org/pod/Net::Firewall::BlockerHelper::backends::nftables | Dedikovaná tabulka a set, kontrola referencí | Bez schvalování a bez auditu | SNIPPET | 2 |
| USPTO patent (tamper-evident log a blokace přístupů podle ML metriky) | ? | https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12204673 | Logy s hash řetězem, blokace po prahu | Patent, ne produkt; neověřeno, zda je to ten správný dokument | NEOVĚŘENO | 2 |

### Bod 8: Měření: simulátor milionů sítí s ground truth, kalibrace a Wilsonovy intervaly

| Nejbližší práce/produkt | Rok | URL | Co dělá | Rozdíl | Ověřeno | Blízkost |
|---|---|---|---|---|---|---|
| Landauer et al., Maintainable Log Datasets for Evaluation of IDS (AIT testbed) | 2022 (arXiv 2203.08580, IEEE TDSC) | https://arxiv.org/abs/2203.08580 | Testbed malé firmy, state machines, modelově generované, 10 kroků útoku označeno | Dataset jednoho testbedu, ne simulátor milionů; štítky na úrovni souboru/kroku | ABSTRAKT | 1 |
| NGIDS-DS (simulované prostředí, labely útoků) | ? | https://fkie-cad.github.io/COMIDDS/content/datasets/ngids_dataset | Simulovaná síť s labely | Dataset, ne generátor | SNIPPET | 1 |
| ID2T toolkit (Vasilomanolakis et al.) | ? | (TU Darmstadt, PDF v rešerši) | Injekce útoků do datasetů s labely | Nástroj na datasety, ne simulace sítí | SNIPPET | 1 |
| ConCap (generování provozu pro flow-based NIDS) | 2025 (arXiv 2509.16038) | https://arxiv.org/html/2509.16038v1 | Generování provozu s labely | Provoz, ne topologie milionů sítí | SNIPPET | 1 |
| Wilsonův interval pro rare události v benchmarku EV nabíjení | 2026 (arXiv 2608.11286) | https://arxiv.org/pdf/2608.11286 | Wilson pro malé počty | Standardní metoda, žádný simulátor | SNIPPET | 1 |
| MCP census (Wilson pro vzácné třídy, opravy prevalence) | 2026 (arXiv 2609.14119) | https://arxiv.org/pdf/2609.14119 | Wilson pro podíly, korekce prevalence | Metodická citace, ne simulátor | SNIPPET | 1 |

---

## 3. Mezery a příležitosti

Co jsem nenašel (a jak jsem hledal):
- Kombinace pasivní + aktivní korelace s hypotézami s typovanou nejistotou v jednom systému. Hledáno přes "active passive correlation", "passive telemetry active scan", "Zeek Suricata nuclei httpx". Výsledek: jen jednotlivé kusy.
- VOI plánovač pro bezpečnostní investigaci s cenou kontroly a rozpočtem. Hledáno přes "expected value of information" (SOC, IDS, sequential testing, cost-sensitive). Výsledek: VOI pro ML dotazy a expertní systémy, ne pro investigační kroky.
- Typovaná nejistota (aleatorická vs. epistemická) u jednotlivého nálezu. Hledáno přes "epistemic aleatoric intrusion detection alert". Výsledek: nejistota u predikce modelu, ne typ nálezu.
- Beta posteriory pro verdikty analytika podle typu nálezu s obranou proti otrávení. Hledáno přes "case memory poisoning", "analyst feedback poisoning", "Beta posterior". Výsledek: otrava je řešena u LLM pamětí (Membrane) a u IDS modelů (AFP), ne u analytické paměti s Beta.
- Simulátor milionů sítí s ground truth a kalibrací. Hledáno přes "simulator million networks ground truth", "large-scale synthetic network dataset". Výsledek: testbedy a generátory malého rozsahu.
- Schválená blokace nftables s hash-řetězem v jednom nástroji. Hledáno přes "nftables approval audit hash chain", "SOAR approval IP block audit". Výsledek: komponenty odděleně.

Příležitosti (podle mezer):
- Publikovat formální definici typovaného nálezu a ukázat, že typování zlepšuje rozhodnutí oproti jednoduchému skóre (je to původní příspěvek, pokud se ukáže, že to nikdo nedělá).
- Srovnat VOI plánovač proti heuristikám (nejlevnější kontrola, náhodná kontrola, pevné pořadí) na simulovaném ground truth. To je měřitelné a obhajitelné.
- Ochrana Case Memory proti otrávení kombinovat s Beta posteriory a ukázat útok z existujících článků (Stellar vs. IMC 2009 pattern).

---

## 4. Inspirace (konkrétní nápady k přebrání)

- Juniper: priorita identity MAC > NetBIOS > DNS > IP a pravidlo, že IP, která má ≥3 MAC/hostname za 2 h, jde na blacklist. Přímo použitelné pro asset ID (https://networkingdocs.hpe.com/documentation//us/en/software/jsa7.5.0/jsa/topics/concept/concept-jsa-user-updates-to-asset-data.html).
- Stellar Cyber: verdikt analytika se ukládá jako "influence", ne jako tvrdé pravidlo, a každé poučení je dohledatelné k lidskému rozhodnutí. Užitečný návrh pro Case Memory (https://stellarcyber.ai/from-influence-to-evidence-teaching-the-soc-not-to-make-the-same-mistake-twice/).
- Ziai 2019 a Margineantu 2005: aktivní učení s cenou štítků. Vhodné jako citace pro VOI část (https://arxiv.org/abs/1904.01555, https://mlanthology.org/ijcai/2005/margineantu2005ijcai-active).
- Ramirez-Loaiza et al. 2013: výběr dotazů podle očekávaného snížení chyby děleného cenou. Přímý metodický základ pro EVOI (https://cs.tulane.edu/~aculotta/pubs/ramirez13towards.pdf, plný text neověřen).
- Gorry 1973, Heckerman 1990: stopovací pravidlo "proveď test, jen když VOI > cena testu". Klasika pro rozpočet a stop kritérium (citováno, primární zdroj neověřen).
- Bernstein a Rampart: brána schválení s klasifikátorem, nejednoznačné jde k člověku a každé rozhodnutí se loguje. Hash-řetěz s kontrolou před sealem (https://bernstein.readthedocs.io/en/latest/security/audit-log/, https://www.mintlify.com/peg/rampart/features/audit-trail).
- nftables backend s dedikovanou tabulkou a kontrolou integrity referencí (https://metacpan.org/pod/Net::Firewall::BlockerHelper::backends::nftables).
- SherAgent: iterativní rozšiřování dotazů při chybějících událostech a filtrování. Vhodné pro pivoting žebřík (https://arxiv.org/abs/2607.09176).
- PentestGPT v2: Memory Subsystem pro držení stavu přes dlouhou kampaň a Evidence-Guided Attack Tree Search (https://arxiv.org/abs/2602.17622). Pozor na útočný kontext, přebírat jen metodicky.
- Landauer et al. 2022: modelově generované logy s labely na úrovni kroků útoku a open source. Vzor pro ground truth (https://arxiv.org/abs/2203.08580).

---

## 5. Seznam zdrojů a míra ověření

Legenda: PLNÝ TEXT = otevřen a přečten text článku nebo dokumentace; ABSTRAKT = viditelný abstrakt nebo oficiální stránka; SNIPPET = jen výsledek vyhledávání; NEOVĚŘENO = nelze ověřit (chyba, binární PDF, cizí zdroj).

| # | Zdroj | Typ | Rok | Ověřeno |
|---|---|---|---|---|
| 1 | https://is.muni.cz/publication/1605419/2020-NOMS-Network-Monitoring-Enumerating-Vulnerabilities-Large-Heterogeneous-Networks-paper.pdf | akademický (NOMS) | 2020 | SNIPPET (fetch prázdný) |
| 2 | https://docs.qualys.com/en/ps/latest/get_started/get_started.htm | vendor dok. | ? | SNIPPET |
| 3 | https://www.radiflow.com/products/active-scanner | vendor | ? | SNIPPET |
| 4 | https://splunkbase.splunk.com/app/9818 | vendor app | ? | SNIPPET |
| 5 | https://arxiv.org/abs/2604.20134 (AgentSOC) | arXiv | 2026 | ABSTRAKT |
| 6 | https://arxiv.org/abs/2604.25846 (Towards Agentic Investigation) | arXiv | 2026 | ABSTRAKT |
| 7 | https://arxiv.org/abs/2605.22324 (STRAL, dříve PACT) | arXiv | 2026 | ABSTRAKT |
| 8 | https://arxiv.org/abs/2505.09843 (AACT) | arXiv | 2025 | ABSTRAKT |
| 9 | https://arxiv.org/abs/2606.05743 (Membrane) | arXiv | 2026 | ABSTRAKT |
| 10 | https://arxiv.org/abs/2607.09176 (SherAgent) | arXiv | 2026 | ABSTRAKT |
| 11 | https://arxiv.org/abs/2602.17622 (PentestGPT v2) | arXiv | 2026 | PLNÝ TEXT (do přílohy C) |
| 12 | https://arxiv.org/abs/2502.04227 (Happe, Cito) | arXiv | 2025 | ABSTRAKT |
| 13 | https://arxiv.org/abs/1904.01555 (Ziai) | arXiv | 2019 | ABSTRAKT |
| 14 | https://arxiv.org/abs/2512.13501 (AFP) | arXiv | 2025 | ABSTRAKT |
| 15 | https://arxiv.org/abs/2203.08580 (Landauer et al.) | arXiv / IEEE TDSC | 2022 | ABSTRAKT |
| 16 | https://stellarcyber.ai/from-influence-to-evidence-teaching-the-soc-not-to-make-the-same-mistake-twice/ | vendor blog | 2026 | PLNÝ TEXT (vendor, vlastní čísla) |
| 17 | https://docs.stellarcyber.ai/6.6.x/Using/Investigate/Asset-Analytics-MAC-or-IP-Identified.htm | vendor dok. | 2026 | PLNÝ TEXT |
| 18 | https://networkingdocs.hpe.com/documentation//us/en/software/jsa7.5.0/jsa/topics/concept/concept-jsa-user-updates-to-asset-data.html (Juniper JSA) | vendor dok. | 2026 | PLNÝ TEXT (přes redirect) |
| 19 | https://www.businesswire.com/news/home/20260729113126/en/ (Horizon3) | tisková zpráva | 2026 | SNIPPET (fetch 403) |
| 20 | https://cs.tulane.edu/~aculotta/pubs/ramirez13towards.pdf | akademický | 2013 | SNIPPET (fetch 403) |
| 21 | https://mlanthology.org/ijcai/2005/margineantu2005ijcai-active | akademický | 2005 | SNIPPET |
| 22 | https://www.osti.gov/servlets/purl/1115032 (Doak, Sandia) | technická zpráva | 2013 | NEOVĚŘENO (ECONNREFUSED) |
| 23 | https://www.neurips.cc/virtual/2025/137134 (CORTEX) | konference | 2025 | NEOVĚŘENO (chyba certifikátu), snippet z vyhledávání |
| 24 | https://papers.mathyvanhoef.com/wisec2016.pdf | akademický | 2016 | NEOVĚŘENO (binární PDF) |
| 26 | https://ietf.potaroo.net/all-ids/draft-ietf-dhc-anonymity-profile-02.txt | IETF draft | 2015 | SNIPPET |
| 27 | https://docs.zeek.org/en/lts/logs/dhcp.html | dokumentace | – | SNIPPET |
| 28 | https://glama.ai/mcp/servers/lidless-labs/zeek-mcp/tools/zeek_dhcp_asset_map | nástroj (MCP) | 2026 | SNIPPET |
| 29 | https://docs.splunk.com/Documentation/ES/7.0.1/BehavioralAnalytics/Identityresolution | vendor dok. | 2024+ | SNIPPET |
| 30 | https://www.fortinet.com/resources/articles/automate-security-operations-with-soar | vendor článek | – | SNIPPET |
| 31 | https://www.mintlify.com/peg/rampart/features/audit-trail | open source dok. | 2026 | SNIPPET |
| 32 | https://bernstein.readthedocs.io/en/latest/security/audit-log/ | open source dok. | 2026 | SNIPPET |
| 33 | https://metacpan.org/pod/Net::Firewall::BlockerHelper::backends::nftables | open source | – | SNIPPET |
| 34 | https://github.com/dreadnode/ares/pull/29 | GitHub PR | 2026 | SNIPPET |
| 35 | https://www.themoonlight.io/es/review/autonomous-adversary-red-teaming-in-the-age-of-llm | recenze třetí strany | – | NEOVĚŘENO (originál nepřečten) |
| 36 | https://arxiv.org/html/2509.16038v1 (ConCap) | arXiv | 2025 | SNIPPET |
| 37 | https://arxiv.org/pdf/2608.11286 (Wilson, EV nabíjení) | arXiv | 2026 | SNIPPET |
| 38 | https://arxiv.org/pdf/2609.14119 (MCP census) | arXiv | 2026 | SNIPPET |
| 39 | https://arxiv.org/pdf/2111.10484 (Dempster-Shafer, SCADA) | arXiv | 2021 | SNIPPET |
| 40 | https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12204673 (patent) | patent | – | NEOVĚŘENO |
| 41 | https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11178037 (CBR patent) | patent | – | SNIPPET |
| 42 | https://ro.uow.edu.au/articles/thesis/New_directions_in_computer_intrusion_detection/27652461 | disertace | – | SNIPPET |
| 43 | https://ptolemy.berkeley.edu/projects/truststc/pubs/725/IMC.2009.pdf | akademický (IMC) | 2009 | SNIPPET |
| 44 | https://fkie-cad.github.io/COMIDDS/content/datasets/ngids_dataset | dataset | – | SNIPPET |

Nepoužito, protože se nepodařilo najít přímou stránku: Corelight „agentic SOC" (zmíněn v The Hacker News 2026/08), Alert-Bench (NeurIPS 2026 listing), Cymulate BAS, Penligent (vendor blog, jen snippet), Scanner.dev blog, AutoAttacker (arXiv 2403.01038), cochise jako název (v abstraktu chybí).

Poctivě: u většiny komerčních produktů jsou tvrzení z marketingu nebo dokumentace vendora. Nezávislé benchmarky jsem nenašel. Čísla z vendor blogů (13 % → 52 %, 61 % snížení alertů, 60–90 % snížení false positive) jsou nepřebraná a nejsou ověřená.

Chybějící kroky ověření (doporučené): plné texty NOMS 2020, Ramirez-Loaiza 2013, Doak 2013, AgentSOC a STRAL (HTML verze), Juniper JSA v HTML, IEEE Xplore a ACM DL pro "value of information" + "intrusion"; GitHub code search pro "nftables block hash chain approval"; Google Patents pro "Beta posterior" + "analyst feedback".
