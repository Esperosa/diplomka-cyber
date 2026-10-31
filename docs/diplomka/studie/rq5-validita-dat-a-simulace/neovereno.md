# RQ5: neověřené zdroje (V1/V0) a zdroje bez extrakce

Tyto zdroje se **nepoužívají v Závěrech**. Jsou zde jako seznam k dalšímu ověření.

## V1: jen shrnutí vyhledávače nebo sekundární zdroj

| zdroj | co se o něm tvrdí (neověřeno) | důvod V1 |
|---|---|---|
| Fontugne R. et al. MAWILab: Combining Diverse Anomaly Detectors for Automated Anomaly Labeling and Performance Benchmarking, CoNEXT 2010 | štítky MAWI vznikají kombinací detektorů, „twice as many anomalies as the most accurate detector“ | HAL blokován (Anubis), ACM nedostupné. Důležité pro otázku cirkularity: hodnotit detektor štítky odvozenými z detektorů. |
| Kenyon A., Deka L., Elizondo D. Are Public Intrusion Datasets Fit for Purpose, Computers & Security 2020 | klasifikace veřejných datasetů, chybějící registr a provenance | jen abstrakt přes agregátor (x-mol) |
| D'hooge L. et al. Inter-dataset generalization strength of supervised ML methods for intrusion detection, JISA 2020 | 12 supervizovaných algoritmů, CIC17 vs CIC18, slabá inter-dataset generalizace | plný text nedostupný, číslo 25,63 % ve shrnutí patří k Verkerken (ověřeno zvlášť jako RQ5-037) |
| D'hooge L. et al. 2023, Sensors (trénink CSE-CIC-IDS2018 → test CIC-IDS2017, CIC-DoS2017, CIC-DDoS2019) | „serious overestimation“ generalizace | jen citace ve shrnutí |
| Moczkodan Z. et al. (CIC-IDS2017, časové sekvence) | náhodný split s paddingem nadhodnotí robustnost až o 0,24 macro-F1 | jen shrnutí z catalyzex a zhuanzhiai |
| CyberBattleSim (Microsoft) a navazující práce | autoři rámec označují za příliš zjednodušený pro reálné nasazení, přenos sim → emulace selhává asi v 1/3 případů | sekundární citace, číslo 1/3 nelze přiřadit konkrétnímu systému |
| CAESAR poster (CAMLIS 2024) | transfer agentů ze simulace do emulace > 1000× rychlejší trénink | poster, neotevřen |
| Moulton, McCully, Hastings 2024, Confronting the Reproducibility Crisis | případová studie reprodukovatelnosti AI v kyberbezpečnosti | neotevřeno |
| Catillo et al. (citace [12] v DSN 2023): DoS útoky CICIDS2017 a dalších datasetů jsou proti zabezpečeným serverům převážně neúčinné | – | citováno v Catillo 2023 (V3), zdrojová práce neotevřena |
| GitHub gist „hamelin“ o OpTC (benigní provoz ze skriptu Firefox, útoky bez maskování) | – | neověřená identita autora, není recenzováno |
| Bezpečnostní preprinty o GAN augmentaci (preprints.org 2025, CTGAN recall Web Attacks 28 → 91) | – | nerecenzované, neotevřeno |

## V0: připomenuto z paměti, nehledáno ani neotevřeno

| zdroj | poznámka |
|---|---|
| McHugh J. Testing Intrusion Detection Systems: A Critique of the 1998 and 1999 DARPA IDS Evaluations, ACM TISSEC 2000 | zakládající kritika DARPA dat. Pro úplnost doplnit V3. |
| Sommer R., Paxson V. Outside the Closed World: On Using Machine Learning for Network Intrusion Detection, IEEE S&P 2010 | koncepční (E5). Doplnit. |
| García S. et al. An empirical comparison of botnet detection methods (CTU-13), Computers & Security 2014 | původní popis štítkování CTU-13, relevantní pro naši kotvu |

## Přečteno (V3), ale bez číselné extrakce

Kvalitativní podklad, v extrakci není nebo jen okrajově.

| zdroj | proč bez čísel |
|---|---|
| Catillo M., Pecchia A., Villano U. Machine Learning on Public Intrusion Datasets: Academic Hype or Concrete Advances in NIDS?, DSN-S 2023 | poziční článek (E5): neúčinné DoS útoky, reprezentativnost baseline, chyby CICFlowMeter, dělení dat |
| Hicks C. et al. Building Better Environments for Autonomous Cyber Defence, arXiv 2604.08805 (2026) | závěry workshopu, rámec rozhraní simulace a reality, bez měření |
| El Mahdaouy A. et al. Deep Learning for Contextualized NetFlow-based NID, arXiv 2602.05594 (2026) | přehled: časový únik, dělení dat |
| Garcia S., Valeros V. Towards a better labeling process for network security datasets, arXiv 2305.01337 (2023) | ontologie štítků, většina datasetů dává štítky do názvů souborů |
| Brown C. et al. Analysis of the 1999 DARPA/LL IDS Evaluation Data with NetADHICT, CISDA 2009 | artefakty (chybějící poškozené pakety, rovnoměrné rozložení hostů, extrémní časová variace), bez metrik detekce |
| Ammara D. A., Ding J., Tutschku K. Synthetic Network Traffic Data Generation: A Comparative Study, IEEE Access 2025 | 12 generátorů, N = 20 běhů, CTGAN/CopulaGAN nejlepší, difuzní modely výpočetně nepraktické. Čísla jsme nevybrali, protože úloha je tabulární (NSL-KDD, CIC-IDS2017) a relevance nepřímá. |
