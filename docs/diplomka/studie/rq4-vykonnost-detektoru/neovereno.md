# RQ4: neověřené zdroje (V1/V0), nepoužité v závěrech

Důvod „snippet“ = viděn jen výtah vyhledávače; „nedostupné“ = plný text nešlo otevřít; „vyloučeno“ = otevřeno, ale nepoužitelné.

| # | Zdroj | Co by mohl dodat | Úroveň | Důvod |
|---|---|---|---|---|
| 1 | Carleton TR-11-08 (STRW vs TRW) | FP 19-50 % zdrojů u TRW, STRW -77 % / -29 % FP | V1 | snippet, PDF nedostupné |
| 2 | UC Davis, jsac06-isand | TRW FPR 8× vyšší při vzorkování 1/10 | V1 | snippet |
| 3 | Gyorgy et al., SDM 2006 (scan detection) | FP z P2P a backscatter | V1 | snippet |
| 4 | Exploit Traffic Detection Method Based on Reverse Shell (MDPI Appl. Sci. 2023, ETDetector) | jediná akademická práce o reverse shellu ze sítě | V1 | MDPI vrací HTTP 403, čísla nepřečtena |
| 5 | Stergiopoulos et al., J. Comput. Secur. 2019 (CART nad TCP side-channels) | reverse shell ze sítě | V1 | paywall |
| 6 | Najafabadi et al., IEEE 2014 (brute force na úrovni sítě) | flow-based brute-force ML | V1 | snippet |
| 7 | TU Delft thesis (netflow exfiltration, k-means + z-score) | FP v exfiltraci z NetFlow | V1 | PDF nedostupné |
| 8 | KCA thesis (Isolation Forest, CICIDS2017 infiltration) | 4,8 % toků anomálních | V1 | snippet |
| 9 | Institute of Technology Carlow (flow metadata exfiltrace) | supervised exfiltrace z toků | V1 | snippet |
| 10 | Utah master thesis (Tripathi 2018), periodicita v NetFlow | FFT na tocích | V1 | snippet |
| 11 | Nikkhah Nasab, reimplementace BAYWATCH (th-deg GitLab diffy) | jitter/interval < 10 % pro robustní detekci | V1 | jen diffy rozpracované práce |
| 12 | Fox-IT, „Hunting for beacons“ (blog) | tolerance 25 % vs jitter | V1 | blog bez dat |
| 13 | Active Countermeasures, „Detecting beacons with jitter“ | krátká okna skryjí jitter | V1 | blog výrobce |
| 14 | FalconForce, FalconFriday: recognizing beaconing | filtry snížily stovky FP denně | V1 | blog |
| 15 | Elastic, Network beaconing framework (dokumentace) | trade-off recall/precision | V1 | dokumentace |
| 16 | Elastic, „Plight at the end of the tunnel“ | CDN jako zdroj FP DNS tunelů | V1 | blog výrobce |
| 17 | Infoblox blog (99,7 % F1) | – | V1 | marketing |
| 18 | Whalebone blog (AV hashe přes DNS) | – | V1 | blog |
| 19 | Splunk research (DNS tunel, odstraněná detekce) | – | V1 | dokumentace |
| 20 | TunnelEye (Senyk 2026) | multi-level DNS tunel | V1 | snippet |
| 21 | Gautam et al. 2026 (CNN+SVM DNS tunel) | – | V1 | snippet |
| 22 | EV-charging adaptive DNS tunneling 2026 (mean F1 0,041 pod evasí) | evase DNS detektorů | V1 | snippet, syntetická data |
| 23 | Song, Wagner, Tian, USENIX Sec. 2001 (SSH timing) | klasika keystroke timing | V1 | pouze výtah (PDF nezpracován) |
| 24 | Salgarelli et al., Crotti et al. (SSH/first-packets) | – | V1 | snippet |
| 25 | Allard et al. (NATO IST-091), Dalhousie SSH/Skype tunely | SSH tunel flow ML | V1 | nezpracováno z kapacitních důvodů |
| 26 | Applied Sciences 2023, přehled tunel detekce 2003-2022 | – | V1 | snippet |
| 27 | Hynek et al., IM 2019 dataset (flow-only FP ~15 %) | FP SSHCure | V1 | PDF nedostupné |
| 28 | Euler: tvrzení „precision 0,243 → 0,986“ (NSF záznam) | – | V1 | sekundární shrnutí, neověřeno proti plnému textu |
| 29 | Vectra / Stamus / Akamai (JA3 randomizace) | – | V1 | blogy výrobců |
| 30 | arXiv 2603.03270 (DGA smishing 2026) | DGA tactics | V1 | snippet |
| 31 | arXiv 2205.14940, 1811.08705 (DGA unknown families, inline) | – | V1 | snippet |
| 32 | arXiv 2003.05703 (DGA side information) | – | V0/V1 | stažen, ale nečten do hloubky |
| 33 | Bian et al., CNSM 2019 (LANL, target assets) | – | vyloučeno | PDF otevřen, tabulky v extrakci textu nečitelné, jiná jednotka (host) |
| 34 | arXiv 2602.11019 (CERT r4.2) | – | vyloučeno | uživatelské audit logy, ne síť |
| 35 | Maiolini et al. 2010 (judicial workspace) | – | vyloučeno | irelevantní |
| 36 | Baywatch (Hu 2016) čísla výkonu | TPR/FPR | V2 | jen abstrakt; plný text nedostupný (řádek RQ4-015) |
| 37 | Lee, Lee, An SSH predictive model using machine learning with web proxy session logs (Int. J. Inf. Secur. 2021, doi:10.1007/s10207-021-00555-6): původní RQ4-033 (Tab. 9: recall 70,52 %, FPR 5,18 %, 23 serverů) a RQ4-034 (Tab. 10: DARPA99, recall 100 %, precision 19,7 %, FPR 1,1 %) | SSH přes proxy, base-rate lekce | V2 | Springer closed access; nezávislá kontrola 2026-10-31 získala jen abstrakt; hodnoty z Tab. 9 a 10 nelze ověřit, přesunuto z extrakce při revizi; nesmí podporovat žádný závěr |

Celkem 37 položek (V1/V0 33, vyloučeno 3, V2 z abstraktu 1 (Lee a Lee); Baywatch (#36) je V2 a zůstává v extrakci jako RQ4-015).
