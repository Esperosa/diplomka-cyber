# RQ2: neověřeno (V1/V0) a vyřazeno po čtení

Tyto položky se **nesmějí** použít v závěrech. Důvod uvádí poslední sloupec.

## V1 (jen shrnutí vyhledávače nebo sekundární zdroj)

| Práce | Co se tvrdí (sekundárně) | Důvod V1 |
|---|---|---|
| Sommer & Paxson, Outside the Closed World, IEEE S&P 2010 | kritika ML pro IDS; vysoká cena chyb | PDF na ICSI nedostupné (ECONNREFUSED), IEEE stránka vrátila prázdný obsah |
| Andresini et al., INSOMNIA, AISec 2021 | time-aware evaluace TESSERACT pro síť, CICIDS2017, lepší než baseline bez driftu | UCL (ECONNREFUSED), ACM 403, UCL Discovery nedostupné |
| Brauckhoff, Salamatian, May, Applying PCA for Traffic Anomaly Detection, INFOCOM 2009 | PCA nezachycuje časovou korelaci; KLT zlepšuje výsledek | core.ac.uk 403, HAL blokováno (Anubis); jen disertace (RQ2-007 až 009, V2) |
| Callegari et al., CUSUM s wavelet prefiltrem na Abilene | lepší detekce i FPR než klasická metoda | pouze snippet |
| Ndong & Salamatian | pro jednu linku vychází základní test rozptylu nejlépe (Abilene) | pouze snippet |
| Čisar et al. (EWMA modifikace) | prostý EWMA dává relativně mnoho falešných alarmů | pouze snippet |
| Sun et al., Online Adaptive Anomaly Thresholding with Confidence Sequences, ICML 2024 | abstain pro cold-start, záruky na FP/FN | PDF z PMLR se nepodařilo stáhnout |
| Konformní detektor pro O-RAN, ICML 2026 | vyšší detekce při cílové FAR | pouze stránka konference |
| ESREL 2025 konformní post-processing pro ICS | časová úprava kvantilu při posunu | pouze stránka |
| Eliades & Papadopoulos, ICM ensemble pro concept drift | konformní martingaly detekují porušení výměnnosti | pouze snippet |
| Preprint 202606.0903 (CSE-CIC-IDS2018), chronologický split | macro-F1 0,79-0,82 (náhodný split) -> ~0,02 (chronologický) | preprints.org stažení selhalo; pouze snippet |
| Článek o CICIDS2017 robustnosti | degradace ~29,64-30,34 % při náhlém driftu | pouze snippet (ejournal.unkhair.ac.id) |
| MAWILab, Fontugne et al., CoNEXT 2010 | kombinace detektorů najde 2x víc anomálií než nejlepší detektor | HAL stažení selhalo; pouze snippet |
| Survey o únavě z alertů (arXiv 2605.08316) | ~0,01 % alertů v jednom SOC souvisí s útokem | pouze snippet |
| Axelsson 2000, base-rate fallacy | původní práce | neotevřena; zmíněna jen přes Erbacher (RQ2-049) |
| Vendor statistiky FP míry (Vectra, Praetorian, n-able, Microsoft/Omdia) | 46 %, 50-80 % FP | vendor, pouze snippet; v §10 studie |

## V0

Žádný záznam nebyl převzat z paměti. Pojmy a metody (BH, BY, Storey, STL, PELT, BOCPD) jsou použity bez číselných tvrzení.

## Přečteno v plném textu a vyřazeno z extrakce

| Práce | Důvod |
|---|---|
| Li et al., PAC-Wrap (arXiv 2205.10798) | nesíťové datasety (NASA, SMD, thyroid); hodnoty v tabulkách nešly spolehlivě číst z rozbitého textu |
| Bashari et al., derandomized conformal e-values (arXiv 2302.07294) | pouze simulace a obecné benchmarky, bez síťové aplikace |
| Komolafe et al., spectral methods on static networks (arXiv 1711.01378) | grafové sítě, ne provoz |
| Skaperas et al., change-point detektory na edge cloudu (arXiv 2401.07717) | syntetika, hlavně zpoždění a CPU |
| Mirsky et al., Kitsune (arXiv 1802.09089) | výsledky jen v grafech (AUC/EER), čísla nejde spolehlivě číst |
| Camarda et al. (CEUR 3962 paper42) | KDD99 |
| Costa et al., Concept Drift Stream Generator (CEUR Ital-IA 2025) | generátor, bez FPR |
| Yumlembam et al., konformní vrstva pro botnet (arXiv 2409.00667) | v textu nenalezena použitelná čísla pokrytí/FPR (jen grep) |
| Araz & Spannowsky, konformní kalibrace pro fyziku částic (arXiv 2606.13780) | mimo doménu |
| Wilmet et al., degree-based outlier detection v link streamu (arXiv 1906.02524) | porovnání s MAWILab bez FPR |
| Spark-based scan detection (arXiv 1806.11047) | stažen, nepřečten (vyřazen po titulu) |

## Zdroje se sníženou spolehlivostí zahrnuté v extrakci

- Youssef, CALIBURN (arXiv 2605.24696 v1), arXiv 2510.09619 v2 a arXiv 2605.24696 v3 (RQ2-034 až 037): autor sám v pozdějších verzích uvádí, že popis skóre neodpovídá kódu a hodnocené proudy jsou sestavené konstrukce. Číselné výsledky v1 (RQ2-034, 035) nejsou důkaz; v závěrech jen Z11 s jistotou velmi nízká.
- Beach & Modaff (RQ2-020): studentská zpráva bez metrik.

## Revize po nezávislé kontrole (2026-10-31)

Žádný řádek nebyl z extrakce přesunut: u všech 53 řádků byla hodnota nebo citace dohledána ve zdroji (kontrola 37 řádků, revize zbylých 16). Nepodložené, ale ponechané závěry: Z5b („ladění na štítcích je nutné“, extrapolace) a Z1b (jednoduchý práh srovnatelný, nízká jistota, jediné měření 021). Podrobnosti v `revize-RQ2.md`.
