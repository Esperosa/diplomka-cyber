# RQ3: neověřeno (V1/V0) a vyloučené

Nic z této přílohy se nesmí použít v závěrech. Důvod je vždy uveden. Datum: 2026-10-31.

## V1/V0 (nepodařilo se otevřít plný text ani oficiální abstrakt s hodnotou)

| Zdroj | Co by přinesl | Proč neověřeno |
|---|---|---|
| Beaugnon, Chifflier, Bach: ILAB (RAID 2017) a End-to-End Active Learning for Computer Security Experts (AICS 2018), disertace Beaugnon 2018 | úspora štítků pro analytika při interaktivním štítkování | cyber.gouv.fr vrací stránku Incapsula, HAL vrací Anubis Access Denied; jen shrnutí vyhledávače |
| Doak et al. 2013 (Sandia ALAT), Bierma et al. (OSTI) | uncertainty sampling na reálných kybernetických alertech | OSTI purl nedostupné (spojení selhalo); jen shrnutí vyhledávače |
| Pospíšil et al. 2021, Active Scanning in the Industrial Control Systems (ZMap: úplná ztráta komunikace, Nmap: zpoždění) | kvantifikace rizika aktivního skenu na testbedu | dspace.vut.cz za Anubis; jen snippet. Riziko dokládá místo toho Samanis 2022 (V3), kazuistika |
| Hu, Zhu, Liu, ACM TOPS 2020 (POMDP + Thompson sampling, více-stupňové útoky) | POMDP výběr obranné akce | par.nsf.gov nedostupné; jen snippet |
| Rezaee Saeed (UniPD diplomka) kaskáda s vysokým recallem v 1. stupni | recall ve stupni 1 | stažení selhalo |
| WebAD² (Springer, kaskáda pro webové útoky) | kaskáda s dílčími příznaky | stažení vrátilo HTML (paywall) |
| GreenShield (sciety/Research Square preprint) | energeticky úsporná kaskáda DT -> RF | stažení vrátilo HTML |
| Kim, Dán, Zhu: Human-in-the-loop Intrusion Detection (TIFS 2024) | Max Ratio / Max KL politiky | PDF staženo, ale nepřečteno (nezahrnuto, rozsah času) |
| Elastic + Tines (SOAR, "3000+ alertů denně bez člověka", 15 min/alert), VMRay | úspora času automatickou triáží | vendor tvrzení bez metodiky; patří jen do tabulky níže |
| ORDR glosář ("40 % OT zařízení spadne při skenu", "pasivní najde 95 %") | prevalence pádů | vendor, bez primárního zdroje |
| SANS 2024 SOC survey (11 000 alertů/den, 19 % stojí za vyšetření) | kontext | jen přetištěno z blogu |
| Turcotte et al. 2025 jako zdroj "61 %" (sekundárně) | | primárně ověřeno v AACT (arXiv 2505.09843), pole V3 |
| Mailing-list Snort 2003/2006 (SnortAV) | | nepublikovaná zpráva, bez dat |
| Provos 2004 virtual honeypots | honeypot jako nízkošumový signál | jen shrnutí vyhledávače; bez metriky |
| TR-11-08 Alsaleh a van Oorschot (Carleton, PDF) | původní TR k STRW | PDF 404; čísla ověřena z disertace Alsaleh 2011 (V3) |

## Přečteno, ale vyloučeno z extrakce (kritérium zahrnutí b: bez metriky triáže/ověřování)

| Zdroj | Důvod |
|---|---|
| Alahmadi, Axon, Martinovic: 99% False Positives (USENIX Sec 2022) | kvalitativní studie (survey n=20, rozhovory n=21), žádná měřená metrika triáže; použito jen jako kontext, ne důkaz |
| Le, Stadler: Learning Optimal Defender Strategies for CAGE-2 using a POMDP Model (arXiv 2509.06539) | POMDP pro obranu v simulaci, skóre CAGE-2, ne ověřování alertů |
| Le, Stadler: Learning Intrusion Response Strategies for OT Systems (arXiv 2609.10298) | POMDP odpovědi na útok, bez metriky verifikace |

## Tvrzení výrobců (nepoužito v závěrech)

| Výrobce/zdroj | Tvrzení | Poznámka |
|---|---|---|
| Elastic + Tines blog | automatické SIEM vyšetřování uzavírá 3000+ alertů denně bez zásahu člověka; analytik by potřeboval 15+ min na alert | bez FN/TPR, bez metodiky |
| ORDR | skenování poškodí/destabilizuje >40 % typů OT zařízení; pasivní objeví 95 %+ | bez primárního zdroje |
| runZero | "freezes are entirely avoidable" při přípravě | marketingová abstrakce konference |

## Nesoulad v literatuře, který se nepodařilo vysvětlit
- NoDoze: oficiální abstrakt NDSS udává pokles falešných poplachů o 86 % (V2), Carbon Filter (V3) cituje 84 %. Rozdíl nevysvětlen.
