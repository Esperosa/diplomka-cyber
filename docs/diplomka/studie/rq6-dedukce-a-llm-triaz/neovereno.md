# RQ6: neověřené zdroje (V1/V0) a vyloučené plné texty

Nic z tohoto seznamu se nepoužívá v Závěrech studie. Čísla uvedená níže pocházejí ze shrnutí vyhledávače nebo sekundárních zdrojů. Jsou to stopy k dalšímu ověření, ne důkazy.

## V1: jen shrnutí vyhledávače nebo sekundární zdroj

| zdroj | co tvrdí shrnutí | proč V1 |
|---|---|---|
| Ning, Cui, Reeves: Constructing Attack Scenarios through Correlation of Intrusion Alerts, ACM CCS 2002 (seminal) | korelace přes prerekvizity a důsledky „významně snižuje míru falešných alertů“ (DARPA 2000) | plný text se nepodařilo stáhnout: 4 URL (NCSU discovery, people.engr, csc2, typeset.io) vrátily 404 nebo HTML; diplomová práce Cui (NCSU repozitář) vrátila HTML místo PDF |
| Kruegel et al.: Bayesian Event Classification for Intrusion Detection, ACSAC 2003 | Bayesova síť místo prahu snižuje falešné alarmy | URL na auto.tuwien.ac.at vrací web fakulty, alternativní URL na UCSB 404 |
| Zhou, Heckman, Reynolds, Carlson, Bishop: Modeling Network Intrusion Detection Alerts for Correlation, ACM TISSEC 2007 | logické „capabilities“ korelovaly přes 2000 alertů Snortu | otevřen jen výsledek vyhledávání, nečteno |
| Morin et al.: logic-based model for alert correlation, Information Fusion 2009 | formální logický model potvrzení/vyvrácení alertů | jen záznam v repozitáři HAL, bez metriky |
| Bouzar-Benlabiod, Benferhat, Bouabana-Tebibel: IFO-QCL, Intelligent Data Analysis 2015 | logika preferencí operátora, experimenty na reálném monitoringu | nečteno |
| Kenaza 2021: ontologie v deskripční logice, korelační engine | testováno na dvou scénářích | nečteno, podle shrnutí bez FP metriky |
| Farhadi et al.: HMM pro korelaci a predikci (DARPA 2000) | predikce další fáze útoku | nečteno, nejde o Markovskou logiku |
| PLOS ONE 2024, Doc2Vec + HMM | „přesnost přes 99 % a precision 100 %“ | jen shrnutí, vlastní čísla autorů |
| HIDPAS (arXiv 0909.4889) | „korelační míra 100 %“ s BN | jen shrnutí |
| Hindriks: ProbLog vs CySeMoL, MSc Twente 2016 | ProbLog na velkých modelech nepřekonal CySeMoL | nečteno; jediná nalezená stopa ProbLog v bezpečnosti |
| FFI 2023: Towards XAI in the SOC (SHAP a LIME) | rozhovory s analytiky o vysvětleních | nečteno |
| Calibrating Trust in AI-Driven Cyber Defenses (CMS konference) | formulace vysvětlení a četnost vysokých konfidencí vedou k nadměrné důvěře | nečteno |
| Microsoft Security Copilot RCT (SSRN 4648700) | velké zlepšení rychlosti i přesnosti | nečteno; navíc střet zájmů (výrobce) |
| Oniagbi: Evaluation of LLM Agents for the SOC Tier 1 Triage, diplomová práce Turku | hybridní přístup s LLM jako copilotem | nečteno |
| Uncovering Vulnerabilities of LLM-Assisted CTI (arXiv 2509.23573) | podobné závěry jako Mezzi et al. | nečteno |
| Flash (IEEE S&P 2024) přímo | – | číslo pro Flash se v Závěrech bere jen z měření třetí strany (ORTHRUS, RQ6-038), vlastní článek Flash nebyl otevřen |
| letsdatascience.com (zpráva o Eilertsen et al.) | 93 % průměrná přesnost | sekundární, nahrazeno plným textem (RQ6-009, RQ6-010) |
| sekundární zpráva o CyberSOCEval (cybersecuritynews.com) | malware 15–28 % | **rozpor** s PDF v2 (23–34 %); v Závěrech platí PDF |

## Vyloučené po čtení plného textu nebo abstraktu

| zdroj | důvod vyloučení |
|---|---|
| Huang et al.: ProvSyn (arXiv 2506.06226) | syntéza grafů pro trénink, mimo otázku ověřování alertů |
| Li, Zuo, Gupta: Logic-Driven Cybersecurity, ASP (arXiv 2512.04908) | proof of concept na 2000 záznamech logu bez metriky TPR/FPR |
| Bilot, Jiang, Pasquier: PIDSMaker (arXiv 2601.22983) | rámec bez nového měření; použit jen kvalitativně (nekonzistentní značkování a dělení datasetů) |
| Cai et al.: SOC-bench design (arXiv 2603.28998) | jen návrh benchmarku, bez výsledků |
| Alert-Bench, NeurIPS 2026 WS listing | duplikát; nahrazen plným textem arXiv 2610.10608 |
| Hossain et al.: SLEUTH (USENIX Sec 2017) | plný text stažen, ale tabulka FP nebyla vyextrahována (nedostatek času); nepoužito |

## Tvrzení výrobců (nepoužito v závěrech)

| výrobce / zdroj | tvrzení | poznámka |
|---|---|---|
| Elastic Security Labs: LLM benchmarking for agentic SOC | veřejné žebříčky neřeknou, kterému LLM v SOC věřit; nejnebezpečnější je plynulá odpověď bez podpůrného volání nástroje | metodický názor, bez dat |
| NeuralTrust blog (říjen 2026) | agent se shell nástroji spustil kód z cloudových logů u 6 z 8 modelů; Azure Prompt Shield zachytil 1 z 32 payloadů v logu; Sygnia: injekce v PowerShellu přiměla MDR souhrn popsat Mimikatz jako údržbu | agregace, nic z toho nebylo ověřeno v primárních zdrojích |
| Semgrep: AppSec AI, 96% shoda s výzkumníky | záměrně minimalizují FN, triáž je konzervativnější než experti | blog výrobce |
| Orca Security 2022, ESG 2023 (citováno v CORTEX) | 40–45 % alertů v podnicích jsou FP | průzkumy, ne měření |
