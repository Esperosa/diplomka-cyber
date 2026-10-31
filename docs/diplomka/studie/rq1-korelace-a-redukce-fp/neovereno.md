# RQ1: neověřeno (V1/V0) a tvrzení výrobců

Nic z tohoto seznamu se nesmí objevit v závěrech. Hodnoty jsou přepsané ze shrnutí vyhledávače nebo z abstraktu, který jsem sám neotevřel.

## V1 (jen shrnutí vyhledávače nebo sekundární zdroj)

| Zdroj | Co tvrdí shrnutí | Proč V1 |
|---|---|---|
| Fuzzy comprehensive evaluation alertů (Beijing Inst. Tech.) | snížení FP a duplicit „významně" | otevřena jen stránka repozitáře, bez čísel |
| Post-correlation framework (IAENG WCE 2012) | FP sníženy o 97 % v jednom scénáři a o 16 % v jiném | PDF jsem neotevřel, rozpětí 16-97 % pochází ze shrnutí |
| Dempster-Shafer přístup (DARPA 2000) | redukce >69 % alertů | PDF jsem neotevřel |
| Hybridní IDS ensembly (UNSW-NB15, CIC-IDS2017) | nižší FPR „5,8" | nejde o fúzi Zeek+Suricata a neznám metriku |
| Landauer et al. 2022, ACM TOPS „Dealing with Security Alert Flooding" | agregace alertů do meta-alertů, nezávislá na doméně | plný text ani tabulky s redukcí se mi nepodařilo získat |
| Marchetti et al. 2016, Computer Networks (hodnocení hostitelů pro APT) | pořadí nejpodezřelejších hostů v síti ~10 000 hostitelů | PDF nešlo stáhnout, jen abstrakt |
| Oprea et al. DSN 2015 (včasná infekce z logů) | zmíněno ve shrnutí | PDF URL 404 |
| Kokulu et al. CCS 2019 (SOC) | kvalitativní studie problémů SOC | abstrakt ani PDF nedohledán |
| Soliman, Mikkelesen, Seljåsen, AMCIS 2025 (alert fatigue) | 12 analytiků z 5 SOC, strategie „mindful balancing"; „50-90 % poplachů je FP" | jen abstrakt na stránce AIS; číslo 50-90 % je odkaz na jiný zdroj |
| „Exchanging security events: which and how many alerts can we aggregate?" (IM 2017) | datasety klesly o 25 % a 8 %, „až 85 %" | jen shrnutí |
| Alarm clustering na DARPA 1998/1999 | průměrná redukce 74 % | jen shrnutí |
| Decision-aware trust signal alignment (arXiv 2601.04486) | simulace: nesladěné zobrazení důvěry zvyšuje FN | jen shrnutí; simulace |
| Ning, Cui, Reeves CCS 2002 | konstrukce scénářů z alertů | původní článek jsem neotevřel; Ning04/Noel04 jsou otevřeny, ale bez použitelné metriky FP |

## V0 (nenalezeno)

- Nezávislá měření snížení FP kombinací Zeek log + Suricata alert přes `community_id` (nenalezena žádná akademická práce).
- Akademické měření UEBA (entitní skórování) v prostředí SOC s FP před/po (nenalezeno; RBA práce záměrně entity nehodnotí, viz RQ1-041).
- Měřená doba triáže jednoho alertu v terénní studii (nenalezeno; jen anekdota RQ1-010 a modelové předpoklady RQ1-027).

## Vyloučeno po přečtení plného textu

| Zdroj | Důvod |
|---|---|
| Ning, Xu et al., „Building Attack Scenarios through Integration of Complementary Alert Correlation Methods" (NDSS 2004) | popisuje hypotézy o zmeškaných útocích, bez metriky redukce FP, kterou bych ověřil |
| Noel et al. ACSAC 2004 (attack graph korelace) | jen doba zpracování (24 ms/událost), bez FP |
| Iyengar, „Evaluation of Network Based IDS and Deployment of multi-sensor IDS" (arXiv 2007.11654) | multi-sensor jen jako umístění senzorů, bez metrik fúze |

## Tabulka: tvrzení výrobců (nepoužito v závěrech)

| Zdroj | Tvrzení | Poznámka |
|---|---|---|
| Splunk (H. Mills, citována v TechTarget) | redukce alertů s RBA 50-80 %, osobně ~95 % | praktikující výrobce, bez metodiky |
| Exabeam blog | váhy podle četnosti, FP výsledky „v dalším blogu" | bez čísel |
| Corelight white paper | Zeek UID je lepší identifikátor toku než Community ID | tvrzení o kolizích hashe bez měření |
| FireEye/IDC 2021 | 44 % analytiků MSSP ignoruje alerty při plné frontě | průzkum sponzorovaný výrobcem |
| Vectra, Microsoft/Omdia, SANS (prostřednictvím shrnutí) | 46 % FP, 73 % týmů označuje FP za hlavní problém | sekundární zdroj |
| D3 Security | norma 20 min L1, 40 min L2 | modelový předpoklad bez zdroje |
| Praetorian / Palo Alto blogy | míra FP 50-80 % | bez odkazu na studie |
