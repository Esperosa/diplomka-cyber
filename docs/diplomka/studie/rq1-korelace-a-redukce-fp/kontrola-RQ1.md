# Kontrola RQ1 (protokol §9): nezávislé ověření extrakce

Datum: 2026-10-31. Kontrolor: nezávislý agent (bez účasti na extrakci). Kontrolované soubory: `extrakce.csv` (56 řádků, všechny V3), `studie.md` (jen tabulka Závěry a souvisící oddíly). Soubory `extrakce.csv` ani `studie.md` jsem neměnil.

## 1. Vzorek a postup

- **Vzorek:** všech 56 řádků (100 %), tedy víc než požadované minimum (30 % a aspoň 20 řádků). Povinná část (řádky, o které se opírají závěry s jistotou vysoká/střední: Z1 až Z5, Z11, Z14) je v tom obsažena celá: 001-005, 011-014, 017-025, 031-032, 037-040, 046, 048, 049, 056 a navíc zbytek.
- **Hloubka kontroly se liší:** u řádků 001-015, 017-027, 028, 030-035, 036-046, 048-056 jsem porovnal hodnotu, jednotky, dataset, konfiguraci a (kde je v poli) doslovnou citaci s čerstvým zdrojem. U několika sekundárních detailů jsem to neudělal (viz "Nezkontrolované detaily").
- **Zdroje:** všechny PDF jsem stáhl znovu (curl / Invoke-WebRequest, adresář `%TEMP%\kon1`, ne z `F:\claude-tmp\rq*pdf\`), převedl `pdftotext -layout` a hodnoty hledal v textu a tabulkách. WebFetch jsem nepoužil, protože pro PDF dává stažení plného textu přesnější výsledek. Ověřené URL: všech 26 zdrojů se otevřelo (Julisch v PowerShellu jednou selhal, přes curl OK; DOI odkazy na Springer (052-054) vrací HTML s plným textem, citace v něm jsou).
- **Tvrzení V (plný text):** potvrzeno u všech zdrojů; vždy šlo o plný text s tabulkami, ne jen abstrakt.
- **Tabulky rozbité při převodu:** u RBA (Tab. 4) a DeepCASE (Tab. I) jsem pořadí sloupců ověřil z hlavičky v mém převodu. Odvozené pořadí kolegy je správné (RBA: Rarity 0,31 až 0,48 a Aperiodicity 0,47 až 0,57; DeepCASE: Overall 90,53 / Precision 96,39 / Recall 91,47 / F1 93,41 / Accuracy 91,47 / Underest. <0,01 %).

## 2. Kontrolované řádky

| id | výsledek | poznámka (opravená hodnota a umístění) |
|---|---|---|
| RQ1-001 | OK | Axelsson, Sec. 5, Obr. 1: "1 z 10^-5" (v převodu "10 25"), 66 % a 58 %; základní četnost 2e-5 v Rov. 6/10. Sedí. |
| RQ1-002 | OK | "100 false alarms per day ... large margin ... 1 z 10^-5", doslovně. Pozn.: strop 100 FA/den by se naplnil až při FPR 1e-3 (tam Bayesovská míra klesne na ~2 %), řádek to nevyužívá, ale je to relevantní pro Z11. |
| RQ1-003 | OK | Erbacher, "Base-Rate in Context", doslovně; skutečně citace [22]. |
| RQ1-004 | OK | ~19 prací ("primary evaluation methods for 19 papers"), kritika různých formulací FPR sedí. |
| RQ1-005 | OK | Arp, Pitfall P8, doslovně. |
| RQ1-006 | DROBNÁ CHYBA | Citace doslovně správná (B3). Umístění "Findings" je nepřesné: je to Sec. 6 "RQ2: Definition of FPs". Opravit umístění. |
| RQ1-007 | OK | 45 % < 5K/den; n = 10 uvedlo podíl; "1 ze 100" a "50 z 200" sedí. |
| RQ1-008 | OK | Sedí (Sec. 4/5, rozlišení FP vs. benigní spouštěč). |
| RQ1-009 | OK | "in most cases analysts are more capable of connecting these patterns themselves ... than SIEMs", doslovně. |
| RQ1-010 | OK | "tier 1 ... about 10 minutes ..., tier 2 ... up to 2 hours", doslovně. |
| RQ1-011 | OK | "reported quantitative results should be treated as upper bounds" a C1 sedí; 119 záznamů/87 jádrových sedí. |
| RQ1-012 | OK | Tab. IV: 1942 -> 164, 91,56 %. |
| RQ1-013 | OK | Tab. IV: 22792 -> 853, 96,26 %. |
| RQ1-014 | OK | Tab. IV: 2259 -> 55, 97,57 %; XSS a finální FTP přenos neidentifikovány (Sec. IV-D). |
| RQ1-015 | OK | Tab. V (Ning 56,18 % / 5,26 %, MAAC 100 % / 0 %), poznámka pod tabulkou 0 % při top 4, 20 % při top 5. |
| RQ1-016 | OK | Abstrakt "a few dozens ... over 90 %" a kap. 6 "average of less than 18 root causes ... 90 %". (Údaj o Tab. 3.2 pro IDS 3 jsem nekontroloval.) |
| RQ1-017 | OK | Abstrakt "reduce the future alarm load by 70 %, on the average"; 48 měsíčních bodů (4 IDS x 12), kap. 6. Autor sám píše, že jde o podhodnocení. |
| RQ1-018 | OK | IDS 3 93 % (únor 2001), IDS 3 a 10 přibližně 95 % v průměru. |
| RQ1-019 | OK | IDS 6 únor 18 % (563 205 "Fragmented IP"); IDS 14 blízko 0 % v dubnu a květnu (1 415 167 "TCP Overlap Data"). Pozn.: IDS 6 měl i září 48 % a říjen 43 %. |
| RQ1-020 | DROBNÁ CHYBA | Citace doslovně správná. Parafráze limitu je zkreslená: zdroj říká "one might choose to filter out true positives if their targets are not vulnerable" (cíle nejsou zranitelné), ne "u necílených zranitelných systémů". Julisch navíc výslovně píše, že kvantifikovat bezpečnost filtrace nelze (kap. 6.4); "recall se neměřil" je správně. |
| RQ1-021 | OK | Tab. 1: 6 659 alertů, 24 TP, 99,64 % -> 0,00 %. Kruegel to sám nazývá "non-relevant positive rate". |
| RQ1-022 | OK | 14 dní, Snort 2.0.2, 2625 pravidel; 161 166 (98,3 %) a 78 785 (99,4 %). |
| RQ1-023 | OK | Citace sedí (granularita CVE ID). |
| RQ1-024 | OK | Závěr (Conclusion) doslovně; Tab. 2 potvrzuje většinu poklesů nad 50 %. |
| RQ1-025 | OK | Telnet + POSEIDON: Tab. 2 63 776 -> 56 885 FP (pokles ~11 %). |
| RQ1-026 | OK | 364 alertů (50 TP, 314 FP), 1 mld. událostí, 5 dní, "100 % of true positives ... 16 % FPR", >84 %. |
| RQ1-027 | OK | Sec. E "Time Saved": 10-40 min, 20 min konzervativně, 104 h, ~90 h, 60-80 % FP. |
| RQ1-028 | OK | RapSheet: 1 104 TP + 56 992 FP, 681 TPG, 5 pravých, "remove 97.8 % of false TPGs", FPR 2,2 %. |
| RQ1-029 | OK | "6 of these 10 techniques are benign in isolation", 93 APT skupin. |
| RQ1-030 | OK | HOLMES: dva týdny benigní činnosti bez falešných poplachů; SSH administrátoři způsobili FP v hlavním testu. |
| RQ1-031 | OK | Tab. 1: T1 81373, 26651, 655, 53; T2 42474, 4922, 609, 7. (Pozn.: součet AGs přes týmy je 197 > 93 kvůli sdíleným grafům, řádek to správně nesčítá.) |
| RQ1-032 | OK | 330 270 -> 93 AG, 70 cílů, 19 obětí, diskuse "still ends up with several AGs". |
| RQ1-033 | OK | k = 200, 86,8 % vs 7,9 %, FPR 4,4 %; poznámka 1 (12. týden vs průměr 3,41x). |
| RQ1-034 | OK | k = 1000: 73,7 % a FPR >22 %; Tab. 2 týden 12 (0,737 / 0,225). |
| RQ1-035 | OK | 42 vs 143 a 211 z 318. |
| RQ1-036 | OK | 2 655 821; Wazuh 2 293 628 (86,4 %), Suricata 306 635 (11,5 %), AMiner 55 558 (2,1 %). |
| RQ1-037 | OK | AUROC 0,92 (0,09) vs 0,72 (0,21) vs 0,50. Pozn. k použití v závěrech: 0,92 je optimalizovaná pipeline všech pěti modulů, viz přesazení Z5. |
| RQ1-038 | OK | Wilcoxon p = 0,016 / 0,012 / 0,0039 (Rule Level / Accumulation / Variety, výchozí konfigurace); Rarity p = 0,63, Aperiodicity p = 0,42 (řádek je neuvádí, ale hodnoty AUROC jsou správně). |
| RQ1-039 | OK | 44 pravých, 9 142 falešných; 43 v horních 10 % vs 28,6. |
| RQ1-040 | OK | Trailing: Accumulation+Variety 0,70 vs 0,79 (SD 0,05 / 0,06), pipeline -17 %; cílová IP 0,61 vs zdrojová 0,65 (sítové datasety). |
| RQ1-041 | OK | "we deliberately refrain from evaluating entity risk modifiers"; a "we do not assign risk scores to entities instead of alerts". |
| RQ1-042 | OK | Sec. 4.4.1: >0,925, o >0,1; bez šumu "almost 0,89", o >0,13. |
| RQ1-043 | DROBNÁ CHYBA | Hodnoty pro more-noise-11 sedí (0,979 vs 0,972; 0,933 vs 0,916). Výběr je ale selektivní: v konfiguracích more-noise-2 a more-noise-6 je time-delta v makro AUC lepší než AlertBERT (např. 0,973 vs 0,936 a 0,957 vs 0,936 včetně šumu), autoři píšou "time-delta scores better ... in the other 3 cases ... up to 0.04" a výsledky označují za smíšené. Řádek to nezachycuje, což je podstata přesazení Z8. |
| RQ1-044 | DROBNÁ CHYBA | Purity 0,81632 vs 0,30353 a silhouette 0,97385 vs 0,90048 sedí. Řádek u "bez dnsteal" uvádí jen silhouette (0,44622 vs 0,06470) a vynechává purity 0,99850 vs 0,95653, kde je rozdíl velmi malý. Doplnit. |
| RQ1-045 | OK | 90,53 %, 86,72 %, 20 organizací, 5 měsíců. |
| RQ1-046 | OK | Precision 96,39 / Recall 91,47 / F1 93,41 / podhodnocení <0,01 % (47 predikcí), Bladabindi. |
| RQ1-047 | OK | Diskuse "adversary with knowledge of existing clusters ... remain undetected". |
| RQ1-048 | OK | "61 % alert reduction over a 6-month period, with FNR 1,36 %", FNR určena vzorkováním. |
| RQ1-049 | DROBNÁ CHYBA | Hodnota 34 % při FNR 1,5 % sedí. Poznámka "rozdíl jsem nevysvětlil" je nepravdivá: zdroj ho vysvětluje. Offline vyhodnocení vynechává 728 834 alertů, které AACT už dříve automaticky zavřel; po jejich započtení je redukce "closer to 74 %". |
| RQ1-050 | OK | Beehive: 784 incidentů, 56/den (SD 6,88), 8 překryvů, 25,25 / 39,41 / 35,33 %, 1,4 mld. logů/den. |
| RQ1-051 | OK | MADE: 97 % precision v top 100, FPR 6e-5, 50 000 domén, 516 škodlivých. |
| RQ1-052 | OK | Citace "1OO2 systems are inherently more sensitive rather than specific ..." na Springer Link (online 12/2023, ročník 2024). |
| RQ1-053 | OK | 177 504 a 3 991 přítomno v textu. |
| RQ1-054 | OK | "unfortunately not labelled ..." doslovně. |
| RQ1-055 | OK | "reduced by several orders of magnitude", run time ~30 %, CPU ~10 %. |
| RQ1-056 | OK | "run the risk of dropping important alerts ..." doslovně. |

**Nezkontrolované detaily** (nejsou hodnoty, na nichž závěry stojí): Julisch Tab. 3.2 (016), charakteristika IDS 3 jako "web hosting, DMZ" (018), "po 1 měsíci ručního režimu" u DeepCASE (045), přesné číslování sekcí u Tedesco (056), venue Kruegel (PIK 2004), tvrzení "nezávislá validace chybí" (017), příznak "labely od analytika" u AI2 (033).

## 3. Chybovost

| Ukazatel | Hodnota |
|---|---|
| Ověřeno řádků | 56 |
| OK | 51 |
| DROBNÁ CHYBA | 5 (006, 020, 043, 044, 049) |
| VĚCNÁ CHYBA | 0 |
| NEOVĚŘITELNÉ | 0 |
| **Věcná chybovost** | **0 / 56 = 0 %** |
| **Podíl NEOVĚŘITELNÝCH** | **0 %** |

Věcné chyby v hodnotách jsem nenašel: žádná vymyšlená citace, žádná zaměněná metrika (TPR vs. precision, FPR vs. FDR), žádný špatný dataset. Hodnoty jsou přenesené přesně, včetně čtení rozbitých tabulek. Slabiny jsou v interpretaci, ne v číslech (viz níže).

## 4. Nutné opravy

Extrakce (`extrakce.csv`):

1. **RQ1-006:** umístění změnit na "Sec. 6 (RQ2: Definition of FPs)".
2. **RQ1-020:** opravit parafrázi limitů autora na "filtrování TP lze zvolit, pokud cíle nejsou zranitelné"; doplnit, že autor (kap. 6.4) považuje kvantifikaci bezpečnosti filtrace za nemožnou.
3. **RQ1-043:** do poznámky doplnit, že v konfiguracích more-noise-2 a more-noise-6 je time-delta v makro AUC lepší než AlertBERT (až o 0,04) a že autoři výsledky hodnotí jako smíšené. Přidat samostatné řádky pro more-noise-2 a more-noise-6.
4. **RQ1-044:** doplnit purity bez dnsteal (0,99850 vs 0,95653).
5. **RQ1-049:** poznámku nahradit vysvětlením rozdílu: offline 34 % je z fronty po vyřazení 728 834 dříve auto-uzavřených alertů; včetně nich asi 74 %; živá hodnota 61 %.

Studie (`studie.md`):

6. **Oddíl 1, bod 4 a závěr Z5:** přepsat (viz přesazení č. 1).
7. **Z8 a oddíl 4 "Rozpor 2":** přepsat (viz přesazení č. 2).
8. **Z10 a H1-8:** vysvětlit rozdíl 34 % vs 61 % (viz přesazení č. 3).
9. **Oddíl 8:** věta "Kontrola druhým agentem (protokol §9) neproběhla ... Chybovost je tedy neznámá" je po této kontrole zastaralá; doplnit odkaz na `kontrola-RQ1.md` (věcná chybovost 0 %).

## 5. Přesazené závěry (jistota vyšší než důkaz)

Zkontroloval jsem Z3, Z4, Z5, Z8, Z10, Z11, Z14 (pět náhodných a dva navíc podle jistoty).

1. **Z5 (jistota střední) a oddíl 1 bod 4: "kumulace a rozmanitost prioritizují lépe než závažnost (AUROC 0,92 vs 0,72)".** Hodnota 0,92 patří optimalizované pipeline všech pěti modulů včetně Rule Level (váhy leave-one-out), ne dvojici akumulace + rozmanitost. Samotná Accumulation má průměr 0,72 až 0,73 (1 min) nebo 0,72 (1 h), tedy stejně jako pravidlo podle závažnosti (0,72); lepší je až Variety (0,85 až 0,87) a pipeline. Pipeline bez Rarity a Aperiodicity má 0,93, takže přínos nese kombinace Rule Level + Accumulation + Variety. Doporučení: formulovat "kombinace modulů Rule Level, Accumulation, Variety dosáhla 0,92; samotná Variety 0,85 až 0,87, samotná Accumulation 0,72 až 0,81". Hypotéza H1-2 ("0,85 až 0,92 vs 0,72") míchá jednotlivý modul a pipeline; rozdělit.
2. **Z8 (jistota nízká) a oddíl 4 "Rozpor 2":** tvrzení "grafové/sémantické seskupení překonává časové okno, při vysokém šumu je rozdíl téměř nulový". Zdroj ukazuje při více šumu opačný směr: v 3 ze 4 případů makro AUC je time-delta lepší než AlertBERT (až o 0,04). Správně: "AlertBERT vede jen při simultánních útocích; při zvýšeném šumu je prosté časové okno srovnatelné nebo lepší". Z8 je navíc podepřen třemi řádky, ale chybí řádky se dvěma konfiguracemi, které závěr zpochybňují. H1-7 zavádějící: "téměř stejné při vysokém šumu (043, 044)" neodpovídá purity bez dnsteal (0,9985 vs 0,9565 je jiný dataset-podmnožina, ne šum).
3. **Z10 (jistota nízká) a H1-8:** rozsah "34 % (offline) až 61 % (živě)" předpokládá dvě srovnatelné měření. Zdroj říká, že offline hodnota nezahrnuje 728 834 dříve auto-zavřených alertů a po jejich započtení je kolem 74 %. Rozsah proto nemá interpretovat jako nejistotu dopadu, ale jako různý jmenovatel. Očekávaný efekt v H1-8 ("34 % ... 61 %") přeformulovat.
4. **Z11 (jistota vysoká pro matematiku):** výrok "Základní četnost útoku vynucuje FPR řádu 1e-5" je správný jen při Axelssonově předpokladu základní četnosti 2e-5 (a 10^5 událostí/den). Do tvrzení doplnit "při základní četnosti 2e-5"; v oddíle 7 sám autor píše, že poměr nálezů k tokům je jiná jednotka, což je správně. Matematika je v pořádku, ale věta "vynucuje" bez podmínky je silnější než zdroj. Druhá část Z11 ("ML detektory mají 1e-2 až 1e-3") je převzatá citace jedné věty z přehledu (Erbacher cituje [22]); jistota "střední" je přiměřená, "vysoká" ne.
5. **Z14 (jistota střední):** "čísla se mimo původní prostředí přenášejí špatně" opírá o 011 (narativní přehled, preprint z 2026, tvrzení C1), 004 (nesrovnatelné definice FPR) a 019 (nestacionarita uvnitř jednoho IDS). Žádný z řádků nezkoumá přenos mezi prostředími měřením. Doporučuji jistotu snížit na nízkou, nebo formulovat jako "autoři přehledu uvádějí".
6. **Z3 (jistota střední):** "provozní studie, které FN měří, ukazují 0,01 až 1,5 %". Hodnota 0,01 % je podhodnocení rizikové úrovně u DeepCASE (47 predikcí z automaticky klasifikované části), ne míra falešně negativních útoků; AACT 1,36 % a 1,5 % je FNR určená vzorkováním. Míchání definic je přesně to, před čím varuje RQ1-004. Rozdělit rozsah na dva různé ukazatele.
7. **Z4 (jistota střední):** OK, odpovídá řádkům 021-025, včetně negativního případu Telnetu a omezení testbed/honeypot. Žádné přesazení. (Poznámka: 98 až 99 % v honeypotu jsou "neúspěšné útoky", ne FP, což studie správně říká v oddíle 3c.)
8. **Z1 a Z2:** OK (podepřeno řádky 012-014, 017-019, 031-032, resp. 019).

## 6. Celkový verdikt

**PŘIJATO S OPRAVAMI.**

Zdůvodnění: věcná chybovost v řádcích je 0 % (limit 5 %), u žádného řádku, o který se opírá závěr s vysokou jistotou, nebyla nalezena chyba, a všech 56 zdrojů je dohledatelných v plném textu. Důvod, proč ne prosté PŘIJATO: tři závěry (Z5, Z8, Z10) a jeden výrok (Z11, Z3) přesazují důkaz, přičemž u Z8 je směr opačný, než čísla v původním zdroji ukazují. Opravy jsou rozsahem malé (formulace závěrů a pár doplněných řádků), celá extrakce se znovu procházet nemusí.
