# Revizní log RQ3 (po nezávislé kontrole, `kontrola-RQ3.md`)

Datum revize: 2026-10-31. Zdroje jsem znovu stáhl (curl + `pdftotext -layout`, nový pracovní adresář) a každou opravenou hodnotu jsem sám znovu našel v textu. Tento soubor je audit trail: původní hodnoty jsou jen zde, v `studie.md` a `extrakce.csv` jsou hodnoty nové. Změněny byly jen `extrakce.csv`, `studie.md` a tento soubor.

## 1. Opravy extrakce a studie

| # | id / sekce | co bylo špatně (původní hodnota) | nová hodnota / formulace | ověření |
|---|---|---|---|---|
| 1 | 054 (`recenzovano`, `venue`) | „ano (nepotvrzeno)“; venue „ACM Comput. Surv.“ | „ne (preprint odeslaný do ACM Computing Surveys, květen 2026)“, venue = arXiv preprint | Titulní strana: „author's preprint of a manuscript submitted to ACM Computing Surveys (May 2026). The version of record will …“. Kontrola správná. Dopad: Z13 snížena. |
| 2 | 040 | „108 z 108“ jako počet případů | 0 % ztraceno z 108 po bias-korekci; původně 32 škodlivých alertů (2 218 falešných); horní hranice 95% CI zhruba 9–11 % (vlastní výpočet) | Carbon Filter Tab.4: TAU před korekcí 32 / 2 218, po korekci 108 / 71 156; Tab.5 text: „retaining a 100% of actual malicious alerts“. Správné. |
| 3 | 041 | 1 003 bez podmínky | 1 003 je po bias-korekci, původně 88 škodlivých (2 734 falešných) | Tab.4 (MDR 88 / 2 734 → 1 003 / 81 294). Správné. |
| 4 | 042 | varianta neuvedena | varianta clustering only; scoring model na ATLASv2 nelze použít; 50 škodlivých z 491; ztráta recallu clusteringu nepublikována | Sec. 4.1: „we cannot apply our scoring model to this dataset“; „491 alerts, among which 50 are … malicious“. Správné. |
| 5 | 043 | AUC 0,94 bez varianty | 0,94 platí pro „Carbon Filter (Clustering Only)“ | Popisek Obr.3: „Carbon Filter (Clustering Only) AUC = 0.94“. Správné. |
| 6 | 029 | 0,868 / 0,737 bez podmínky | hodnoty 12. (posledního) týdne, nejlepší, ne typický týden | Poznámka pod čarou 1: „This result corresponds to the 12th and last week of deployment“; Tab.2 řádek 12 obsahuje 0,868 a 0,737. Správné. Dopad: abstrakt bod 4, Z5, H-3. |
| 7 | 019 | „dva datasety“, rozsah 19–50 % | jen Class C (Tab.5.3, 10 konfigurací); Class B: FD rate TRW vůči stejnému kritériu < 1 %, nejvýše 24 % v exp. 8 | Alsaleh Sec.5.4.2: „the F D rate for TRW was less than 1% for all 10 TRW experiments … the highest FD rate for TRW is in experiment 8 (24%)“. Správné. |
| 8 | 021 | umístění Sec.5.3, „dva datasety“ | Sec.5.4.1, Class C | „In all the experiments, TRW classified less than 20% of remote hosts … leaving over 80% unclassified“ je v Sec.5.4.1. Správné. |
| 9 | 020 | 29 % a 77 % jako „dva datasety“ | 77 % přiřazeno Class C (STRW2); 29 % jen v souhrnu autora, v textu nepřiřazeno; STRW hlásí o 43 % méně skenerů; „bez ztráty detekce“ je tvrzení autora | Sec.5.4.1: „The average number of false positives in STRW2 decreased by 77% compared to TRW“; „the number of scanners decreased by an average 43% compared to TRW“; STRW1 FD 34 %. Hodnotu „29 %“ jsem v těle kapitoly nenašel, jen v abstraktu a Sec.5.5. Kontrola správná. |
| 10 | 022 | umístění Sec.5.4 | Sec.5.4.2 (Class B); 94 % je vůči TRWaGTFP | Sec.5.4.2, doslovně „on average 94% of TRW false positives in all experiments are eliminated“. Správné. |
| 11 | 039 | citace z abstraktu | citace z přehledu příspěvků v úvodu; abstrakt říká „requires as little of 24 % of the training data“ | Úvod: „using up to 76% less labelled data“; abstrakt řádek 17. Správné. |
| 12 | 006 | „1 SMTP klient“ | 29 crawlerů/proxy + 3 hosty s IDENT odpověďmi + 1 SMTP klient = 33 | Jung 2004 Sec.5.2: „3 of them sent out IDENT requests …“, „One host was an SMTP client“, „remaining 29 … Web crawlers and proxies“. Správné. |
| 13 | 014 | bez varování | varování: 0,07 a 0,57 FP/h nelze odvodit z Tab.3; zdroj to nevysvětluje | Jung 2008: Lab-II 137 hodinových tras, ISP 10,5 h (Tab.2); 3 FP / 137 h = 0,02; 3 FP / 10,5 h = 0,29. Textová hodnota 0,07 / 0,57 doslovně souhlasí. Správné. |
| 14 | 010 (kontrola navrhla Tab.5 místo Tab.4) | – | **Neprovedeno, kontrolor se mýlí.** Umístění zůstává Tab.4. | V převodu `pdftotext` stojí popisek tabulky nad jejím tělem: Tab.2 „Alarms reported by reverse sequential …“ předchází tělu „isp-03 isp-04 / Worms/Scanners detected“; popisek „Table 5. Comparison of rate limiting …“ předchází tělu „Unnecessary rate limiting 0 0 84 59“. Tělo „H--T 34 11 0.324 0.917“ stojí těsně za popiskem „Table 4. Composite results for both traces. A total of 7 HTTP scanning worms and 5 email worms were present“ a text říká „our composite results summarized in Table 4“. Doslovně pdftotext bez -layout: „Table 4. Composite results for both traces …“ bezprostředně před „Alarms Detection Efficiency Effectiveness / H--T / 34 / 11 / 0.324“. Hodnoty 34/11/0,324/0,917 jsou tedy z Tab.4, pouze poznamenáno v poznámce. |

Dopočtené (mimo kontrolní zprávu): horní hranice 95% CI pro 0 z 32 (kolem 9–11 %) je vlastní výpočet (pravidlo tří 3/32 ≈ 9,4 %, Clopper-Pearson 10,9 %).

## 2. Změny jistoty závěrů

| Z-id | stará | nová | důvod |
|---|---|---|---|
| Z1 | střední | nízká až střední (směr vůči Bro střední; rozsah a výhoda vůči Snortu nízká) | Jung 2008 má TRW 10,0 až 18,5 prvních spojení, mimo „4–10“; smíšené jednotky; u ICSI TRW jen 1,5× rychlejší než Snort (4,06 vs 6,00); u LBL 3,4×. Nový rozsah: TRW 4–18,5, RBS+TRW 5,0–6,9. |
| Z2 | střední | nízká až střední | 19–50 % jen z Class C; v Class B < 1 % / max. 24 %; „bez ztráty detekce“ je tvrzení autora (STRW hlásí o 43 % méně skenerů); 29 % nepřiřazeno; formulace „29 až 94 %“ nahrazena 77 % (Class C) / 94 % (Class B, podmnožina). |
| Z4 | nízká | nízká (přeformulováno) | α platí jen pro BotSniffer; 014 nemá srovnatelné α a nesedí s Tab.3; přidán protipříklad Alsaleh (018, 019). |
| Z5 | střední | střední (formulace upřesněna) | 0,868 vs 0,737 jsou hodnoty 12. týdne, ne průměr. Jistotu jsem nesnížil: směr (aktivní učení šetří štítky) dále nesou Chen a ActDroid; o číselné hodnotě AI² mluví nová poznámka. |
| Z7 | střední (směr), nízká (velikost) | nízká až střední (směr), nízká (velikost) | −65 % je clustering-only na jednom datasetu (ATLASv2, 491 alertů), recall 0–5,7 % je scoring model (0 % z 32 případů); spojení zakázáno a formulace „dva datasety“ odstraněna. |
| Z8 | nízká | nízká (důkaz 048 odebrán) | 048 je jen V2 (abstrakt stránky NDSS); zůstává kontextem, ne důkazem. |
| Z12 | nízká | nízká (důkaz jen 056) | 057 (Hammar a Stadler) o entropii belief a MSE nic neříká. |
| Z13 | střední | nízká až střední | přehled je nerecenzovaný preprint odeslaný do časopisu (oprava 054). |
| Z3, Z6, Z9, Z10, Z11 | beze změny | beze změny | Z9 kontrola potvrdila; ostatních se kontrola netýkala. |

Dále upraveno (odvozeně z chybných závěrů): abstrakt body 1, 2, 4, 5, 6, 8 a 3 (Class C u 80 %); tabulky §3 (a, c, d, e) a syntéza §4 (rozsahy pozorování, ztráta recallu, rozpor 3 u Alsaleha); §6 Překlad do praxe, body 1, 2 (Z12), 5 a 7 (rozsah „84 až 97 %“ nahrazen „82,5 až 99,64 %“ podle řádků 040, 041, 049; původní „97 %“ jsem v extrakci nenašel); hypotézy H-1 (cíl ≤ 7 ověření byl odvozen z „4–10“, nyní označen jako pracovní odhad), H-2 (původně „29 až 77 %“), H-3, H-4 (původně „−50 až −65 %“); §8 Hrozby validity; PRISMA/Metodika (odstavec o nezávislé kontrole).

## 3. Znovuověření 9 řádků, které kontrola neověřila

| id | zdroj | výsledek |
|---|---|---|
| 028 | Ganesh et al. | Potvrzeno, abstrakt: „worms could evade detection by being less aggressive“. V3. |
| 032 | Jasmine | Potvrzeno: „F1 = 0.760 for Figure 4a“ a „(F1 = 0.720)“. V3. |
| 033 | Jasmine | Potvrzeno: „Only querying anomalies was clearly a bad strategy for these two datasets“ (umístění v převodu mimo číslování, Sec. 7.1 nepotvrzeno čísly sekce). V3. |
| 047 | DeepCASE imbalance | Potvrzeno: „about 30% of the vectors have a cosine similarity of 0.25 or lower for the unfiltered dataset“. V3. |
| 048 | NoDoze | Znovu čten jen oficiální stránka NDSS: „decreases the volume of false alarms by 86%, saving more than 90 hours“. PDF nepřečteno, zůstává V2. Odstraněno z Z8; v syntéze označeno „V2 jen abstrakt“. |
| 050 | Tong et al. | Potvrzeno: „the proposed approach is 50% better than the Uniform policy, which in turn is significantly better than using Suricata priorities“. V3. |
| 051 | Yan et al. | Potvrzeno: „when the audit order is fixed (or is predictable), adversaries have greater evasion ability“. V3. |
| 055 | Gao et al. | Potvrzeno abstrakt: 15,1 % a 33,6 %. V3. |
| 057 | Hammar a Stadler | Potvrzeno abstrakt („threshold properties“) a existence srovnání se Snort IPS; čísla jen v grafech. V3 pro kvalitativní tvrzení, ale nepodporuje Z12. |

Do `neovereno.md` jsem nepřesouval žádný řádek: všech 9 se podařilo znovu otevřít (048 jen na úrovni V2). `neovereno.md` jsem neměnil.

## 4. Metodika

V sekci Metodika a PRISMA studie je odstavec o proběhlé kontrole (datum 2026-10-31, 48 z 57 řádků = 84 %, věcná chybovost 2,1 % = 1/48, drobné chyby 12, neověřitelné 0, verdikt PŘIJATO S OPRAVAMI, co se změnilo). Původní hodnoty chyb jsou jen v tomto souboru.

## 5. Nevyřešeno

- 29 % (Alsaleh): zdroj ho neuvádí v těle kapitoly, jen v souhrnech; nelze ho přiřadit k datasetu a rozpor 29 % vs 94 % u Class B zůstává nevysvětlený.
- 014: nesoulad 0,07/0,57 FP/h vs Tab.3 zdroj nevysvětluje.
- 048 (NoDoze) zůstává V2; PDF nečteno, 84 % vs 86 % nevysvětleno.
- Pole `limity_autoru`, `riziko_zkresleni` a venue NoDoze, Kim a Dán, Sudyana kontrola ověřila jen okrajově; revize je znovu neověřovala.
- Systematický průchod referencí klíčových prací dosud neproběhl.
- Nesouhlas s kontrolou: oprava č. 14 (010, Tab.5) neprovedena, viz výše.
