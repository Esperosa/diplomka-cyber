# Revize RQ1 po nezávislé kontrole (audit trail)

Datum: 2026-10-31. Vstup: `kontrola-RQ1.md` (verdikt PŘIJATO S OPRAVAMI, věcná chybovost 0/56, 5 drobných chyb, 4 přesazené závěry). Revidované soubory: `extrakce.csv` (56 -> 58 řádků), `studie.md`. `neovereno.md` beze změny (viz bod D). Původní hodnoty chyb jsou uvedeny tady, v hlavním textu ne.

## Postup ověření

Zdroje jsem znovu stáhl do dočasného adresáře a převedl `pdftotext` (u RBA i s `-raw`, který zachová sloupce tabulky 4): AlertBERT (arXiv 2602.06534), AACT (2505.09843), RBA (2609.02465), graf-kontextualizace (2509.12923), Alahmadi (USENIX), Julisch (disertace Dortmund). Každou opravu jsem ověřil z textu, nepřebral jsem ji z kontroly. Kde se kontrolor mýlil nebo nepřesně citoval, je to uvedeno.

## A. Opravy řádků extrakce

| id | Co bylo špatně (původně) | Nová hodnota | Ověření |
|---|---|---|---|
| RQ1-006 | umístění „Findings (pasáž o počtu poplachů)“ | „Sec. 6 (RQ2: Definition of FPs)“ | Alahmadi, nadpis „6 RQ2: Definition of FPs“, hned pod ním „B3 quantified it as 99%, stating: ‚We know 99% of the alarms we generate are false positives...‘“. Kontrolor měl pravdu. |
| RQ1-017 | limity: „autor: dolní odhad, nezávislá validace chybí“ | „70 % je podle autora podhodnocení dosažitelného snížení (kap. 6)“ | Julisch, kap. 6: „we believe that it actually underestimates the attainable alarm load reduction“. Tvrzení „nezávislá validace chybí“ jsem v textu nenašel, proto jsem ho odstranil (bylo mezi nezkontrolovanými detaily). |
| RQ1-020 | limit: „v praxi by se filtrovaly TP jen u necílených zranitelných systémů“ | „filtrovat TP lze zvolit, pokud cíle nejsou zranitelné; kvantifikovat bezpečnost filtrace autor považuje za neřešitelné (kap. 6.4)“, doplněna citace kap. 6.4 | Julisch: „one might choose to filter out true positives if their targets are not vulnerable [136]“ a v kap. 6.4: „there probably is no simple solution to the problem of quantifying safety“. Kontrolor měl pravdu včetně čísla kapitoly (6.4 On the Risks of Filtering). |
| RQ1-043 | poznámka: „při vysokém šumu je jednoduché časové okno téměř stejně dobré“ (výběr jen more-noise-11) | poznámka upozorňuje na výběr konfigurace a odkazuje na 057, 058, autoři výsledky hodnotí jako smíšené | AlertBERT Sec. 4.4.2: „time-delta scores better than AlertBERT in the other 3 cases and does so with somewhat larger leads of up to 0.04“, „we view these mixed results...“. **Nuance, kterou kontrola neuvedla:** autoři konfiguraci more-noise-11 vybírají sami jako smysluplnější, protože v -2 a -6 je málo šumu („limited amount of noise“). Hodnoty 0,979 vs 0,972 a 0,933 vs 0,916 jsou správné (Tab. 6). |
| RQ1-057 (nový) | chyběl | more-noise-2: včetně šumu time-delta 0,97274 vs AlertBERT 0,93600, bez šumu 0,92625 vs 0,91958 | Tab. 5 přečtena z `pdftotext -layout`. |
| RQ1-058 (nový) | chyběl | more-noise-6: včetně šumu time-delta 0,95749 vs AlertBERT 0,93645, bez šumu AlertBERT 0,91623 vs time-delta 0,91612 (shoda) | Tab. 5. Poznámka: v případě „bez šumu“ vede AlertBERT o 0,0001, to je ta jedna ze čtyř konfigurací, kde AlertBERT těsně vede (souhlasí s „1 of the 4 cases“ v textu). |
| RQ1-044 | „bez dnsteal“ uváděla jen silhouette 0,44622 vs 0,06470 | doplněna purity 0,99850 vs 0,95653; doplněn odkaz na Tab. 3 | graf-kontextualizace, Tab. 3, sloupec „Excluding dnsteal“. Kontrolor měl pravdu. |
| RQ1-049 | poznámka „rozdíl 34 % vs 61 % jsem nevysvětlil“ | rozdíl vysvětlen: offline 34 % je bez 728 834 dříve auto-uzavřených alertů, s nimi „closer to 74 %“; živě 61 % | AACT Sec. V: „if you include the 728,834 alerts removed from the analysis due to them being closed by AACT, the reduction rate is closer to 74%“ (v PDF „728, 834“). Kontrolor měl pravdu. Doplněna i druhá citace do pole umístění. |
| RQ1-037 | hodnota „kombinace 0,92“ bez upřesnění, co kombinace je | upřesněno: vážený součet všech pěti modulů (leave-one-out), nejlepší samostatný modul 0,87 (SD 0,17) | RBA Intro: „weighted combination of the five risk modules ... AUROC 0.92 ... best single risk module (0.87, 0.17)“. |
| RQ1-038 | „Rarity a Aperiodicity 0,31-0,57“, tabulka „nečitelná, hodnoty odvozeny“ | doplněny hodnoty všech modulů a oken z Tab. 4: Rule Level 0,72; Accumulation 0,81 / 0,72 / 0,75 (1 min / 1 h / 1 den); Variety 0,73 / 0,87 / 0,85; Rarity 0,31 / 0,45 / 0,48; Aperiodicity 0,47 / 0,55 / 0,57; pipeline bez Rarity a Aperiodicity 0,93 (váhy 12,5 / 35 / 52,5 %) | `pdftotext -raw` dal čistou tabulku 4. **Rozdíl proti kontrole:** kontrolor píše, že samotná Accumulation má „0,72 až 0,73 (1 min) nebo 0,72 (1 h)“ a Variety „0,85 až 0,87“. Podle mé čtení je Accumulation 1 min 0,81, 1 h 0,72, 1 den 0,75 a Variety 1 min 0,73, 1 h 0,87, 1 den 0,85. Závěr kontrolora (samotná Accumulation je na úrovni závažnosti, lepší je Variety a kombinace) platí, jen čísla nesedí přesně. Pozn. kontrolora „pipeline bez Rarity a Aperiodicity 0,93“ je správně (Příloha D: „0.93 instead of 0.92“). |
| RQ1-040 | „-17 % průměrný AUROC“ bez absolutní hodnoty | doplněno: Tab. 4c trailing okno 0,75 vs reference 0,92, rozdíl 0,17 (vlastní výpočet) | RBA Sec. 7.2: „trailing window results in a 17% drop“; Tab. 4 (c) „Trailing Window“ 0,75 (SD 0,21). Důsledek: online kombinace je na úrovni pravidla dle závažnosti (0,72). |
| RQ1-046 | bez upozornění na druh ukazatele | doplněno: podhodnocení rizika není míra falešně negativních, nelze sčítat s FNR | kontrola, Z3; definice podle DeepCASE (podhodnocení rizikové úrovně) a AACT (FNR vzorkováním). |
| RQ1-033, RQ1-045 | tvrzení „labely od analytika“ a „po 1 měsíci ručního režimu“ bez nezávislé kontroly | v poznámce označeno „nebylo nezávisle potvrzeno“ | Zdroj jsem znovu neotevíral (AI2, DeepCASE). Neověřeno, jen přiznáno. |

## B. Opravy studie.md a změny jistoty

| Místo | Co bylo špatně | Nově |
|---|---|---|
| Hlavička | 56 řádků, 46 číselných | 58 řádků, 48 číselných, odkazy na kontrolu a revizi |
| Abstrakt, bod 4 | „akumulace a rozmanitost prioritizují lépe než závažnost, AUROC 0,92 vs 0,72“ | rozděleno: kombinace 5 modulů 0,92, kombinace Rule Level + Accumulation + Variety 0,93, samotná Accumulation 0,72 až 0,81, samotná Variety 0,73 až 0,87, online 0,75, jediný preprint bez replikace |
| Abstrakt, bod 6 | „ML práce mívají FPR 1e-2 až 1e-3“ jako vlastní zjištění | přiznáno, že jde o Erbacherovu citaci práce [22] |
| Metodika / PRISMA | chyběl popis kontroly | doplněn odstavec Nezávislá kontrola (datum, vzorek, chybovost, verdikt, co se změnilo) |
| Tabulky (a), (b), pomocné | stará čísla 042-044, 037, 038, 040, 045-049 | opraveno podle řádků extrakce |
| Syntéza, Rozpor 2 | „při vysokém šumu rozdíl téměř nulový“ | AlertBERT vede jen při simultánních útocích, při zvýšeném šumu je okno srovnatelné nebo lepší (až o 0,04), v nejhlučnější konfiguraci těsně vede AlertBERT |
| Překlad do praxe 2, 3, 7, 9 | váhy „nevyčtené“, „~17 %“, základní linie bez 057-058, „34 až 61 %“ | váhy 12,5 / 35 / 52,5 %, 17 p. b. (0,75 místo 0,92), doplněny 057-058, AACT s rozlišením jmenovatelů |
| Hypotézy | H1-2, H1-7, H1-8 vycházely z chybných závěrů | H1-2 rozděleno na H1-2a (kombinace, trailing 0,75 vs 0,72), H1-2b (Variety 0,87), H1-2c (Accumulation jako negativní kontrola). H1-7: smíšené výsledky, purity bez dnsteal. H1-8: 61 % živě, 34 % vs 74 % jako různé jmenovatele |
| Hrozby validity | „kontrola neproběhla“ | proběhla, odkaz na kontrolu a revizi, seznam nezkontrolovaných detailů |

Změny jistoty závěrů:

| Z-id | Stará | Nová | Důvod |
|---|---|---|---|
| Z3 | střední | střední (zúžen na kvalitativní tvrzení, řádky 020, 056) | číselná část přesunuta do Z3b |
| Z3b (nový) | - | nízká | dva různé ukazatele (FNR 1,36 až 1,5 % vs. podhodnocení <0,01 %), nesčítat |
| Z5 | střední | nízká | 0,92 je kombinace všech modulů, samotná Accumulation ≈ závažnost, jediný preprint, online 0,75 |
| Z8 | nízká | velmi nízká | směr zdroje je při zvýšeném šumu opačný, výsledky smíšené |
| Z10 | nízká | nízká (přeformulováno) | 34 % vs 61 % jsou různé jmenovatele, 74 % se započtením |
| Z11 | vysoká (mat.) / střední | vysoká (mat., podmíněně 2e-5) / střední | doplněna podmínka, ML 1e-2 až 1e-3 je citace [22], ne vlastní měření |
| Z14 | střední | nízká | tvrzení přeformulováno na „autoři přehledu uvádějí“, žádný řádek nemeří přenos |
| Z1, Z2, Z4, Z6, Z7, Z9, Z12, Z13 | beze změny | beze změny | kontrola bez nálezu (Z4, Z1, Z2) nebo mimo kontrolovaný vzorek (ostatní) |

## C. Souhrnné rozsahy a mediány

Studie nepoužívala mediány ani sdružené odhady (protokol §8, nesrovnatelné metriky). Přepočítávat se musel jen rozsah v Z3 (rozdělen na dva ukazatele, bez společného rozsahu) a v Z10 / H1-8 (34 % vs 61 %, nyní různé jmenovatele, ne rozsah). Rozsah redukce v oddíle 3(a) („od ~0 % do 97,6 %“) se řádků 057, 058 netýká.

## D. Neověřitelné řádky a V2

Kontrola: neověřitelných 0, všechny řádky V3. Z `extrakce.csv` do `neovereno.md` proto nepřesouvám nic. Řádky s vysokou jistotou závěru a jen abstraktem (V2) neexistují. Závěry vysoké jistoty (jen Z11, matematická část) stojí na V3 řádcích 001 až 005.

## E. Co zůstává nevyřešené

- Detaily, které neověřila kontrola ani revize: „po 1 měsíci ručního režimu“ (045), „labely od analytika“ (033), číslování sekcí Tedesco (056), venue Kruegel (021-023).
- Citační řetězení (protokol §3) zůstává volné, odchylka od protokolu trvá.
- Kontrola vzorkovala řádky, ne závěry Z6, Z7, Z9, Z12, Z13. Tyto závěry nebyly zpochybněny, ale ani nezávisle prověřeny.
- Hodnoty Tab. 4 RBA jsem četl z `pdftotext -raw`; hodnoty pro Accumulation a Variety se liší od údajů v kontrole (viz řádek RQ1-038) a rozpor nemám čím rozsoudit mimo další kontrolu PDF člověkem.
- Řádek 011 (narativní přehled z 2026): tvrzení „horní odhady“ je výrok autorů přehledu, ne měření.
