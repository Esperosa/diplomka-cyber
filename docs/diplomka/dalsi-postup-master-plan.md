# Další postup — syntéza 3-agentního plánovacího kola (29. 10. 2026)

**Metodika:** podle `CLAUDE.md` — 3 nezávislí agenti (Opus comprehensive, pragmatik, skeptik), každý četl aktuální stav repa přímo, ne přes zprostředkované shrnutí. Debata/korekce proběhla implicitně: pragmatik a skeptik nezávisle na sobě dospěli ke stejnému závěru (scope down, ne scope up), což je silnější signál než jediný průchod. Opusův plán slouží jako strop toho, co by šlo udělat s neomezenými zdroji — pragmatik a skeptik proti němu oprávněně argumentovali citací vlastní priority diplomky v návrhovém dokumentu (sekce 7.2, 10, 13: wave 2+ datasety a P2/P3 infrastruktura jsou explicitně NE-nutné pro samotnou diplomku).

Toto kolo navíc přímo vedlo k 6 opraveným chybám (N7-N10, viz `souhrn-vysledku-a-hypotez.md` a commity `a0ba36d`) — Botnet-54 Virut/RBot, H1 pasivní/aktivní terminologie, IoT-23 stejná třída chyby jako N1, chybějící regresní asserty na CTU-13 čísla. To samo potvrzuje, že multi-agentní audit proces skutečně nachází reálné chyby, ne jen generuje teoretická doporučení (otázka, kterou si skeptik sám položil a kladně zodpověděl).

## Rozhodnutí (autonomní, v rámci už schváleného zadání — ne odklon)

1. **H5 (distribuované škálování) a H2 v doslovném znění (multi-senzorová fúze s korekcí závislosti zdrojů) se explicitně škálují MIMO rozsah empirické validace diplomky**, stejně jako firewall/DNS/IPS/multi-tenant/HA-DR už jsou mimo rozsah dle návrhu samotného (sekce 11). Důvod u H5: žádná distribuovaná infrastruktura neexistuje, postavit a změřit ji legitimně (byť jen single-machine sharding) je investice řádu týdnů, nesouměřitelná s touto jedinou hypotézou z pěti. Důvod u H2: skutečná multi-senzorová fúze (Community ID dedup Zeek↔Suricata) je nová netriviální funkce, ne měření nad existujícím kódem — pragmatik i skeptik nezávisle doporučili tohle NEstavět, jen честně zdokumentovat proč H2 v doslovném znění nelze změřit na single-sensor datasetech. Broker crash-recovery (Deliverable 6) zůstává citovatelná částečná precedence pro H5 (nutná, ne dostačující podmínka), ne tvrzení, že H5 je ověřeno.
2. **Rozšiřování datasetů (dalších 12 CTU-13 scénářů, CICIDS2017/2018, UNSW-NB15) se odkládá.** CTU-13 nález (heuristika prohrává s triviálním baseline na obou datasetech) je už nejsilnější a nejdůležitější empirický výsledek projektu — třetí/čtvrtý dataset by s velkou pravděpodobností jen potvrdil stejný závěr jinými čísly (klesající návratnost), ne přinesl nový vhled. Návrh sám (sekce 7.2, 13) tohle řadí do vlny 2+, ne do povinného rozsahu.
3. **Statistický aparát (bootstrap CI, signifikance testy mezi běhy) se odkládá, dokud nebude mít smysl.** Při N=1 scénář/cíl nejde počítat confidence interval, který by nebyl falešně přesný. Místo toho: tam, kde je to levné (CTU-13 test, viz N10 výše), se čísla aspoň pinují regresními asserty — to už je hotovo.
4. **Kalibrace/Case Memory pro H4 se nestaví.** `hypothesis.rs` už dokumentuje `probability` jako vědomě odloženou. H4 se reportuje honestně s už změřeným cross-dataset baseline jako laťkou, kterou by budoucí kalibrace musela překonat — to je už hotovo v opraveném `souhrn-vysledku-a-hypotez.md`.
5. **Jediný nejvyšší-leverage next deliverable (Deliverable 15), na kterém se shodli pragmatik i skeptik nezávisle**: jeden nový nebo překonfigurovaný lab cíl s 2-3 odlišitelnými nálezy různé jistoty, znovu využívající existující Docker/nmap/httpx/nuclei harness z Deliverable 7. Tohle současně:
   - zvedá H1 z N=1 na N=2 lab cílů (silnější, ne jen anekdotický nález),
   - odblokovává H3 měření — přesně ten gap, který `h3-measurement-difficulty.md` identifikoval (eval harness nemá zároveň aktivní inventář a víc nálezů s různou jistotou).
   - nevyžaduje žádnou novou infrastrukturu — jen novou/upravenou Docker compose konfiguraci a test.

## Definition of Done pro empirickou část diplomky (nahrazuje vágní "dokonalý")

- [x] Baseline (ablace A) změřen na IoT-23, s triviálním baseline vedle něj.
- [x] Cross-dataset měření (CTU-13) s opraveným tříhodnotým labelem, triviálním baseline, regresními asserty na klíčová čísla.
- [x] H1 změřeno na jednom lab cíli (poctivě přeznačeno jako "lehký vs. hlubší aktivní", ne "pasivní vs. aktivní").
- [x] H3 strukturální blok zdokumentován s konkrétním, splnitelným požadavkem na odblokování.
- [x] H4 baseline pro budoucí kalibraci změřen a honestně reportován.
- [ ] H1 změřeno na ≥2 nezávislých lab cílech (Deliverable 15, next).
- [ ] H3 skutečně změřeno na lab cíli s ≥2-3 nálezy různé jistoty (Deliverable 15, next).
- [ ] H2 a H5 mají explicitní, zdůvodněný "mimo rozsah" zápis v `souhrn-vysledku-a-hypotez.md` (ne jen "netestováno"/"neověřeno" bez vysvětlení proč se to nebude stavět).
- [ ] Všechny citlivé numerické tvrzení v `docs/diplomka/eval/*.md` mají odpovídající regresní assert v kódu (zatím jen CTU-13 cross-dataset; IoT-23 ablace A/B/C/D baseline čísla ještě ne).

Done = každý bod zaškrtnutý a ověřitelný čtením repa, ne subjektivní pocit "je to dost dobré".

## Priorita dalších kroků

1. **Deliverable 15** (začíná hned, ve stejném tahu): nový/upravený lab cíl s 2-3 nálezy různé jistoty → reálné měření H3 (VOI vs. blanket) + H1 na druhém cíli.
2. Po D15: zapsat H2/H5 "mimo rozsah" zápis s odůvodněním do `souhrn-vysledku-a-hypotez.md`.
3. Po tom: doplnit regresní asserty na IoT-23 baseline čísla (malý, levný krok, dokončuje Definition-of-Done bod).
4. Teprve pak, pokud čas/rozsah dovolí: zvážit threat-model dokument (sekce 11 ho jmenuje jako očekávaný výstup) jako konsolidaci už existujícího rozptýleného obsahu (design doc sekce 4/9.3/12 + `h3-measurement-difficulty.md`), ne nový výzkum.
