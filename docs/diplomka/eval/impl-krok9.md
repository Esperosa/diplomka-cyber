# Implementace, krok 9: rozšíření pokrytí, provozní incidenty a hloubka ověřování

Datum 2026-11-13. Výchozí stav: krok 8 (`eb27baf`), `recommended()` = sestava kroku 7, `endpoint` mimo preset, výchozí režim `legacy`. Rešerše: `studie/09-open-source-pouceni.md`.

Výchozí čísla (dlouhý běh kroku 7, 7 988 sítí): exploit_attempt 74,6 % (správný typ 42,5 %), c2_beacon 85,5 % (70,4 %), ics_attack 87,2 % (55,6 %), ddos_volume 90,4 %, port_scan_vertical 89,7 %, fleet_beacon 93,5 % (74,3 %). Ostatních 12 rodin má 90 až 98 %.

Poctivost: 100 % se neslibuje. Každé slepé místo je buď (a) uzavřeno měřeným účinkem, (b) zadrženo kódem vynuceným opatřením, nebo (c) uvedeno jako otevřené. Rodina s n < 50 útoků je označena „nedostatek dat“, ne „splněno“.

## A) Rozsah

1. **Rodiny a varianty (generátor).** Nový svět `--coverage k9` (= `k7` + parametrické varianty podle ATT&CK) přidává 72 bezpečnostních variant (`Family::Var`) a 28 provozních poruch a incidentů (`Lookalike::Var`). Varianty jsou data (tabulka vzorů chování: protokol, port, tempo, jitter, objem, topologie, rozprostření zdrojů a času, maskování), ne kód na míru. Emise je jediný obecný generátor syntetických záznamů toků a IDS řádků. Neobsahuje žádný exploit, payload ani nástroj. Ground truth, ID techniky ATT&CK a očekávané typy nálezů jsou součástí tabulky. Bez `--coverage k9` je výstup bajtově beze změny.
2. **Provozní incidenty jako rovnocenná kategorie.** Každá položka pravdy má kategorii: `security`, `ops_fault`, `benign_change`. Provozní řetězce příčina → následek (kaskáda, částečný výpadek, flapping, pomalá degradace, sezónní špička, plánovaná údržba vs. neplánovaný výpadek, falešný výpadek způsobený senzorem) mají společné `incident_id` v pravdě, aby šlo měřit seskupení.
3. **Detekce a ověřování.** Obecné detektory a kontext, ladění jen na ladicích seedech. Žebřík a plánovač nabízejí další nezávislé kontroly při nejistotě (viz C). Vyhodnotí se podíl „potvrzeno / vyvráceno / nerozhodnuto“ a jeho přesnost.
4. **Koncová telemetrie.** Rozhodnutí o zapnutí `endpoint` v `recommended()` se činí jen z měření (práh K9-E).

## B) Předregistrace prahů (zamčeno commitem před prvním měřicím během)

Sekce B se po prvním měřicím běhu nemění. Oprava chyby harnessu se zapíše jako odchylka do sekce D, práh se nemění.

### B1. Seedy a ramena

| účel | seedy | svět | sítí |
|---|---|---|---:|
| ladění | 20261102, 20261103, 20261104, 20262201, 20262202, 20262301, 20262302 | `--coverage k9 --families all` | po 40 (kde to dovolí čas, jinak méně a uvede se skutečný počet) |
| držené, pustit jednou na konci | 20261901, 20262001, 20262101, 20262102, 20261201, 20261301 | totéž | po 40 |

Nepoužije se seed 20261110 (dlouhý běh kroku 8 běží). Ramena: `k8ref` (`recommended()` + `endpoint`, srovnání s krokem 8 na světě `k9`), `k9` (kandidát po úpravách detekce a ověřování). Společné volby: `--no-legs --no-feedback --counterfactual --block-size 2`, nejvýš 4 vlákna, priorita Idle, jedno rameno najednou. Rozhoduje se párově po sítích, bootstrap po sítích (B = 2000), intervaly Wilsonovy.

### B2. Prahy bezpečnostních rodin (každá rodina, každá varianta s n ≥ 50)

| práh | definice | splněno, když |
|---|---|---|
| K9-1 | detekce rodiny | ≥ 90 % a dolní mez Wilsonova 95% intervalu ≥ 85 % (cíl 95 %) |
| K9-2 | správný typ nálezu | ≥ 85 % a dolní mez ≥ 80 % (u rodin s typovanými nálezy) |
| K9-3 | zobrazené FP na síť-den a všechny zobrazené položky | ≤ 1,15 × krok 8 na stejném světě |
| K9-4 | zavřeno omylem | ≤ 2,2 % |
| K9-5 | chráněná automatická zavření | 0 |
| K9-6 | determinismus a kompatibilita | stejný seed dvakrát bit po bitu; legacy a stávající v3 bez nových přepínačů bajtově beze změny; golden snapshot zelený |
| K9-7 | paniky a porušené invarianty | 0 |
| K9-8 | velikost vzorku | n ≥ 50 útoků na rodinu, jinak „nedostatek dat“ (nepočítá se jako splněno ani jako nesplněno) |

### B3. Prahy provozních incidentů (zvlášť, každá rodina poruch s n ≥ 50)

| práh | definice | splněno, když |
|---|---|---|
| O1 | detekce poruchy (nález připsaný incidentu v okně +2 cykly) | ≥ 90 %, dolní mez ≥ 85 % |
| O2 | správná klasifikace (bezpečnostní / provozní / neškodná změna / nerozhodnuto), správná = shoda s kategorií pravdy, `nerozhodnuto` se počítá zvlášť a nepočítá se jako správné | ≥ 85 % |
| O3 | seskupení: počet incidentů na pravdivý incident (cíl 1) a čistota (podíl nálezů incidentu, které patří jeho pravdě) | poměr nálezů k incidentům aspoň 3:1 u poruch s ≥ 3 nálezy a čistota ≥ 90 % |
| O4 | čas do prvního nálezu | medián ≤ 2 cykly od začátku, 90. percentil ≤ 6 cyklů |
| O5 | FP provozních incidentů (zobrazený incident bez pravdy) | ≤ 1,15 × krok 8 |
| O6 | prázdná telemetrie nikdy neznamená „v pořádku“ | výpadek senzoru nikdy nezavře ani nevyvrátí nález (invariantní test) |
| O7 | záměna | poruchy označené jako bezpečnostní ≤ 15 %, bezpečnostní označené jako porucha a zavřené ≤ 2,2 % |

Klasifikace a seskupení do incidentu je v době předregistrace v jádře jen částečně (třída provoz, kontext). Pokud se nepodaří implementovat, práh O2, O3 a O7 se uvede jako nesplněný (kategorie c) a změna prahu se nepovolí.

### B4. Ověřování a kalibrace

| práh | definice | splněno, když |
|---|---|---|
| V1 | při nejistotě se nález neuzavírá: podíl nálezů se stavem `nerozhodnuto`, který skončil zavřený bez důkazu | 0 |
| V2 | zavřeno omylem (útok s omylem zavřeným nálezem) | ≤ 2,2 % a ≤ krok 8 + 1 % |
| V3 | kalibrace: pravděpodobnost „potvrzeno“ vs. skutečnost, chyba kalibrace (ECE) | ≤ 0,10 (jen pokud je ≥ 200 uzavřených případů, jinak „nedostatek dat“) |
| V4 | přesnost „potvrzeno“ a „vyvráceno“ (podíl správných) | uvede se s intervalem, bez cílové hodnoty |
| V5 | rozpočet: žádná další kontrola nad rámec rozpočtu cyklu | 0 překročení |

### B5. Koncová telemetrie

`endpoint` se zapne v `recommended()` jen když na světě `k9` platí: detekce `on100` − `off` ≥ +3 p. b., FP poměr ≤ 1,10, omylem zavřeno `comp-ok` ≤ `off` + 1 % útoků, 0 chráněných zavření. Jinak zůstává mimo preset. Měření je simulované (generátor vychází z těch samých rodin), proto rozhodnutí je „připraveno na držený běh“, ne „zapnuto jako výchozí“.

## C) Návrh

### C1. Generátor (`src/soak/variants.rs`)

- `VariantSpec`: id, popis, ATT&CK ID (jen číslo a název techniky), kategorie, vzor (`Pattern`), směr, protokol, port nebo sada portů, základní tempo na cyklus, jitter, objem, doba trvání v cyklech, počet zdrojů, maskování do legitimního provozu, příznak IDS.
- Vzory: `Periodic` (maják s jitterem), `Burst`, `Sweep` (horizontální), `PortSweep` (vertikální), `Flood`, `Sustained` (dlouhé spojení), `FanOut`, `FailedAuth` (série neúspěšných přihlášení), `BulkOut` (objem ven), `Trickle` (nízkoobjemový únik).
- Provozní vzory: `Outage`, `Flap`, `Degrade`, `Storm`, `Saturate`, `TimeDrift`, `PlannedWindow`, `SensorFalse`, `Cascade`.
- Vlastní proud náhody a vlastní větev plánu, takže ostatní světy zůstanou bajtově stejné.

### C2. Realističtější provoz

Denní a týdenní vzory a svátky už jsou. Doplní se dlouhý ocas služeb, zálohy v noci, aktualizace, CDN churn a sezónnost jako parametry světa `k9`, kalibrované na veřejných datech (CIC-IDS2017, CTU-13, IoT-23, UNSW-NB15). Licence a podmínky se zapíší do `dataset-registry.md`. Labely datasetů se nemíchají do jednoho schématu. Kde simulace realistická není, uvede se v sekci E.

### C3. Detekce a ověřování

Obecné detektory a kontext (ne pravidla na míru). Ověřovací žebřík a plánovač: pivot na DNS/TLS/JA3/časování, GeoIP/ASN, srovnání s baseline hostu a peerů, koncová telemetrie, historie případu, opakované měření v čase, aktivní čtecí ověření v povoleném rozsahu. Případ se neuzavírá ani nezahazuje, dokud není překročen práh jistoty nebo vyčerpán rozpočet.

## D) Průběh a odchylky

(vyplní se po měření)

## E) Registr slepých míst a nerealistických částí simulace

(vyplní se po měření)
