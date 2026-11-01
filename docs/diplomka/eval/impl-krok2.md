# Implementace, krok 2 ze 4: okamžité ověřování, učení, rozpoznání zařízení a obnova recallu

Datum 2026-11-01. Kód: commity `bf9123c` až `4062941` (větev `main`, nepushnuto). Měření: ladicí seedy 20261102, 20261103, 20261104, každý 40 sítí, `--block-size 2 --no-legs --no-feedback --counterfactual`. Párově se porovnává 118 sítí (1 192 virtuálních síť-dnů), kde doběhla obě ramena; srovnání legacy s krokem 1 má všech 120 sítí (1 236 síť-dnů). Dvě největší sítě seedu 20261104 v posledních ramenech nedoběhly a jsou vynechané v obou ramenech. Držené seedy (20261201, 20261301) ani kotva CTU-13/IoT-23 se nepoužily. Všechna čísla jsou ze simulace.

Surové výstupy: `F:\bakula-soak\ab\k2\reports\` (`ab-<A>-<B>.md` = plné párové tabulky, `calib-*.md` = kalibrace). Přepočet: `python tools/soak_ab.py --a <dirs> --b <dirs>` a `python tools/soak_calib.py <dirs>`.

Ramena (všechna se stejným harnessem a kontrafaktuálem):

| rameno | konfigurace |
|---|---|
| `a1-legacy` | legacy |
| `a1-v3` | v3 po kroku 1 (`--v3-off recall,ladder,learning,devices`, binárka z kroku 1 se stejnou logikou) |
| `a3-recall` | + obnova recallu (A) |
| `b4-ladder` | + žebřík ověřování a typ zařízení, autorské LR (B, D) |
| `c3-final` | + učení LR a priorů (C); výchozí v3 tohoto kroku |
| `c4-cal` | jako `c3-final` + izotonická kalibrace v rozhodování (fit bez testovaného seedu) |
| `d1-nodev`, `e1-nopeers` | ablace: bez typu zařízení, bez peer baseline detektoru |

## Shrnutí

1. **Recall je obnovený a ověřený plným kontrafaktuálem.** Kontrafaktuál = stejná síť, stejný seed, svět bez útoků. Útoku se připíše jen nález, který v tomto světě chybí. Proti legacy nemá v3 žádnou rodinu s ≥ 100 útoky horší o víc než 5 p. b. Největší zisky: dns_tunnel +82,1 p. b. (95% CI +73,6 až +89,7), exploit_attempt +33,3 (+24,4 až +41,5), port_scan_vertical +67,4. lateral_movement −0,6 (−9,3 až +7,9). Jen u rodin s n < 100 je bodový pokles: insider_hoarding −5,8 (n = 52, CI −13,6 až 0), exfiltration −3,4 (n = 87).
2. **Krok 1 skutečně ztratil jen dvě rodiny, ne šest.** Kontrafaktuál ukazuje reálnou ztrátu kroku 1 jen u lateral_movement (−51,1 p. b., CI −58,3 až −42,9) a exploit_attempt (−6,8, CI −11,0 až −3,4). Ostatní čtyři „ztráty“ byly náhodná shoda legacy s pozadím. Korekce placebo okny z kroku 1 přitom u lateral i exploit vycházela kladně (+4,1 a +8,9 p. b.), takže **skutečnou ztrátu zakryla**. Placebo okna proto v tomto kroku nahrazuje kontrafaktuál.
3. **Náhodná shoda v recallu legacy:** dns_tunnel 84,8 p. b. ze 99,2 % „detekce“, exfiltrace 56,3 ze 60,2 %, exploit 44,6 ze 63,7 %, port_scan_vertical 44,0 p. b. Recall legacy z tabulek v1, v2b a kroku 1 je u těchto rodin z větší části artefakt.
4. **Zobrazené falešné poplachy proti legacy klesly o 98,0 %** (95% CI −98,5 až −97,4 %), z 438,9 na 8,6 na síť-den. Proti kroku 1 klesly o 53,4 % (−64,7 až −39,0 %). Hlavní podíl má rozdělení `connection_timeout_burst` podle rozložení zdrojů: 14,5 → 1,2 FP/síť-den.
5. **Automatické ověřování funguje, ale rozhoduje málo.** Plně automaticky (potvrzeno nebo vyvráceno) se rozhodne 9,6 % ověřovaných případů. Bez učení, jen s autorskými LR, to je 0,2 %. Přesnost potvrzení je 97,4 % (96,5 až 98,0). Vyvráceno omylem, tj. nález kontrafaktuálně způsobený útokem: 1,16 % (0,59 až 2,28 %). Podíl automaticky vyřešených odlišných stavů je jen 0,9 %. Většina případů (90 %) jde po kontrolách člověku, protože prázdný výsledek kontroly záměrně není důkaz neškodnosti (RQ6 Z3).
6. **Plány mimo rozpočet: 88,3 % (legacy) → 63,2 % (krok 1) → 3,3 %.** Plány vznikají stavově, jen pro otevřené nálezy (28,5 plánů a 48,6 plánů s případy na síť-den proti 4 928 u legacy), a čekají ve frontě, místo aby propadly.
7. **Učení dává lepší pravděpodobnosti. Izotonická kalibrace nad naučenou posteriorou přínos mimo trénovací sítě nemá.** Brier behaviorálních predikcí 0,1949 → 0,1282, ECE 0,145 → 0,054. Kalibrace křížově validovaná napříč seedy: Brier 0,1282 → 0,1295, ECE 0,054 → 0,057. Kalibrace v rozhodování (`c4-cal`) ztrojnásobí automatické vyřešení (0,6 → 1,9 stavu na síť-den). Příčinně omylem zavřeno je ale 3,22 % (2,70 až 3,83 %), tedy nad mezí 2 %. Proto zůstává jen volitelná.
8. **Typ zařízení v jádru:** v simulaci je správně 92,0 % klasifikací (n = 2,99 M), 80,6 % se střední a vyšší jistotou. V žebříku zvyšuje počet automatických rozhodnutí o 13 % (1 975 → 2 238) při stejné chybovosti a brání aktivní kontrole křehkých zařízení. **Peer baseline detektoru podle typu zařízení nemá měřitelný přínos** (FP −1,1 %, CI −3,4 až +0,1 %), proto je ve výchozím stavu vypnutá.

## A) Obnova recallu

### A1. Plný kontrafaktuál (náhrada okna ±2 cykly a placebo oken)

Harness (`src/soak/traffic.rs`, `episode.rs`, `runner.rs`):
- **Nezávislé náhodné proudy událostí.** Každá událost (útok i benigní) má vlastní proud `derive(seed_cyklu, id)` a vlastní rozsah `flow_id`. Ztráta a duplicita telemetrie se rozhodují podle otisku toku, ne podle pořadí v proudu. Rozvrh skenu inventáře nezávisí na tom, zda je útok maskovaný. Vynechání jednoho útoku proto nezmění žádný jiný tok. Test `masking_an_attack_removes_only_its_flows` to ověřuje na 40 sítích při ztrátě 8 %, duplicitách 5 % a posunu hodin.
- **Kontrafaktuál** (`--counterfactual`): pro každou síť se nejdřív pustí svět bez všech útoků se stejným enginem. Z něj se uloží behaviorální nálezy, které by šlo připsat útoku (stejné okno a klíčová IP). Ve faktickém běhu se útoku připíše:
  - „zachyceno“ jen nález, který v kontrafaktuálu ve stejném cyklu chybí,
  - „zobrazeno“ jen nález zobrazený tehdy, když ho kontrafaktuál nezobrazil (eskalace kvůli útoku se tak počítá, opakované zobrazení pozadí ne).
  
  Přísná varianta chybí i v sousedních cyklech. Okno atribuce zůstává jen jako mez zpoždění detekce, odečet šumu dělá kontrafaktuál.
- **Validace leave-one-out** (`--cf-loo 1`): pro jeden náhodně vybraný útok na síť se pustí i svět bez TOHOTO útoku. Atribuce proti světu bez všech útoků souhlasí s leave-one-out v 98,3 % (95% CI 93,9 až 99,5 %, n = 115) u legacy i u v3 kroku 1 a v 99,1 % (95,2 až 99,8 %, n = 113) u finálního v3. Svět bez všech útoků je tedy dobrá a levnější náhrada (dvojnásobek výpočtu místo n + 1).
- Cena: CPU čas sítě se zdvojnásobí.

### A2. Kolik z recallu legacy byla náhodná shoda

Zobrazená detekce oknem minus kontrafaktuální detekce (legacy, 120 sítí; plně v `ab-a1-legacy-a1-v3.md`):

| rodina | n | legacy oknem | legacy kontrafaktuálně | náhodná shoda |
|---|---:|---:|---:|---:|
| dns_tunnel | 125 | 99,2 % | 14,4 % | 84,8 p. b. |
| exfiltration | 103 | 60,2 % | 3,9 % | 56,3 p. b. |
| exploit_attempt | 278 | 63,7 % | 19,1 % | 44,6 p. b. |
| port_scan_vertical | 331 | 69,1 % | 25,2 % | 44,0 p. b. |
| port_scan_horizontal | 206 | 89,3 % | 68,4 % | 20,9 p. b. |
| lateral_movement | 190 | 91,1 % | 74,2 % | 16,8 p. b. |
| c2_beacon | 215 | 15,5 % | 2,7 % | 12,8 p. b. |
| ssh_bruteforce | 389 | 94,9 % | 90,7 % | 4,1 p. b. |

### A3. Příčiny poklesu v kroku 1 (kontrafaktuálně)

| rodina | krok 1 − legacy, oknem (krok 1) | kontrafaktuálně | příčina v kódu |
|---|---:|---:|---|
| dns_tunnel | −59,2 | +15,2 (+3,3 až +27,7) | žádná ztráta; legacy „detekoval“ vytížený DNS server v 100 % placebo oken |
| exfiltration | −57,3 | −2,9 (−5,7 až 0) | odchozí tok je mimo rozsah (A10) v obou ramenech; legacy jen náhodou |
| ssh_bruteforce | −5,9 | −2,1 (−4,4 až 0) | v mezi |
| port_scan_horizontal | −7,4 | +13,1 | žádná ztráta |
| **exploit_attempt** | −48,2 | **−6,8 (−11,0 až −3,4)** | IDS alert nevytvářel žádný nález typu `suricata_alert` (chybí pravidlo, R3). Signatura na portu 80 se mapovala na `insecure_auth_possible`. Legacy body pocházely z objemové anomálie srovnávající služby mezi sebou, kterou v3 odstranil. |
| **lateral_movement** | −30,5 | **−51,1 (−58,3 až −42,9)** | Útočník pošle každé oběti jeden úspěšný tok na správcovský port. To je pod minimem 3 toků na klíč pro `unexpected_traffic` a v3 neměl detektor rozptylu zdroje po hostech. Legacy body byly z mezislužbové objemové anomálie a z `unmapped`. |

Další nalezená příčina, nezávislá na rodině: paměť nálezů eskalovala nový zdroj jen tehdy, když otevřený stav už nějaký dominantní zdroj měl. Útok jednoho zdroje na službu s rozptýleným šumem (otevřený timeout bez zdroje) se tak schoval pod existující stav (`finding_memory.rs`, `escalate_first_source`).

### A4. Změny v detekci (`passive/anomaly_v3.rs`, `findings.rs`, `finding_memory.rs`; volba `recall`)

- **IDS nálezy podle signatury:** jeden nález `suricata_alert` na (službu, signaturu), se zdroji alertu v paměti. Nová signatura na hostu se starším otevřeným alertem je nový stav. Řeší to typ u exploitů (0 → 49,2 % správného typu).
- **`multi_target_pattern`:** zdroj oslovil správcovské porty (SSH, Telnet, RPC, SMB, RDP, VNC, WinRM) u ≥ 8 hostů a ≥ 4× víc, než je medián jeho historie, nebo u ≥ 12 hostů bez historie. Alarmový vzorek se neučí (RQ2 Z3). Opírá se o RQ4 Z12a (rozptyl first-seen hran, nízká jistota).
- **`source_volume_outlier`:** jeden zdroj služby má ≥ 8× víc toků než medián ostatních zdrojů a aspoň o 60 toků víc. Je to peer srovnání zdrojů téhož cíle (RQ2 Z4, nízká jistota). Pokrývá DNS tunel a webový exploit z jednoho zdroje.
- **Pokusy i na známé služby:** S0/REJ na otevřený port se připíší zdroji pro `scan_attempts` (horizontální sken otevřeného portu).
- **`connection_timeout_burst` (A07, 66 % zbylých FP po kroku 1):**
  - nejdřív binomický test proti běžné míře selhání (p0 = 0,06, α = 10⁻³), takže 2 selhání z 8 toků nejsou nález,
  - dominantní zdroj (≥ 50 % selhání, ≥ 5) znamená tlak zdroje a typ zůstává,
  - mnoho převážně vnitřních klientů bez skoku objemu je `service_unreachable` (výpadek, nízká závažnost, vysvětluje ho kontext výpadku nebo údržby),
  - mnoho vnějších zdrojů je DoS a typ zůstává.
  
  Opírá se o RQ3 Z2: kontext služeb snížil FP sekvenčního testu, selhání na přechodně nedostupnou službu není důkaz skenu. Výsledek: zobrazené FP timeoutů 14,5 → 1,2 na síť-den.
- **Eskalace prvního dominantního zdroje** v paměti nálezů.

### A5. `expected_types` (definice „správného typu“)

Pravidlo: typ odpovídá mechanismu útoku a platí pro obě ramena stejně. Doplněno:
- `suricata_alert` u skenů a DDoS,
- `source_volume_outlier` u ssh_bruteforce, dns_tunnel, web_exploit, insider_hoarding a ransomware,
- `inductive_volume_anomaly` u credential_stuffing (hádání hesel z botnetu je nárůst objemu na službu; legacy tento typ vydává také).

Nové typy legacy nevydává, takže legacy čísla se mění jen u credential_stuffing.

### A6. Výsledek A (krok 1 → `a3-recall`, 120 sítí)

| metrika na síť-den | krok 1 | + recall | změna (95% CI) |
|---|---:|---:|---|
| zobrazené položky | 81,6 | 55,9 | −31,6 % (−41,1 až −20,5) |
| zobrazené FP | 22,1 | 10,3 | −53,4 % (−64,7 až −39,0) |
| čeká na člověka, FP stavy | 21,9 | 10,0 | −54,3 % (−65,5 až −39,7) |

Kontrafaktuální zobrazená detekce: dns_tunnel 29,6 → 96,8 % (+67,2, +56,4 až +77,9), exploit 12,2 → 51,4 % (+39,2, +31,8 až +47,1), lateral 23,2 → 73,2 % (+50,0, +40,9 až +57,4), ssh +8,0, web_exploit +6,3, port_scan_horizontal +4,9. Pokles o víc než 1 p. b. nemá žádná rodina. DDoS má správný typ beze změny (89 → 90 % `connection_timeout_burst`), protože vnější zdroje zůstávají timeoutem. Kontext zavřel příčinně omylem 1,69 % (1,07 až 2,65 %), audit vzorku 1/101.

**Neřešeno:** exfiltrace, C2 a cryptomining. Cíl je mimo rozsah a egress detekce (R2) v tomto kroku není. Kontrafaktuální detekce je 0 až 3 % v obou ramenech.

## B) Žebřík okamžitého ověřování

### B1. Návrh (`src/verify_ladder.rs`, `src/flow_history.rs`)

- **Případ** = otevřený behaviorální nález s jedním případem na stabilní klíč paměti nálezů. Nový plán vzniká jen pro nový, znovuotevřený nebo eskalovaný stav. Opakování otevřeného stavu jen doplní pozorování (idempotence). Statické expozice jdou dál přes `verification_planner`, ale přes **stavovou frontu** (`verification_exec::PlanQueue`): plán bez rozpočtu čeká na další cyklus a stejný plán je ve frontě jednou.
- **Sekvenční stav:** stav případu je log-šance a každá kontrola přičte ln LR. Pravidla zastavení se testují po každé kontrole:
  - potvrzeno při p ≥ 0,9,
  - vyvráceno při p ≤ 0,03 (u vysokého dopadu ≤ 0,01) a jen s aspoň jedním doloženým neškodným důkazem,
  - eskalace člověku při stropu 8 kontrol, vyčerpaném plánu nebo po 4 cyklech bez rozpočtu.
  
  Opírá se o RQ3 Z1, Z3 a Z4: α a β jsou parametry, ne záruka.
- **Prázdný výsledek není důkaz neškodnosti** (RQ6 Z3, Dodatek A.2 d). Výsledek „nezjištěno“ ani „neprovedeno“ víru nemění. Test `empty_results_never_refute_and_case_escalates_after_cap`.
- **Úrovně a kontroly** (pořadí od nejlevnější úrovně; uvnitř úrovně náhodně podle tajného klíče, RQ3 Z11; čekání L2 až nakonec, aby okamžité kontroly viděly aktuální stav):
  - **L0** `history`: stalo se to už dřív? Uložená historie toků v SQLite (`flow_history`, `flow_edge`): maximum za hodinu týdne pro službu (toky, selhání) a zdroj (toky, rozptyl, pokusy), 7 dní. „Opakuje se“ znamená ≥ 2 dny ve stejné hodině ±1 h s hodnotou ≥ 50 %. Klíče s alarmem se v daném cyklu neučí.
  - **L1** `context` (kalendář, podpůrná shoda bez výjimky pro závažné typy, zdrojová konzistence zůstává), `reputation` (neúplný feed), `intel` (KEV/EPSS cílové služby z intel dat reportu), `device_profile` (služba nebo chování neobvyklé pro typ zařízení).
  - **L2** `peers` (podíl zařízení stejného typu a podsítě se stejným nálezem v okně), `persistence` (přetrvá jev další 2 cykly, se stejným zdrojem?). Přechodný jev je „nezjištěno“, ne „neškodné“, protože krátké útoky jsou přechodné.
  - **L3** `liveness`: dostupnost služby, read-only TCP spojení v produkci jen s `--execute-verification` a jen v rozsahu. Křehká zařízení (PLC, HMI, zdravotnictví, IoT, kamery, tiskárny se střední a vyšší jistotou typu) se bez schválení neproklepávají (RQ3 Z10).
  - **L4** `pivot`: BFS po komunikačních hranách z entity a zdrojů, hloubka ≤ 3, ≤ 5 uzlů, jen v rozsahu, náhodné pořadí. Hledá podezřelé nálezy na souvisejících zařízeních.
- **Pořadí napříč případy:** po kolech, v každém kole se případy seřadí podle EVOI proxy = dopad × entropie víry / cena kontroly (RQ3 Z12, nízká jistota) a 15 % pozic se prohodí losem. Abecedu `finding_id` (A23) to nahrazuje. Rozpočet: ceny L0 0,05, L1 0,1, L2 0,05, L3 1, L4 0,3, 500 jednotek na cyklus a nejvýš 10 aktivních kontrol.
- **Výsledek mění stav nálezu s auditem:**
  - vyvráceno: nový stav `Refuted` v paměti nálezů (akce `verify_refute` s důvody všech kontrol v `finding_audit`, vratné). Opakování se nezobrazí, eskalace ano,
  - potvrzeno: `Confirmed` plus `verify_confirm`,
  - eskalováno: `verify_escalate` a zobrazení.
  
  Nález nízkého dopadu se zobrazí až po ověření. Vysoký dopad (High a závažné typy) se zobrazí hned a ověřuje se souběžně. Report má pole `verificationDecisions`.
- **Produkce** (`pipeline/v3.rs`): stav žebříku a tajný klíč žijí v `engine-state.sqlite` (kv `ladder`), historie v tabulkách. Reputaci čte z `reputation.json` ve workspace (síť, verdikt, zdroj, expirace; chybějící soubor znamená vše neznámé). Integrační test `tests/engine_v3.rs` ověřuje stav mezi dvěma procesy a beze změny legacy výstupu.
- **Simulace bez úniku pravdy** (`soak/ladder_env.rs`):
  - reputační feed zná 35 % veřejných adres útočníků a 60 % legitimních cílů a omylem hlásí 0,5 % náhodných adres,
  - kalendář je neúplný z kroku 1,
  - dostupnost služby se bere z modelu se 4 % selhání nástroje.

### B2. Výsledek B (`a3-recall` → `b4-ladder`, autorské LR, 118 sítí)

- Plány a případy na síť-den: 49,6 → 28,5 plánů statických expozic plus 20,1 případu žebříku. Mimo rozpočet 3,3 % (3,1 až 3,4). Legacy mělo 88,3 % a krok 1 63,2 % (agregát `final-report.json`).
- Rozhodnutí: potvrzeno 11, vyvráceno 40, eskalováno 23 692. Automaticky rozhodnuto 0,2 %.
- Zobrazené behaviorální položky +8,0 % (+6,1 až +10,0). Nález nízkého dopadu se zobrazí až po ověření (latence průměrně 2,0 cyklu, nejvýš 5), takže zachytí i nálezy, které by paměť jinak potlačila. Zobrazené FP +0,5 % (−1,8 až +2,5). Kontrafaktuální recall beze změny (všechny rodiny ±1 p. b. kromě c2 −0,5).
- **Neúspěch B s autorskými LR:** žebřík skoro nic nerozhodne. Autorské LR jsou na rozhodnutí příliš slabé (`history_seen` 0,25 proti empirickým 0,05). Empirické LR z rozhodnutých případů (tabulka v `ab-a3-recall-b4-ladder.md`) ukazují, které kontroly nesou informaci:
  - reputace „špatná“: LR ≈ 1 170,
  - pivot s podezřením: 6,0,
  - přetrvání: 4,7,
  - historie „už se stalo“: 0,05,
  - kontext: 0,03,
  - peer „rozšířené“: 0,06.
  
  Kalendářová shoda a výpadek služby tedy silně svědčí pro neškodnost, ale autorské LR je podceňují. To je vstup pro krok C.

## C) Učení a kalibrace

### C1. Návrh

- **Štítky** přicházejí jen přes Case Memory, takže ochrana proti otrávení zůstává (rate limit, strop zdroje, kontradikce, karanténa). Člověk posoudí eskalovaný nebo potvrzený případ s pravděpodobností 0,5 a vyvrácený u 10% auditu, s 5% chybou verdiktu. Záznam jde jako `ladder:<typ>` a `ladder:<typ>@<typ zařízení>`.
- **Priory:** Beta posteriora Case Memory pro kontext (typ nálezu a typ zařízení), ústup na typ, jinak výchozí 0,15. Je to hierarchický ústup R12b (A21).
- **LR** (`LadderLearner`): počty podle zdroje štítku a (kontroly, výsledku), smrštění k autorskému LR s váhou n / (n + 20), minimum 10 případů na třídu. Bezpečnostní meze: neškodný výsledek smí víru jen snižovat (LR 0,02 až 1), podezřelý jen zvyšovat (1 až 50). „Nezjištěno“ a „neprovedeno“ se neučí vůbec, i když jsou v datech prediktivní (`device_profile:nezjištěno` má empirické LR 9). Učit z nich by znamenalo brát nepřítomnost dat jako důkaz (RQ6 Z3). Zdroj, který Case Memory označí za otrávený, se z LR vyřadí i zpětně (test `learner_shrinks_toward_author_respects_bounds_and_drops_poisoned_source`).
- **Kalibrace** (`src/calibration.rs`): izotonická regrese (vážená PAVA, sloučení vazeb, schodová funkce, minimum 200 vzorků), fit offline v `tools/soak_calib.py` křížovou validací napříč sítěmi (leave-one-seed-out a 5-fold po sítích). V jádru je volitelná (`--calibration`, při kalibraci seedu X fit bez seedu X). Konformní práh není implementovaný, viz „Co zůstává“.

### C2. Výsledek C (`b4-ladder` → `c3-final`, 118 sítí)

| | autorské LR (`b4`) | učení (`c3`) | učení + kalibrace v rozhodování (`c4`) |
|---|---:|---:|---:|
| potvrzeno / vyvráceno / eskalováno | 11 / 40 / 23 692 | 1 592 / 688 / 21 506 | 1 847 / 3 787 / 18 241 |
| automaticky rozhodnuto (potvrzeno + vyvráceno) | 0,2 % | 9,6 % | 23,6 % |
| přesnost potvrzení (95% CI) | 100 % (74 až 100, n = 11) | 97,4 % (96,5 až 98,0) | 95,5 % (94,5 až 96,4) |
| vyvráceno omylem, kontrafaktuálně (95% CI) | 0/40 | **1,16 % (0,59 až 2,28)** | 1,69 % (1,33 až 2,15) |
| vyvráceno omylem, příčinně (95% CI) | 1/40 | 2,33 % (1,44 až 3,74) | **3,22 % (2,70 až 3,83)** |
| audit 10% vzorku vyvrácených | 0/3 | 3/65 = 4,6 % (1,6 až 12,7) | 9/362 = 2,5 % (1,3 až 4,7) |
| automaticky vyřešené stavy / síť-den | 0,4 | 0,6 (+72 %, +46 až +100 %) | 1,9 (+210 % proti c3) |
| zobrazené FP / síť-den | 8,8 | 8,6 (−2,0 %, −2,8 až −1,2) | 7,6 (−11,3 %, −23,5 až −3,1) |
| latence rozhodnutí (cykly, průměr / max) | 2,0 / 5 | 1,9 / 5 | 1,6 / 4 |

Brier a ECE behaviorálních predikcí (posteriora rozhodnutých případů proti kontrafaktuální pravdě, n ≈ 23 800, podíl útoků 31,4 %, Brier konstantní predikce 0,215; `calib-*.md`):

| | Brier | ECE |
|---|---:|---:|
| autorské LR a prior (`b4`) | 0,1949 | 0,145 |
| učení (`c3`) | 0,1282 | 0,054 |
| `c3` + izotonická, leave-one-seed-out | 0,1295 | 0,057 |
| `c3` + izotonická, 5-fold po sítích | 0,1268 ± 0,023 | 0,051 ± 0,039 |
| `b4` + izotonická, leave-one-seed-out | 0,1804 | 0,072 |

Kalibrační křivka před učením (`b4`) je výrazně podkonfidentní ve středu rozsahu: koš 0,2 až 0,3 má 54 % útoků, koš 0,7 až 0,8 má 97 %. Po učení (`c3`) jsou koše do 0,1 odchylky, výjimkou je 0,2 až 0,3 (25 % proti 42 %). Plné křivky jsou v `calib-b4.md` a `calib-c3.md`.

**Čtení:**
- Učení LR a priorů snižuje Brier o 34 % a ECE o 63 %.
- Izotonická kalibrace pomáhá jen nad nenaučenou posteriorou (`b4`: ECE 0,145 → 0,072). Nad naučenou mimo trénovací seed nepomáhá: u seedu 20261104 Brier zhorší z 0,1268 na 0,1328. To odpovídá výhradám RQ2: Z11 (přínos velmi slabě doložen) a Z7 (při posunu distribuce kalibrace degraduje).
- Kalibrace v rozhodování posune víc případů pod mez vyvrácení. Kontrafaktuálně zůstane omyl pod 2 %, ale příčinná definice dá 3,22 %, a mez z kroku 1 (bod ≤ 2 %) tak nesplní. Kalibrace proto **není výchozí**.
- Pro výchozí `c3` je kontrafaktuální míra 1,16 % pod mezí. Příčinná definice z kroku 1 dává 2,33 % a mez těsně překračuje. Příčinná definice počítá i nález na cíli, kam útok v tom cyklu posílal toky, i když nález útok nezpůsobil, a kontrafaktuál je přesnější. Rozdíl uvádím, protože sloučená míra kontextu a žebříku po kontrafaktuálu ještě nezávisle ověřená není.

**Otrávení:** 4 otrávené sítě, 35 702 podvržených verdiktů, z toho 98,6 % v karanténě. Poctivé verdikty přijala Case Memory jen v 78,7 % (9 072 z 11 530). Zbytek zastavil limit 30 záznamů za hodinu na zdroj, který sdílejí staré verdikty operátora i nové verdikty žebříku. Pro provoz s jedním správcem je to omezení, které je potřeba vyřešit oddělením zdrojů.

## D) Rozpoznání typu zařízení v jádru

- **Modul** `src/device_class.rs` je ekvivalent `classifyHost` z UI. Hlasuje z aktiva CMDB, portů, produktů, tokenů jména (bez koncových číslic, celé tokeny), výrobce z OUI a lokálně spravované MAC. Výstup je typ, jistota a důvody. Tabulky jsou data a dají se rozšířit JSONem (`ClassifierTables::extended_with_json`). Klasifikace je deterministická i při shodě skóre.
- **Model hostů a API:** `HostReport.device_class` (`kind`, `confidence`, `reasons`) se plní v režimu v3 a je v `report.json`, které API vrací. V legacy pole chybí (golden snapshot beze změny).
- **Použití:**
  - peer skupina `typ@podsíť /24` pro studený start detektoru (volba `peers`),
  - kontext pro ověřování: L1 `device_profile` (tiskárna s portem 22, rozptyl z IoT), L2 `peers` a ochrana křehkých zařízení před L3.
- **Přesnost** v simulaci: 92,0 % správně (n = 2 990 421 klasifikací při skenech), 80,6 % se střední a vyšší jistotou. Je to optimistické, protože jména hostů v simulátoru nesou roli (`printer-12`) a služby jsou podle role deterministické.
- **Přínos:**

| ablace | zobrazené FP / síť-den | automaticky rozhodnuto (potvrzeno + vyvráceno) | vyvráceno omylem (kontrafaktuálně) |
|---|---|---|---|
| bez typu zařízení (`d1-nodev`) proti `c1` (učení, stejná logika jako `c3` před opravou výkonu) | 8,7 → 8,6 (−0,7 %, −3,1 až +0,9) | 1 975 → 2 238 (+13 %) | 0,71 % → 0,46 % |
| bez peer baseline detektoru (`e1-nopeers`) proti `c3` | 8,7 → 8,6 (−1,1 %, −3,4 až +0,1) | beze změny | beze změny |

  Typ zařízení v žebříku přidává automatická rozhodnutí při stejné chybovosti a v simulaci zablokoval 101 aktivních kontrol křehkých zařízení (`liveness:unavailable` 157 proti 56). Zůstává zapnutý. **Peer baseline detektoru přínos nemá**, a podle zadání je proto ve výchozím stavu vypnutá (`V3Features::recommended`, `peers = false`). Kód zůstává pro měření na kotvě. RQ2 §3b k tomu uvádí, že peer-group baseline pro zařízení nikdo neměřil, takže negativní výsledek se nemá s čím srovnat.

## Výkon a stabilita

- 0 panik a 0 porušených invariantů ve všech ramenech.
- Medián p99 doby cyklu: legacy 274 ms, krok 1 41 ms, `c3` 67 ms.
- Při prvním měření měl žebřík s učením p99 cyklu 37,8 s na síti s 1 391 zařízeními. Výběr kontroly měl složitost O(kontroly × případy) a odhad prioru procházel celou Case Memory pro každý případ. Oprava: výběr po kolech s řazením O(n log n) a priory jednou za cyklus. Teď je to 0,28 s (`profile_step2_slowest_network`) a max p99 všech sítí 1,1 s.
- CPU čas sítí: legacy 422 min, `c3` 81 min (bez kontrafaktuálu, který ho zdvojnásobí).

## Testy a kvalita

- Nové testy:
  - harness: maskování a kontrafaktuál,
  - detektor: binomický test, timeouty podle zdrojů včetně DoS, rozptyl, odlehlý zdroj, pokusy na známé služby, peer skupina typu zařízení,
  - nálezy: IDS podle signatury, `finding_signal`,
  - paměť: eskalace prvního zdroje, `Refuted`, klíč IDS,
  - žebřík: prázdný výsledek, vyvrácení, potvrzení, idempotence, křehké zařízení, pivot, rozpočet a náhodné pořadí, serializace, učení,
  - fronta plánů, historie toků, kalibrace, klasifikátor, epizody v3 s žebříkem a učením, produkční integrace.
- `cargo test --lib`: 420 testů prochází. Neprochází 8 známých výjimek: `broker::*` (Redis), `identity_lab` (Docker), 2× časování lease v `platform` pod zátěží. Integrační testy procházejí kromě `broker_two_process` (Redis) a `e2e::autopilot…` (httpx). Golden snapshot je zelený.
- `cargo clippy --all-targets`: lib 85 (dřív 86), lib test 93 (dřív 94), bin 3, e2e 1.

## Co zůstává

- **Automatické vyřešení je pořád malé** (0,9 % stavů, 9,6 % případů). Hlavní brzdou je zásada „nezjištěno ≠ neškodné“. Dál by šlo:
  - přidat skutečné neškodné důkazy (DHCP a ARP logy pro nové zařízení, inventura úloh pro dávky, potvrzení výpadku z monitoringu),
  - oddělit zdroje verdiktů v Case Memory (limit 30 za hodinu ubírá poctivé štítky).
- Konformní práh vyvrácení (volitelný, nízká jistota) není implementovaný. Kalibrace v rozhodování už sama překročila příčinnou mez, takže agresivnější práh bez nových neškodných důkazů nedává smysl.
- Egress (R2) pro exfiltraci, C2 a cryptomining. Kontrafaktuální recall je 0 až 3 % v obou ramenech.
- Sloučit dvě definice „zavřeno omylem“ (příčinná a kontrafaktuální) do jedné s nezávislou kontrolou.
- Potvrzení na držených seedech a kotvě CTU-13/IoT-23. Prahy detektorů a autorské LR jsou laděné jen na simulátoru (riziko A34/B6) a naučené LR jsou naučené na simulovaných verdiktech.
- UI zobrazení `deviceClass` z jádra a `verificationDecisions` (jiná práce, `ui/` se v tomto kroku neměnilo).
- Produkce: `reputation.json` plní člověk nebo import feedu (Pásmo B). Aktivní L3 jen s `--execute-verification`.

## Studie tvrdily chybně (nebo neověřeně)

1. **Krok 1 (`impl-krok1.md`) tvrdil**, že po korekci placebo okny je v3 u všech rodin s ≥ 100 placebo okny lepší nebo stejná. Kontrafaktuál to vyvrací u lateral_movement (−51 p. b.) a exploit_attempt (−7 p. b.). Placebo okna jako korekce na pozadí v tomto harnessu selhávají, protože pozadí v posunutém čase není pozadí v čase útoku. Naopak „ztráty“ dns_tunnel, exfiltrace, ssh a horizontálního skenu byly náhodná shoda legacy, přesně jak krok 1 tušil.
2. **01-analyza, A07:** `connection_timeout_burst` je z velké části statistický šum malých služeb (2 selhání z 8 toků). Rozdíl „provoz proti útoku“ podle rozložení zdrojů pak řeší zbytek. Samotné rozložení zdrojů by nestačilo.
3. **00-zaver, §5.b:** „pro EVOI ve výběru kontroly není podklad“ platí. Data tohoto kroku ale ukazují, že větší než pořadí je síla důkazů (LR). Autorské LR podceňovaly kontext a historii zhruba pětkrát.
