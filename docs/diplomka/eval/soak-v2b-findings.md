# Soak v2b: nálezy (14,56 h, 2 312 sítí, 22 600 virtuálních síť-dnů)

Zdroj: `F:\bakula-soak\run-v2b\final-report.md`. Běh s opraveným měřením (přesné porovnání IP, zaručeně neprázdný seznam obětí, atribuce provozních událostí jen v okně události; commit harnessu `a293d2b`, status uvádí `15e6fd5`, binárka vznikla z necommitnutého stromu). Seed 20261101 (v návrhu studie označen jako ladicí). Engine beze změny: jde o **základní hodnotu (baseline) pro A/B měření**.
Čísla jsou ze simulace; nejsou měřením skutečných sítí. Starší běh v2 (měření se starými chybami) se nepoužívá.

## Zdraví
- 20 vláken, 1,71 mld. toků, 185 M nálezů, 20,7 cyklů/s. Zastaveno ručně (STOP ve 13:11), plánovaný úkol v relaci se nespustil.
- 0 porušených invariantů, **1 panika**: síť 808, „kapacita podsítí“ (viz Chyby harnessu).
- Paměť: halda +2,36 MiB/h (R2 0,06), RSS +6,74 MiB/h (R2 0,12): **bez statisticky patrného trendu** (dřívější obava z úniku 28 MiB/h z průběžného snímku se v celku nepotvrdila).
- Cyklus p50 450 ms, p99 6,9 s, max 180 s (velké sítě). `hypothesis_plan_exec` p50 109 ms.

## Pokrytí
Všech 5 velikostních tříd, všech 10 archetypů (Metro 76, XXL 77 sítí; Soho 507, Smb 427). Délky běhu 1 až 60 dní. Provozní realita: 5 748 restartů enginu, 8 826 patchnutých a 2 840 nově nasazených zařízení, 127 533 poškozených řádků alertů zpracováno bez pádu. Stale nálezy po patchi: 0 z 0 kontrol (nebylo co kontrolovat, měření je prázdné, ne důkaz).

## Detekce po rodinách (Wilson 95 %)
| rodina | detekováno | správný typ | poznámka |
|---|---:|---:|---|
| ransomware | 99,5 % | 99,4 % | |
| apt_chain | 99,5 % | 98,6 % | zadrženo blokem 78 % |
| dns_tunnel | 99,6 % | 99,6 % | optimistické (bez CDN/AV lookalike) |
| insider_hoarding | 97,5 % | 96,4 % | |
| credential_stuffing | 97,1 % | 77,6 % | |
| ics_attack | 97,3 % | 47,5 % | n = 183 |
| slow_scan | 95,9 % | 93,3 % | |
| ssh_bruteforce | 95,9 % | 71,5 % | zadrženo 80,1 % |
| web_exploit | 95,6 % | 57,6 % | zadrženo 54,2 % |
| ddos_volume | 95,8 % | 94,1 % | |
| port_scan_horizontal | 94,0 % | 84,6 % | |
| lateral_movement | 93,5 % | 57,5 % | |
| port_scan_vertical | 72,0 % | 47,7 % | |
| exploit_attempt | 69,7 % | **0,0 %** | IDS vidělo 2 270 z 5 145; typ `suricata_alert` se nikdy nevydá |
| fleet_beacon | 69,3 % | 24,8 % | |
| exfiltration | 67,4 % | 65,1 % | zdrojové pořadí 0,2 % produkčně, 33,5 % s odchozími toky |
| cryptomining | **23,0 %** | 3,1 % | |
| c2_beacon | **13,7 %** | 7,9 % | medián latence 570 min |
| rogue_device | **10,7 %** | 10,7 % | |
Nejslabší: C2 beacon, mining, rogue device, správný typ u exploitů (strukturální chyba, ne ladění). Silné jsou hlasité a objemové útoky.

## Falešné poplachy (nejdůležitější problém)
- **1 317 / síť-den**, 29,8 M nálezů bez příčiny. Rozdělení: `unexpected_traffic` 15,3 M (51 %), `inductive_volume_anomaly` 9,8 M (33 %), `packet_rate_spike` 2,8 M (9 %), `unmapped_passive_event` 1,3 M, ostatní < 2 %.
- **Roste se velikostí sítě:** S 69, M 249, L 2 406, XL 5 829, XXL 2 306 na síť-den. XXL klesá, což může být typ sítě (Cloud) nebo kratší běhy, nejde o jednoduchý lineární vztah.
- Benigní událost vyvolá falešný nález: patch window 98,5 %, collector replay 95,1 %, service crash 90,4 %, batch job 77,9 %, log corruption 77,1 %, flash crowd 74,0 %, backup 64,4 %, authorized scanner 41,9 %, decommission 22,9 %, NTP 20,0 %; sensor crash 0,0 %, retry storm 0,0 %, software update 0,0 %, onboarding 1,2 %.
- Část šumu je artefakt opakování: stejný stav se vydává v každém cyklu a počítá se vícekrát (audit kódu `01-analyza-kodu`), skutečný počet odlišných problémů je nižší. Přesné číslo se změří až po zavedení paměti nálezů.

## Identita (výrazné zhoršení oproti v1)
- Falešné rozdělení zařízení **35,4 %**, falešné sloučení **25,6 %** (v1: 8,7 % a 1,7 %). 2,0 M změn adres, 5 748 restartů enginu, mobilní zařízení s 4× častější změnou adresy.
- Možné příčiny (hypotézy, neověřeno): restart enginu maže inventář (pak se zařízení znovu párují), mobilní zařízení a dormantní zařízení v modelu v1 nebyly, velké sítě s MAC viditelnou jen v části podsítí. Může jít částečně o artefakt harnessu; vyžaduje samostatné prošetření před jakýmkoli závěrem.

## Ověřování a zásahy
- 183 M plánů, provedeno 8,6 M, znovu použito 7,9 M, **mimo rozpočet 165,9 M (90,6 %)**, selhalo 0,83 M (vstřikované poruchy). Porušení rozpočtu, schválení i rozsahu: 0.
- Zásahy: navrženo 30 343, aplikováno 26 092, chyby operátora 4 375 (243 zachyceno chráněným rozsahem), kolaterála 0,0016 %, 270 selhání a 269 selhání sweepu (vstřikované poruchy jádra).

## Učení
Brier 0,031 (naivní 0,25). Kalibrace: model je při predikci 0,2 až 0,7 **nadkonfidentní** (např. predikce 0,535 → skutečnost 0,358; 0,636 → 0,482). Nízký počet případů (0 až 9) Brier 0,22 a stoupá s historií (100+: 0,012). Brier dominují statické expozice (podle auditu), proto je celkové číslo optimistické.

## Chyby harnessu odhalené během běhu
1. Panika sítě 808: `generate` hlásí „kapacita podsítí“, když je málo statických adres (98 na /24) pro hustě serverové archetypy (Cloud, Datacenter). `needed = total / 110` je příliš optimistické pro sítě s téměř jen statickými zařízeními. Oprava: počítat podle statických adres (≈ /90).
2. Identita při restartu (viz výše) a mobilní churn: ověřit, zda je to engine, nebo model.

## Vliv na plán
Potvrzuje pořadí z `00-zaver-jak-vylepsit-core.md` (Dodatek A): nejdřív paměť nálezů a deduplikace a kontextové vyloučení, pak `unexpected_traffic`, `inductive_volume_anomaly`, `packet_rate_spike`. Navíc: identita (35 % / 26 %) je nový prioritní problém a oprava harnessu (panika, kapacita).
