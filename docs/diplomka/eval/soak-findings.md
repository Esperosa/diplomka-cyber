# Soak v1: nalezy (3 h, 15 664 siti, 31 079 virtualnich sit-dnu)

Zdroj: `F:\Projekty\bakula-soak\run80h\final-report.md`, commit `995ec76`, seed 20260131, 18 vlaken, legs zapnute.
Beh byl cisty (STOP po 3,03 h). `soak verify --samples 30`: **30/30 bloku bit po bitu shodnych**.
Cisla jsou z modelu (simulace) a kotvy na realnych datech; nejsou meranim zivych siti.

## Rozsah a zdravi
- 15 664 siti, 1 491 792 cyklu (30 virt. minut), 912,7 M toku, 74,1 M nalezu, propustnost 1,43 site/s.
- 0 porusenych invariantu, 0 panik. Halda bez trendu (+1,1 MiB/h, R2 0,00), RSS 83 MiB, propustnost se v case nezhorsuje.
- Cyklus: p50 70 ms, p99 809 ms, max 5,1 s. Nejdrazsi faze: `hypothesis_plan_exec` (prumer 33 ms).

## Detekce po rodinach (Wilsonuv 95 %)
| rodina | detekovano | spravny typ | poznamka |
|---|---:|---:|---|
| ddos_volume | 100,0 % | 100,0 % | |
| dns_tunnel | 99,8 % | 99,8 % | |
| ssh_bruteforce | 99,8 % | 78,9 % | zadrzeno blokem 86,5 % |
| slow_scan | 91,9 % | 86,8 % | |
| lateral_movement | 90,2 % | **12,5 %** | nalez vznika, ale spatneho typu |
| port_scan_horizontal | 89,5 % | 72,4 % | |
| port_scan_vertical | 72,7 % | 48,7 % | zadrzeno 8,1 % |
| exploit_attempt | 68,8 % | **0,0 %** | IDS videlo 2 301 z 5 061, ale typ `suricata_alert` se nikdy nevyda |
| exfiltration | 66,6 % | 65,9 % | zdrojove poradi: **0,0 %** (produkcni filtr), 42,1 % s egress |
| c2_beacon | **4,7 %** | 0,3 % | nejslabsi rodina, median latence 60 min |
| rogue_device | **0,2 %** | 0,0 % | skoro neviditelne |

Zdrojove poradi (utocnik v top-3): c2 67,6 %, dns_tunnel 74,2 %, lateral 53,7 %; exfiltrace 0 % -> 42,1 % kdyz se zapocitaji odchozi toky.
Zaver: engine drzi hlasite objemove utoky; selhava na pomalych a nenapadnych (C2, rogue) a u typovani (exploit, lateral).
Potvrzeny produkcni nalez: Zeek parser zahazuje toky s cilem mimo scope, exfiltrace je proto v produkci slepa.

## Falesne poplachy
- 6,55 M behavioralnich nalezu bez pricinny = **210,7 / sit-den**; 75 % je `inductive_volume_anomaly` (4,95 M), dalsich 22 % `packet_rate_spike`.
- Benigni lookalike: flash_crowd 56 441 nalezu, backup 31 368, authorized_scanner 5 824, ntp_fanout 4 142, software_update 0.
- Zaver: bez ladeni `inductive_volume_anomaly` a prahu objemu je sum neprovozovatelny (cíl dalsiho kola, ne tento).

## Expozice z inventare
9,95 M ocekavanych nalezu, 100 % nalezeno (inventarni cesta je spolehliva).

## Identita
668 054 zarizeni, 266 800 zmen adres (DHCP/swap): **falesne rozdeleni 8,7 %** (57 901), falesne sloucenych 1,7 % (12 880), 99 ambiguous.
Zaver: churn je nejslabsi misto identity vrstvy; 8,7 % rozdeleni zkresluje historii zarizeni.

## Zasahy (ops.rs + simulovane jadro)
- navrzeno 21 619, aplikovano 18 832, vyprselo 18 097, drift odstranen 18 519.
- 5 890 chyb operatora (blokace nahodne vnitrni IP), **699 zachyceno chranenym rozsahem** (zbytek nebyl chraneny rozsah, ale bezna interni adresa; guard chrani jen definovane rozsahy).
- kolaterala 0,0068 % legitimnich toku; utocnikova data zahozena jadrem 24,7 %.
- vstrikle zavady jadra: 3 275, 364 prikazu selhalo, `sweep` selhal 191x; nikdy nevznikl falesny drift, chranene IP v jadre 0.

## Overovani
74,1 M planu: provedeno 12,4 M, znovu pouzito 10,5 M, **mimo rozpocet 50,6 M (68 %)**, selhalo 0,68 M (vstrikovane poruchy ve v2); porusenych rozpoctu/schvaleni/scope 0.
Zaver: rozpocet kontrol je limitujici; planner/EVOI rozhoduje, co se ze 68 % neprovede.

## Uceni (Case Memory)
- 48,4 M predikci, **Brier 0,0107** vs naivni 0,25. Se vzrustajicim poctem pripadu klesa 0,047 -> 0,0004.
- Kalibrace: pro p >= 0,6 je model **podkonfidentni** (predikce 0,75 -> skutecnost 0,996), pro p 0,1 az 0,5 **prekonfidentni** (0,137 -> 0,065; 0,43 -> 0,21). Kalibrace v produkci (izotonicka) zatim neni zapojena.
- Otraveni: 457 epizod, 774 680 falesnych zaznamu, **99,4 % zachyceno**; 24 753 poctivych zaznamu v karantene (cena guardu).

## Realna data (kotva)
23 scenaru CTU-13 + IoT-23, 3 pruchody, **0 nedeterministickych**. Ablace A porazi triviální baseline jen na 6 z 20 scenaru s malicious provozem; zdrojovy lift 1,0 az 90x.

## Zatez a H5
- ops.sqlite na disku: 41 372 iteraci, 0 chyb, retezec auditu OK, sweep p50 1,6 s (soubor + fsync, ne uzke hrdlo enginu).
- Broker: 0 ztracenych jobu, ale propustnost se saturuje na ~180 jobu/s uz od 2 konzumentu (1: 137, 16: 180). Skalovani pres konzumenty zde neplati; potrebuje jiny backend nebo shardovani (H5 zustava neprokazano).

## Mezery pokryti (proc v2)
- jen 5 archetypu, 5 az 220 zarizeni, 1 az 4 podsite; zadne OT/zdravotnictvi/cloud, role jen 11;
- 11 rodin utoku (chybi credential stuffing, ransomware, mining, insider, web exploit, ICS, flotilovy beacon, vicefazova kampan);
- zadne provozni poruchy (pad serveru, patche, onboarding, vypadek senzoru, poskozene logy, restarty enginu), nejdelsi epizoda 4 dny.
Resi soak v2 (commit `106afea`): 10 archetypu az ~4000 zarizeni a 80 podsiti, 19 roli, 19 rodin, 9 provoznich udalosti, slepe podsite senzoru, svatky, restarty a poruchy nastroju, behy 1 az 60 dni.
Prvni vzorek v2 (28 siti) uz ukazal: provozni udalosti jsou pro engine "utok" (sensor_crash 82 %, log_corruption 100 %, patch_window 97 %, collector_replay 97 %, service_crash 95 % s falesnym nalezem).
