## Pokrytí, křivky skrytosti a registr slepých míst

Ramena: v3, v3graph; hodnocené rameno `v3graph`. Detekce = kontrafaktuální zobrazená detekce na útok (Wilson 95 %; souhrny a rozdíly s bootstrapem po sítích).

Hranice pásem S (zadané předem): 0.172, 0.236, 0.305, 0.392

| rameno | sítí | útoků | detekce (bootstrap) | zobrazené FP/síť-den | zavřeno omylem (G3) | panik/invariantů |
|---|---:|---:|---:|---:|---:|---:|
| v3 | 120 | 3042 | 79,7 % (76,2 až 82,5) | 18,8 | 1,7 % (1,3 až 2,1) [67/4023] | 0/0 |
| v3graph | 120 | 3042 | 81,7 % (78,2 až 84,4) | 22,7 | 1,7 % (1,3 až 2,2) [58/3423] | 0/0 |

### Párově `v3graph` − `v3`

| výběr | párů | rozdíl detekce |
|---|---:|---:|
| vše | 3042 | +2,0 p. b. (+1,4 až +2,6) |
| Q4 + Q5 | 1215 | +1,7 p. b. (+0,9 až +2,5) |
| Q5 | 609 | +1,6 p. b. (+0,7 až +2,6) |

### Křivka skrytosti: pásma S

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| Q1 | 607 | 80,2 % (76,9 až 83,2) | 82,0 % (78,8 až 84,9) |  |
| Q2 | 609 | 80,0 % (76,6 až 83,0) | 81,4 % (78,2 až 84,3) |  |
| Q3 | 611 | 78,6 % (75,1 až 81,6) | 81,8 % (78,6 až 84,7) |  |
| Q4 | 606 | 81,4 % (78,1 až 84,3) | 83,2 % (80,0 až 85,9) |  |
| Q5 | 609 | 78,5 % (75,1 až 81,6) | 80,1 % (76,8 až 83,1) |  |

### Osa: intenzita

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| 0.0–0.2 | 362 | 75,1 % (70,4 až 79,3) | 79,0 % (74,5 až 82,9) |  |
| 0.2–0.4 | 665 | 78,8 % (75,5 až 81,7) | 80,3 % (77,1 až 83,1) |  |
| 0.4–0.6 | 699 | 83,5 % (80,6 až 86,1) | 85,3 % (82,4 až 87,7) |  |
| 0.6–0.8 | 663 | 78,6 % (75,3 až 81,5) | 80,5 % (77,4 až 83,4) |  |
| 0.8–1.0 | 653 | 80,2 % (77,0 až 83,1) | 82,1 % (79,0 až 84,8) |  |

### Osa: tempo

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| 0.5× | 568 | 82,0 % (78,7 až 85,0) | 84,0 % (80,7 až 86,8) |  |
| 1× | 1262 | 77,5 % (75,1 až 79,7) | 79,9 % (77,6 až 82,0) |  |
| 2× | 622 | 78,5 % (75,1 až 81,5) | 81,4 % (78,1 až 84,2) |  |
| 4× | 590 | 83,6 % (80,4 až 86,3) | 83,9 % (80,7 až 86,6) |  |

### Osa: rozptyl

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| 0 | 1174 | 80,7 % (78,4 až 82,9) | 82,5 % (80,2 až 84,5) |  |
| 0.15 | 946 | 78,2 % (75,5 až 80,7) | 80,2 % (77,6 až 82,6) |  |
| 0.3 | 922 | 79,9 % (77,2 až 82,4) | 82,3 % (79,7 až 84,6) |  |

### Osa: zdroje

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| 1 | 1276 | 79,2 % (76,8 až 81,3) | 80,3 % (78,1 až 82,4) |  |
| 3 | 1766 | 80,1 % (78,2 až 81,9) | 82,7 % (80,9 až 84,4) |  |

### Osa: doba

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| 0.5× | 605 | 72,2 % (68,5 až 75,7) | 74,7 % (71,1 až 78,0) |  |
| 1× | 1202 | 78,7 % (76,3 až 80,9) | 81,4 % (79,1 až 83,5) |  |
| 2× | 610 | 84,1 % (81,0 až 86,8) | 85,2 % (82,2 až 87,8) |  |
| 4× | 625 | 84,6 % (81,6 až 87,3) | 85,8 % (82,8 až 88,3) |  |

### Osa: objem

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| 0.25× | 606 | 79,0 % (75,6 až 82,1) | 80,4 % (77,0 až 83,3) |  |
| 0.5× | 605 | 77,9 % (74,4 až 81,0) | 79,8 % (76,5 až 82,8) |  |
| 1× | 1190 | 81,4 % (79,1 až 83,5) | 83,4 % (81,2 až 85,4) |  |
| 2× | 641 | 78,9 % (75,6 až 81,9) | 81,6 % (78,4 až 84,4) |  |

### Osa: mimo pracovní dobu

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| ano | 646 | 82,0 % (78,9 až 84,8) | 83,0 % (79,9 až 85,7) |  |
| ne | 2396 | 79,1 % (77,4 až 80,7) | 81,4 % (79,8 až 82,9) |  |

### Osa: míchání s provozem

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| ano | 889 | 80,4 % (77,7 až 82,9) | 81,7 % (79,0 až 84,1) |  |
| ne | 2153 | 79,4 % (77,7 až 81,1) | 81,7 % (80,1 až 83,3) |  |

### Osa: IDS signatura

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| ano | 793 | 93,2 % (91,2 až 94,7) | 94,5 % (92,6 až 95,8) |  |
| ne | 2249 | 75,0 % (73,1 až 76,7) | 77,2 % (75,5 až 78,9) |  |

### Rodiny

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| c2_beacon | 388 | 78,4 % (74,0 až 82,2) | 79,1 % (74,8 až 82,9) |  |
| credential_stuffing | 267 | 90,3 % (86,1 až 93,3) | 90,3 % (86,1 až 93,3) |  |
| ddos_volume | 104 | 88,5 % (80,9 až 93,3) | 88,5 % (80,9 až 93,3) |  |
| dns_tunnel | 164 | 86,0 % (79,8 až 90,5) | 87,2 % (81,2 až 91,5) |  |
| exfiltration | 289 | 89,3 % (85,2 až 92,3) | 89,3 % (85,2 až 92,3) |  |
| exploit_attempt | 309 | 46,3 % (40,8 až 51,8) | 46,9 % (41,4 až 52,5) | SLEPÉ MÍSTO |
| lateral_movement | 371 | 66,3 % (61,4 až 70,9) | 79,5 % (75,1 až 83,3) |  |
| port_scan_horizontal | 316 | 77,2 % (72,3 až 81,5) | 78,8 % (74,0 až 82,9) |  |
| port_scan_vertical | 297 | 86,9 % (82,6 až 90,2) | 86,9 % (82,6 až 90,2) |  |
| rogue_device | 81 | 90,1 % (81,7 až 94,9) | 90,1 % (81,7 až 94,9) |  |
| ssh_bruteforce | 456 | 93,2 % (90,5 až 95,2) | 93,2 % (90,5 až 95,2) |  |

### Rodina × pásmo S

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| c2_beacon | Q1 | 72 | 76,4 % (65,4 až 84,7) | 77,8 % (66,9 až 85,8) |  |
| c2_beacon | Q2 | 79 | 75,9 % (65,5 až 84,0) | 75,9 % (65,5 až 84,0) |  |
| c2_beacon | Q3 | 83 | 74,7 % (64,4 až 82,8) | 75,9 % (65,7 až 83,8) |  |
| c2_beacon | Q4 | 70 | 84,3 % (74,0 až 91,0) | 84,3 % (74,0 až 91,0) |  |
| c2_beacon | Q5 | 84 | 81,0 % (71,3 až 87,9) | 82,1 % (72,6 až 88,9) |  |
| credential_stuffing | Q1 | 54 | 96,3 % (87,5 až 99,0) | 96,3 % (87,5 až 99,0) |  |
| credential_stuffing | Q2 | 60 | 93,3 % (84,1 až 97,4) | 93,3 % (84,1 až 97,4) |  |
| credential_stuffing | Q3 | 43 | 88,4 % (75,5 až 94,9) | 90,7 % (78,4 až 96,3) |  |
| credential_stuffing | Q4 | 54 | 81,5 % (69,2 až 89,6) | 79,6 % (67,1 až 88,2) |  |
| credential_stuffing | Q5 | 56 | 91,1 % (80,7 až 96,1) | 91,1 % (80,7 až 96,1) |  |
| ddos_volume | Q1 | 24 | 95,8 % (79,8 až 99,3) | 95,8 % (79,8 až 99,3) |  |
| ddos_volume | Q2 | 24 | 91,7 % (74,2 až 97,7) | 91,7 % (74,2 až 97,7) |  |
| ddos_volume | Q3 | 21 | 90,5 % (71,1 až 97,3) | 90,5 % (71,1 až 97,3) |  |
| ddos_volume | Q4 | 16 | 87,5 % (64,0 až 96,5) | 87,5 % (64,0 až 96,5) | nedostatečná data |
| ddos_volume | Q5 | 19 | 73,7 % (51,2 až 88,2) | 73,7 % (51,2 až 88,2) | nedostatečná data |
| dns_tunnel | Q1 | 30 | 100,0 % (88,6 až 100,0) | 100,0 % (88,6 až 100,0) |  |
| dns_tunnel | Q2 | 23 | 91,3 % (73,2 až 97,6) | 91,3 % (73,2 až 97,6) |  |
| dns_tunnel | Q3 | 32 | 84,4 % (68,2 až 93,1) | 87,5 % (71,9 až 95,0) |  |
| dns_tunnel | Q4 | 32 | 81,2 % (64,7 až 91,1) | 84,4 % (68,2 až 93,1) |  |
| dns_tunnel | Q5 | 47 | 78,7 % (65,1 až 88,0) | 78,7 % (65,1 až 88,0) |  |
| exfiltration | Q1 | 46 | 89,1 % (77,0 až 95,3) | 89,1 % (77,0 až 95,3) |  |
| exfiltration | Q2 | 61 | 88,5 % (78,2 až 94,3) | 88,5 % (78,2 až 94,3) |  |
| exfiltration | Q3 | 74 | 94,6 % (86,9 až 97,9) | 94,6 % (86,9 až 97,9) |  |
| exfiltration | Q4 | 48 | 85,4 % (72,8 až 92,8) | 85,4 % (72,8 až 92,8) |  |
| exfiltration | Q5 | 60 | 86,7 % (75,8 až 93,1) | 86,7 % (75,8 až 93,1) |  |
| exploit_attempt | Q1 | 72 | 47,2 % (36,1 až 58,6) | 48,6 % (37,4 až 59,9) | SLEPÉ MÍSTO |
| exploit_attempt | Q2 | 61 | 44,3 % (32,5 až 56,7) | 45,9 % (34,0 až 58,3) | SLEPÉ MÍSTO |
| exploit_attempt | Q3 | 57 | 42,1 % (30,2 až 55,0) | 42,1 % (30,2 až 55,0) | SLEPÉ MÍSTO |
| exploit_attempt | Q4 | 60 | 46,7 % (34,6 až 59,1) | 46,7 % (34,6 až 59,1) | SLEPÉ MÍSTO |
| exploit_attempt | Q5 | 59 | 50,8 % (38,4 až 63,2) | 50,8 % (38,4 až 63,2) | slabé místo |
| lateral_movement | Q1 | 72 | 65,3 % (53,8 až 75,2) | 76,4 % (65,4 až 84,7) |  |
| lateral_movement | Q2 | 64 | 68,8 % (56,6 až 78,8) | 78,1 % (66,6 až 86,5) |  |
| lateral_movement | Q3 | 89 | 65,2 % (54,8 až 74,3) | 83,1 % (74,0 až 89,5) |  |
| lateral_movement | Q4 | 78 | 69,2 % (58,3 až 78,4) | 82,1 % (72,1 až 89,0) |  |
| lateral_movement | Q5 | 68 | 63,2 % (51,4 až 73,7) | 76,5 % (65,1 až 85,0) |  |
| port_scan_horizontal | Q1 | 62 | 79,0 % (67,4 až 87,3) | 80,6 % (69,1 až 88,6) |  |
| port_scan_horizontal | Q2 | 69 | 76,8 % (65,6 až 85,2) | 79,7 % (68,8 až 87,5) |  |
| port_scan_horizontal | Q3 | 59 | 78,0 % (65,9 až 86,6) | 79,7 % (67,7 až 88,0) |  |
| port_scan_horizontal | Q4 | 64 | 79,7 % (68,3 až 87,7) | 81,2 % (70,0 až 88,9) |  |
| port_scan_horizontal | Q5 | 62 | 72,6 % (60,4 až 82,1) | 72,6 % (60,4 až 82,1) |  |
| port_scan_vertical | Q1 | 64 | 87,5 % (77,2 až 93,5) | 87,5 % (77,2 až 93,5) |  |
| port_scan_vertical | Q2 | 55 | 85,5 % (73,8 až 92,4) | 85,5 % (73,8 až 92,4) |  |
| port_scan_vertical | Q3 | 50 | 84,0 % (71,5 až 91,7) | 84,0 % (71,5 až 91,7) |  |
| port_scan_vertical | Q4 | 71 | 93,0 % (84,6 až 97,0) | 93,0 % (84,6 až 97,0) |  |
| port_scan_vertical | Q5 | 57 | 82,5 % (70,6 až 90,2) | 82,5 % (70,6 až 90,2) |  |
| rogue_device | Q1 | 16 | 81,2 % (57,0 až 93,4) | 81,2 % (57,0 až 93,4) | nedostatečná data |
| rogue_device | Q2 | 14 | 85,7 % (60,1 až 96,0) | 85,7 % (60,1 až 96,0) | nedostatečná data |
| rogue_device | Q3 | 19 | 89,5 % (68,6 až 97,1) | 89,5 % (68,6 až 97,1) | nedostatečná data |
| rogue_device | Q4 | 13 | 92,3 % (66,7 až 98,6) | 92,3 % (66,7 až 98,6) | nedostatečná data |
| rogue_device | Q5 | 19 | 100,0 % (83,2 až 100,0) | 100,0 % (83,2 až 100,0) | nedostatečná data |
| ssh_bruteforce | Q1 | 95 | 91,6 % (84,3 až 95,7) | 91,6 % (84,3 až 95,7) |  |
| ssh_bruteforce | Q2 | 99 | 91,9 % (84,9 až 95,8) | 91,9 % (84,9 až 95,8) |  |
| ssh_bruteforce | Q3 | 84 | 91,7 % (83,8 až 95,9) | 91,7 % (83,8 až 95,9) |  |
| ssh_bruteforce | Q4 | 100 | 98,0 % (93,0 až 99,4) | 98,0 % (93,0 až 99,4) |  |
| ssh_bruteforce | Q5 | 78 | 92,3 % (84,2 až 96,4) | 92,3 % (84,2 až 96,4) |  |

### Rodina × osa (tempo, zdroje, objem)

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| c2_beacon | objem 0.25× | 79 | 82,3 % (72,4 až 89,1) | 82,3 % (72,4 až 89,1) |  |
| c2_beacon | objem 0.5× | 75 | 73,3 % (62,4 až 82,0) | 74,7 % (63,8 až 83,1) |  |
| c2_beacon | objem 1× | 153 | 76,5 % (69,2 až 82,5) | 77,8 % (70,6 až 83,6) |  |
| c2_beacon | objem 2× | 81 | 82,7 % (73,1 až 89,4) | 82,7 % (73,1 až 89,4) |  |
| c2_beacon | tempo 0.5× | 79 | 91,1 % (82,8 až 95,6) | 91,1 % (82,8 až 95,6) |  |
| c2_beacon | tempo 1× | 159 | 85,5 % (79,2 až 90,2) | 86,2 % (79,9 až 90,7) |  |
| c2_beacon | tempo 2× | 65 | 72,3 % (60,4 až 81,7) | 73,8 % (62,0 až 83,0) |  |
| c2_beacon | tempo 4× | 85 | 57,6 % (47,0 až 67,6) | 58,8 % (48,2 až 68,7) | slabé místo |
| c2_beacon | zdroje 1 | 149 | 71,1 % (63,4 až 77,8) | 71,8 % (64,1 až 78,4) |  |
| c2_beacon | zdroje 3 | 239 | 82,8 % (77,6 až 87,1) | 83,7 % (78,5 až 87,8) |  |
| credential_stuffing | objem 0.25× | 47 | 83,0 % (69,9 až 91,1) | 80,9 % (67,5 až 89,6) |  |
| credential_stuffing | objem 0.5× | 63 | 92,1 % (82,7 až 96,6) | 92,1 % (82,7 až 96,6) |  |
| credential_stuffing | objem 1× | 102 | 95,1 % (89,0 až 97,9) | 95,1 % (89,0 až 97,9) |  |
| credential_stuffing | objem 2× | 55 | 85,5 % (73,8 až 92,4) | 87,3 % (76,0 až 93,7) |  |
| credential_stuffing | tempo 0.5× | 39 | 76,9 % (61,7 až 87,4) | 76,9 % (61,7 až 87,4) |  |
| credential_stuffing | tempo 1× | 114 | 93,9 % (87,9 až 97,0) | 94,7 % (89,0 až 97,6) |  |
| credential_stuffing | tempo 2× | 63 | 95,2 % (86,9 až 98,4) | 95,2 % (86,9 až 98,4) |  |
| credential_stuffing | tempo 4× | 51 | 86,3 % (74,3 až 93,2) | 84,3 % (72,0 až 91,8) |  |
| credential_stuffing | zdroje 1 | 105 | 89,5 % (82,2 až 94,0) | 89,5 % (82,2 až 94,0) |  |
| credential_stuffing | zdroje 3 | 162 | 90,7 % (85,3 až 94,3) | 90,7 % (85,3 až 94,3) |  |
| ddos_volume | objem 0.25× | 21 | 85,7 % (65,4 až 95,0) | 85,7 % (65,4 až 95,0) |  |
| ddos_volume | objem 0.5× | 15 | 93,3 % (70,2 až 98,8) | 93,3 % (70,2 až 98,8) | nedostatečná data |
| ddos_volume | objem 1× | 42 | 88,1 % (75,0 až 94,8) | 88,1 % (75,0 až 94,8) |  |
| ddos_volume | objem 2× | 26 | 88,5 % (71,0 až 96,0) | 88,5 % (71,0 až 96,0) |  |
| ddos_volume | tempo 0.5× | 16 | 87,5 % (64,0 až 96,5) | 87,5 % (64,0 až 96,5) | nedostatečná data |
| ddos_volume | tempo 1× | 47 | 89,4 % (77,4 až 95,4) | 89,4 % (77,4 až 95,4) |  |
| ddos_volume | tempo 2× | 24 | 87,5 % (69,0 až 95,7) | 87,5 % (69,0 až 95,7) |  |
| ddos_volume | tempo 4× | 17 | 88,2 % (65,7 až 96,7) | 88,2 % (65,7 až 96,7) | nedostatečná data |
| ddos_volume | zdroje 1 | 40 | 90,0 % (76,9 až 96,0) | 90,0 % (76,9 až 96,0) |  |
| ddos_volume | zdroje 3 | 64 | 87,5 % (77,2 až 93,5) | 87,5 % (77,2 až 93,5) |  |
| dns_tunnel | objem 0.25× | 38 | 76,3 % (60,8 až 87,0) | 78,9 % (63,7 až 88,9) |  |
| dns_tunnel | objem 0.5× | 36 | 86,1 % (71,3 až 93,9) | 86,1 % (71,3 až 93,9) |  |
| dns_tunnel | objem 1× | 69 | 88,4 % (78,8 až 94,0) | 89,9 % (80,5 až 95,0) |  |
| dns_tunnel | objem 2× | 21 | 95,2 % (77,3 až 99,2) | 95,2 % (77,3 až 99,2) |  |
| dns_tunnel | tempo 0.5× | 35 | 85,7 % (70,6 až 93,7) | 88,6 % (74,0 až 95,5) |  |
| dns_tunnel | tempo 1× | 59 | 78,0 % (65,9 až 86,6) | 79,7 % (67,7 až 88,0) |  |
| dns_tunnel | tempo 2× | 40 | 90,0 % (76,9 až 96,0) | 90,0 % (76,9 až 96,0) |  |
| dns_tunnel | tempo 4× | 30 | 96,7 % (83,3 až 99,4) | 96,7 % (83,3 až 99,4) |  |
| dns_tunnel | zdroje 1 | 62 | 88,7 % (78,5 až 94,4) | 90,3 % (80,5 až 95,5) |  |
| dns_tunnel | zdroje 3 | 102 | 84,3 % (76,0 až 90,1) | 85,3 % (77,1 až 90,9) |  |
| exfiltration | objem 0.25× | 55 | 81,8 % (69,7 až 89,8) | 81,8 % (69,7 až 89,8) |  |
| exfiltration | objem 0.5× | 57 | 93,0 % (83,3 až 97,2) | 93,0 % (83,3 až 97,2) |  |
| exfiltration | objem 1× | 117 | 91,5 % (85,0 až 95,3) | 91,5 % (85,0 až 95,3) |  |
| exfiltration | objem 2× | 60 | 88,3 % (77,8 až 94,2) | 88,3 % (77,8 až 94,2) |  |
| exfiltration | tempo 0.5× | 61 | 91,8 % (82,2 až 96,4) | 91,8 % (82,2 až 96,4) |  |
| exfiltration | tempo 1× | 119 | 87,4 % (80,2 až 92,2) | 87,4 % (80,2 až 92,2) |  |
| exfiltration | tempo 2× | 61 | 88,5 % (78,2 až 94,3) | 88,5 % (78,2 až 94,3) |  |
| exfiltration | tempo 4× | 48 | 91,7 % (80,4 až 96,7) | 91,7 % (80,4 až 96,7) |  |
| exfiltration | zdroje 1 | 122 | 82,0 % (74,2 až 87,8) | 82,0 % (74,2 až 87,8) |  |
| exfiltration | zdroje 3 | 167 | 94,6 % (90,1 až 97,1) | 94,6 % (90,1 až 97,1) |  |
| exploit_attempt | objem 0.25× | 57 | 50,9 % (38,3 až 63,4) | 52,6 % (39,9 až 65,0) | slabé místo |
| exploit_attempt | objem 0.5× | 69 | 47,8 % (36,5 až 59,4) | 49,3 % (37,8 až 60,8) | SLEPÉ MÍSTO |
| exploit_attempt | objem 1× | 107 | 38,3 % (29,7 až 47,8) | 38,3 % (29,7 až 47,8) | SLEPÉ MÍSTO |
| exploit_attempt | objem 2× | 76 | 52,6 % (41,6 až 63,5) | 52,6 % (41,6 až 63,5) | slabé místo |
| exploit_attempt | tempo 0.5× | 65 | 53,8 % (41,9 až 65,4) | 53,8 % (41,9 až 65,4) | slabé místo |
| exploit_attempt | tempo 1× | 137 | 35,8 % (28,2 až 44,1) | 37,2 % (29,6 až 45,6) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 2× | 57 | 43,9 % (31,8 až 56,7) | 43,9 % (31,8 až 56,7) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 4× | 50 | 68,0 % (54,2 až 79,2) | 68,0 % (54,2 až 79,2) | slabé místo |
| exploit_attempt | zdroje 1 | 136 | 44,9 % (36,8 až 53,2) | 46,3 % (38,2 až 54,7) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 3 | 173 | 47,4 % (40,1 až 54,8) | 47,4 % (40,1 až 54,8) | SLEPÉ MÍSTO |
| lateral_movement | objem 0.25× | 71 | 69,0 % (57,5 až 78,6) | 78,9 % (68,0 až 86,8) |  |
| lateral_movement | objem 0.5× | 71 | 60,6 % (48,9 až 71,1) | 74,6 % (63,4 až 83,3) |  |
| lateral_movement | objem 1× | 165 | 72,7 % (65,5 až 78,9) | 83,6 % (77,2 až 88,5) |  |
| lateral_movement | objem 2× | 64 | 53,1 % (41,1 až 64,8) | 75,0 % (63,2 až 84,0) |  |
| lateral_movement | tempo 0.5× | 72 | 66,7 % (55,2 až 76,5) | 80,6 % (70,0 až 88,0) |  |
| lateral_movement | tempo 1× | 141 | 58,9 % (50,6 až 66,6) | 74,5 % (66,7 až 80,9) |  |
| lateral_movement | tempo 2× | 77 | 49,4 % (38,5 až 60,3) | 70,1 % (59,2 až 79,2) |  |
| lateral_movement | tempo 4× | 81 | 95,1 % (88,0 až 98,1) | 96,3 % (89,7 až 98,7) |  |
| lateral_movement | zdroje 1 | 170 | 70,0 % (62,7 až 76,4) | 76,5 % (69,6 až 82,2) |  |
| lateral_movement | zdroje 3 | 201 | 63,2 % (56,3 až 69,5) | 82,1 % (76,2 až 86,8) |  |
| port_scan_horizontal | objem 0.25× | 67 | 74,6 % (63,1 až 83,5) | 74,6 % (63,1 až 83,5) |  |
| port_scan_horizontal | objem 0.5× | 60 | 78,3 % (66,4 až 86,9) | 78,3 % (66,4 až 86,9) |  |
| port_scan_horizontal | objem 1× | 113 | 78,8 % (70,3 až 85,3) | 81,4 % (73,3 až 87,5) |  |
| port_scan_horizontal | objem 2× | 76 | 76,3 % (65,6 až 84,5) | 78,9 % (68,5 až 86,6) |  |
| port_scan_horizontal | tempo 0.5× | 54 | 75,9 % (63,1 až 85,4) | 75,9 % (63,1 až 85,4) |  |
| port_scan_horizontal | tempo 1× | 136 | 71,3 % (63,2 až 78,3) | 73,5 % (65,5 až 80,2) |  |
| port_scan_horizontal | tempo 2× | 57 | 77,2 % (64,8 až 86,2) | 78,9 % (66,7 až 87,5) |  |
| port_scan_horizontal | tempo 4× | 69 | 89,9 % (80,5 až 95,0) | 91,3 % (82,3 až 96,0) |  |
| port_scan_horizontal | zdroje 1 | 148 | 84,5 % (77,8 až 89,4) | 84,5 % (77,8 až 89,4) |  |
| port_scan_horizontal | zdroje 3 | 168 | 70,8 % (63,6 až 77,2) | 73,8 % (66,7 až 79,9) |  |
| port_scan_vertical | objem 0.25× | 61 | 80,3 % (68,7 až 88,4) | 80,3 % (68,7 až 88,4) |  |
| port_scan_vertical | objem 0.5× | 51 | 84,3 % (72,0 až 91,8) | 84,3 % (72,0 až 91,8) |  |
| port_scan_vertical | objem 1× | 118 | 91,5 % (85,1 až 95,3) | 91,5 % (85,1 až 95,3) |  |
| port_scan_vertical | objem 2× | 67 | 86,6 % (76,4 až 92,8) | 86,6 % (76,4 až 92,8) |  |
| port_scan_vertical | tempo 0.5× | 56 | 91,1 % (80,7 až 96,1) | 91,1 % (80,7 až 96,1) |  |
| port_scan_vertical | tempo 1× | 116 | 85,3 % (77,8 až 90,6) | 85,3 % (77,8 až 90,6) |  |
| port_scan_vertical | tempo 2× | 61 | 88,5 % (78,2 až 94,3) | 88,5 % (78,2 až 94,3) |  |
| port_scan_vertical | tempo 4× | 64 | 84,4 % (73,6 až 91,3) | 84,4 % (73,6 až 91,3) |  |
| port_scan_vertical | zdroje 1 | 106 | 87,7 % (80,1 až 92,7) | 87,7 % (80,1 až 92,7) |  |
| port_scan_vertical | zdroje 3 | 191 | 86,4 % (80,8 až 90,5) | 86,4 % (80,8 až 90,5) |  |
| rogue_device | objem 0.25× | 21 | 100,0 % (84,5 až 100,0) | 100,0 % (84,5 až 100,0) |  |
| rogue_device | objem 0.5× | 10 | 80,0 % (49,0 až 94,3) | 80,0 % (49,0 až 94,3) | nedostatečná data |
| rogue_device | objem 1× | 30 | 90,0 % (74,4 až 96,5) | 90,0 % (74,4 až 96,5) |  |
| rogue_device | objem 2× | 20 | 85,0 % (64,0 až 94,8) | 85,0 % (64,0 až 94,8) |  |
| rogue_device | tempo 0.5× | 12 | 100,0 % (75,8 až 100,0) | 100,0 % (75,8 až 100,0) | nedostatečná data |
| rogue_device | tempo 1× | 40 | 92,5 % (80,1 až 97,4) | 92,5 % (80,1 až 97,4) |  |
| rogue_device | tempo 2× | 16 | 75,0 % (50,5 až 89,8) | 75,0 % (50,5 až 89,8) | nedostatečná data |
| rogue_device | tempo 4× | 13 | 92,3 % (66,7 až 98,6) | 92,3 % (66,7 až 98,6) | nedostatečná data |
| rogue_device | zdroje 1 | 31 | 90,3 % (75,1 až 96,7) | 90,3 % (75,1 až 96,7) |  |
| rogue_device | zdroje 3 | 50 | 90,0 % (78,6 až 95,7) | 90,0 % (78,6 až 95,7) |  |
| ssh_bruteforce | objem 0.25× | 89 | 95,5 % (89,0 až 98,2) | 95,5 % (89,0 až 98,2) |  |
| ssh_bruteforce | objem 0.5× | 98 | 87,8 % (79,8 až 92,9) | 87,8 % (79,8 až 92,9) |  |
| ssh_bruteforce | objem 1× | 174 | 94,8 % (90,5 až 97,3) | 94,8 % (90,5 až 97,3) |  |
| ssh_bruteforce | objem 2× | 95 | 93,7 % (86,9 až 97,1) | 93,7 % (86,9 až 97,1) |  |
| ssh_bruteforce | tempo 0.5× | 79 | 97,5 % (91,2 až 99,3) | 97,5 % (91,2 až 99,3) |  |
| ssh_bruteforce | tempo 1× | 194 | 91,8 % (87,0 až 94,9) | 91,8 % (87,0 až 94,9) |  |
| ssh_bruteforce | tempo 2× | 101 | 96,0 % (90,3 až 98,4) | 96,0 % (90,3 až 98,4) |  |
| ssh_bruteforce | tempo 4× | 82 | 89,0 % (80,4 až 94,1) | 89,0 % (80,4 až 94,1) |  |
| ssh_bruteforce | zdroje 1 | 207 | 93,2 % (89,0 až 95,9) | 93,2 % (89,0 až 95,9) |  |
| ssh_bruteforce | zdroje 3 | 249 | 93,2 % (89,3 až 95,7) | 93,2 % (89,3 až 95,7) |  |

### Souběh útoku s provozní poruchou

| buňka | n | detekce v3 | detekce v3graph | registr |
|---|---:|---:|---:|---:|
| bez souběhu | 711 | 78,3 % (75,2 až 81,2) | 80,6 % (77,5 až 83,3) |  |
| nesenzorová porucha | 2118 | 81,1 % (79,3 až 82,7) | 83,0 % (81,3 až 84,5) |  |
| s backup_failed | 417 | 87,1 % (83,5 až 89,9) | 88,0 % (84,5 až 90,8) |  |
| s batch_job | 491 | 84,7 % (81,3 až 87,6) | 86,6 % (83,3 až 89,3) |  |
| s collector_replay | 387 | 85,3 % (81,4 až 88,5) | 86,6 % (82,8 až 89,6) |  |
| s device_decommission | 238 | 85,3 % (80,2 až 89,2) | 87,4 % (82,6 až 91,0) |  |
| s device_onboarding | 365 | 85,5 % (81,5 až 88,7) | 86,6 % (82,7 až 89,7) |  |
| s dhcp_renumber | 423 | 81,6 % (77,6 až 85,0) | 83,2 % (79,4 až 86,5) |  |
| s dns_outage | 428 | 87,4 % (83,9 až 90,2) | 89,0 % (85,7 až 91,6) |  |
| s link_flapping | 493 | 84,4 % (80,9 až 87,3) | 85,6 % (82,2 až 88,4) |  |
| s log_corruption | 321 | 86,3 % (82,1 až 89,6) | 88,8 % (84,9 až 91,8) |  |
| s misconfig | 397 | 85,9 % (82,1 až 89,0) | 87,4 % (83,8 až 90,3) |  |
| s patch_window | 359 | 85,5 % (81,5 až 88,8) | 86,1 % (82,1 až 89,3) |  |
| s retry_storm | 465 | 86,2 % (82,8 až 89,1) | 88,0 % (84,7 až 90,6) |  |
| s sensor_crash | 460 | 71,1 % (66,8 až 75,0) | 73,0 % (68,8 až 76,9) |  |
| s service_crash | 620 | 83,5 % (80,4 až 86,3) | 85,5 % (82,5 až 88,0) |  |
| senzorová porucha | 934 | 78,7 % (76,0 až 81,2) | 80,7 % (78,1 až 83,1) |  |

### Kampaně

| rameno | šablona | kampaní | aspoň jedna fáze | první fáze | všechny fáze |
|---|---:|---:|---:|---:|---:|
| v3 | K-T1 | 103 | 98,1 % (93,2 až 99,5) | 62,1 % (52,5 až 70,9) | 31,1 % (22,9 až 40,5) |
| v3 | K-T2 | 82 | 98,8 % (93,4 až 99,8) | 93,9 % (86,5 až 97,4) | 68,3 % (57,6 až 77,4) |
| v3 | K-T3 | 91 | 97,8 % (92,3 až 99,4) | 48,4 % (38,4 až 58,5) | 20,9 % (13,8 až 30,3) |
| v3 | vše | 276 | 98,2 % (95,8 až 99,2) | 67,0 % (61,3 až 72,3) | 38,8 % (33,2 až 44,6) |
| v3graph | K-T1 | 103 | 98,1 % (93,2 až 99,5) | 63,1 % (53,5 až 71,8) | 45,6 % (36,3 až 55,2) |
| v3graph | K-T2 | 82 | 98,8 % (93,4 až 99,8) | 93,9 % (86,5 až 97,4) | 68,3 % (57,6 až 77,4) |
| v3graph | K-T3 | 91 | 98,9 % (94,0 až 99,8) | 49,5 % (39,4 až 59,5) | 29,7 % (21,3 až 39,7) |
| v3graph | vše | 276 | 98,6 % (96,3 až 99,4) | 67,8 % (62,0 až 73,0) | 47,1 % (41,3 až 53,0) |

### Leave-one-family-out (náhrada A5), rameno `v3graph`

| rodina | vynechané typy D(X) | n | detekce všemi signály | obecná detekce | verdikt |
|---|---:|---:|---:|---:|---:|
| c2_beacon | beacon_periodic | 67 | 67,2 % (55,3 až 77,2) | 19,4 % (11,7 až 30,4) | SLEPÉ MÍSTO |
| exfiltration | egress_volume_anomaly, long_lived_tunnel | 70 | 85,7 % (75,7 až 92,1) | 7,1 % (3,1 až 15,7) | SLEPÉ MÍSTO |
| ssh_bruteforce | connection_timeout_burst, source_volume_outlier | 53 | 94,3 % (84,6 až 98,1) | 92,5 % (82,1 až 97,0) | zobecňuje |
| port_scan_vertical | connection_timeout_burst, scan_attempts | 61 | 86,9 % (76,2 až 93,2) | 4,9 % (1,7 až 13,5) | SLEPÉ MÍSTO |
| lateral_movement | multi_target_pattern, pivot_chain | 68 | 75,0 % (63,6 až 83,8) | 42,6 % (31,6 až 54,5) | SLEPÉ MÍSTO |
| dns_tunnel | egress_volume_anomaly, source_volume_outlier | 57 | 91,2 % (81,1 až 96,2) | 57,9 % (45,0 až 69,8) | zobecňuje |

### Útoky s automaticky zavřeným připsaným nálezem

| rameno | rodiny | útoků | podíl s automatickým zavřením | z toho první výskyt (A7) |
|---|---:|---:|---:|---:|
| v3 | laděné | 3042 | 0,9 % (0,6 až 1,3) | 12 |
| v3 | držené | 0 | – % (0,0 až 100,0) | 0 |
| v3graph | laděné | 3042 | 0,6 % (0,3 až 0,9) | 11 |
| v3graph | držené | 0 | – % (0,0 až 100,0) | 0 |

### Poruchy a lookalike: podíl výskytů s FP

| rameno | událost | výskytů | zobrazené FP | zachycené FP | registr |
|---|---:|---:|---:|---:|---:|
| v3 | authorized_scanner | 383 | 94,3 % (91,5 až 96,2) | 96,6 % (94,3 až 98,0) | FP SLEPÉ MÍSTO |
| v3 | backup_burst | 776 | 40,1 % (36,7 až 43,6) | 71,0 % (67,7 až 74,1) | FP SLEPÉ MÍSTO |
| v3 | backup_failed | 262 | 89,3 % (85,0 až 92,5) | 96,6 % (93,6 až 98,2) | FP SLEPÉ MÍSTO |
| v3 | batch_job | 276 | 64,1 % (58,3 až 69,6) | 84,8 % (80,1 až 88,5) | FP SLEPÉ MÍSTO |
| v3 | collector_replay | 254 | 76,8 % (71,2 až 81,5) | 94,5 % (91,0 až 96,7) | FP SLEPÉ MÍSTO |
| v3 | device_decommission | 161 | 9,9 % (6,2 až 15,5) | 21,7 % (16,1 až 28,7) |  |
| v3 | device_onboarding | 236 | 16,1 % (12,0 až 21,3) | 18,2 % (13,8 až 23,6) |  |
| v3 | dhcp_renumber | 270 | 75,6 % (70,1 až 80,3) | 78,5 % (73,2 až 83,0) | FP SLEPÉ MÍSTO |
| v3 | dns_outage | 298 | 85,2 % (80,8 až 88,8) | 97,7 % (95,2 až 98,9) | FP SLEPÉ MÍSTO |
| v3 | flash_crowd | 821 | 45,4 % (42,1 až 48,9) | 83,6 % (80,9 až 85,9) | FP SLEPÉ MÍSTO |
| v3 | link_flapping | 267 | 0,0 % (0,0 až 1,4) | 0,0 % (0,0 až 1,4) |  |
| v3 | log_corruption | 186 | 46,2 % (39,2 až 53,4) | 89,2 % (84,0 až 92,9) | FP SLEPÉ MÍSTO |
| v3 | misconfig | 266 | 97,0 % (94,2 až 98,5) | 97,7 % (95,2 až 99,0) | FP SLEPÉ MÍSTO |
| v3 | ntp_fanout | 413 | 4,8 % (3,2 až 7,4) | 16,7 % (13,4 až 20,6) |  |
| v3 | patch_window | 197 | 93,4 % (89,0 až 96,1) | 98,5 % (95,6 až 99,5) | FP SLEPÉ MÍSTO |
| v3 | retry_storm | 268 | 0,0 % (0,0 až 1,4) | 0,0 % (0,0 až 1,4) |  |
| v3 | sensor_crash | 235 | 14,0 % (10,2 až 19,1) | 14,0 % (10,2 až 19,1) |  |
| v3 | service_crash | 386 | 62,4 % (57,5 až 67,1) | 74,4 % (69,8 až 78,5) | FP SLEPÉ MÍSTO |
| v3 | software_update | 810 | 1,2 % (0,7 až 2,3) | 1,2 % (0,7 až 2,3) |  |
| v3graph | authorized_scanner | 383 | 94,3 % (91,5 až 96,2) | 96,6 % (94,3 až 98,0) | FP SLEPÉ MÍSTO |
| v3graph | backup_burst | 776 | 49,5 % (46,0 až 53,0) | 71,6 % (68,4 až 74,7) | FP SLEPÉ MÍSTO |
| v3graph | backup_failed | 262 | 90,1 % (85,9 až 93,1) | 96,6 % (93,6 až 98,2) | FP SLEPÉ MÍSTO |
| v3graph | batch_job | 276 | 78,3 % (73,0 až 82,7) | 84,8 % (80,1 až 88,5) | FP SLEPÉ MÍSTO |
| v3graph | collector_replay | 254 | 78,3 % (72,9 až 83,0) | 94,5 % (91,0 až 96,7) | FP SLEPÉ MÍSTO |
| v3graph | device_decommission | 161 | 10,6 % (6,7 až 16,3) | 21,7 % (16,1 až 28,7) |  |
| v3graph | device_onboarding | 236 | 16,5 % (12,3 až 21,8) | 18,2 % (13,8 až 23,6) |  |
| v3graph | dhcp_renumber | 270 | 78,1 % (72,8 až 82,7) | 79,6 % (74,4 až 84,0) | FP SLEPÉ MÍSTO |
| v3graph | dns_outage | 298 | 88,3 % (84,1 až 91,4) | 97,7 % (95,2 až 98,9) | FP SLEPÉ MÍSTO |
| v3graph | flash_crowd | 821 | 47,6 % (44,2 až 51,0) | 83,7 % (81,0 až 86,0) | FP SLEPÉ MÍSTO |
| v3graph | link_flapping | 267 | 0,0 % (0,0 až 1,4) | 0,0 % (0,0 až 1,4) |  |
| v3graph | log_corruption | 186 | 67,2 % (60,2 až 73,5) | 92,5 % (87,8 až 95,5) | FP SLEPÉ MÍSTO |
| v3graph | misconfig | 266 | 97,0 % (94,2 až 98,5) | 97,7 % (95,2 až 99,0) | FP SLEPÉ MÍSTO |
| v3graph | ntp_fanout | 413 | 5,8 % (3,9 až 8,5) | 17,2 % (13,9 až 21,1) |  |
| v3graph | patch_window | 197 | 94,4 % (90,3 až 96,9) | 98,5 % (95,6 až 99,5) | FP SLEPÉ MÍSTO |
| v3graph | retry_storm | 268 | 0,0 % (0,0 až 1,4) | 0,0 % (0,0 až 1,4) |  |
| v3graph | sensor_crash | 235 | 14,0 % (10,2 až 19,1) | 14,0 % (10,2 až 19,1) |  |
| v3graph | service_crash | 386 | 65,3 % (60,4 až 69,9) | 74,6 % (70,0 až 78,7) | FP SLEPÉ MÍSTO |
| v3graph | software_update | 810 | 1,2 % (0,7 až 2,3) | 1,2 % (0,7 až 2,3) |  |

### Registr slepých míst (rameno `v3graph`, automaticky podle A8)

| oblast | buňka | n | hodnota | zařazení |
|---|---:|---:|---:|---:|
| Rodiny | exploit_attempt | 309 | 46,9 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q1 | 72 | 48,6 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q2 | 61 | 45,9 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q3 | 57 | 42,1 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q4 | 60 | 46,7 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q5 | 59 | 50,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 4× | 85 | 58,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.25× | 57 | 52,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.5× | 69 | 49,3 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 1× | 107 | 38,3 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 2× | 76 | 52,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 0.5× | 65 | 53,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 1× | 137 | 37,2 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 2× | 57 | 43,9 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 4× | 50 | 68,0 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 1 | 136 | 46,3 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 3 | 173 | 47,4 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | c2_beacon | 67 | 19,4 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | exfiltration | 70 | 7,1 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | port_scan_vertical | 61 | 4,9 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | lateral_movement | 68 | 42,6 % | SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | authorized_scanner | 383 | 94,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | backup_burst | 776 | 49,5 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | backup_failed | 262 | 90,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | batch_job | 276 | 78,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | collector_replay | 254 | 78,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | dhcp_renumber | 270 | 78,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | dns_outage | 298 | 88,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | flash_crowd | 821 | 47,6 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | log_corruption | 186 | 67,2 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | misconfig | 266 | 97,0 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | patch_window | 197 | 94,4 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | service_crash | 386 | 65,3 % | FP SLEPÉ MÍSTO |

