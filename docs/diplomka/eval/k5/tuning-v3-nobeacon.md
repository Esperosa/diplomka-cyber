## Pokrytí, křivky skrytosti a registr slepých míst

Ramena: v3, v3nobeacon; hodnocené rameno `v3nobeacon`. Detekce = kontrafaktuální zobrazená detekce na útok (Wilson 95 %; souhrny a rozdíly s bootstrapem po sítích).

Hranice pásem S (zadané předem): 0.172, 0.236, 0.305, 0.392

| rameno | sítí | útoků | detekce (bootstrap) | zobrazené FP/síť-den | zavřeno omylem (G3) | panik/invariantů |
|---|---:|---:|---:|---:|---:|---:|
| v3 | 120 | 3042 | 79,7 % (76,2 až 82,5) | 18,8 | 1,7 % (1,3 až 2,1) [67/4023] | 0/0 |
| v3nobeacon | 120 | 3042 | 74,0 % (70,5 až 76,7) | 18,5 | 1,8 % (1,4 až 2,3) [64/3580] | 0/0 |

### Párově `v3nobeacon` − `v3`

| výběr | párů | rozdíl detekce |
|---|---:|---:|
| vše | 3042 | -5,7 p. b. (-6,6 až -4,9) |
| Q4 + Q5 | 1215 | -5,6 p. b. (-6,6 až -4,6) |
| Q5 | 609 | -5,4 p. b. (-7,1 až -3,9) |

### Křivka skrytosti: pásma S

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| Q1 | 607 | 80,2 % (76,9 až 83,2) | 75,6 % (72,0 až 78,9) |  |
| Q2 | 609 | 80,0 % (76,6 až 83,0) | 73,6 % (69,9 až 76,9) |  |
| Q3 | 611 | 78,6 % (75,1 až 81,6) | 72,2 % (68,5 až 75,6) |  |
| Q4 | 606 | 81,4 % (78,1 až 84,3) | 75,6 % (72,0 až 78,8) |  |
| Q5 | 609 | 78,5 % (75,1 až 81,6) | 73,1 % (69,4 až 76,4) |  |

### Osa: intenzita

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| 0.0–0.2 | 362 | 75,1 % (70,4 až 79,3) | 69,1 % (64,1 až 73,6) | slabé místo |
| 0.2–0.4 | 665 | 78,8 % (75,5 až 81,7) | 71,7 % (68,2 až 75,0) |  |
| 0.4–0.6 | 699 | 83,5 % (80,6 až 86,1) | 77,4 % (74,2 až 80,3) |  |
| 0.6–0.8 | 663 | 78,6 % (75,3 až 81,5) | 73,0 % (69,5 až 76,2) |  |
| 0.8–1.0 | 653 | 80,2 % (77,0 až 83,1) | 76,4 % (73,0 až 79,5) |  |

### Osa: tempo

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| 0.5× | 568 | 82,0 % (78,7 až 85,0) | 76,1 % (72,4 až 79,4) |  |
| 1× | 1262 | 77,5 % (75,1 až 79,7) | 71,1 % (68,5 až 73,5) |  |
| 2× | 622 | 78,5 % (75,1 až 81,5) | 73,8 % (70,2 až 77,1) |  |
| 4× | 590 | 83,6 % (80,4 až 86,3) | 78,5 % (75,0 až 81,6) |  |

### Osa: rozptyl

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| 0 | 1174 | 80,7 % (78,4 až 82,9) | 74,2 % (71,6 až 76,6) |  |
| 0.15 | 946 | 78,2 % (75,5 až 80,7) | 72,8 % (69,9 až 75,6) |  |
| 0.3 | 922 | 79,9 % (77,2 až 82,4) | 74,9 % (72,0 až 77,6) |  |

### Osa: zdroje

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| 1 | 1276 | 79,2 % (76,8 až 81,3) | 74,1 % (71,6 až 76,4) |  |
| 3 | 1766 | 80,1 % (78,2 až 81,9) | 74,0 % (71,9 až 75,9) |  |

### Osa: doba

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| 0.5× | 605 | 72,2 % (68,5 až 75,7) | 65,1 % (61,2 až 68,8) | slabé místo |
| 1× | 1202 | 78,7 % (76,3 až 80,9) | 73,5 % (70,9 až 75,9) |  |
| 2× | 610 | 84,1 % (81,0 až 86,8) | 78,2 % (74,7 až 81,3) |  |
| 4× | 625 | 84,6 % (81,6 až 87,3) | 79,5 % (76,2 až 82,5) |  |

### Osa: objem

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| 0.25× | 606 | 79,0 % (75,6 až 82,1) | 72,6 % (68,9 až 76,0) |  |
| 0.5× | 605 | 77,9 % (74,4 až 81,0) | 72,9 % (69,2 až 76,3) |  |
| 1× | 1190 | 81,4 % (79,1 až 83,5) | 76,1 % (73,6 až 78,5) |  |
| 2× | 641 | 78,9 % (75,6 až 81,9) | 72,4 % (68,8 až 75,7) |  |

### Osa: mimo pracovní dobu

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| ano | 646 | 82,0 % (78,9 až 84,8) | 77,7 % (74,3 až 80,7) |  |
| ne | 2396 | 79,1 % (77,4 až 80,7) | 73,0 % (71,2 až 74,7) |  |

### Osa: míchání s provozem

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| ano | 889 | 80,4 % (77,7 až 82,9) | 75,1 % (72,2 až 77,9) |  |
| ne | 2153 | 79,4 % (77,7 až 81,1) | 73,5 % (71,6 až 75,3) |  |

### Osa: IDS signatura

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| ano | 793 | 93,2 % (91,2 až 94,7) | 92,6 % (90,5 až 94,2) |  |
| ne | 2249 | 75,0 % (73,1 až 76,7) | 67,5 % (65,5 až 69,4) | slabé místo |

### Rodiny

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| c2_beacon | 388 | 78,4 % (74,0 až 82,2) | 34,8 % (30,2 až 39,7) | SLEPÉ MÍSTO |
| credential_stuffing | 267 | 90,3 % (86,1 až 93,3) | 89,9 % (85,7 až 93,0) |  |
| ddos_volume | 104 | 88,5 % (80,9 až 93,3) | 88,5 % (80,9 až 93,3) |  |
| dns_tunnel | 164 | 86,0 % (79,8 až 90,5) | 86,0 % (79,8 až 90,5) |  |
| exfiltration | 289 | 89,3 % (85,2 až 92,3) | 89,3 % (85,2 až 92,3) |  |
| exploit_attempt | 309 | 46,3 % (40,8 až 51,8) | 46,3 % (40,8 až 51,8) | SLEPÉ MÍSTO |
| lateral_movement | 371 | 66,3 % (61,4 až 70,9) | 65,5 % (60,5 až 70,2) | slabé místo |
| port_scan_horizontal | 316 | 77,2 % (72,3 až 81,5) | 76,9 % (71,9 až 81,2) |  |
| port_scan_vertical | 297 | 86,9 % (82,6 až 90,2) | 86,9 % (82,6 až 90,2) |  |
| rogue_device | 81 | 90,1 % (81,7 až 94,9) | 90,1 % (81,7 až 94,9) |  |
| ssh_bruteforce | 456 | 93,2 % (90,5 až 95,2) | 93,2 % (90,5 až 95,2) |  |

### Rodina × pásmo S

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| c2_beacon | Q1 | 72 | 76,4 % (65,4 až 84,7) | 38,9 % (28,5 až 50,4) | SLEPÉ MÍSTO |
| c2_beacon | Q2 | 79 | 75,9 % (65,5 až 84,0) | 29,1 % (20,3 až 39,9) | SLEPÉ MÍSTO |
| c2_beacon | Q3 | 83 | 74,7 % (64,4 až 82,8) | 27,7 % (19,2 až 38,2) | SLEPÉ MÍSTO |
| c2_beacon | Q4 | 70 | 84,3 % (74,0 až 91,0) | 37,1 % (26,8 až 48,9) | SLEPÉ MÍSTO |
| c2_beacon | Q5 | 84 | 81,0 % (71,3 až 87,9) | 41,7 % (31,7 až 52,3) | SLEPÉ MÍSTO |
| credential_stuffing | Q1 | 54 | 96,3 % (87,5 až 99,0) | 96,3 % (87,5 až 99,0) |  |
| credential_stuffing | Q2 | 60 | 93,3 % (84,1 až 97,4) | 93,3 % (84,1 až 97,4) |  |
| credential_stuffing | Q3 | 43 | 88,4 % (75,5 až 94,9) | 88,4 % (75,5 až 94,9) |  |
| credential_stuffing | Q4 | 54 | 81,5 % (69,2 až 89,6) | 79,6 % (67,1 až 88,2) |  |
| credential_stuffing | Q5 | 56 | 91,1 % (80,7 až 96,1) | 91,1 % (80,7 až 96,1) |  |
| ddos_volume | Q1 | 24 | 95,8 % (79,8 až 99,3) | 95,8 % (79,8 až 99,3) |  |
| ddos_volume | Q2 | 24 | 91,7 % (74,2 až 97,7) | 91,7 % (74,2 až 97,7) |  |
| ddos_volume | Q3 | 21 | 90,5 % (71,1 až 97,3) | 90,5 % (71,1 až 97,3) |  |
| ddos_volume | Q4 | 16 | 87,5 % (64,0 až 96,5) | 87,5 % (64,0 až 96,5) | nedostatečná data |
| ddos_volume | Q5 | 19 | 73,7 % (51,2 až 88,2) | 73,7 % (51,2 až 88,2) | nedostatečná data |
| dns_tunnel | Q1 | 30 | 100,0 % (88,6 až 100,0) | 100,0 % (88,6 až 100,0) |  |
| dns_tunnel | Q2 | 23 | 91,3 % (73,2 až 97,6) | 91,3 % (73,2 až 97,6) |  |
| dns_tunnel | Q3 | 32 | 84,4 % (68,2 až 93,1) | 84,4 % (68,2 až 93,1) |  |
| dns_tunnel | Q4 | 32 | 81,2 % (64,7 až 91,1) | 81,2 % (64,7 až 91,1) |  |
| dns_tunnel | Q5 | 47 | 78,7 % (65,1 až 88,0) | 78,7 % (65,1 až 88,0) |  |
| exfiltration | Q1 | 46 | 89,1 % (77,0 až 95,3) | 89,1 % (77,0 až 95,3) |  |
| exfiltration | Q2 | 61 | 88,5 % (78,2 až 94,3) | 88,5 % (78,2 až 94,3) |  |
| exfiltration | Q3 | 74 | 94,6 % (86,9 až 97,9) | 94,6 % (86,9 až 97,9) |  |
| exfiltration | Q4 | 48 | 85,4 % (72,8 až 92,8) | 85,4 % (72,8 až 92,8) |  |
| exfiltration | Q5 | 60 | 86,7 % (75,8 až 93,1) | 86,7 % (75,8 až 93,1) |  |
| exploit_attempt | Q1 | 72 | 47,2 % (36,1 až 58,6) | 47,2 % (36,1 až 58,6) | SLEPÉ MÍSTO |
| exploit_attempt | Q2 | 61 | 44,3 % (32,5 až 56,7) | 44,3 % (32,5 až 56,7) | SLEPÉ MÍSTO |
| exploit_attempt | Q3 | 57 | 42,1 % (30,2 až 55,0) | 42,1 % (30,2 až 55,0) | SLEPÉ MÍSTO |
| exploit_attempt | Q4 | 60 | 46,7 % (34,6 až 59,1) | 46,7 % (34,6 až 59,1) | SLEPÉ MÍSTO |
| exploit_attempt | Q5 | 59 | 50,8 % (38,4 až 63,2) | 50,8 % (38,4 až 63,2) | slabé místo |
| lateral_movement | Q1 | 72 | 65,3 % (53,8 až 75,2) | 63,9 % (52,4 až 74,0) | slabé místo |
| lateral_movement | Q2 | 64 | 68,8 % (56,6 až 78,8) | 65,6 % (53,4 až 76,1) | slabé místo |
| lateral_movement | Q3 | 89 | 65,2 % (54,8 až 74,3) | 65,2 % (54,8 až 74,3) | slabé místo |
| lateral_movement | Q4 | 78 | 69,2 % (58,3 až 78,4) | 69,2 % (58,3 až 78,4) | slabé místo |
| lateral_movement | Q5 | 68 | 63,2 % (51,4 až 73,7) | 63,2 % (51,4 až 73,7) | slabé místo |
| port_scan_horizontal | Q1 | 62 | 79,0 % (67,4 až 87,3) | 79,0 % (67,4 až 87,3) |  |
| port_scan_horizontal | Q2 | 69 | 76,8 % (65,6 až 85,2) | 76,8 % (65,6 až 85,2) |  |
| port_scan_horizontal | Q3 | 59 | 78,0 % (65,9 až 86,6) | 78,0 % (65,9 až 86,6) |  |
| port_scan_horizontal | Q4 | 64 | 79,7 % (68,3 až 87,7) | 78,1 % (66,6 až 86,5) |  |
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

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| c2_beacon | objem 0.25× | 79 | 82,3 % (72,4 až 89,1) | 34,2 % (24,7 až 45,2) | SLEPÉ MÍSTO |
| c2_beacon | objem 0.5× | 75 | 73,3 % (62,4 až 82,0) | 33,3 % (23,7 až 44,6) | SLEPÉ MÍSTO |
| c2_beacon | objem 1× | 153 | 76,5 % (69,2 až 82,5) | 36,6 % (29,4 až 44,5) | SLEPÉ MÍSTO |
| c2_beacon | objem 2× | 81 | 82,7 % (73,1 až 89,4) | 33,3 % (24,0 až 44,1) | SLEPÉ MÍSTO |
| c2_beacon | tempo 0.5× | 79 | 91,1 % (82,8 až 95,6) | 49,4 % (38,6 až 60,2) | SLEPÉ MÍSTO |
| c2_beacon | tempo 1× | 159 | 85,5 % (79,2 až 90,2) | 36,5 % (29,4 až 44,2) | SLEPÉ MÍSTO |
| c2_beacon | tempo 2× | 65 | 72,3 % (60,4 až 81,7) | 27,7 % (18,3 až 39,6) | SLEPÉ MÍSTO |
| c2_beacon | tempo 4× | 85 | 57,6 % (47,0 až 67,6) | 23,5 % (15,8 až 33,6) | SLEPÉ MÍSTO |
| c2_beacon | zdroje 1 | 149 | 71,1 % (63,4 až 77,8) | 28,2 % (21,6 až 35,9) | SLEPÉ MÍSTO |
| c2_beacon | zdroje 3 | 239 | 82,8 % (77,6 až 87,1) | 38,9 % (33,0 až 45,2) | SLEPÉ MÍSTO |
| credential_stuffing | objem 0.25× | 47 | 83,0 % (69,9 až 91,1) | 80,9 % (67,5 až 89,6) |  |
| credential_stuffing | objem 0.5× | 63 | 92,1 % (82,7 až 96,6) | 92,1 % (82,7 až 96,6) |  |
| credential_stuffing | objem 1× | 102 | 95,1 % (89,0 až 97,9) | 95,1 % (89,0 až 97,9) |  |
| credential_stuffing | objem 2× | 55 | 85,5 % (73,8 až 92,4) | 85,5 % (73,8 až 92,4) |  |
| credential_stuffing | tempo 0.5× | 39 | 76,9 % (61,7 až 87,4) | 76,9 % (61,7 až 87,4) |  |
| credential_stuffing | tempo 1× | 114 | 93,9 % (87,9 až 97,0) | 93,9 % (87,9 až 97,0) |  |
| credential_stuffing | tempo 2× | 63 | 95,2 % (86,9 až 98,4) | 95,2 % (86,9 až 98,4) |  |
| credential_stuffing | tempo 4× | 51 | 86,3 % (74,3 až 93,2) | 84,3 % (72,0 až 91,8) |  |
| credential_stuffing | zdroje 1 | 105 | 89,5 % (82,2 až 94,0) | 89,5 % (82,2 až 94,0) |  |
| credential_stuffing | zdroje 3 | 162 | 90,7 % (85,3 až 94,3) | 90,1 % (84,6 až 93,8) |  |
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
| dns_tunnel | objem 0.25× | 38 | 76,3 % (60,8 až 87,0) | 76,3 % (60,8 až 87,0) |  |
| dns_tunnel | objem 0.5× | 36 | 86,1 % (71,3 až 93,9) | 86,1 % (71,3 až 93,9) |  |
| dns_tunnel | objem 1× | 69 | 88,4 % (78,8 až 94,0) | 88,4 % (78,8 až 94,0) |  |
| dns_tunnel | objem 2× | 21 | 95,2 % (77,3 až 99,2) | 95,2 % (77,3 až 99,2) |  |
| dns_tunnel | tempo 0.5× | 35 | 85,7 % (70,6 až 93,7) | 85,7 % (70,6 až 93,7) |  |
| dns_tunnel | tempo 1× | 59 | 78,0 % (65,9 až 86,6) | 78,0 % (65,9 až 86,6) |  |
| dns_tunnel | tempo 2× | 40 | 90,0 % (76,9 až 96,0) | 90,0 % (76,9 až 96,0) |  |
| dns_tunnel | tempo 4× | 30 | 96,7 % (83,3 až 99,4) | 96,7 % (83,3 až 99,4) |  |
| dns_tunnel | zdroje 1 | 62 | 88,7 % (78,5 až 94,4) | 88,7 % (78,5 až 94,4) |  |
| dns_tunnel | zdroje 3 | 102 | 84,3 % (76,0 až 90,1) | 84,3 % (76,0 až 90,1) |  |
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
| exploit_attempt | objem 0.25× | 57 | 50,9 % (38,3 až 63,4) | 50,9 % (38,3 až 63,4) | slabé místo |
| exploit_attempt | objem 0.5× | 69 | 47,8 % (36,5 až 59,4) | 47,8 % (36,5 až 59,4) | SLEPÉ MÍSTO |
| exploit_attempt | objem 1× | 107 | 38,3 % (29,7 až 47,8) | 38,3 % (29,7 až 47,8) | SLEPÉ MÍSTO |
| exploit_attempt | objem 2× | 76 | 52,6 % (41,6 až 63,5) | 52,6 % (41,6 až 63,5) | slabé místo |
| exploit_attempt | tempo 0.5× | 65 | 53,8 % (41,9 až 65,4) | 53,8 % (41,9 až 65,4) | slabé místo |
| exploit_attempt | tempo 1× | 137 | 35,8 % (28,2 až 44,1) | 35,8 % (28,2 až 44,1) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 2× | 57 | 43,9 % (31,8 až 56,7) | 43,9 % (31,8 až 56,7) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 4× | 50 | 68,0 % (54,2 až 79,2) | 68,0 % (54,2 až 79,2) | slabé místo |
| exploit_attempt | zdroje 1 | 136 | 44,9 % (36,8 až 53,2) | 44,9 % (36,8 až 53,2) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 3 | 173 | 47,4 % (40,1 až 54,8) | 47,4 % (40,1 až 54,8) | SLEPÉ MÍSTO |
| lateral_movement | objem 0.25× | 71 | 69,0 % (57,5 až 78,6) | 69,0 % (57,5 až 78,6) | slabé místo |
| lateral_movement | objem 0.5× | 71 | 60,6 % (48,9 až 71,1) | 60,6 % (48,9 až 71,1) | slabé místo |
| lateral_movement | objem 1× | 165 | 72,7 % (65,5 až 78,9) | 71,5 % (64,2 až 77,9) |  |
| lateral_movement | objem 2× | 64 | 53,1 % (41,1 až 64,8) | 51,6 % (39,6 až 63,4) | slabé místo |
| lateral_movement | tempo 0.5× | 72 | 66,7 % (55,2 až 76,5) | 65,3 % (53,8 až 75,2) | slabé místo |
| lateral_movement | tempo 1× | 141 | 58,9 % (50,6 až 66,6) | 57,4 % (49,2 až 65,3) | slabé místo |
| lateral_movement | tempo 2× | 77 | 49,4 % (38,5 až 60,3) | 49,4 % (38,5 až 60,3) | SLEPÉ MÍSTO |
| lateral_movement | tempo 4× | 81 | 95,1 % (88,0 až 98,1) | 95,1 % (88,0 až 98,1) |  |
| lateral_movement | zdroje 1 | 170 | 70,0 % (62,7 až 76,4) | 69,4 % (62,1 až 75,8) | slabé místo |
| lateral_movement | zdroje 3 | 201 | 63,2 % (56,3 až 69,5) | 62,2 % (55,3 až 68,6) | slabé místo |
| port_scan_horizontal | objem 0.25× | 67 | 74,6 % (63,1 až 83,5) | 74,6 % (63,1 až 83,5) |  |
| port_scan_horizontal | objem 0.5× | 60 | 78,3 % (66,4 až 86,9) | 78,3 % (66,4 až 86,9) |  |
| port_scan_horizontal | objem 1× | 113 | 78,8 % (70,3 až 85,3) | 78,8 % (70,3 až 85,3) |  |
| port_scan_horizontal | objem 2× | 76 | 76,3 % (65,6 až 84,5) | 75,0 % (64,2 až 83,4) |  |
| port_scan_horizontal | tempo 0.5× | 54 | 75,9 % (63,1 až 85,4) | 75,9 % (63,1 až 85,4) |  |
| port_scan_horizontal | tempo 1× | 136 | 71,3 % (63,2 až 78,3) | 70,6 % (62,4 až 77,6) |  |
| port_scan_horizontal | tempo 2× | 57 | 77,2 % (64,8 až 86,2) | 77,2 % (64,8 až 86,2) |  |
| port_scan_horizontal | tempo 4× | 69 | 89,9 % (80,5 až 95,0) | 89,9 % (80,5 až 95,0) |  |
| port_scan_horizontal | zdroje 1 | 148 | 84,5 % (77,8 až 89,4) | 84,5 % (77,8 až 89,4) |  |
| port_scan_horizontal | zdroje 3 | 168 | 70,8 % (63,6 až 77,2) | 70,2 % (62,9 až 76,6) |  |
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

| buňka | n | detekce v3 | detekce v3nobeacon | registr |
|---|---:|---:|---:|---:|
| bez souběhu | 711 | 78,3 % (75,2 až 81,2) | 75,4 % (72,1 až 78,4) |  |
| nesenzorová porucha | 2118 | 81,1 % (79,3 až 82,7) | 74,1 % (72,2 až 75,9) |  |
| s backup_failed | 417 | 87,1 % (83,5 až 89,9) | 76,3 % (71,9 až 80,1) |  |
| s batch_job | 491 | 84,7 % (81,3 až 87,6) | 74,1 % (70,1 až 77,8) |  |
| s collector_replay | 387 | 85,3 % (81,4 až 88,5) | 73,4 % (68,8 až 77,5) |  |
| s device_decommission | 238 | 85,3 % (80,2 až 89,2) | 71,4 % (65,4 až 76,8) |  |
| s device_onboarding | 365 | 85,5 % (81,5 až 88,7) | 74,2 % (69,5 až 78,5) |  |
| s dhcp_renumber | 423 | 81,6 % (77,6 až 85,0) | 70,9 % (66,4 až 75,0) |  |
| s dns_outage | 428 | 87,4 % (83,9 až 90,2) | 77,8 % (73,6 až 81,5) |  |
| s link_flapping | 493 | 84,4 % (80,9 až 87,3) | 72,8 % (68,7 až 76,6) |  |
| s log_corruption | 321 | 86,3 % (82,1 až 89,6) | 74,5 % (69,4 až 78,9) |  |
| s misconfig | 397 | 85,9 % (82,1 až 89,0) | 75,3 % (70,8 až 79,3) |  |
| s patch_window | 359 | 85,5 % (81,5 až 88,8) | 76,9 % (72,2 až 80,9) |  |
| s retry_storm | 465 | 86,2 % (82,8 až 89,1) | 75,7 % (71,6 až 79,4) |  |
| s sensor_crash | 460 | 71,1 % (66,8 až 75,0) | 62,6 % (58,1 až 66,9) | slabé místo |
| s service_crash | 620 | 83,5 % (80,4 až 86,3) | 72,1 % (68,4 až 75,5) |  |
| senzorová porucha | 934 | 78,7 % (76,0 až 81,2) | 69,3 % (66,2 až 72,1) | slabé místo |

### Kampaně

| rameno | šablona | kampaní | aspoň jedna fáze | první fáze | všechny fáze |
|---|---:|---:|---:|---:|---:|
| v3 | K-T1 | 103 | 98,1 % (93,2 až 99,5) | 62,1 % (52,5 až 70,9) | 31,1 % (22,9 až 40,5) |
| v3 | K-T2 | 82 | 98,8 % (93,4 až 99,8) | 93,9 % (86,5 až 97,4) | 68,3 % (57,6 až 77,4) |
| v3 | K-T3 | 91 | 97,8 % (92,3 až 99,4) | 48,4 % (38,4 až 58,5) | 20,9 % (13,8 až 30,3) |
| v3 | vše | 276 | 98,2 % (95,8 až 99,2) | 67,0 % (61,3 až 72,3) | 38,8 % (33,2 až 44,6) |
| v3nobeacon | K-T1 | 103 | 98,1 % (93,2 až 99,5) | 62,1 % (52,5 až 70,9) | 31,1 % (22,9 až 40,5) |
| v3nobeacon | K-T2 | 82 | 97,6 % (91,5 až 99,3) | 93,9 % (86,5 až 97,4) | 42,7 % (32,5 až 53,5) |
| v3nobeacon | K-T3 | 91 | 95,6 % (89,2 až 98,3) | 48,4 % (38,4 až 58,5) | 9,9 % (5,3 až 17,7) |
| v3nobeacon | vše | 276 | 97,1 % (94,4 až 98,5) | 67,0 % (61,3 až 72,3) | 27,5 % (22,6 až 33,1) |

### Leave-one-family-out (náhrada A5), rameno `v3nobeacon`

| rodina | vynechané typy D(X) | n | detekce všemi signály | obecná detekce | verdikt |
|---|---:|---:|---:|---:|---:|
| c2_beacon | beacon_periodic | 67 | 13,4 % (7,2 až 23,6) | 11,9 % (6,2 až 21,8) | SLEPÉ MÍSTO |
| exfiltration | egress_volume_anomaly, long_lived_tunnel | 70 | 85,7 % (75,7 až 92,1) | 2,9 % (0,8 až 9,8) | SLEPÉ MÍSTO |
| ssh_bruteforce | connection_timeout_burst, source_volume_outlier | 53 | 94,3 % (84,6 až 98,1) | 92,5 % (82,1 až 97,0) | zobecňuje |
| port_scan_vertical | connection_timeout_burst, scan_attempts | 61 | 86,9 % (76,2 až 93,2) | 4,9 % (1,7 až 13,5) | SLEPÉ MÍSTO |
| lateral_movement | multi_target_pattern, pivot_chain | 68 | 66,2 % (54,3 až 76,3) | 42,6 % (31,6 až 54,5) | SLEPÉ MÍSTO |
| dns_tunnel | egress_volume_anomaly, source_volume_outlier | 57 | 91,2 % (81,1 až 96,2) | 56,1 % (43,3 až 68,2) | zobecňuje |

### Útoky s automaticky zavřeným připsaným nálezem

| rameno | rodiny | útoků | podíl s automatickým zavřením | z toho první výskyt (A7) |
|---|---:|---:|---:|---:|
| v3 | laděné | 3042 | 0,9 % (0,6 až 1,3) | 12 |
| v3 | držené | 0 | – % (0,0 až 100,0) | 0 |
| v3nobeacon | laděné | 3042 | 0,8 % (0,6 až 1,2) | 10 |
| v3nobeacon | držené | 0 | – % (0,0 až 100,0) | 0 |

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
| v3nobeacon | authorized_scanner | 383 | 94,0 % (91,2 až 96,0) | 96,6 % (94,3 až 98,0) | FP SLEPÉ MÍSTO |
| v3nobeacon | backup_burst | 776 | 39,9 % (36,6 až 43,4) | 70,7 % (67,5 až 73,8) | FP SLEPÉ MÍSTO |
| v3nobeacon | backup_failed | 262 | 89,3 % (85,0 až 92,5) | 96,6 % (93,6 až 98,2) | FP SLEPÉ MÍSTO |
| v3nobeacon | batch_job | 276 | 65,6 % (59,8 až 70,9) | 84,8 % (80,1 až 88,5) | FP SLEPÉ MÍSTO |
| v3nobeacon | collector_replay | 254 | 77,2 % (71,6 až 81,9) | 94,5 % (91,0 až 96,7) | FP SLEPÉ MÍSTO |
| v3nobeacon | device_decommission | 161 | 9,9 % (6,2 až 15,5) | 20,5 % (15,0 až 27,4) |  |
| v3nobeacon | device_onboarding | 236 | 16,1 % (12,0 až 21,3) | 18,2 % (13,8 až 23,6) |  |
| v3nobeacon | dhcp_renumber | 270 | 74,8 % (69,3 až 79,6) | 78,5 % (73,2 až 83,0) | FP SLEPÉ MÍSTO |
| v3nobeacon | dns_outage | 298 | 86,2 % (81,9 až 89,7) | 97,7 % (95,2 až 98,9) | FP SLEPÉ MÍSTO |
| v3nobeacon | flash_crowd | 821 | 45,3 % (41,9 až 48,7) | 83,4 % (80,7 až 85,8) | FP SLEPÉ MÍSTO |
| v3nobeacon | link_flapping | 267 | 0,0 % (0,0 až 1,4) | 0,0 % (0,0 až 1,4) |  |
| v3nobeacon | log_corruption | 186 | 46,2 % (39,2 až 53,4) | 89,2 % (84,0 až 92,9) | FP SLEPÉ MÍSTO |
| v3nobeacon | misconfig | 266 | 97,0 % (94,2 až 98,5) | 97,7 % (95,2 až 99,0) | FP SLEPÉ MÍSTO |
| v3nobeacon | ntp_fanout | 413 | 4,8 % (3,2 až 7,4) | 16,2 % (13,0 až 20,1) |  |
| v3nobeacon | patch_window | 197 | 93,9 % (89,7 až 96,5) | 98,5 % (95,6 až 99,5) | FP SLEPÉ MÍSTO |
| v3nobeacon | retry_storm | 268 | 0,0 % (0,0 až 1,4) | 0,0 % (0,0 až 1,4) |  |
| v3nobeacon | sensor_crash | 235 | 13,2 % (9,5 až 18,1) | 13,2 % (9,5 až 18,1) |  |
| v3nobeacon | service_crash | 386 | 61,9 % (57,0 až 66,6) | 74,4 % (69,8 až 78,5) | FP SLEPÉ MÍSTO |
| v3nobeacon | software_update | 810 | 1,2 % (0,7 až 2,3) | 1,2 % (0,7 až 2,3) |  |

### Registr slepých míst (rameno `v3nobeacon`, automaticky podle A8)

| oblast | buňka | n | hodnota | zařazení |
|---|---:|---:|---:|---:|
| Osa: intenzita | 0.0–0.2 | 362 | 69,1 % | slabé místo |
| Osa: doba | 0.5× | 605 | 65,1 % | slabé místo |
| Osa: IDS signatura | ne | 2249 | 67,5 % | slabé místo |
| Rodiny | c2_beacon | 388 | 34,8 % | SLEPÉ MÍSTO |
| Rodiny | exploit_attempt | 309 | 46,3 % | SLEPÉ MÍSTO |
| Rodiny | lateral_movement | 371 | 65,5 % | slabé místo |
| Rodina × pásmo S | c2_beacon | Q1 | 72 | 38,9 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | c2_beacon | Q2 | 79 | 29,1 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | c2_beacon | Q3 | 83 | 27,7 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | c2_beacon | Q4 | 70 | 37,1 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | c2_beacon | Q5 | 84 | 41,7 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q1 | 72 | 47,2 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q2 | 61 | 44,3 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q3 | 57 | 42,1 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q4 | 60 | 46,7 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q5 | 59 | 50,8 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q1 | 72 | 63,9 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q2 | 64 | 65,6 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q3 | 89 | 65,2 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q4 | 78 | 69,2 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q5 | 68 | 63,2 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | objem 0.25× | 79 | 34,2 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | objem 0.5× | 75 | 33,3 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | objem 1× | 153 | 36,6 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | objem 2× | 81 | 33,3 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 0.5× | 79 | 49,4 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 1× | 159 | 36,5 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 2× | 65 | 27,7 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 4× | 85 | 23,5 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | zdroje 1 | 149 | 28,2 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | zdroje 3 | 239 | 38,9 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.25× | 57 | 50,9 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.5× | 69 | 47,8 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 1× | 107 | 38,3 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 2× | 76 | 52,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 0.5× | 65 | 53,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 1× | 137 | 35,8 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 2× | 57 | 43,9 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 4× | 50 | 68,0 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 1 | 136 | 44,9 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 3 | 173 | 47,4 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 0.25× | 71 | 69,0 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 0.5× | 71 | 60,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 2× | 64 | 51,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 0.5× | 72 | 65,3 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 1× | 141 | 57,4 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 2× | 77 | 49,4 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | zdroje 1 | 170 | 69,4 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | zdroje 3 | 201 | 62,2 % | slabé místo |
| Souběh útoku s provozní poruchou | s sensor_crash | 460 | 62,6 % | slabé místo |
| Souběh útoku s provozní poruchou | senzorová porucha | 934 | 69,3 % | slabé místo |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | c2_beacon | 67 | 11,9 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | exfiltration | 70 | 2,9 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | port_scan_vertical | 61 | 4,9 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | lateral_movement | 68 | 42,6 % | SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | authorized_scanner | 383 | 94,0 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | backup_burst | 776 | 39,9 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | backup_failed | 262 | 89,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | batch_job | 276 | 65,6 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | collector_replay | 254 | 77,2 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | dhcp_renumber | 270 | 74,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | dns_outage | 298 | 86,2 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | flash_crowd | 821 | 45,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | log_corruption | 186 | 46,2 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | misconfig | 266 | 97,0 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | patch_window | 197 | 93,9 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | service_crash | 386 | 61,9 % | FP SLEPÉ MÍSTO |

