## Pokrytí, křivky skrytosti a registr slepých míst

Ramena: legacy, v3; hodnocené rameno `v3`. Detekce = kontrafaktuální zobrazená detekce na útok (Wilson 95 %; souhrny a rozdíly s bootstrapem po sítích).

Hranice pásem S (zadané předem): 0.172, 0.236, 0.305, 0.392

| rameno | sítí | útoků | detekce (bootstrap) | zobrazené FP/síť-den | zavřeno omylem (G3) | panik/invariantů |
|---|---:|---:|---:|---:|---:|---:|
| legacy | 120 | 3042 | 56,6 % (52,9 až 60,0) | 969,6 | – % (0,0 až 100,0) [0/0] | 0/0 |
| v3 | 120 | 3042 | 79,7 % (76,2 až 82,5) | 18,8 | 1,7 % (1,3 až 2,1) [67/4023] | 0/0 |

### Párově `v3` − `legacy`

| výběr | párů | rozdíl detekce |
|---|---:|---:|
| vše | 3042 | +23,1 p. b. (+20,6 až +25,7) |
| Q4 + Q5 | 1215 | +23,3 p. b. (+19,8 až +26,8) |
| Q5 | 609 | +25,6 p. b. (+20,8 až +30,3) |

### Křivka skrytosti: pásma S

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| Q1 | 607 | 58,5 % (54,5 až 62,3) | 80,2 % (76,9 až 83,2) |  |
| Q2 | 609 | 57,3 % (53,3 až 61,2) | 80,0 % (76,6 až 83,0) |  |
| Q3 | 611 | 54,0 % (50,0 až 57,9) | 78,6 % (75,1 až 81,6) |  |
| Q4 | 606 | 60,4 % (56,4 až 64,2) | 81,4 % (78,1 až 84,3) |  |
| Q5 | 609 | 52,9 % (48,9 až 56,8) | 78,5 % (75,1 až 81,6) |  |

### Osa: intenzita

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0.0–0.2 | 362 | 56,6 % (51,5 až 61,6) | 75,1 % (70,4 až 79,3) |  |
| 0.2–0.4 | 665 | 55,9 % (52,1 až 59,7) | 78,8 % (75,5 až 81,7) |  |
| 0.4–0.6 | 699 | 57,2 % (53,5 až 60,8) | 83,5 % (80,6 až 86,1) |  |
| 0.6–0.8 | 663 | 55,4 % (51,6 až 59,1) | 78,6 % (75,3 až 81,5) |  |
| 0.8–1.0 | 653 | 57,9 % (54,1 až 61,6) | 80,2 % (77,0 až 83,1) |  |

### Osa: tempo

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0.5× | 568 | 57,0 % (52,9 až 61,1) | 82,0 % (78,7 až 85,0) |  |
| 1× | 1262 | 51,3 % (48,5 až 54,0) | 77,5 % (75,1 až 79,7) |  |
| 2× | 622 | 60,8 % (56,9 až 64,5) | 78,5 % (75,1 až 81,5) |  |
| 4× | 590 | 63,2 % (59,3 až 67,0) | 83,6 % (80,4 až 86,3) |  |

### Osa: rozptyl

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0 | 1174 | 57,2 % (54,3 až 60,0) | 80,7 % (78,4 až 82,9) |  |
| 0.15 | 946 | 55,8 % (52,6 až 58,9) | 78,2 % (75,5 až 80,7) |  |
| 0.3 | 922 | 56,7 % (53,5 až 59,9) | 79,9 % (77,2 až 82,4) |  |

### Osa: zdroje

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 1 | 1276 | 56,6 % (53,8 až 59,3) | 79,2 % (76,8 až 81,3) |  |
| 3 | 1766 | 56,6 % (54,3 až 58,9) | 80,1 % (78,2 až 81,9) |  |

### Osa: doba

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0.5× | 605 | 52,1 % (48,1 až 56,0) | 72,2 % (68,5 až 75,7) |  |
| 1× | 1202 | 56,4 % (53,6 až 59,2) | 78,7 % (76,3 až 80,9) |  |
| 2× | 610 | 56,6 % (52,6 až 60,4) | 84,1 % (81,0 až 86,8) |  |
| 4× | 625 | 61,4 % (57,6 až 65,2) | 84,6 % (81,6 až 87,3) |  |

### Osa: objem

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0.25× | 606 | 54,3 % (50,3 až 58,2) | 79,0 % (75,6 až 82,1) |  |
| 0.5× | 605 | 53,4 % (49,4 až 57,3) | 77,9 % (74,4 až 81,0) |  |
| 1× | 1190 | 59,4 % (56,6 až 62,2) | 81,4 % (79,1 až 83,5) |  |
| 2× | 641 | 56,6 % (52,8 až 60,4) | 78,9 % (75,6 až 81,9) |  |

### Osa: mimo pracovní dobu

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| ano | 646 | 60,2 % (56,4 až 63,9) | 82,0 % (78,9 až 84,8) |  |
| ne | 2396 | 55,6 % (53,6 až 57,6) | 79,1 % (77,4 až 80,7) |  |

### Osa: míchání s provozem

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| ano | 889 | 56,6 % (53,3 až 59,8) | 80,4 % (77,7 až 82,9) |  |
| ne | 2153 | 56,6 % (54,5 až 58,7) | 79,4 % (77,7 až 81,1) |  |

### Osa: IDS signatura

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| ano | 793 | 64,9 % (61,6 až 68,2) | 93,2 % (91,2 až 94,7) |  |
| ne | 2249 | 53,7 % (51,6 až 55,7) | 75,0 % (73,1 až 76,7) |  |

### Rodiny

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| c2_beacon | 388 | 26,3 % (22,2 až 30,9) | 78,4 % (74,0 až 82,2) |  |
| credential_stuffing | 267 | 85,0 % (80,2 až 88,8) | 90,3 % (86,1 až 93,3) |  |
| ddos_volume | 104 | 88,5 % (80,9 až 93,3) | 88,5 % (80,9 až 93,3) |  |
| dns_tunnel | 164 | 42,1 % (34,8 až 49,7) | 86,0 % (79,8 až 90,5) |  |
| exfiltration | 289 | 13,8 % (10,3 až 18,3) | 89,3 % (85,2 až 92,3) |  |
| exploit_attempt | 309 | 24,6 % (20,1 až 29,7) | 46,3 % (40,8 až 51,8) | SLEPÉ MÍSTO |
| lateral_movement | 371 | 71,2 % (66,4 až 75,5) | 66,3 % (61,4 až 70,9) | slabé místo |
| port_scan_horizontal | 316 | 78,5 % (73,6 až 82,7) | 77,2 % (72,3 až 81,5) |  |
| port_scan_vertical | 297 | 57,9 % (52,2 až 63,4) | 86,9 % (82,6 až 90,2) |  |
| rogue_device | 81 | 34,6 % (25,1 až 45,4) | 90,1 % (81,7 až 94,9) |  |
| ssh_bruteforce | 456 | 88,6 % (85,4 až 91,2) | 93,2 % (90,5 až 95,2) |  |

### Rodina × pásmo S

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| c2_beacon | Q1 | 72 | 25,0 % (16,4 až 36,1) | 76,4 % (65,4 až 84,7) |  |
| c2_beacon | Q2 | 79 | 21,5 % (13,9 až 31,8) | 75,9 % (65,5 až 84,0) |  |
| c2_beacon | Q3 | 83 | 21,7 % (14,2 až 31,7) | 74,7 % (64,4 až 82,8) |  |
| c2_beacon | Q4 | 70 | 31,4 % (21,8 až 43,0) | 84,3 % (74,0 až 91,0) |  |
| c2_beacon | Q5 | 84 | 32,1 % (23,1 až 42,7) | 81,0 % (71,3 až 87,9) |  |
| credential_stuffing | Q1 | 54 | 94,4 % (84,9 až 98,1) | 96,3 % (87,5 až 99,0) |  |
| credential_stuffing | Q2 | 60 | 88,3 % (77,8 až 94,2) | 93,3 % (84,1 až 97,4) |  |
| credential_stuffing | Q3 | 43 | 79,1 % (64,8 až 88,6) | 88,4 % (75,5 až 94,9) |  |
| credential_stuffing | Q4 | 54 | 83,3 % (71,3 až 91,0) | 81,5 % (69,2 až 89,6) |  |
| credential_stuffing | Q5 | 56 | 78,6 % (66,2 až 87,3) | 91,1 % (80,7 až 96,1) |  |
| ddos_volume | Q1 | 24 | 95,8 % (79,8 až 99,3) | 95,8 % (79,8 až 99,3) |  |
| ddos_volume | Q2 | 24 | 91,7 % (74,2 až 97,7) | 91,7 % (74,2 až 97,7) |  |
| ddos_volume | Q3 | 21 | 90,5 % (71,1 až 97,3) | 90,5 % (71,1 až 97,3) |  |
| ddos_volume | Q4 | 16 | 87,5 % (64,0 až 96,5) | 87,5 % (64,0 až 96,5) | nedostatečná data |
| ddos_volume | Q5 | 19 | 73,7 % (51,2 až 88,2) | 73,7 % (51,2 až 88,2) | nedostatečná data |
| dns_tunnel | Q1 | 30 | 50,0 % (33,2 až 66,8) | 100,0 % (88,6 až 100,0) |  |
| dns_tunnel | Q2 | 23 | 34,8 % (18,8 až 55,1) | 91,3 % (73,2 až 97,6) |  |
| dns_tunnel | Q3 | 32 | 40,6 % (25,5 až 57,7) | 84,4 % (68,2 až 93,1) |  |
| dns_tunnel | Q4 | 32 | 40,6 % (25,5 až 57,7) | 81,2 % (64,7 až 91,1) |  |
| dns_tunnel | Q5 | 47 | 42,6 % (29,5 až 56,7) | 78,7 % (65,1 až 88,0) |  |
| exfiltration | Q1 | 46 | 13,0 % (6,1 až 25,7) | 89,1 % (77,0 až 95,3) |  |
| exfiltration | Q2 | 61 | 13,1 % (6,8 až 23,8) | 88,5 % (78,2 až 94,3) |  |
| exfiltration | Q3 | 74 | 17,6 % (10,6 až 27,8) | 94,6 % (86,9 až 97,9) |  |
| exfiltration | Q4 | 48 | 12,5 % (5,9 až 24,7) | 85,4 % (72,8 až 92,8) |  |
| exfiltration | Q5 | 60 | 11,7 % (5,8 až 22,2) | 86,7 % (75,8 až 93,1) |  |
| exploit_attempt | Q1 | 72 | 15,3 % (8,8 až 25,3) | 47,2 % (36,1 až 58,6) | SLEPÉ MÍSTO |
| exploit_attempt | Q2 | 61 | 24,6 % (15,5 až 36,7) | 44,3 % (32,5 až 56,7) | SLEPÉ MÍSTO |
| exploit_attempt | Q3 | 57 | 26,3 % (16,6 až 39,0) | 42,1 % (30,2 až 55,0) | SLEPÉ MÍSTO |
| exploit_attempt | Q4 | 60 | 28,3 % (18,5 až 40,8) | 46,7 % (34,6 až 59,1) | SLEPÉ MÍSTO |
| exploit_attempt | Q5 | 59 | 30,5 % (20,3 až 43,1) | 50,8 % (38,4 až 63,2) | slabé místo |
| lateral_movement | Q1 | 72 | 73,6 % (62,4 až 82,4) | 65,3 % (53,8 až 75,2) | slabé místo |
| lateral_movement | Q2 | 64 | 73,4 % (61,5 až 82,7) | 68,8 % (56,6 až 78,8) | slabé místo |
| lateral_movement | Q3 | 89 | 67,4 % (57,1 až 76,3) | 65,2 % (54,8 až 74,3) | slabé místo |
| lateral_movement | Q4 | 78 | 70,5 % (59,6 až 79,5) | 69,2 % (58,3 až 78,4) | slabé místo |
| lateral_movement | Q5 | 68 | 72,1 % (60,4 až 81,3) | 63,2 % (51,4 až 73,7) | slabé místo |
| port_scan_horizontal | Q1 | 62 | 83,9 % (72,8 až 91,0) | 79,0 % (67,4 až 87,3) |  |
| port_scan_horizontal | Q2 | 69 | 72,5 % (61,0 až 81,6) | 76,8 % (65,6 až 85,2) |  |
| port_scan_horizontal | Q3 | 59 | 83,1 % (71,5 až 90,5) | 78,0 % (65,9 až 86,6) |  |
| port_scan_horizontal | Q4 | 64 | 81,2 % (70,0 až 88,9) | 79,7 % (68,3 až 87,7) |  |
| port_scan_horizontal | Q5 | 62 | 72,6 % (60,4 až 82,1) | 72,6 % (60,4 až 82,1) |  |
| port_scan_vertical | Q1 | 64 | 64,1 % (51,8 až 74,7) | 87,5 % (77,2 až 93,5) |  |
| port_scan_vertical | Q2 | 55 | 58,2 % (45,0 až 70,3) | 85,5 % (73,8 až 92,4) |  |
| port_scan_vertical | Q3 | 50 | 62,0 % (48,2 až 74,1) | 84,0 % (71,5 až 91,7) |  |
| port_scan_vertical | Q4 | 71 | 60,6 % (48,9 až 71,1) | 93,0 % (84,6 až 97,0) |  |
| port_scan_vertical | Q5 | 57 | 43,9 % (31,8 až 56,7) | 82,5 % (70,6 až 90,2) |  |
| rogue_device | Q1 | 16 | 25,0 % (10,2 až 49,5) | 81,2 % (57,0 až 93,4) | nedostatečná data |
| rogue_device | Q2 | 14 | 50,0 % (26,8 až 73,2) | 85,7 % (60,1 až 96,0) | nedostatečná data |
| rogue_device | Q3 | 19 | 26,3 % (11,8 až 48,8) | 89,5 % (68,6 až 97,1) | nedostatečná data |
| rogue_device | Q4 | 13 | 38,5 % (17,7 až 64,5) | 92,3 % (66,7 až 98,6) | nedostatečná data |
| rogue_device | Q5 | 19 | 36,8 % (19,1 až 59,0) | 100,0 % (83,2 až 100,0) | nedostatečná data |
| ssh_bruteforce | Q1 | 95 | 85,3 % (76,8 až 91,0) | 91,6 % (84,3 až 95,7) |  |
| ssh_bruteforce | Q2 | 99 | 90,9 % (83,6 až 95,1) | 91,9 % (84,9 až 95,8) |  |
| ssh_bruteforce | Q3 | 84 | 86,9 % (78,1 až 92,5) | 91,7 % (83,8 až 95,9) |  |
| ssh_bruteforce | Q4 | 100 | 94,0 % (87,5 až 97,2) | 98,0 % (93,0 až 99,4) |  |
| ssh_bruteforce | Q5 | 78 | 84,6 % (75,0 až 91,0) | 92,3 % (84,2 až 96,4) |  |

### Rodina × osa (tempo, zdroje, objem)

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| c2_beacon | objem 0.25× | 79 | 26,6 % (18,1 až 37,2) | 82,3 % (72,4 až 89,1) |  |
| c2_beacon | objem 0.5× | 75 | 20,0 % (12,5 až 30,4) | 73,3 % (62,4 až 82,0) |  |
| c2_beacon | objem 1× | 153 | 30,1 % (23,4 až 37,7) | 76,5 % (69,2 až 82,5) |  |
| c2_beacon | objem 2× | 81 | 24,7 % (16,6 až 35,1) | 82,7 % (73,1 až 89,4) |  |
| c2_beacon | tempo 0.5× | 79 | 41,8 % (31,5 až 52,8) | 91,1 % (82,8 až 95,6) |  |
| c2_beacon | tempo 1× | 159 | 25,8 % (19,6 až 33,1) | 85,5 % (79,2 až 90,2) |  |
| c2_beacon | tempo 2× | 65 | 18,5 % (10,9 až 29,6) | 72,3 % (60,4 až 81,7) |  |
| c2_beacon | tempo 4× | 85 | 18,8 % (11,9 až 28,4) | 57,6 % (47,0 až 67,6) | slabé místo |
| c2_beacon | zdroje 1 | 149 | 22,8 % (16,8 až 30,2) | 71,1 % (63,4 až 77,8) |  |
| c2_beacon | zdroje 3 | 239 | 28,5 % (23,1 až 34,5) | 82,8 % (77,6 až 87,1) |  |
| credential_stuffing | objem 0.25× | 47 | 70,2 % (56,0 až 81,3) | 83,0 % (69,9 až 91,1) |  |
| credential_stuffing | objem 0.5× | 63 | 88,9 % (78,8 až 94,5) | 92,1 % (82,7 až 96,6) |  |
| credential_stuffing | objem 1× | 102 | 89,2 % (81,7 až 93,9) | 95,1 % (89,0 až 97,9) |  |
| credential_stuffing | objem 2× | 55 | 85,5 % (73,8 až 92,4) | 85,5 % (73,8 až 92,4) |  |
| credential_stuffing | tempo 0.5× | 39 | 82,1 % (67,3 až 91,0) | 76,9 % (61,7 až 87,4) |  |
| credential_stuffing | tempo 1× | 114 | 90,4 % (83,5 až 94,5) | 93,9 % (87,9 až 97,0) |  |
| credential_stuffing | tempo 2× | 63 | 85,7 % (75,0 až 92,3) | 95,2 % (86,9 až 98,4) |  |
| credential_stuffing | tempo 4× | 51 | 74,5 % (61,1 až 84,5) | 86,3 % (74,3 až 93,2) |  |
| credential_stuffing | zdroje 1 | 105 | 88,6 % (81,1 až 93,3) | 89,5 % (82,2 až 94,0) |  |
| credential_stuffing | zdroje 3 | 162 | 82,7 % (76,2 až 87,8) | 90,7 % (85,3 až 94,3) |  |
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
| dns_tunnel | objem 0.25× | 38 | 44,7 % (30,1 až 60,3) | 76,3 % (60,8 až 87,0) |  |
| dns_tunnel | objem 0.5× | 36 | 38,9 % (24,8 až 55,1) | 86,1 % (71,3 až 93,9) |  |
| dns_tunnel | objem 1× | 69 | 40,6 % (29,8 až 52,4) | 88,4 % (78,8 až 94,0) |  |
| dns_tunnel | objem 2× | 21 | 47,6 % (28,3 až 67,6) | 95,2 % (77,3 až 99,2) |  |
| dns_tunnel | tempo 0.5× | 35 | 54,3 % (38,2 až 69,5) | 85,7 % (70,6 až 93,7) |  |
| dns_tunnel | tempo 1× | 59 | 39,0 % (27,6 až 51,7) | 78,0 % (65,9 až 86,6) |  |
| dns_tunnel | tempo 2× | 40 | 45,0 % (30,7 až 60,2) | 90,0 % (76,9 až 96,0) |  |
| dns_tunnel | tempo 4× | 30 | 30,0 % (16,7 až 47,9) | 96,7 % (83,3 až 99,4) |  |
| dns_tunnel | zdroje 1 | 62 | 37,1 % (26,2 až 49,5) | 88,7 % (78,5 až 94,4) |  |
| dns_tunnel | zdroje 3 | 102 | 45,1 % (35,8 až 54,8) | 84,3 % (76,0 až 90,1) |  |
| exfiltration | objem 0.25× | 55 | 10,9 % (5,1 až 21,8) | 81,8 % (69,7 až 89,8) |  |
| exfiltration | objem 0.5× | 57 | 14,0 % (7,3 až 25,3) | 93,0 % (83,3 až 97,2) |  |
| exfiltration | objem 1× | 117 | 14,5 % (9,3 až 22,0) | 91,5 % (85,0 až 95,3) |  |
| exfiltration | objem 2× | 60 | 15,0 % (8,1 až 26,1) | 88,3 % (77,8 až 94,2) |  |
| exfiltration | tempo 0.5× | 61 | 23,0 % (14,2 až 34,9) | 91,8 % (82,2 až 96,4) |  |
| exfiltration | tempo 1× | 119 | 13,4 % (8,4 až 20,7) | 87,4 % (80,2 až 92,2) |  |
| exfiltration | tempo 2× | 61 | 8,2 % (3,6 až 17,8) | 88,5 % (78,2 až 94,3) |  |
| exfiltration | tempo 4× | 48 | 10,4 % (4,5 až 22,2) | 91,7 % (80,4 až 96,7) |  |
| exfiltration | zdroje 1 | 122 | 11,5 % (7,0 až 18,3) | 82,0 % (74,2 až 87,8) |  |
| exfiltration | zdroje 3 | 167 | 15,6 % (10,9 až 21,8) | 94,6 % (90,1 až 97,1) |  |
| exploit_attempt | objem 0.25× | 57 | 33,3 % (22,5 až 46,3) | 50,9 % (38,3 až 63,4) | slabé místo |
| exploit_attempt | objem 0.5× | 69 | 15,9 % (9,1 až 26,3) | 47,8 % (36,5 až 59,4) | SLEPÉ MÍSTO |
| exploit_attempt | objem 1× | 107 | 24,3 % (17,2 až 33,2) | 38,3 % (29,7 až 47,8) | SLEPÉ MÍSTO |
| exploit_attempt | objem 2× | 76 | 26,3 % (17,7 až 37,2) | 52,6 % (41,6 až 63,5) | slabé místo |
| exploit_attempt | tempo 0.5× | 65 | 35,4 % (24,9 až 47,5) | 53,8 % (41,9 až 65,4) | slabé místo |
| exploit_attempt | tempo 1× | 137 | 16,8 % (11,5 až 23,9) | 35,8 % (28,2 až 44,1) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 2× | 57 | 15,8 % (8,5 až 27,4) | 43,9 % (31,8 až 56,7) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 4× | 50 | 42,0 % (29,4 až 55,8) | 68,0 % (54,2 až 79,2) | slabé místo |
| exploit_attempt | zdroje 1 | 136 | 22,1 % (15,9 až 29,7) | 44,9 % (36,8 až 53,2) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 3 | 173 | 26,6 % (20,6 až 33,6) | 47,4 % (40,1 až 54,8) | SLEPÉ MÍSTO |
| lateral_movement | objem 0.25× | 71 | 71,8 % (60,5 až 81,0) | 69,0 % (57,5 až 78,6) | slabé místo |
| lateral_movement | objem 0.5× | 71 | 64,8 % (53,2 až 74,9) | 60,6 % (48,9 až 71,1) | slabé místo |
| lateral_movement | objem 1× | 165 | 73,9 % (66,8 až 80,0) | 72,7 % (65,5 až 78,9) |  |
| lateral_movement | objem 2× | 64 | 70,3 % (58,2 až 80,1) | 53,1 % (41,1 až 64,8) | slabé místo |
| lateral_movement | tempo 0.5× | 72 | 70,8 % (59,5 až 80,1) | 66,7 % (55,2 až 76,5) | slabé místo |
| lateral_movement | tempo 1× | 141 | 61,7 % (53,5 až 69,3) | 58,9 % (50,6 až 66,6) | slabé místo |
| lateral_movement | tempo 2× | 77 | 63,6 % (52,5 až 73,5) | 49,4 % (38,5 až 60,3) | SLEPÉ MÍSTO |
| lateral_movement | tempo 4× | 81 | 95,1 % (88,0 až 98,1) | 95,1 % (88,0 až 98,1) |  |
| lateral_movement | zdroje 1 | 170 | 69,4 % (62,1 až 75,8) | 70,0 % (62,7 až 76,4) |  |
| lateral_movement | zdroje 3 | 201 | 72,6 % (66,1 až 78,3) | 63,2 % (56,3 až 69,5) | slabé místo |
| port_scan_horizontal | objem 0.25× | 67 | 76,1 % (64,7 až 84,7) | 74,6 % (63,1 až 83,5) |  |
| port_scan_horizontal | objem 0.5× | 60 | 76,7 % (64,6 až 85,6) | 78,3 % (66,4 až 86,9) |  |
| port_scan_horizontal | objem 1× | 113 | 83,2 % (75,2 až 89,0) | 78,8 % (70,3 až 85,3) |  |
| port_scan_horizontal | objem 2× | 76 | 75,0 % (64,2 až 83,4) | 76,3 % (65,6 až 84,5) |  |
| port_scan_horizontal | tempo 0.5× | 54 | 64,8 % (51,5 až 76,2) | 75,9 % (63,1 až 85,4) |  |
| port_scan_horizontal | tempo 1× | 136 | 70,6 % (62,4 až 77,6) | 71,3 % (63,2 až 78,3) |  |
| port_scan_horizontal | tempo 2× | 57 | 94,7 % (85,6 až 98,2) | 77,2 % (64,8 až 86,2) |  |
| port_scan_horizontal | tempo 4× | 69 | 91,3 % (82,3 až 96,0) | 89,9 % (80,5 až 95,0) |  |
| port_scan_horizontal | zdroje 1 | 148 | 81,8 % (74,8 až 87,1) | 84,5 % (77,8 až 89,4) |  |
| port_scan_horizontal | zdroje 3 | 168 | 75,6 % (68,6 až 81,5) | 70,8 % (63,6 až 77,2) |  |
| port_scan_vertical | objem 0.25× | 61 | 39,3 % (28,1 až 51,9) | 80,3 % (68,7 až 88,4) |  |
| port_scan_vertical | objem 0.5× | 51 | 56,9 % (43,3 až 69,5) | 84,3 % (72,0 až 91,8) |  |
| port_scan_vertical | objem 1× | 118 | 66,1 % (57,2 až 74,0) | 91,5 % (85,1 až 95,3) |  |
| port_scan_vertical | objem 2× | 67 | 61,2 % (49,2 až 72,0) | 86,6 % (76,4 až 92,8) |  |
| port_scan_vertical | tempo 0.5× | 56 | 44,6 % (32,4 až 57,6) | 91,1 % (80,7 až 96,1) |  |
| port_scan_vertical | tempo 1× | 116 | 35,3 % (27,2 až 44,4) | 85,3 % (77,8 až 90,6) |  |
| port_scan_vertical | tempo 2× | 61 | 86,9 % (76,2 až 93,2) | 88,5 % (78,2 až 94,3) |  |
| port_scan_vertical | tempo 4× | 64 | 82,8 % (71,8 až 90,1) | 84,4 % (73,6 až 91,3) |  |
| port_scan_vertical | zdroje 1 | 106 | 62,3 % (52,8 až 70,9) | 87,7 % (80,1 až 92,7) |  |
| port_scan_vertical | zdroje 3 | 191 | 55,5 % (48,4 až 62,4) | 86,4 % (80,8 až 90,5) |  |
| rogue_device | objem 0.25× | 21 | 47,6 % (28,3 až 67,6) | 100,0 % (84,5 až 100,0) |  |
| rogue_device | objem 0.5× | 10 | 30,0 % (10,8 až 60,3) | 80,0 % (49,0 až 94,3) | nedostatečná data |
| rogue_device | objem 1× | 30 | 26,7 % (14,2 až 44,4) | 90,0 % (74,4 až 96,5) |  |
| rogue_device | objem 2× | 20 | 35,0 % (18,1 až 56,7) | 85,0 % (64,0 až 94,8) |  |
| rogue_device | tempo 0.5× | 12 | 33,3 % (13,8 až 60,9) | 100,0 % (75,8 až 100,0) | nedostatečná data |
| rogue_device | tempo 1× | 40 | 10,0 % (4,0 až 23,1) | 92,5 % (80,1 až 97,4) |  |
| rogue_device | tempo 2× | 16 | 68,8 % (44,4 až 85,8) | 75,0 % (50,5 až 89,8) | nedostatečná data |
| rogue_device | tempo 4× | 13 | 69,2 % (42,4 až 87,3) | 92,3 % (66,7 až 98,6) | nedostatečná data |
| rogue_device | zdroje 1 | 31 | 22,6 % (11,4 až 39,8) | 90,3 % (75,1 až 96,7) |  |
| rogue_device | zdroje 3 | 50 | 42,0 % (29,4 až 55,8) | 90,0 % (78,6 až 95,7) |  |
| ssh_bruteforce | objem 0.25× | 89 | 88,8 % (80,5 až 93,8) | 95,5 % (89,0 až 98,2) |  |
| ssh_bruteforce | objem 0.5× | 98 | 82,7 % (74,0 až 88,9) | 87,8 % (79,8 až 92,9) |  |
| ssh_bruteforce | objem 1× | 174 | 92,0 % (86,9 až 95,1) | 94,8 % (90,5 až 97,3) |  |
| ssh_bruteforce | objem 2× | 95 | 88,4 % (80,4 až 93,4) | 93,7 % (86,9 až 97,1) |  |
| ssh_bruteforce | tempo 0.5× | 79 | 93,7 % (86,0 až 97,3) | 97,5 % (91,2 až 99,3) |  |
| ssh_bruteforce | tempo 1× | 194 | 88,1 % (82,8 až 92,0) | 91,8 % (87,0 až 94,9) |  |
| ssh_bruteforce | tempo 2× | 101 | 91,1 % (83,9 až 95,2) | 96,0 % (90,3 až 98,4) |  |
| ssh_bruteforce | tempo 4× | 82 | 81,7 % (72,0 až 88,6) | 89,0 % (80,4 až 94,1) |  |
| ssh_bruteforce | zdroje 1 | 207 | 87,0 % (81,7 až 90,9) | 93,2 % (89,0 až 95,9) |  |
| ssh_bruteforce | zdroje 3 | 249 | 90,0 % (85,6 až 93,1) | 93,2 % (89,3 až 95,7) |  |

### Souběh útoku s provozní poruchou

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| bez souběhu | 711 | 56,4 % (52,7 až 60,0) | 78,3 % (75,2 až 81,2) |  |
| nesenzorová porucha | 2118 | 57,2 % (55,1 až 59,3) | 81,1 % (79,3 až 82,7) |  |
| s backup_failed | 417 | 57,6 % (52,8 až 62,2) | 87,1 % (83,5 až 89,9) |  |
| s batch_job | 491 | 57,8 % (53,4 až 62,1) | 84,7 % (81,3 až 87,6) |  |
| s collector_replay | 387 | 57,1 % (52,1 až 61,9) | 85,3 % (81,4 až 88,5) |  |
| s device_decommission | 238 | 54,6 % (48,3 až 60,8) | 85,3 % (80,2 až 89,2) |  |
| s device_onboarding | 365 | 60,8 % (55,7 až 65,7) | 85,5 % (81,5 až 88,7) |  |
| s dhcp_renumber | 423 | 55,3 % (50,6 až 60,0) | 81,6 % (77,6 až 85,0) |  |
| s dns_outage | 428 | 61,4 % (56,8 až 65,9) | 87,4 % (83,9 až 90,2) |  |
| s link_flapping | 493 | 55,0 % (50,6 až 59,3) | 84,4 % (80,9 až 87,3) |  |
| s log_corruption | 321 | 59,2 % (53,7 až 64,4) | 86,3 % (82,1 až 89,6) |  |
| s misconfig | 397 | 58,9 % (54,0 až 63,7) | 85,9 % (82,1 až 89,0) |  |
| s patch_window | 359 | 61,3 % (56,1 až 66,2) | 85,5 % (81,5 až 88,8) |  |
| s retry_storm | 465 | 59,6 % (55,0 až 63,9) | 86,2 % (82,8 až 89,1) |  |
| s sensor_crash | 460 | 49,3 % (44,8 až 53,9) | 71,1 % (66,8 až 75,0) |  |
| s service_crash | 620 | 58,4 % (54,5 až 62,2) | 83,5 % (80,4 až 86,3) |  |
| senzorová porucha | 934 | 54,5 % (51,3 až 57,7) | 78,7 % (76,0 až 81,2) |  |

### Kampaně

| rameno | šablona | kampaní | aspoň jedna fáze | první fáze | všechny fáze |
|---|---:|---:|---:|---:|---:|
| legacy | K-T1 | 103 | 97,1 % (91,8 až 99,0) | 67,0 % (57,4 až 75,3) | 5,8 % (2,7 až 12,1) |
| legacy | K-T2 | 82 | 92,7 % (84,9 až 96,6) | 90,2 % (81,9 až 95,0) | 23,2 % (15,4 až 33,4) |
| legacy | K-T3 | 91 | 76,9 % (67,3 až 84,4) | 28,6 % (20,3 až 38,6) | 6,6 % (3,1 až 13,6) |
| legacy | vše | 276 | 89,1 % (84,9 až 92,3) | 61,2 % (55,4 až 66,8) | 11,2 % (8,0 až 15,5) |
| v3 | K-T1 | 103 | 98,1 % (93,2 až 99,5) | 62,1 % (52,5 až 70,9) | 31,1 % (22,9 až 40,5) |
| v3 | K-T2 | 82 | 98,8 % (93,4 až 99,8) | 93,9 % (86,5 až 97,4) | 68,3 % (57,6 až 77,4) |
| v3 | K-T3 | 91 | 97,8 % (92,3 až 99,4) | 48,4 % (38,4 až 58,5) | 20,9 % (13,8 až 30,3) |
| v3 | vše | 276 | 98,2 % (95,8 až 99,2) | 67,0 % (61,3 až 72,3) | 38,8 % (33,2 až 44,6) |

### Leave-one-family-out (náhrada A5), rameno `v3`

| rodina | vynechané typy D(X) | n | detekce všemi signály | obecná detekce | verdikt |
|---|---:|---:|---:|---:|---:|
| c2_beacon | beacon_periodic | 67 | 67,2 % (55,3 až 77,2) | 11,9 % (6,2 až 21,8) | SLEPÉ MÍSTO |
| exfiltration | egress_volume_anomaly, long_lived_tunnel | 70 | 85,7 % (75,7 až 92,1) | 2,9 % (0,8 až 9,8) | SLEPÉ MÍSTO |
| ssh_bruteforce | connection_timeout_burst, source_volume_outlier | 53 | 94,3 % (84,6 až 98,1) | 92,5 % (82,1 až 97,0) | zobecňuje |
| port_scan_vertical | connection_timeout_burst, scan_attempts | 61 | 86,9 % (76,2 až 93,2) | 4,9 % (1,7 až 13,5) | SLEPÉ MÍSTO |
| lateral_movement | multi_target_pattern, pivot_chain | 68 | 66,2 % (54,3 až 76,3) | 42,6 % (31,6 až 54,5) | SLEPÉ MÍSTO |
| dns_tunnel | egress_volume_anomaly, source_volume_outlier | 57 | 91,2 % (81,1 až 96,2) | 57,9 % (45,0 až 69,8) | zobecňuje |

### Útoky s automaticky zavřeným připsaným nálezem

| rameno | rodiny | útoků | podíl s automatickým zavřením | z toho první výskyt (A7) |
|---|---:|---:|---:|---:|
| legacy | laděné | 3042 | 0,0 % (0,0 až 0,1) | 0 |
| legacy | držené | 0 | – % (0,0 až 100,0) | 0 |
| v3 | laděné | 3042 | 0,9 % (0,6 až 1,3) | 12 |
| v3 | držené | 0 | – % (0,0 až 100,0) | 0 |

### Poruchy a lookalike: podíl výskytů s FP

| rameno | událost | výskytů | zobrazené FP | zachycené FP | registr |
|---|---:|---:|---:|---:|---:|
| legacy | authorized_scanner | 383 | 43,9 % (39,0 až 48,9) | 43,9 % (39,0 až 48,9) | FP SLEPÉ MÍSTO |
| legacy | backup_burst | 776 | 74,0 % (70,8 až 76,9) | 74,0 % (70,8 až 76,9) | FP SLEPÉ MÍSTO |
| legacy | backup_failed | 262 | 97,7 % (95,1 až 98,9) | 97,7 % (95,1 až 98,9) | FP SLEPÉ MÍSTO |
| legacy | batch_job | 276 | 85,1 % (80,5 až 88,9) | 85,1 % (80,5 až 88,9) | FP SLEPÉ MÍSTO |
| legacy | collector_replay | 254 | 94,1 % (90,5 až 96,4) | 94,1 % (90,5 až 96,4) | FP SLEPÉ MÍSTO |
| legacy | device_decommission | 161 | 22,4 % (16,6 až 29,4) | 22,4 % (16,6 až 29,4) | FP SLEPÉ MÍSTO |
| legacy | device_onboarding | 236 | 2,1 % (0,9 až 4,9) | 2,1 % (0,9 až 4,9) |  |
| legacy | dhcp_renumber | 270 | 84,8 % (80,0 až 88,6) | 84,8 % (80,0 až 88,6) | FP SLEPÉ MÍSTO |
| legacy | dns_outage | 298 | 99,0 % (97,1 až 99,7) | 99,0 % (97,1 až 99,7) | FP SLEPÉ MÍSTO |
| legacy | flash_crowd | 821 | 85,9 % (83,3 až 88,1) | 85,9 % (83,3 až 88,1) | FP SLEPÉ MÍSTO |
| legacy | link_flapping | 267 | 0,0 % (0,0 až 1,4) | 0,0 % (0,0 až 1,4) |  |
| legacy | log_corruption | 186 | 94,6 % (90,4 až 97,1) | 94,6 % (90,4 až 97,1) | FP SLEPÉ MÍSTO |
| legacy | misconfig | 266 | 96,2 % (93,2 až 97,9) | 96,2 % (93,2 až 97,9) | FP SLEPÉ MÍSTO |
| legacy | ntp_fanout | 413 | 22,5 % (18,8 až 26,8) | 22,5 % (18,8 až 26,8) | FP SLEPÉ MÍSTO |
| legacy | patch_window | 197 | 100,0 % (98,1 až 100,0) | 100,0 % (98,1 až 100,0) | FP SLEPÉ MÍSTO |
| legacy | retry_storm | 268 | 0,0 % (0,0 až 1,4) | 0,0 % (0,0 až 1,4) |  |
| legacy | sensor_crash | 235 | 0,0 % (0,0 až 1,6) | 0,0 % (0,0 až 1,6) |  |
| legacy | service_crash | 386 | 86,5 % (82,8 až 89,6) | 86,5 % (82,8 až 89,6) | FP SLEPÉ MÍSTO |
| legacy | software_update | 810 | 0,0 % (0,0 až 0,5) | 0,0 % (0,0 až 0,5) |  |
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

### Registr slepých míst (rameno `v3`, automaticky podle A8)

| oblast | buňka | n | hodnota | zařazení |
|---|---:|---:|---:|---:|
| Rodiny | exploit_attempt | 309 | 46,3 % | SLEPÉ MÍSTO |
| Rodiny | lateral_movement | 371 | 66,3 % | slabé místo |
| Rodina × pásmo S | exploit_attempt | Q1 | 72 | 47,2 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q2 | 61 | 44,3 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q3 | 57 | 42,1 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q4 | 60 | 46,7 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q5 | 59 | 50,8 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q1 | 72 | 65,3 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q2 | 64 | 68,8 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q3 | 89 | 65,2 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q4 | 78 | 69,2 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q5 | 68 | 63,2 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 4× | 85 | 57,6 % | slabé místo |
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
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 2× | 64 | 53,1 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 0.5× | 72 | 66,7 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 1× | 141 | 58,9 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 2× | 77 | 49,4 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | zdroje 3 | 201 | 63,2 % | slabé místo |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | c2_beacon | 67 | 11,9 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | exfiltration | 70 | 2,9 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | port_scan_vertical | 61 | 4,9 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | lateral_movement | 68 | 42,6 % | SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | authorized_scanner | 383 | 94,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | backup_burst | 776 | 40,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | backup_failed | 262 | 89,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | batch_job | 276 | 64,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | collector_replay | 254 | 76,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | dhcp_renumber | 270 | 75,6 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | dns_outage | 298 | 85,2 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | flash_crowd | 821 | 45,4 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | log_corruption | 186 | 46,2 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | misconfig | 266 | 97,0 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | patch_window | 197 | 93,4 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | service_crash | 386 | 62,4 % | FP SLEPÉ MÍSTO |

### Prahy K1 až K8

| práh | hodnota | splněno |
|---|---:|---:|
| K1 | Q5/Q1 = 0,98 | ano |
| K2 | vše +23,1 p. b., Q4+Q5 +23,3 p. b. | ano |
| K4 | +2,8 p. b. | ano |
| K5 | c2_beacon: 8/67, exfiltration: 2/70, ssh_bruteforce: 49/53, port_scan_vertical: 3/61, lateral_movement: 29/68, dns_tunnel: 33/57 | 2 ze 6 zobecňuje |
| K6 | 67/4023, horní mez 2,1 % | ano |
| K7 | 98,2 % (95,8 až 99,2) | ano |
| K8 | 0 panik, 0 invariantů | ano |

