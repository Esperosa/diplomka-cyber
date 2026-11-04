## Pokrytí, křivky skrytosti a registr slepých míst

Ramena: legacy, v3; hodnocené rameno `v3`. Detekce = kontrafaktuální zobrazená detekce na útok (Wilson 95 %; souhrny a rozdíly s bootstrapem po sítích).

Hranice pásem S (zadané předem): 0.172, 0.236, 0.305, 0.392

| rameno | sítí | útoků | detekce (bootstrap) | zobrazené FP/síť-den | zavřeno omylem (G3) | panik/invariantů |
|---|---:|---:|---:|---:|---:|---:|
| legacy | 80 | 2856 | 61,4 % (58,9 až 64,2) | 653,8 | – % (0,0 až 100,0) [0/0] | 0/0 |
| v3 | 80 | 2856 | 77,9 % (74,9 až 81,1) | 14,1 | 5,8 % (5,1 až 6,7) [185/3165] | 0/0 |

### Párově `v3` − `legacy`

| výběr | párů | rozdíl detekce |
|---|---:|---:|
| vše | 2856 | +16,5 p. b. (+14,1 až +19,0) |
| Q4 + Q5 | 1654 | +13,6 p. b. (+10,3 až +16,9) |
| Q5 | 1081 | +11,6 p. b. (+7,6 až +15,5) |

### Křivka skrytosti: pásma S

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| Q1 | 387 | 58,4 % (53,4 až 63,2) | 80,1 % (75,8 až 83,8) |  |
| Q2 | 372 | 59,9 % (54,9 až 64,8) | 80,1 % (75,8 až 83,8) |  |
| Q3 | 443 | 60,9 % (56,3 až 65,4) | 80,6 % (76,6 až 84,0) |  |
| Q4 | 573 | 60,0 % (56,0 až 64,0) | 77,5 % (73,9 až 80,7) |  |
| Q5 | 1081 | 64,0 % (61,1 až 66,8) | 75,6 % (72,9 až 78,0) |  |

### Osa: intenzita

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0.0–0.2 | 454 | 58,6 % (54,0 až 63,0) | 73,3 % (69,1 až 77,2) |  |
| 0.2–0.4 | 577 | 64,5 % (60,5 až 68,3) | 78,9 % (75,3 až 82,0) |  |
| 0.4–0.6 | 640 | 63,4 % (59,6 až 67,1) | 80,0 % (76,7 až 82,9) |  |
| 0.6–0.8 | 588 | 61,7 % (57,7 až 65,6) | 78,4 % (74,9 až 81,5) |  |
| 0.8–1.0 | 597 | 58,3 % (54,3 až 62,2) | 77,9 % (74,4 až 81,0) |  |

### Osa: tempo

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0.25× | 356 | 66,6 % (61,5 až 71,3) | 80,3 % (75,9 až 84,1) |  |
| 0.5× | 339 | 64,3 % (59,1 až 69,2) | 77,3 % (72,5 až 81,4) |  |
| 1× | 1139 | 59,4 % (56,6 až 62,3) | 77,0 % (74,5 až 79,3) |  |
| 2× | 328 | 64,9 % (59,6 až 69,9) | 78,0 % (73,3 až 82,2) |  |
| 4× | 327 | 59,0 % (53,6 až 64,2) | 76,8 % (71,9 až 81,0) |  |
| 8× | 367 | 59,1 % (54,0 až 64,0) | 80,1 % (75,7 až 83,9) |  |

### Osa: rozptyl

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0 | 1130 | 62,9 % (60,1 až 65,7) | 78,6 % (76,1 až 80,9) |  |
| 0.15 | 549 | 61,0 % (56,9 až 65,0) | 79,2 % (75,6 až 82,4) |  |
| 0.3 | 592 | 58,8 % (54,8 až 62,7) | 76,5 % (72,9 až 79,8) |  |
| 0.5 | 585 | 61,7 % (57,7 až 65,6) | 76,9 % (73,3 až 80,2) |  |

### Osa: zdroje

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 1 | 1165 | 57,7 % (54,8 až 60,5) | 78,7 % (76,3 až 81,0) |  |
| 10 | 825 | 64,1 % (60,8 až 67,3) | 73,6 % (70,5 až 76,5) |  |
| 3 | 866 | 64,0 % (60,7 až 67,1) | 81,1 % (78,3 až 83,5) |  |

### Osa: doba

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0.5× | 517 | 53,2 % (48,9 až 57,5) | 68,7 % (64,5 až 72,5) | slabé místo |
| 1× | 1156 | 60,5 % (57,6 až 63,2) | 78,2 % (75,7 až 80,5) |  |
| 2× | 572 | 64,0 % (60,0 až 67,8) | 79,2 % (75,7 až 82,3) |  |
| 4× | 611 | 67,9 % (64,1 až 71,5) | 84,1 % (81,0 až 86,8) |  |

### Osa: objem

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| 0.25× | 553 | 62,2 % (58,1 až 66,2) | 76,7 % (73,0 až 80,0) |  |
| 0.5× | 575 | 61,0 % (57,0 až 64,9) | 76,0 % (72,3 až 79,3) |  |
| 1× | 1158 | 61,5 % (58,6 až 64,2) | 78,8 % (76,3 až 81,0) |  |
| 2× | 570 | 61,1 % (57,0 až 65,0) | 79,5 % (76,0 až 82,6) |  |

### Osa: mimo pracovní dobu

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| ano | 656 | 61,4 % (57,7 až 65,1) | 78,2 % (74,9 až 81,2) |  |
| ne | 2200 | 61,5 % (59,4 až 63,5) | 77,9 % (76,1 až 79,5) |  |

### Osa: míchání s provozem

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| ano | 848 | 61,2 % (57,9 až 64,4) | 76,7 % (73,7 až 79,4) |  |
| ne | 2008 | 61,6 % (59,4 až 63,7) | 78,5 % (76,6 až 80,2) |  |

### Osa: IDS signatura

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| ano | 791 | 65,4 % (62,0 až 68,6) | 92,3 % (90,2 až 93,9) |  |
| ne | 2065 | 60,0 % (57,8 až 62,0) | 72,4 % (70,5 až 74,3) |  |

### Rodiny

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| apt_chain (H) | 59 | 96,6 % (88,5 až 99,1) | 98,3 % (91,0 až 99,7) |  |
| c2_beacon | 262 | 33,6 % (28,1 až 39,5) | 60,3 % (54,3 až 66,0) | slabé místo |
| credential_stuffing | 159 | 84,9 % (78,5 až 89,6) | 81,8 % (75,0 až 87,0) |  |
| cryptomining (H) | 125 | 31,2 % (23,7 až 39,8) | 79,2 % (71,3 až 85,4) |  |
| ddos_volume | 83 | 85,5 % (76,4 až 91,5) | 84,3 % (75,0 až 90,6) |  |
| dns_tunnel | 117 | 41,0 % (32,5 až 50,1) | 73,5 % (64,9 až 80,7) |  |
| exfiltration | 205 | 19,0 % (14,2 až 24,9) | 82,4 % (76,6 až 87,0) |  |
| exploit_attempt | 270 | 28,5 % (23,5 až 34,2) | 49,6 % (43,7 až 55,6) | SLEPÉ MÍSTO |
| fleet_beacon (H) | 34 | 61,8 % (45,0 až 76,1) | 76,5 % (60,0 až 87,6) |  |
| ics_attack (H) | 3 | 66,7 % (20,8 až 93,9) | 66,7 % (20,8 až 93,9) | nedostatečná data |
| insider_hoarding (H) | 53 | 92,5 % (82,1 až 97,0) | 94,3 % (84,6 až 98,1) |  |
| lateral_movement | 239 | 74,9 % (69,0 až 80,0) | 69,5 % (63,3 až 74,9) | slabé místo |
| port_scan_horizontal | 195 | 82,1 % (76,1 až 86,8) | 81,0 % (74,9 až 85,9) |  |
| port_scan_vertical | 233 | 55,8 % (49,4 až 62,0) | 83,3 % (77,9 až 87,5) |  |
| ransomware (H) | 82 | 92,7 % (84,9 až 96,6) | 92,7 % (84,9 až 96,6) |  |
| rogue_device | 63 | 42,9 % (31,4 až 55,1) | 96,8 % (89,1 až 99,1) |  |
| slow_scan (H) | 201 | 86,1 % (80,6 až 90,2) | 86,1 % (80,6 až 90,2) |  |
| ssh_bruteforce | 285 | 82,8 % (78,0 až 86,7) | 90,2 % (86,2 až 93,1) |  |
| web_exploit (H) | 188 | 78,7 % (72,3 až 84,0) | 84,6 % (78,7 až 89,0) |  |

### Rodina × pásmo S

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| apt_chain | Q1 | 11 | 100,0 % (74,1 až 100,0) | 100,0 % (74,1 až 100,0) | nedostatečná data |
| apt_chain | Q2 | 5 | 100,0 % (56,6 až 100,0) | 100,0 % (56,6 až 100,0) | nedostatečná data |
| apt_chain | Q3 | 9 | 88,9 % (56,5 až 98,0) | 100,0 % (70,1 až 100,0) | nedostatečná data |
| apt_chain | Q4 | 18 | 100,0 % (82,4 až 100,0) | 100,0 % (82,4 až 100,0) | nedostatečná data |
| apt_chain | Q5 | 16 | 93,8 % (71,7 až 98,9) | 93,8 % (71,7 až 98,9) | nedostatečná data |
| c2_beacon | Q1 | 29 | 17,2 % (7,6 až 34,5) | 65,5 % (47,3 až 80,1) | slabé místo |
| c2_beacon | Q2 | 36 | 19,4 % (9,8 až 35,0) | 55,6 % (39,6 až 70,5) | slabé místo |
| c2_beacon | Q3 | 28 | 46,4 % (29,5 až 64,2) | 78,6 % (60,5 až 89,8) |  |
| c2_beacon | Q4 | 60 | 26,7 % (17,1 až 39,0) | 56,7 % (44,1 až 68,4) | slabé místo |
| c2_beacon | Q5 | 109 | 43,1 % (34,2 až 52,5) | 57,8 % (48,4 až 66,6) | slabé místo |
| credential_stuffing | Q1 | 20 | 85,0 % (64,0 až 94,8) | 90,0 % (69,9 až 97,2) |  |
| credential_stuffing | Q2 | 17 | 88,2 % (65,7 až 96,7) | 94,1 % (73,0 až 99,0) | nedostatečná data |
| credential_stuffing | Q3 | 22 | 81,8 % (61,5 až 92,7) | 81,8 % (61,5 až 92,7) |  |
| credential_stuffing | Q4 | 38 | 86,8 % (72,7 až 94,2) | 68,4 % (52,5 až 80,9) | slabé místo |
| credential_stuffing | Q5 | 62 | 83,9 % (72,8 až 91,0) | 83,9 % (72,8 až 91,0) |  |
| cryptomining | Q1 | 17 | 35,3 % (17,3 až 58,7) | 100,0 % (81,6 až 100,0) | nedostatečná data |
| cryptomining | Q2 | 19 | 31,6 % (15,4 až 54,0) | 89,5 % (68,6 až 97,1) | nedostatečná data |
| cryptomining | Q3 | 19 | 21,1 % (8,5 až 43,3) | 94,7 % (75,4 až 99,1) | nedostatečná data |
| cryptomining | Q4 | 21 | 14,3 % (5,0 až 34,6) | 61,9 % (40,9 až 79,2) | slabé místo |
| cryptomining | Q5 | 49 | 40,8 % (28,2 až 54,8) | 69,4 % (55,5 až 80,5) | slabé místo |
| ddos_volume | Q1 | 10 | 100,0 % (72,2 až 100,0) | 100,0 % (72,2 až 100,0) | nedostatečná data |
| ddos_volume | Q2 | 11 | 81,8 % (52,3 až 94,9) | 72,7 % (43,4 až 90,3) | nedostatečná data |
| ddos_volume | Q3 | 10 | 80,0 % (49,0 až 94,3) | 80,0 % (49,0 až 94,3) | nedostatečná data |
| ddos_volume | Q4 | 18 | 77,8 % (54,8 až 91,0) | 83,3 % (60,8 až 94,2) | nedostatečná data |
| ddos_volume | Q5 | 34 | 88,2 % (73,4 až 95,3) | 85,3 % (69,9 až 93,6) |  |
| dns_tunnel | Q1 | 13 | 38,5 % (17,7 až 64,5) | 100,0 % (77,2 až 100,0) | nedostatečná data |
| dns_tunnel | Q2 | 12 | 66,7 % (39,1 až 86,2) | 91,7 % (64,6 až 98,5) | nedostatečná data |
| dns_tunnel | Q3 | 16 | 43,8 % (23,1 až 66,8) | 81,2 % (57,0 až 93,4) | nedostatečná data |
| dns_tunnel | Q4 | 34 | 35,3 % (21,5 až 52,1) | 76,5 % (60,0 až 87,6) |  |
| dns_tunnel | Q5 | 42 | 38,1 % (25,0 až 53,2) | 54,8 % (39,9 až 68,8) | slabé místo |
| exfiltration | Q1 | 25 | 0,0 % (0,0 až 13,3) | 68,0 % (48,4 až 82,8) | slabé místo |
| exfiltration | Q2 | 32 | 9,4 % (3,2 až 24,2) | 84,4 % (68,2 až 93,1) |  |
| exfiltration | Q3 | 51 | 31,4 % (20,3 až 45,0) | 82,4 % (69,7 až 90,4) |  |
| exfiltration | Q4 | 28 | 10,7 % (3,7 až 27,2) | 85,7 % (68,5 až 94,3) |  |
| exfiltration | Q5 | 69 | 24,6 % (16,0 až 36,0) | 85,5 % (75,3 až 91,9) |  |
| exploit_attempt | Q1 | 37 | 29,7 % (17,5 až 45,8) | 43,2 % (28,7 až 59,1) | SLEPÉ MÍSTO |
| exploit_attempt | Q2 | 39 | 28,2 % (16,5 až 43,8) | 51,3 % (36,2 až 66,1) | slabé místo |
| exploit_attempt | Q3 | 44 | 31,8 % (20,0 až 46,6) | 43,2 % (29,7 až 57,8) | SLEPÉ MÍSTO |
| exploit_attempt | Q4 | 52 | 28,8 % (18,3 až 42,3) | 53,8 % (40,5 až 66,7) | slabé místo |
| exploit_attempt | Q5 | 98 | 26,5 % (18,8 až 36,0) | 52,0 % (42,3 až 61,7) | slabé místo |
| fleet_beacon | Q1 | 4 | 50,0 % (15,0 až 85,0) | 75,0 % (30,1 až 95,4) | nedostatečná data |
| fleet_beacon | Q2 | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| fleet_beacon | Q3 | 6 | 50,0 % (18,8 až 81,2) | 83,3 % (43,6 až 97,0) | nedostatečná data |
| fleet_beacon | Q4 | 6 | 50,0 % (18,8 až 81,2) | 83,3 % (43,6 až 97,0) | nedostatečná data |
| fleet_beacon | Q5 | 14 | 64,3 % (38,8 až 83,7) | 64,3 % (38,8 až 83,7) | nedostatečná data |
| ics_attack | Q5 | 3 | 66,7 % (20,8 až 93,9) | 66,7 % (20,8 až 93,9) | nedostatečná data |
| insider_hoarding | Q1 | 10 | 70,0 % (39,7 až 89,2) | 70,0 % (39,7 až 89,2) | nedostatečná data |
| insider_hoarding | Q2 | 6 | 100,0 % (61,0 až 100,0) | 100,0 % (61,0 až 100,0) | nedostatečná data |
| insider_hoarding | Q3 | 9 | 100,0 % (70,1 až 100,0) | 100,0 % (70,1 až 100,0) | nedostatečná data |
| insider_hoarding | Q4 | 8 | 87,5 % (52,9 až 97,8) | 100,0 % (67,6 až 100,0) | nedostatečná data |
| insider_hoarding | Q5 | 20 | 100,0 % (83,9 až 100,0) | 100,0 % (83,9 až 100,0) |  |
| lateral_movement | Q1 | 34 | 70,6 % (53,8 až 83,2) | 67,6 % (50,8 až 80,9) | slabé místo |
| lateral_movement | Q2 | 33 | 78,8 % (62,2 až 89,3) | 81,8 % (65,6 až 91,4) |  |
| lateral_movement | Q3 | 38 | 76,3 % (60,8 až 87,0) | 63,2 % (47,3 až 76,6) | slabé místo |
| lateral_movement | Q4 | 48 | 77,1 % (63,5 až 86,7) | 70,8 % (56,8 až 81,8) |  |
| lateral_movement | Q5 | 86 | 73,3 % (63,1 až 81,5) | 67,4 % (57,0 až 76,4) | slabé místo |
| port_scan_horizontal | Q1 | 27 | 88,9 % (71,9 až 96,1) | 85,2 % (67,5 až 94,1) |  |
| port_scan_horizontal | Q2 | 23 | 73,9 % (53,5 až 87,5) | 73,9 % (53,5 až 87,5) |  |
| port_scan_horizontal | Q3 | 31 | 83,9 % (67,4 až 92,9) | 83,9 % (67,4 až 92,9) |  |
| port_scan_horizontal | Q4 | 45 | 77,8 % (63,7 až 87,5) | 84,4 % (71,2 až 92,3) |  |
| port_scan_horizontal | Q5 | 69 | 84,1 % (73,7 až 90,9) | 78,3 % (67,2 až 86,4) |  |
| port_scan_vertical | Q1 | 34 | 44,1 % (28,9 až 60,5) | 76,5 % (60,0 až 87,6) |  |
| port_scan_vertical | Q2 | 29 | 62,1 % (44,0 až 77,3) | 86,2 % (69,4 až 94,5) |  |
| port_scan_vertical | Q3 | 39 | 48,7 % (33,9 až 63,8) | 82,1 % (67,3 až 91,0) |  |
| port_scan_vertical | Q4 | 51 | 66,7 % (53,0 až 78,0) | 90,2 % (79,0 až 95,7) |  |
| port_scan_vertical | Q5 | 80 | 55,0 % (44,1 až 65,4) | 81,2 % (71,3 až 88,3) |  |
| ransomware | Q1 | 13 | 100,0 % (77,2 až 100,0) | 100,0 % (77,2 až 100,0) | nedostatečná data |
| ransomware | Q2 | 11 | 90,9 % (62,3 až 98,4) | 100,0 % (74,1 až 100,0) | nedostatečná data |
| ransomware | Q3 | 14 | 100,0 % (78,5 až 100,0) | 92,9 % (68,5 až 98,7) | nedostatečná data |
| ransomware | Q4 | 10 | 90,0 % (59,6 až 98,2) | 90,0 % (59,6 až 98,2) | nedostatečná data |
| ransomware | Q5 | 34 | 88,2 % (73,4 až 95,3) | 88,2 % (73,4 až 95,3) |  |
| rogue_device | Q1 | 8 | 37,5 % (13,7 až 69,4) | 87,5 % (52,9 až 97,8) | nedostatečná data |
| rogue_device | Q2 | 5 | 60,0 % (23,1 až 88,2) | 100,0 % (56,6 až 100,0) | nedostatečná data |
| rogue_device | Q3 | 11 | 27,3 % (9,7 až 56,6) | 100,0 % (74,1 až 100,0) | nedostatečná data |
| rogue_device | Q4 | 11 | 27,3 % (9,7 až 56,6) | 100,0 % (74,1 až 100,0) | nedostatečná data |
| rogue_device | Q5 | 28 | 53,6 % (35,8 až 70,5) | 96,4 % (82,3 až 99,4) |  |
| slow_scan | Q1 | 28 | 75,0 % (56,6 až 87,3) | 92,9 % (77,4 až 98,0) |  |
| slow_scan | Q2 | 33 | 84,8 % (69,1 až 93,3) | 90,9 % (76,4 až 96,9) |  |
| slow_scan | Q3 | 32 | 84,4 % (68,2 až 93,1) | 90,6 % (75,8 až 96,8) |  |
| slow_scan | Q4 | 32 | 87,5 % (71,9 až 95,0) | 90,6 % (75,8 až 96,8) |  |
| slow_scan | Q5 | 76 | 90,8 % (82,2 až 95,5) | 77,6 % (67,1 až 85,5) |  |
| ssh_bruteforce | Q1 | 44 | 79,5 % (65,5 až 88,8) | 88,6 % (76,0 až 95,0) |  |
| ssh_bruteforce | Q2 | 37 | 78,4 % (62,8 až 88,6) | 86,5 % (72,0 až 94,1) |  |
| ssh_bruteforce | Q3 | 35 | 80,0 % (64,1 až 90,0) | 97,1 % (85,5 až 99,5) |  |
| ssh_bruteforce | Q4 | 61 | 82,0 % (70,5 až 89,6) | 85,2 % (74,3 až 92,0) |  |
| ssh_bruteforce | Q5 | 108 | 87,0 % (79,4 až 92,1) | 92,6 % (86,1 až 96,2) |  |
| web_exploit | Q1 | 23 | 73,9 % (53,5 až 87,5) | 95,7 % (79,0 až 99,2) |  |
| web_exploit | Q2 | 20 | 90,0 % (69,9 až 97,2) | 85,0 % (64,0 až 94,8) |  |
| web_exploit | Q3 | 29 | 82,8 % (65,5 až 92,4) | 86,2 % (69,4 až 94,5) |  |
| web_exploit | Q4 | 32 | 75,0 % (57,9 až 86,7) | 87,5 % (71,9 až 95,0) |  |
| web_exploit | Q5 | 84 | 77,4 % (67,4 až 85,0) | 79,8 % (70,0 až 87,0) |  |

### Rodina × osa (tempo, zdroje, objem)

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| apt_chain | objem 0.25× | 10 | 100,0 % (72,2 až 100,0) | 100,0 % (72,2 až 100,0) | nedostatečná data |
| apt_chain | objem 0.5× | 9 | 88,9 % (56,5 až 98,0) | 100,0 % (70,1 až 100,0) | nedostatečná data |
| apt_chain | objem 1× | 29 | 96,6 % (82,8 až 99,4) | 96,6 % (82,8 až 99,4) |  |
| apt_chain | objem 2× | 11 | 100,0 % (74,1 až 100,0) | 100,0 % (74,1 až 100,0) | nedostatečná data |
| apt_chain | tempo 0.25× | 8 | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | nedostatečná data |
| apt_chain | tempo 0.5× | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| apt_chain | tempo 1× | 24 | 95,8 % (79,8 až 99,3) | 100,0 % (86,2 až 100,0) |  |
| apt_chain | tempo 2× | 10 | 100,0 % (72,2 až 100,0) | 100,0 % (72,2 až 100,0) | nedostatečná data |
| apt_chain | tempo 4× | 6 | 100,0 % (61,0 až 100,0) | 100,0 % (61,0 až 100,0) | nedostatečná data |
| apt_chain | tempo 8× | 7 | 100,0 % (64,6 až 100,0) | 100,0 % (64,6 až 100,0) | nedostatečná data |
| apt_chain | zdroje 1 | 26 | 96,2 % (81,1 až 99,3) | 96,2 % (81,1 až 99,3) |  |
| apt_chain | zdroje 10 | 15 | 93,3 % (70,2 až 98,8) | 100,0 % (79,6 až 100,0) | nedostatečná data |
| apt_chain | zdroje 3 | 18 | 100,0 % (82,4 až 100,0) | 100,0 % (82,4 až 100,0) | nedostatečná data |
| c2_beacon | objem 0.25× | 63 | 34,9 % (24,3 až 47,2) | 54,0 % (41,8 až 65,7) | slabé místo |
| c2_beacon | objem 0.5× | 54 | 37,0 % (25,4 až 50,4) | 64,8 % (51,5 až 76,2) | slabé místo |
| c2_beacon | objem 1× | 107 | 30,8 % (22,9 až 40,1) | 59,8 % (50,3 až 68,6) | slabé místo |
| c2_beacon | objem 2× | 38 | 34,2 % (21,2 až 50,1) | 65,8 % (49,9 až 78,8) | slabé místo |
| c2_beacon | tempo 0.25× | 28 | 57,1 % (39,1 až 73,5) | 82,1 % (64,4 až 92,1) |  |
| c2_beacon | tempo 0.5× | 31 | 38,7 % (23,7 až 56,2) | 77,4 % (60,2 až 88,6) |  |
| c2_beacon | tempo 1× | 104 | 42,3 % (33,3 až 51,9) | 68,3 % (58,8 až 76,4) | slabé místo |
| c2_beacon | tempo 2× | 22 | 27,3 % (13,2 až 48,2) | 40,9 % (23,3 až 61,3) | SLEPÉ MÍSTO |
| c2_beacon | tempo 4× | 38 | 23,7 % (13,0 až 39,2) | 36,8 % (23,4 až 52,7) | SLEPÉ MÍSTO |
| c2_beacon | tempo 8× | 39 | 2,6 % (0,5 až 13,2) | 43,6 % (29,3 až 59,0) | SLEPÉ MÍSTO |
| c2_beacon | zdroje 1 | 97 | 22,7 % (15,5 až 32,0) | 55,7 % (45,8 až 65,2) | slabé místo |
| c2_beacon | zdroje 10 | 93 | 44,1 % (34,4 až 54,2) | 53,8 % (43,7 až 63,5) | slabé místo |
| c2_beacon | zdroje 3 | 72 | 34,7 % (24,8 až 46,2) | 75,0 % (63,9 až 83,6) |  |
| credential_stuffing | objem 0.25× | 29 | 86,2 % (69,4 až 94,5) | 89,7 % (73,6 až 96,4) |  |
| credential_stuffing | objem 0.5× | 38 | 84,2 % (69,6 až 92,6) | 76,3 % (60,8 až 87,0) |  |
| credential_stuffing | objem 1× | 72 | 84,7 % (74,7 až 91,2) | 81,9 % (71,5 až 89,1) |  |
| credential_stuffing | objem 2× | 20 | 85,0 % (64,0 až 94,8) | 80,0 % (58,4 až 91,9) |  |
| credential_stuffing | tempo 0.25× | 17 | 94,1 % (73,0 až 99,0) | 82,4 % (59,0 až 93,8) | nedostatečná data |
| credential_stuffing | tempo 0.5× | 21 | 90,5 % (71,1 až 97,3) | 71,4 % (50,0 až 86,2) |  |
| credential_stuffing | tempo 1× | 62 | 83,9 % (72,8 až 91,0) | 83,9 % (72,8 až 91,0) |  |
| credential_stuffing | tempo 2× | 17 | 82,4 % (59,0 až 93,8) | 82,4 % (59,0 až 93,8) | nedostatečná data |
| credential_stuffing | tempo 4× | 22 | 81,8 % (61,5 až 92,7) | 81,8 % (61,5 až 92,7) |  |
| credential_stuffing | tempo 8× | 20 | 80,0 % (58,4 až 91,9) | 85,0 % (64,0 až 94,8) |  |
| credential_stuffing | zdroje 1 | 63 | 77,8 % (66,1 až 86,3) | 79,4 % (67,8 až 87,5) |  |
| credential_stuffing | zdroje 10 | 44 | 93,2 % (81,8 až 97,7) | 86,4 % (73,3 až 93,6) |  |
| credential_stuffing | zdroje 3 | 52 | 86,5 % (74,7 až 93,3) | 80,8 % (68,1 až 89,2) |  |
| cryptomining | objem 0.25× | 20 | 20,0 % (8,1 až 41,6) | 80,0 % (58,4 až 91,9) |  |
| cryptomining | objem 0.5× | 25 | 40,0 % (23,4 až 59,3) | 80,0 % (60,9 až 91,1) |  |
| cryptomining | objem 1× | 47 | 29,8 % (18,7 až 44,0) | 76,6 % (62,8 až 86,4) |  |
| cryptomining | objem 2× | 33 | 33,3 % (19,8 až 50,4) | 81,8 % (65,6 až 91,4) |  |
| cryptomining | tempo 0.25× | 16 | 68,8 % (44,4 až 85,8) | 87,5 % (64,0 až 96,5) | nedostatečná data |
| cryptomining | tempo 0.5× | 14 | 42,9 % (21,4 až 67,4) | 78,6 % (52,4 až 92,4) | nedostatečná data |
| cryptomining | tempo 1× | 38 | 31,6 % (19,1 až 47,5) | 84,2 % (69,6 až 92,6) |  |
| cryptomining | tempo 2× | 17 | 35,3 % (17,3 až 58,7) | 94,1 % (73,0 až 99,0) | nedostatečná data |
| cryptomining | tempo 4× | 23 | 8,7 % (2,4 až 26,8) | 69,6 % (49,1 až 84,4) | slabé místo |
| cryptomining | tempo 8× | 17 | 11,8 % (3,3 až 34,3) | 58,8 % (36,0 až 78,4) | nedostatečná data |
| cryptomining | zdroje 1 | 45 | 22,2 % (12,5 až 36,3) | 88,9 % (76,5 až 95,2) |  |
| cryptomining | zdroje 10 | 41 | 39,0 % (25,7 až 54,3) | 63,4 % (48,1 až 76,4) | slabé místo |
| cryptomining | zdroje 3 | 39 | 33,3 % (20,6 až 49,0) | 84,6 % (70,3 až 92,8) |  |
| ddos_volume | objem 0.25× | 8 | 75,0 % (40,9 až 92,9) | 75,0 % (40,9 až 92,9) | nedostatečná data |
| ddos_volume | objem 0.5× | 14 | 78,6 % (52,4 až 92,4) | 78,6 % (52,4 až 92,4) | nedostatečná data |
| ddos_volume | objem 1× | 45 | 86,7 % (73,8 až 93,7) | 84,4 % (71,2 až 92,3) |  |
| ddos_volume | objem 2× | 16 | 93,8 % (71,7 až 98,9) | 93,8 % (71,7 až 98,9) | nedostatečná data |
| ddos_volume | tempo 0.25× | 11 | 90,9 % (62,3 až 98,4) | 90,9 % (62,3 až 98,4) | nedostatečná data |
| ddos_volume | tempo 0.5× | 6 | 66,7 % (30,0 až 90,3) | 66,7 % (30,0 až 90,3) | nedostatečná data |
| ddos_volume | tempo 1× | 36 | 86,1 % (71,3 až 93,9) | 80,6 % (65,0 až 90,2) |  |
| ddos_volume | tempo 2× | 10 | 80,0 % (49,0 až 94,3) | 80,0 % (49,0 až 94,3) | nedostatečná data |
| ddos_volume | tempo 4× | 9 | 100,0 % (70,1 až 100,0) | 100,0 % (70,1 až 100,0) | nedostatečná data |
| ddos_volume | tempo 8× | 11 | 81,8 % (52,3 až 94,9) | 90,9 % (62,3 až 98,4) | nedostatečná data |
| ddos_volume | zdroje 1 | 32 | 90,6 % (75,8 až 96,8) | 87,5 % (71,9 až 95,0) |  |
| ddos_volume | zdroje 10 | 25 | 84,0 % (65,3 až 93,6) | 84,0 % (65,3 až 93,6) |  |
| ddos_volume | zdroje 3 | 26 | 80,8 % (62,1 až 91,5) | 80,8 % (62,1 až 91,5) |  |
| dns_tunnel | objem 0.25× | 25 | 48,0 % (30,0 až 66,5) | 64,0 % (44,5 až 79,8) | slabé místo |
| dns_tunnel | objem 0.5× | 28 | 32,1 % (17,9 až 50,7) | 75,0 % (56,6 až 87,3) |  |
| dns_tunnel | objem 1× | 45 | 44,4 % (30,9 až 58,8) | 73,3 % (59,0 až 84,0) |  |
| dns_tunnel | objem 2× | 19 | 36,8 % (19,1 až 59,0) | 84,2 % (62,4 až 94,5) | nedostatečná data |
| dns_tunnel | tempo 0.25× | 14 | 57,1 % (32,6 až 78,6) | 42,9 % (21,4 až 67,4) | nedostatečná data |
| dns_tunnel | tempo 0.5× | 10 | 40,0 % (16,8 až 68,7) | 50,0 % (23,7 až 76,3) | nedostatečná data |
| dns_tunnel | tempo 1× | 52 | 44,2 % (31,6 až 57,7) | 73,1 % (59,7 až 83,2) |  |
| dns_tunnel | tempo 2× | 15 | 53,3 % (30,1 až 75,2) | 86,7 % (62,1 až 96,3) | nedostatečná data |
| dns_tunnel | tempo 4× | 11 | 18,2 % (5,1 až 47,7) | 90,9 % (62,3 až 98,4) | nedostatečná data |
| dns_tunnel | tempo 8× | 15 | 20,0 % (7,0 až 45,2) | 93,3 % (70,2 až 98,8) | nedostatečná data |
| dns_tunnel | zdroje 1 | 43 | 41,9 % (28,4 až 56,7) | 83,7 % (70,0 až 91,9) |  |
| dns_tunnel | zdroje 10 | 42 | 33,3 % (21,0 až 48,4) | 54,8 % (39,9 až 68,8) | slabé místo |
| dns_tunnel | zdroje 3 | 32 | 50,0 % (33,6 až 66,4) | 84,4 % (68,2 až 93,1) |  |
| exfiltration | objem 0.25× | 41 | 24,4 % (13,8 až 39,3) | 87,8 % (74,5 až 94,7) |  |
| exfiltration | objem 0.5× | 45 | 11,1 % (4,8 až 23,5) | 80,0 % (66,2 až 89,1) |  |
| exfiltration | objem 1× | 77 | 19,5 % (12,2 až 29,7) | 84,4 % (74,7 až 90,9) |  |
| exfiltration | objem 2× | 42 | 21,4 % (11,7 až 35,9) | 76,2 % (61,5 až 86,5) |  |
| exfiltration | tempo 0.25× | 30 | 33,3 % (19,2 až 51,2) | 90,0 % (74,4 až 96,5) |  |
| exfiltration | tempo 0.5× | 19 | 21,1 % (8,5 až 43,3) | 63,2 % (41,0 až 80,9) | nedostatečná data |
| exfiltration | tempo 1× | 79 | 19,0 % (11,9 až 29,0) | 81,0 % (71,0 až 88,1) |  |
| exfiltration | tempo 2× | 26 | 23,1 % (11,0 až 42,1) | 92,3 % (75,9 až 97,9) |  |
| exfiltration | tempo 4× | 23 | 0,0 % (0,0 až 14,3) | 78,3 % (58,1 až 90,3) |  |
| exfiltration | tempo 8× | 28 | 14,3 % (5,7 až 31,5) | 85,7 % (68,5 až 94,3) |  |
| exfiltration | zdroje 1 | 96 | 10,4 % (5,8 až 18,1) | 68,8 % (58,9 až 77,1) | slabé místo |
| exfiltration | zdroje 10 | 49 | 22,4 % (13,0 až 35,9) | 95,9 % (86,3 až 98,9) |  |
| exfiltration | zdroje 3 | 60 | 30,0 % (19,9 až 42,5) | 93,3 % (84,1 až 97,4) |  |
| exploit_attempt | objem 0.25× | 60 | 31,7 % (21,3 až 44,2) | 45,0 % (33,1 až 57,5) | SLEPÉ MÍSTO |
| exploit_attempt | objem 0.5× | 55 | 25,5 % (15,8 až 38,3) | 43,6 % (31,4 až 56,7) | SLEPÉ MÍSTO |
| exploit_attempt | objem 1× | 103 | 29,1 % (21,2 až 38,5) | 52,4 % (42,9 až 61,8) | slabé místo |
| exploit_attempt | objem 2× | 52 | 26,9 % (16,8 až 40,3) | 55,8 % (42,3 až 68,4) | slabé místo |
| exploit_attempt | tempo 0.25× | 32 | 25,0 % (13,3 až 42,1) | 59,4 % (42,3 až 74,5) | slabé místo |
| exploit_attempt | tempo 0.5× | 37 | 29,7 % (17,5 až 45,8) | 56,8 % (40,9 až 71,3) | slabé místo |
| exploit_attempt | tempo 1× | 105 | 28,6 % (20,8 až 37,8) | 42,9 % (33,8 až 52,4) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 2× | 36 | 36,1 % (22,5 až 52,4) | 61,1 % (44,9 až 75,2) | slabé místo |
| exploit_attempt | tempo 4× | 29 | 31,0 % (17,3 až 49,2) | 44,8 % (28,4 až 62,5) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 8× | 31 | 19,4 % (9,2 až 36,3) | 45,2 % (29,2 až 62,2) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 1 | 121 | 25,6 % (18,7 až 34,1) | 52,1 % (43,2 až 60,8) | slabé místo |
| exploit_attempt | zdroje 10 | 69 | 36,2 % (25,9 až 48,0) | 40,6 % (29,8 až 52,4) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 3 | 80 | 26,2 % (17,9 až 36,8) | 53,8 % (42,9 až 64,3) | slabé místo |
| fleet_beacon | objem 0.25× | 8 | 62,5 % (30,6 až 86,3) | 75,0 % (40,9 až 92,9) | nedostatečná data |
| fleet_beacon | objem 0.5× | 6 | 33,3 % (9,7 až 70,0) | 66,7 % (30,0 až 90,3) | nedostatečná data |
| fleet_beacon | objem 1× | 12 | 58,3 % (32,0 až 80,7) | 83,3 % (55,2 až 95,3) | nedostatečná data |
| fleet_beacon | objem 2× | 8 | 87,5 % (52,9 až 97,8) | 75,0 % (40,9 až 92,9) | nedostatečná data |
| fleet_beacon | tempo 0.25× | 5 | 40,0 % (11,8 až 76,9) | 60,0 % (23,1 až 88,2) | nedostatečná data |
| fleet_beacon | tempo 0.5× | 5 | 80,0 % (37,6 až 96,4) | 80,0 % (37,6 až 96,4) | nedostatečná data |
| fleet_beacon | tempo 1× | 13 | 69,2 % (42,4 až 87,3) | 76,9 % (49,7 až 91,8) | nedostatečná data |
| fleet_beacon | tempo 2× | 3 | 66,7 % (20,8 až 93,9) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| fleet_beacon | tempo 4× | 3 | 0,0 % (0,0 až 56,1) | 66,7 % (20,8 až 93,9) | nedostatečná data |
| fleet_beacon | tempo 8× | 5 | 80,0 % (37,6 až 96,4) | 80,0 % (37,6 až 96,4) | nedostatečná data |
| fleet_beacon | zdroje 1 | 12 | 33,3 % (13,8 až 60,9) | 50,0 % (25,4 až 74,6) | nedostatečná data |
| fleet_beacon | zdroje 10 | 8 | 75,0 % (40,9 až 92,9) | 87,5 % (52,9 až 97,8) | nedostatečná data |
| fleet_beacon | zdroje 3 | 14 | 78,6 % (52,4 až 92,4) | 92,9 % (68,5 až 98,7) | nedostatečná data |
| ics_attack | objem 0.25× | 2 | 100,0 % (34,2 až 100,0) | 100,0 % (34,2 až 100,0) | nedostatečná data |
| ics_attack | objem 1× | 1 | 0,0 % (0,0 až 79,3) | 0,0 % (0,0 až 79,3) | nedostatečná data |
| ics_attack | tempo 0.25× | 2 | 50,0 % (9,5 až 90,5) | 50,0 % (9,5 až 90,5) | nedostatečná data |
| ics_attack | tempo 8× | 1 | 100,0 % (20,7 až 100,0) | 100,0 % (20,7 až 100,0) | nedostatečná data |
| ics_attack | zdroje 10 | 2 | 100,0 % (34,2 až 100,0) | 100,0 % (34,2 až 100,0) | nedostatečná data |
| ics_attack | zdroje 3 | 1 | 0,0 % (0,0 až 79,3) | 0,0 % (0,0 až 79,3) | nedostatečná data |
| insider_hoarding | objem 0.25× | 9 | 100,0 % (70,1 až 100,0) | 100,0 % (70,1 až 100,0) | nedostatečná data |
| insider_hoarding | objem 0.5× | 12 | 100,0 % (75,8 až 100,0) | 100,0 % (75,8 až 100,0) | nedostatečná data |
| insider_hoarding | objem 1× | 18 | 83,3 % (60,8 až 94,2) | 88,9 % (67,2 až 96,9) | nedostatečná data |
| insider_hoarding | objem 2× | 14 | 92,9 % (68,5 až 98,7) | 92,9 % (68,5 až 98,7) | nedostatečná data |
| insider_hoarding | tempo 0.25× | 5 | 100,0 % (56,6 až 100,0) | 100,0 % (56,6 až 100,0) | nedostatečná data |
| insider_hoarding | tempo 0.5× | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| insider_hoarding | tempo 1× | 24 | 91,7 % (74,2 až 97,7) | 91,7 % (74,2 až 97,7) |  |
| insider_hoarding | tempo 2× | 8 | 100,0 % (67,6 až 100,0) | 100,0 % (67,6 až 100,0) | nedostatečná data |
| insider_hoarding | tempo 4× | 4 | 75,0 % (30,1 až 95,4) | 75,0 % (30,1 až 95,4) | nedostatečná data |
| insider_hoarding | tempo 8× | 8 | 87,5 % (52,9 až 97,8) | 100,0 % (67,6 až 100,0) | nedostatečná data |
| insider_hoarding | zdroje 1 | 22 | 86,4 % (66,7 až 95,3) | 86,4 % (66,7 až 95,3) |  |
| insider_hoarding | zdroje 10 | 16 | 100,0 % (80,6 až 100,0) | 100,0 % (80,6 až 100,0) | nedostatečná data |
| insider_hoarding | zdroje 3 | 15 | 93,3 % (70,2 až 98,8) | 100,0 % (79,6 až 100,0) | nedostatečná data |
| lateral_movement | objem 0.25× | 35 | 71,4 % (54,9 až 83,7) | 62,9 % (46,3 až 76,8) | slabé místo |
| lateral_movement | objem 0.5× | 55 | 81,8 % (69,7 až 89,8) | 67,3 % (54,1 až 78,2) | slabé místo |
| lateral_movement | objem 1× | 98 | 74,5 % (65,0 až 82,1) | 70,4 % (60,7 až 78,5) |  |
| lateral_movement | objem 2× | 51 | 70,6 % (57,0 až 81,3) | 74,5 % (61,1 až 84,5) |  |
| lateral_movement | tempo 0.25× | 29 | 86,2 % (69,4 až 94,5) | 72,4 % (54,3 až 85,3) |  |
| lateral_movement | tempo 0.5× | 37 | 78,4 % (62,8 až 88,6) | 67,6 % (51,5 až 80,4) | slabé místo |
| lateral_movement | tempo 1× | 104 | 66,3 % (56,8 až 74,7) | 62,5 % (52,9 až 71,2) | slabé místo |
| lateral_movement | tempo 2× | 20 | 50,0 % (29,9 až 70,1) | 45,0 % (25,8 až 65,8) | SLEPÉ MÍSTO |
| lateral_movement | tempo 4× | 16 | 93,8 % (71,7 až 98,9) | 93,8 % (71,7 až 98,9) | nedostatečná data |
| lateral_movement | tempo 8× | 33 | 93,9 % (80,4 až 98,3) | 93,9 % (80,4 až 98,3) |  |
| lateral_movement | zdroje 1 | 102 | 73,5 % (64,2 až 81,1) | 67,6 % (58,1 až 75,9) | slabé místo |
| lateral_movement | zdroje 10 | 65 | 75,4 % (63,7 až 84,2) | 70,8 % (58,8 až 80,4) |  |
| lateral_movement | zdroje 3 | 72 | 76,4 % (65,4 až 84,7) | 70,8 % (59,5 až 80,1) |  |
| port_scan_horizontal | objem 0.25× | 38 | 86,8 % (72,7 až 94,2) | 78,9 % (63,7 až 88,9) |  |
| port_scan_horizontal | objem 0.5× | 41 | 82,9 % (68,7 až 91,5) | 75,6 % (60,7 až 86,2) |  |
| port_scan_horizontal | objem 1× | 76 | 81,6 % (71,4 až 88,7) | 85,5 % (75,9 až 91,7) |  |
| port_scan_horizontal | objem 2× | 40 | 77,5 % (62,5 až 87,7) | 80,0 % (65,2 až 89,5) |  |
| port_scan_horizontal | tempo 0.25× | 21 | 76,2 % (54,9 až 89,4) | 90,5 % (71,1 až 97,3) |  |
| port_scan_horizontal | tempo 0.5× | 24 | 83,3 % (64,1 až 93,3) | 83,3 % (64,1 až 93,3) |  |
| port_scan_horizontal | tempo 1× | 72 | 69,4 % (58,0 až 78,9) | 75,0 % (63,9 až 83,6) |  |
| port_scan_horizontal | tempo 2× | 26 | 96,2 % (81,1 až 99,3) | 61,5 % (42,5 až 77,6) | slabé místo |
| port_scan_horizontal | tempo 4× | 25 | 92,0 % (75,0 až 97,8) | 92,0 % (75,0 až 97,8) |  |
| port_scan_horizontal | tempo 8× | 27 | 96,3 % (81,7 až 99,3) | 96,3 % (81,7 až 99,3) |  |
| port_scan_horizontal | zdroje 1 | 67 | 82,1 % (71,3 až 89,4) | 88,1 % (78,2 až 93,8) |  |
| port_scan_horizontal | zdroje 10 | 56 | 89,3 % (78,5 až 95,0) | 76,8 % (64,2 až 85,9) |  |
| port_scan_horizontal | zdroje 3 | 72 | 76,4 % (65,4 až 84,7) | 77,8 % (66,9 až 85,8) |  |
| port_scan_vertical | objem 0.25× | 35 | 57,1 % (40,9 až 72,0) | 85,7 % (70,6 až 93,7) |  |
| port_scan_vertical | objem 0.5× | 43 | 55,8 % (41,1 až 69,6) | 79,1 % (64,8 až 88,6) |  |
| port_scan_vertical | objem 1× | 102 | 57,8 % (48,1 až 67,0) | 89,2 % (81,7 až 93,9) |  |
| port_scan_vertical | objem 2× | 53 | 50,9 % (37,9 až 63,9) | 73,6 % (60,4 až 83,6) |  |
| port_scan_vertical | tempo 0.25× | 29 | 51,7 % (34,4 až 68,6) | 82,8 % (65,5 až 92,4) |  |
| port_scan_vertical | tempo 0.5× | 20 | 40,0 % (21,9 až 61,3) | 90,0 % (69,9 až 97,2) |  |
| port_scan_vertical | tempo 1× | 92 | 42,4 % (32,8 až 52,6) | 83,7 % (74,8 až 89,9) |  |
| port_scan_vertical | tempo 2× | 34 | 79,4 % (63,2 až 89,7) | 88,2 % (73,4 až 95,3) |  |
| port_scan_vertical | tempo 4× | 27 | 66,7 % (47,8 až 81,4) | 74,1 % (55,3 až 86,8) |  |
| port_scan_vertical | tempo 8× | 31 | 74,2 % (56,8 až 86,3) | 80,6 % (63,7 až 90,8) |  |
| port_scan_vertical | zdroje 1 | 98 | 55,1 % (45,2 až 64,6) | 85,7 % (77,4 až 91,3) |  |
| port_scan_vertical | zdroje 10 | 61 | 50,8 % (38,6 až 62,9) | 78,7 % (66,9 až 87,1) |  |
| port_scan_vertical | zdroje 3 | 74 | 60,8 % (49,4 až 71,1) | 83,8 % (73,8 až 90,5) |  |
| ransomware | objem 0.25× | 16 | 87,5 % (64,0 až 96,5) | 87,5 % (64,0 až 96,5) | nedostatečná data |
| ransomware | objem 0.5× | 17 | 94,1 % (73,0 až 99,0) | 94,1 % (73,0 až 99,0) | nedostatečná data |
| ransomware | objem 1× | 33 | 90,9 % (76,4 až 96,9) | 93,9 % (80,4 až 98,3) |  |
| ransomware | objem 2× | 16 | 100,0 % (80,6 až 100,0) | 93,8 % (71,7 až 98,9) | nedostatečná data |
| ransomware | tempo 0.25× | 18 | 83,3 % (60,8 až 94,2) | 88,9 % (67,2 až 96,9) | nedostatečná data |
| ransomware | tempo 0.5× | 12 | 91,7 % (64,6 až 98,5) | 100,0 % (75,8 až 100,0) | nedostatečná data |
| ransomware | tempo 1× | 27 | 96,3 % (81,7 až 99,3) | 88,9 % (71,9 až 96,1) |  |
| ransomware | tempo 2× | 7 | 100,0 % (64,6 až 100,0) | 100,0 % (64,6 až 100,0) | nedostatečná data |
| ransomware | tempo 4× | 8 | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | nedostatečná data |
| ransomware | tempo 8× | 10 | 100,0 % (72,2 až 100,0) | 100,0 % (72,2 až 100,0) | nedostatečná data |
| ransomware | zdroje 1 | 32 | 96,9 % (84,3 až 99,4) | 100,0 % (89,3 až 100,0) |  |
| ransomware | zdroje 10 | 22 | 81,8 % (61,5 až 92,7) | 86,4 % (66,7 až 95,3) |  |
| ransomware | zdroje 3 | 28 | 96,4 % (82,3 až 99,4) | 89,3 % (72,8 až 96,3) |  |
| rogue_device | objem 0.25× | 15 | 60,0 % (35,7 až 80,2) | 100,0 % (79,6 až 100,0) | nedostatečná data |
| rogue_device | objem 0.5× | 11 | 54,5 % (28,0 až 78,7) | 100,0 % (74,1 až 100,0) | nedostatečná data |
| rogue_device | objem 1× | 27 | 37,0 % (21,5 až 55,8) | 92,6 % (76,6 až 97,9) |  |
| rogue_device | objem 2× | 10 | 20,0 % (5,7 až 51,0) | 100,0 % (72,2 až 100,0) | nedostatečná data |
| rogue_device | tempo 0.25× | 11 | 27,3 % (9,7 až 56,6) | 100,0 % (74,1 až 100,0) | nedostatečná data |
| rogue_device | tempo 0.5× | 3 | 0,0 % (0,0 až 56,1) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| rogue_device | tempo 1× | 26 | 15,4 % (6,2 až 33,5) | 92,3 % (75,9 až 97,9) |  |
| rogue_device | tempo 2× | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| rogue_device | tempo 4× | 9 | 88,9 % (56,5 až 98,0) | 100,0 % (70,1 až 100,0) | nedostatečná data |
| rogue_device | tempo 8× | 10 | 80,0 % (49,0 až 94,3) | 100,0 % (72,2 až 100,0) | nedostatečná data |
| rogue_device | zdroje 1 | 34 | 41,2 % (26,4 až 57,8) | 97,1 % (85,1 až 99,5) |  |
| rogue_device | zdroje 10 | 18 | 55,6 % (33,7 až 75,4) | 94,4 % (74,2 až 99,0) | nedostatečná data |
| rogue_device | zdroje 3 | 11 | 27,3 % (9,7 až 56,6) | 100,0 % (74,1 až 100,0) | nedostatečná data |
| slow_scan | objem 0.25× | 34 | 91,2 % (77,0 až 97,0) | 82,4 % (66,5 až 91,7) |  |
| slow_scan | objem 0.5× | 35 | 91,4 % (77,6 až 97,0) | 91,4 % (77,6 až 97,0) |  |
| slow_scan | objem 1× | 91 | 83,5 % (74,6 až 89,7) | 86,8 % (78,4 až 92,3) |  |
| slow_scan | objem 2× | 41 | 82,9 % (68,7 až 91,5) | 82,9 % (68,7 až 91,5) |  |
| slow_scan | tempo 0.25× | 21 | 90,5 % (71,1 až 97,3) | 85,7 % (65,4 až 95,0) |  |
| slow_scan | tempo 0.5× | 22 | 72,7 % (51,8 až 86,8) | 86,4 % (66,7 až 95,3) |  |
| slow_scan | tempo 1× | 89 | 78,7 % (69,0 až 85,9) | 82,0 % (72,8 až 88,6) |  |
| slow_scan | tempo 2× | 21 | 95,2 % (77,3 až 99,2) | 81,0 % (60,0 až 92,3) |  |
| slow_scan | tempo 4× | 20 | 100,0 % (83,9 až 100,0) | 100,0 % (83,9 až 100,0) |  |
| slow_scan | tempo 8× | 28 | 100,0 % (87,9 až 100,0) | 92,9 % (77,4 až 98,0) |  |
| slow_scan | zdroje 1 | 75 | 82,7 % (72,6 až 89,6) | 98,7 % (92,8 až 99,8) |  |
| slow_scan | zdroje 10 | 64 | 89,1 % (79,1 až 94,6) | 71,9 % (59,9 až 81,4) |  |
| slow_scan | zdroje 3 | 62 | 87,1 % (76,6 až 93,3) | 85,5 % (74,7 až 92,2) |  |
| ssh_bruteforce | objem 0.25× | 51 | 90,2 % (79,0 až 95,7) | 96,1 % (86,8 až 98,9) |  |
| ssh_bruteforce | objem 0.5× | 58 | 84,5 % (73,1 až 91,6) | 89,7 % (79,2 až 95,2) |  |
| ssh_bruteforce | objem 1× | 112 | 78,6 % (70,1 až 85,2) | 85,7 % (78,0 až 91,0) |  |
| ssh_bruteforce | objem 2× | 64 | 82,8 % (71,8 až 90,1) | 93,8 % (85,0 až 97,5) |  |
| ssh_bruteforce | tempo 0.25× | 30 | 93,3 % (78,7 až 98,2) | 96,7 % (83,3 až 99,4) |  |
| ssh_bruteforce | tempo 0.5× | 42 | 88,1 % (75,0 až 94,8) | 90,5 % (77,9 až 96,2) |  |
| ssh_bruteforce | tempo 1× | 114 | 80,7 % (72,5 až 86,9) | 89,5 % (82,5 až 93,9) |  |
| ssh_bruteforce | tempo 2× | 35 | 88,6 % (74,0 až 95,5) | 94,3 % (81,4 až 98,4) |  |
| ssh_bruteforce | tempo 4× | 34 | 82,4 % (66,5 až 91,7) | 85,3 % (69,9 až 93,6) |  |
| ssh_bruteforce | tempo 8× | 30 | 66,7 % (48,8 až 80,8) | 86,7 % (70,3 až 94,7) |  |
| ssh_bruteforce | zdroje 1 | 123 | 82,1 % (74,4 až 87,9) | 91,9 % (85,7 až 95,5) |  |
| ssh_bruteforce | zdroje 10 | 82 | 86,6 % (77,6 až 92,3) | 89,0 % (80,4 až 94,1) |  |
| ssh_bruteforce | zdroje 3 | 80 | 80,0 % (70,0 až 87,3) | 88,8 % (80,0 až 94,0) |  |
| web_exploit | objem 0.25× | 54 | 77,8 % (65,1 až 86,8) | 88,9 % (77,8 až 94,8) |  |
| web_exploit | objem 0.5× | 29 | 75,9 % (57,9 až 87,8) | 79,3 % (61,6 až 90,2) |  |
| web_exploit | objem 1× | 63 | 82,5 % (71,4 až 90,0) | 84,1 % (73,2 až 91,1) |  |
| web_exploit | objem 2× | 42 | 76,2 % (61,5 až 86,5) | 83,3 % (69,4 až 91,7) |  |
| web_exploit | tempo 0.25× | 29 | 75,9 % (57,9 až 87,8) | 65,5 % (47,3 až 80,1) | slabé místo |
| web_exploit | tempo 0.5× | 28 | 89,3 % (72,8 až 96,3) | 82,1 % (64,4 až 92,1) |  |
| web_exploit | tempo 1× | 78 | 84,6 % (75,0 až 91,0) | 91,0 % (82,6 až 95,6) |  |
| web_exploit | tempo 2× | 17 | 47,1 % (26,2 až 69,0) | 76,5 % (52,7 až 90,4) | nedostatečná data |
| web_exploit | tempo 4× | 20 | 80,0 % (58,4 až 91,9) | 95,0 % (76,4 až 99,1) |  |
| web_exploit | tempo 8× | 16 | 68,8 % (44,4 až 85,8) | 87,5 % (64,0 až 96,5) | nedostatečná data |
| web_exploit | zdroje 1 | 77 | 81,8 % (71,8 až 88,8) | 85,7 % (76,2 až 91,8) |  |
| web_exploit | zdroje 10 | 53 | 67,9 % (54,5 až 78,9) | 79,2 % (66,5 až 88,0) |  |
| web_exploit | zdroje 3 | 58 | 84,5 % (73,1 až 91,6) | 87,9 % (77,1 až 94,0) |  |

### Souběh útoku s provozní poruchou

| buňka | n | detekce legacy | detekce v3 | registr |
|---|---:|---:|---:|---:|
| bez souběhu | 482 | 57,9 % (53,4 až 62,2) | 80,9 % (77,2 až 84,2) |  |
| nesenzorová porucha | 2197 | 62,8 % (60,7 až 64,8) | 78,2 % (76,5 až 79,9) |  |
| s backup_failed | 314 | 64,6 % (59,2 až 69,7) | 83,4 % (78,9 až 87,1) |  |
| s batch_job | 512 | 61,7 % (57,4 až 65,8) | 82,0 % (78,5 až 85,1) |  |
| s cert_expired | 400 | 70,0 % (65,3 až 74,3) | 83,5 % (79,5 až 86,8) |  |
| s cloud_migration | 911 | 65,3 % (62,2 až 68,3) | 80,1 % (77,4 až 82,6) |  |
| s collector_replay | 575 | 66,3 % (62,3 až 70,0) | 82,6 % (79,3 až 85,5) |  |
| s device_decommission | 298 | 75,2 % (70,0 až 79,7) | 86,9 % (82,6 až 90,3) |  |
| s device_onboarding | 328 | 69,5 % (64,3 až 74,2) | 86,6 % (82,5 až 89,9) |  |
| s dhcp_renumber | 326 | 68,7 % (63,5 až 73,5) | 85,0 % (80,7 až 88,4) |  |
| s dns_outage | 319 | 77,4 % (72,5 až 81,7) | 85,6 % (81,3 až 89,0) |  |
| s link_flapping | 365 | 62,7 % (57,7 až 67,5) | 82,2 % (77,9 až 85,8) |  |
| s log_corruption | 451 | 66,3 % (61,8 až 70,5) | 84,3 % (80,6 až 87,3) |  |
| s misconfig | 343 | 70,6 % (65,5 až 75,1) | 85,4 % (81,3 až 88,8) |  |
| s patch_window | 384 | 71,9 % (67,2 až 76,1) | 84,1 % (80,1 až 87,4) |  |
| s retry_storm | 422 | 68,2 % (63,7 až 72,5) | 84,1 % (80,3 až 87,3) |  |
| s segment_power_loss | 336 | 70,8 % (65,8 až 75,4) | 87,5 % (83,5 až 90,6) |  |
| s sensor_crash | 560 | 58,2 % (54,1 až 62,2) | 71,6 % (67,7 až 75,2) |  |
| s service_crash | 705 | 65,5 % (61,9 až 68,9) | 82,1 % (79,1 až 84,8) |  |
| s vpn_reconnect_storm | 258 | 67,8 % (61,9 až 73,2) | 86,4 % (81,7 až 90,1) |  |
| senzorová porucha | 1119 | 60,1 % (57,2 až 63,0) | 75,4 % (72,8 až 77,9) |  |

### Kampaně

| rameno | šablona | kampaní | aspoň jedna fáze | první fáze | všechny fáze |
|---|---:|---:|---:|---:|---:|
| legacy | K-H1 | 29 | 100,0 % (88,3 až 100,0) | 86,2 % (69,4 až 94,5) | 48,3 % (31,4 až 65,6) |
| legacy | K-H2 | 38 | 81,6 % (66,6 až 90,8) | 73,7 % (58,0 až 85,0) | 15,8 % (7,4 až 30,4) |
| legacy | K-H3 | 37 | 100,0 % (90,6 až 100,0) | 83,8 % (68,9 až 92,3) | 10,8 % (4,3 až 24,7) |
| legacy | K-T1 | 32 | 93,8 % (79,9 až 98,3) | 71,9 % (54,6 až 84,4) | 21,9 % (11,0 až 38,8) |
| legacy | K-T2 | 29 | 96,6 % (82,8 až 99,4) | 96,6 % (82,8 až 99,4) | 27,6 % (14,7 až 45,7) |
| legacy | K-T3 | 38 | 89,5 % (75,9 až 95,8) | 18,4 % (9,2 až 33,4) | 0,0 % (0,0 až 9,2) |
| legacy | vše | 203 | 93,1 % (88,8 až 95,8) | 70,0 % (63,3 až 75,8) | 19,2 % (14,4 až 25,2) |
| v3 | K-H1 | 29 | 100,0 % (88,3 až 100,0) | 89,7 % (73,6 až 96,4) | 48,3 % (31,4 až 65,6) |
| v3 | K-H2 | 38 | 97,4 % (86,5 až 99,5) | 81,6 % (66,6 až 90,8) | 50,0 % (34,8 až 65,2) |
| v3 | K-H3 | 37 | 94,6 % (82,3 až 98,5) | 81,1 % (65,8 až 90,5) | 37,8 % (24,1 až 53,9) |
| v3 | K-T1 | 32 | 96,9 % (84,3 až 99,4) | 71,9 % (54,6 až 84,4) | 34,4 % (20,4 až 51,7) |
| v3 | K-T2 | 29 | 100,0 % (88,3 až 100,0) | 93,1 % (78,0 až 98,1) | 58,6 % (40,7 až 74,5) |
| v3 | K-T3 | 38 | 100,0 % (90,8 až 100,0) | 65,8 % (49,9 až 78,8) | 26,3 % (15,0 až 42,0) |
| v3 | vše | 203 | 98,0 % (95,0 až 99,2) | 79,8 % (73,8 až 84,7) | 41,9 % (35,3 až 48,7) |

### Leave-one-family-out (náhrada A5), rameno `v3`

| rodina | vynechané typy D(X) | n | detekce všemi signály | obecná detekce | verdikt |
|---|---:|---:|---:|---:|---:|
| c2_beacon | beacon_periodic | 49 | 38,8 % (26,4 až 52,8) | 16,3 % (8,5 až 29,0) | SLEPÉ MÍSTO |
| exfiltration | egress_volume_anomaly, long_lived_tunnel | 41 | 85,4 % (71,6 až 93,1) | 14,6 % (6,9 až 28,4) | SLEPÉ MÍSTO |
| ssh_bruteforce | connection_timeout_burst, source_volume_outlier | 29 | 75,9 % (57,9 až 87,8) | 75,9 % (57,9 až 87,8) | zobecňuje |
| port_scan_vertical | connection_timeout_burst, scan_attempts | 41 | 95,1 % (83,9 až 98,7) | 0,0 % (0,0 až 8,6) | SLEPÉ MÍSTO |
| lateral_movement | multi_target_pattern, pivot_chain | 38 | 60,5 % (44,7 až 74,4) | 47,4 % (32,5 až 62,7) | SLEPÉ MÍSTO |
| dns_tunnel | egress_volume_anomaly, source_volume_outlier | 33 | 75,8 % (59,0 až 87,2) | 54,5 % (38,0 až 70,2) | zobecňuje |

### Útoky s automaticky zavřeným připsaným nálezem

| rameno | rodiny | útoků | podíl s automatickým zavřením | z toho první výskyt (A7) |
|---|---:|---:|---:|---:|
| legacy | laděné | 2111 | 0,0 % (0,0 až 0,2) | 0 |
| legacy | držené | 745 | 0,0 % (0,0 až 0,5) | 0 |
| v3 | laděné | 2111 | 1,0 % (0,7 až 1,6) | 10 |
| v3 | držené | 745 | 4,2 % (2,9 až 5,8) | 14 |

### Poruchy a lookalike: podíl výskytů s FP

| rameno | událost | výskytů | zobrazené FP | zachycené FP | registr |
|---|---:|---:|---:|---:|---:|
| legacy | authorized_scanner | 273 | 45,4 % (39,6 až 51,4) | 45,4 % (39,6 až 51,4) | FP SLEPÉ MÍSTO |
| legacy | backup_burst | 667 | 63,6 % (59,8 až 67,1) | 63,6 % (59,8 až 67,1) | FP SLEPÉ MÍSTO |
| legacy | backup_failed | 97 | 89,7 % (82,1 až 94,3) | 89,7 % (82,1 až 94,3) | FP SLEPÉ MÍSTO |
| legacy | batch_job | 168 | 81,0 % (74,3 až 86,2) | 81,0 % (74,3 až 86,2) | FP SLEPÉ MÍSTO |
| legacy | cert_expired (H) | 119 | 99,2 % (95,4 až 99,9) | 99,2 % (95,4 až 99,9) | FP SLEPÉ MÍSTO |
| legacy | cloud_migration (H) | 119 | 88,2 % (81,2 až 92,9) | 88,2 % (81,2 až 92,9) | FP SLEPÉ MÍSTO |
| legacy | collector_replay | 228 | 91,2 % (86,8 až 94,2) | 91,2 % (86,8 až 94,2) | FP SLEPÉ MÍSTO |
| legacy | device_decommission | 114 | 20,2 % (13,8 až 28,5) | 20,2 % (13,8 až 28,5) | FP SLEPÉ MÍSTO |
| legacy | device_onboarding | 135 | 4,4 % (2,1 až 9,4) | 4,4 % (2,1 až 9,4) |  |
| legacy | dhcp_renumber | 132 | 78,8 % (71,1 až 84,9) | 78,8 % (71,1 až 84,9) | FP SLEPÉ MÍSTO |
| legacy | dns_outage | 128 | 100,0 % (97,1 až 100,0) | 100,0 % (97,1 až 100,0) | FP SLEPÉ MÍSTO |
| legacy | flash_crowd | 618 | 80,9 % (77,6 až 83,8) | 80,9 % (77,6 až 83,8) | FP SLEPÉ MÍSTO |
| legacy | link_flapping | 129 | 0,0 % (0,0 až 2,9) | 0,0 % (0,0 až 2,9) |  |
| legacy | log_corruption | 163 | 89,6 % (83,9 až 93,4) | 89,6 % (83,9 až 93,4) | FP SLEPÉ MÍSTO |
| legacy | misconfig | 126 | 88,9 % (82,2 až 93,3) | 88,9 % (82,2 až 93,3) | FP SLEPÉ MÍSTO |
| legacy | ntp_fanout | 335 | 19,4 % (15,5 až 24,0) | 19,4 % (15,5 až 24,0) |  |
| legacy | patch_window | 155 | 92,9 % (87,7 až 96,0) | 92,9 % (87,7 až 96,0) | FP SLEPÉ MÍSTO |
| legacy | retry_storm | 183 | 0,0 % (0,0 až 2,1) | 0,0 % (0,0 až 2,1) |  |
| legacy | segment_power_loss (H) | 128 | 57,0 % (48,4 až 65,3) | 57,0 % (48,4 až 65,3) | FP SLEPÉ MÍSTO |
| legacy | sensor_crash | 203 | 0,0 % (0,0 až 1,9) | 0,0 % (0,0 až 1,9) |  |
| legacy | service_crash | 310 | 85,8 % (81,5 až 89,3) | 85,8 % (81,5 až 89,3) | FP SLEPÉ MÍSTO |
| legacy | software_update | 635 | 0,0 % (0,0 až 0,6) | 0,0 % (0,0 až 0,6) |  |
| legacy | vpn_reconnect_storm (H) | 102 | 87,3 % (79,4 až 92,4) | 87,3 % (79,4 až 92,4) | FP SLEPÉ MÍSTO |
| v3 | authorized_scanner | 273 | 93,4 % (89,8 až 95,8) | 95,6 % (92,5 až 97,5) | FP SLEPÉ MÍSTO |
| v3 | backup_burst | 667 | 37,5 % (33,9 až 41,2) | 58,3 % (54,5 až 62,0) | FP SLEPÉ MÍSTO |
| v3 | backup_failed | 97 | 77,3 % (68,0 až 84,5) | 84,5 % (76,0 až 90,4) | FP SLEPÉ MÍSTO |
| v3 | batch_job | 168 | 64,9 % (57,4 až 71,7) | 75,0 % (67,9 až 80,9) | FP SLEPÉ MÍSTO |
| v3 | cert_expired (H) | 119 | 89,1 % (82,2 až 93,5) | 97,5 % (92,8 až 99,1) | FP SLEPÉ MÍSTO |
| v3 | cloud_migration (H) | 119 | 89,9 % (83,2 až 94,1) | 90,8 % (84,2 až 94,8) | FP SLEPÉ MÍSTO |
| v3 | collector_replay | 228 | 66,7 % (60,3 až 72,5) | 88,6 % (83,8 až 92,1) | FP SLEPÉ MÍSTO |
| v3 | device_decommission | 114 | 12,3 % (7,5 až 19,6) | 22,8 % (16,1 až 31,3) |  |
| v3 | device_onboarding | 135 | 23,7 % (17,3 až 31,5) | 28,1 % (21,2 až 36,3) | FP SLEPÉ MÍSTO |
| v3 | dhcp_renumber | 132 | 72,0 % (63,8 až 78,9) | 75,8 % (67,8 až 82,3) | FP SLEPÉ MÍSTO |
| v3 | dns_outage | 128 | 89,1 % (82,5 až 93,4) | 97,7 % (93,3 až 99,2) | FP SLEPÉ MÍSTO |
| v3 | flash_crowd | 618 | 38,5 % (34,8 až 42,4) | 76,4 % (72,9 až 79,6) | FP SLEPÉ MÍSTO |
| v3 | link_flapping | 129 | 0,0 % (0,0 až 2,9) | 0,0 % (0,0 až 2,9) |  |
| v3 | log_corruption | 163 | 42,9 % (35,6 až 50,6) | 77,9 % (70,9 až 83,6) | FP SLEPÉ MÍSTO |
| v3 | misconfig | 126 | 96,8 % (92,1 až 98,8) | 97,6 % (93,2 až 99,2) | FP SLEPÉ MÍSTO |
| v3 | ntp_fanout | 335 | 6,3 % (4,1 až 9,4) | 13,1 % (9,9 až 17,2) |  |
| v3 | patch_window | 155 | 86,5 % (80,2 až 91,0) | 94,8 % (90,1 až 97,4) | FP SLEPÉ MÍSTO |
| v3 | retry_storm | 183 | 0,0 % (0,0 až 2,1) | 0,0 % (0,0 až 2,1) |  |
| v3 | segment_power_loss (H) | 128 | 58,6 % (49,9 až 66,8) | 77,3 % (69,4 až 83,7) | FP SLEPÉ MÍSTO |
| v3 | sensor_crash | 203 | 22,2 % (17,0 až 28,4) | 22,2 % (17,0 až 28,4) | FP SLEPÉ MÍSTO |
| v3 | service_crash | 310 | 58,1 % (52,5 až 63,4) | 68,7 % (63,3 až 73,6) | FP SLEPÉ MÍSTO |
| v3 | software_update | 635 | 1,1 % (0,5 až 2,3) | 1,4 % (0,7 až 2,7) |  |
| v3 | vpn_reconnect_storm (H) | 102 | 79,4 % (70,6 až 86,1) | 85,3 % (77,1 až 90,9) | FP SLEPÉ MÍSTO |

### Registr slepých míst (rameno `v3`, automaticky podle A8)

| oblast | buňka | n | hodnota | zařazení |
|---|---:|---:|---:|---:|
| Osa: doba | 0.5× | 517 | 68,7 % | slabé místo |
| Rodiny | c2_beacon | 262 | 60,3 % | slabé místo |
| Rodiny | exploit_attempt | 270 | 49,6 % | SLEPÉ MÍSTO |
| Rodiny | lateral_movement | 239 | 69,5 % | slabé místo |
| Rodina × pásmo S | c2_beacon | Q1 | 29 | 65,5 % | slabé místo |
| Rodina × pásmo S | c2_beacon | Q2 | 36 | 55,6 % | slabé místo |
| Rodina × pásmo S | c2_beacon | Q4 | 60 | 56,7 % | slabé místo |
| Rodina × pásmo S | c2_beacon | Q5 | 109 | 57,8 % | slabé místo |
| Rodina × pásmo S | credential_stuffing | Q4 | 38 | 68,4 % | slabé místo |
| Rodina × pásmo S | cryptomining | Q4 | 21 | 61,9 % | slabé místo |
| Rodina × pásmo S | cryptomining | Q5 | 49 | 69,4 % | slabé místo |
| Rodina × pásmo S | dns_tunnel | Q5 | 42 | 54,8 % | slabé místo |
| Rodina × pásmo S | exfiltration | Q1 | 25 | 68,0 % | slabé místo |
| Rodina × pásmo S | exploit_attempt | Q1 | 37 | 43,2 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q2 | 39 | 51,3 % | slabé místo |
| Rodina × pásmo S | exploit_attempt | Q3 | 44 | 43,2 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q4 | 52 | 53,8 % | slabé místo |
| Rodina × pásmo S | exploit_attempt | Q5 | 98 | 52,0 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q1 | 34 | 67,6 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q3 | 38 | 63,2 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q5 | 86 | 67,4 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | objem 0.25× | 63 | 54,0 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | objem 0.5× | 54 | 64,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | objem 1× | 107 | 59,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | objem 2× | 38 | 65,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 1× | 104 | 68,3 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 2× | 22 | 40,9 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 4× | 38 | 36,8 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 8× | 39 | 43,6 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | zdroje 1 | 97 | 55,7 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | zdroje 10 | 93 | 53,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | cryptomining | tempo 4× | 23 | 69,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | cryptomining | zdroje 10 | 41 | 63,4 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | dns_tunnel | objem 0.25× | 25 | 64,0 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | dns_tunnel | zdroje 10 | 42 | 54,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exfiltration | zdroje 1 | 96 | 68,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.25× | 60 | 45,0 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.5× | 55 | 43,6 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 1× | 103 | 52,4 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 2× | 52 | 55,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 0.25× | 32 | 59,4 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 0.5× | 37 | 56,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 1× | 105 | 42,9 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 2× | 36 | 61,1 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 4× | 29 | 44,8 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 8× | 31 | 45,2 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 1 | 121 | 52,1 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 10 | 69 | 40,6 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 3 | 80 | 53,8 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 0.25× | 35 | 62,9 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 0.5× | 55 | 67,3 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 0.5× | 37 | 67,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 1× | 104 | 62,5 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 2× | 20 | 45,0 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | zdroje 1 | 102 | 67,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | port_scan_horizontal | tempo 2× | 26 | 61,5 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | web_exploit | tempo 0.25× | 29 | 65,5 % | slabé místo |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | c2_beacon | 49 | 16,3 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | exfiltration | 41 | 14,6 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | port_scan_vertical | 41 | 0,0 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | lateral_movement | 38 | 47,4 % | SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | authorized_scanner | 273 | 93,4 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | backup_burst | 667 | 37,5 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | backup_failed | 97 | 77,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | batch_job | 168 | 64,9 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | cert_expired | 119 | 89,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | cloud_migration | 119 | 89,9 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | collector_replay | 228 | 66,7 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | device_onboarding | 135 | 23,7 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | dhcp_renumber | 132 | 72,0 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | dns_outage | 128 | 89,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | flash_crowd | 618 | 38,5 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | log_corruption | 163 | 42,9 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | misconfig | 126 | 96,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | patch_window | 155 | 86,5 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | segment_power_loss | 128 | 58,6 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | sensor_crash | 203 | 22,2 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | service_crash | 310 | 58,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (zobrazené FP) | vpn_reconnect_storm | 102 | 79,4 % | FP SLEPÉ MÍSTO |

### Prahy K1 až K8

| práh | hodnota | splněno |
|---|---:|---:|
| K1 | Q5/Q1 = 0,94 | ano |
| K2 | vše +16,5 p. b., Q4+Q5 +13,6 p. b. | ano |
| K3 | držené 78,8 % vs laděné 66,3 % | ne |
| K4 | -1,9 p. b. | ano |
| K5 | c2_beacon: 8/49, exfiltration: 6/41, ssh_bruteforce: 22/29, port_scan_vertical: 0/41, lateral_movement: 18/38, dns_tunnel: 18/33 | 2 ze 6 zobecňuje |
| K6 | 185/3165, horní mez 6,7 % | ne |
| K6b | držené 4,2 % vs laděné 1,0 % | ano |
| K7 | 98,0 % (95,0 až 99,2) | ano |
| K8 | 0 panik, 0 invariantů | ano |

