## Pokrytí, křivky skrytosti a registr slepých míst

Ramena: legacy, v3k6; hodnocené rameno `v3k6`. Detekce = kontrafaktuální zobrazená detekce na útok (Wilson 95 %; souhrny a rozdíly s bootstrapem po sítích).

Hranice pásem S (zadané předem): 0.172, 0.236, 0.305, 0.392

| rameno | sítí | útoků | detekce (bootstrap) | zobrazené FP/síť-den | zavřeno omylem (G3) | panik/invariantů |
|---|---:|---:|---:|---:|---:|---:|
| legacy | 80 | 2224 | 59,5 % (55,4 až 62,6) | 900,8 | – % (0,0 až 100,0) [0/0] | 0/0 |
| v3k6 | 80 | 2224 | 78,4 % (74,8 až 81,8) | 13,1 | 2,5 % (1,8 až 3,5) [33/1320] | 0/0 |

### Párově `v3k6` − `legacy`

| výběr | párů | rozdíl detekce |
|---|---:|---:|
| vše | 2224 | +18,9 p. b. (+16,8 až +21,6) |
| Q4 + Q5 | 1300 | +17,1 p. b. (+14,5 až +20,8) |
| Q5 | 845 | +16,4 p. b. (+13,7 až +19,7) |

### Párově po rodinách `v3k6` − `legacy`

| rodina | párů | rozdíl detekce | B5/D1 |
|---|---:|---:|---:|
| apt_chain | 38 | +0,0 p. b. (-7,4 až +7,5) |  |
| c2_beacon | 182 | +34,1 p. b. (+26,3 až +43,2) |  |
| credential_stuffing | 124 | +3,2 p. b. (-3,2 až +10,7) |  |
| cryptomining | 86 | +46,5 p. b. (+34,2 až +60,7) |  |
| ddos_volume | 56 | -1,8 p. b. (-4,1 až +0,0) |  |
| dns_tunnel | 91 | +45,1 p. b. (+31,1 až +57,6) |  |
| exfiltration | 148 | +70,9 p. b. (+61,8 až +79,0) |  |
| exploit_attempt | 233 | +17,6 p. b. (+7,8 až +31,4) |  |
| fleet_beacon | 35 | +5,7 p. b. (+0,0 až +12,5) |  |
| ics_attack | 8 | +0,0 p. b. (+0,0 až +0,0) |  |
| insider_hoarding | 36 | +5,6 p. b. (-4,0 až +17,9) |  |
| lateral_movement | 197 | -2,5 p. b. (-7,1 až +1,3) |  |
| port_scan_horizontal | 155 | +2,6 p. b. (-3,7 až +8,7) |  |
| port_scan_vertical | 195 | +33,8 p. b. (+23,6 až +41,6) |  |
| ransomware | 65 | +1,5 p. b. (+0,0 až +6,5) |  |
| rogue_device | 34 | +76,5 p. b. (+61,3 až +90,0) |  |
| slow_scan | 145 | +1,4 p. b. (-7,3 až +7,4) |  |
| ssh_bruteforce | 263 | +6,8 p. b. (+3,3 až +11,7) |  |
| web_exploit | 133 | +9,0 p. b. (+3,0 až +16,2) |  |

### Poměr zobrazených FP `v3k6` / `legacy` (stejné sítě)

| metrika | poměr (bootstrap 95 %) |
|---|---:|
| displayed_fp | 0,015 (0,012 až 0,020) |
| displayed_fp_suspect | 0,015 (0,012 až 0,020) |

### Křivka skrytosti: pásma S

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| Q1 | 294 | 56,8 % (51,1 až 62,3) | 83,0 % (78,3 až 86,9) |  |
| Q2 | 278 | 57,2 % (51,3 až 62,9) | 77,7 % (72,4 až 82,2) |  |
| Q3 | 352 | 60,2 % (55,0 až 65,2) | 78,4 % (73,8 až 82,4) |  |
| Q4 | 455 | 59,3 % (54,8 až 63,8) | 77,6 % (73,5 až 81,2) |  |
| Q5 | 845 | 60,9 % (57,6 až 64,2) | 77,4 % (74,5 až 80,1) |  |

### Osa: intenzita

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| 0.0–0.2 | 330 | 60,0 % (54,6 až 65,1) | 75,5 % (70,5 až 79,8) |  |
| 0.2–0.4 | 466 | 60,3 % (55,8 až 64,6) | 79,4 % (75,5 až 82,8) |  |
| 0.4–0.6 | 463 | 62,2 % (57,7 až 66,5) | 79,5 % (75,6 až 82,9) |  |
| 0.6–0.8 | 473 | 58,8 % (54,3 až 63,1) | 78,9 % (75,0 až 82,3) |  |
| 0.8–1.0 | 492 | 56,5 % (52,1 až 60,8) | 77,8 % (74,0 až 81,3) |  |

### Osa: tempo

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| 0.25× | 276 | 61,6 % (55,7 až 67,1) | 76,1 % (70,7 až 80,7) |  |
| 0.5× | 269 | 65,1 % (59,2 až 70,5) | 84,0 % (79,2 až 87,9) |  |
| 1× | 886 | 54,4 % (51,1 až 57,7) | 76,6 % (73,7 až 79,3) |  |
| 2× | 284 | 61,6 % (55,8 až 67,1) | 77,8 % (72,6 až 82,3) |  |
| 4× | 256 | 65,6 % (59,6 až 71,2) | 82,8 % (77,7 až 86,9) |  |
| 8× | 253 | 60,5 % (54,3 až 66,3) | 77,1 % (71,5 až 81,8) |  |

### Osa: rozptyl

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| 0 | 880 | 60,2 % (57,0 až 63,4) | 80,3 % (77,6 až 82,8) |  |
| 0.15 | 476 | 54,6 % (50,1 až 59,0) | 75,4 % (71,4 až 79,1) |  |
| 0.3 | 441 | 62,4 % (57,7 až 66,8) | 77,6 % (73,4 až 81,2) |  |
| 0.5 | 427 | 60,4 % (55,7 až 64,9) | 78,5 % (74,3 až 82,1) |  |

### Osa: zdroje

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| 1 | 877 | 58,7 % (55,4 až 61,9) | 79,4 % (76,6 až 81,9) |  |
| 10 | 699 | 62,5 % (58,9 až 66,0) | 77,8 % (74,6 až 80,7) |  |
| 3 | 648 | 57,3 % (53,4 až 61,0) | 77,6 % (74,3 až 80,7) |  |

### Osa: doba

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| 0.5× | 425 | 53,9 % (49,1 až 58,6) | 72,5 % (68,0 až 76,5) |  |
| 1× | 899 | 56,2 % (52,9 až 59,4) | 76,9 % (74,0 až 79,5) |  |
| 2× | 442 | 59,7 % (55,1 až 64,2) | 77,6 % (73,5 až 81,2) |  |
| 4× | 458 | 71,0 % (66,6 až 74,9) | 87,6 % (84,2 až 90,3) |  |

### Osa: objem

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| 0.25× | 439 | 62,2 % (57,6 až 66,6) | 78,8 % (74,8 až 82,4) |  |
| 0.5× | 452 | 57,3 % (52,7 až 61,8) | 79,6 % (75,7 až 83,1) |  |
| 1× | 914 | 59,6 % (56,4 až 62,8) | 78,2 % (75,4 až 80,8) |  |
| 2× | 419 | 58,7 % (53,9 až 63,3) | 76,8 % (72,6 až 80,6) |  |

### Osa: mimo pracovní dobu

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| ano | 507 | 61,9 % (57,6 až 66,1) | 82,4 % (78,9 až 85,5) |  |
| ne | 1717 | 58,8 % (56,4 až 61,1) | 77,2 % (75,1 až 79,1) |  |

### Osa: míchání s provozem

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| ano | 679 | 58,6 % (54,9 až 62,3) | 77,9 % (74,6 až 80,9) |  |
| ne | 1545 | 59,9 % (57,4 až 62,3) | 78,6 % (76,5 až 80,5) |  |

### Osa: IDS signatura

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| ano | 543 | 64,6 % (60,5 až 68,5) | 93,4 % (91,0 až 95,2) |  |
| ne | 1681 | 57,8 % (55,4 až 60,2) | 73,5 % (71,4 až 75,6) |  |

### Rodiny

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| apt_chain (H) | 38 | 94,7 % (82,7 až 98,5) | 94,7 % (82,7 až 98,5) |  |
| c2_beacon | 182 | 37,9 % (31,2 až 45,1) | 72,0 % (65,1 až 78,0) |  |
| credential_stuffing | 124 | 81,5 % (73,7 až 87,3) | 84,7 % (77,3 až 90,0) |  |
| cryptomining (H) | 86 | 33,7 % (24,6 až 44,2) | 80,2 % (70,6 až 87,3) |  |
| ddos_volume | 56 | 89,3 % (78,5 až 95,0) | 87,5 % (76,4 až 93,8) |  |
| dns_tunnel | 91 | 35,2 % (26,1 až 45,4) | 80,2 % (70,9 až 87,1) |  |
| exfiltration | 148 | 10,8 % (6,8 až 16,8) | 81,8 % (74,8 až 87,1) |  |
| exploit_attempt | 233 | 21,9 % (17,1 až 27,6) | 39,5 % (33,4 až 45,9) | SLEPÉ MÍSTO |
| fleet_beacon (H) | 35 | 65,7 % (49,2 až 79,2) | 71,4 % (54,9 až 83,7) |  |
| ics_attack (H) | 8 | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | nedostatečná data |
| insider_hoarding (H) | 36 | 86,1 % (71,3 až 93,9) | 91,7 % (78,2 až 97,1) |  |
| lateral_movement | 197 | 69,5 % (62,8 až 75,5) | 67,0 % (60,2 až 73,2) | slabé místo |
| port_scan_horizontal | 155 | 77,4 % (70,2 až 83,3) | 80,0 % (73,0 až 85,5) |  |
| port_scan_vertical | 195 | 52,8 % (45,8 až 59,7) | 86,7 % (81,2 až 90,7) |  |
| ransomware (H) | 65 | 98,5 % (91,8 až 99,7) | 100,0 % (94,4 až 100,0) |  |
| rogue_device | 34 | 20,6 % (10,3 až 36,8) | 97,1 % (85,1 až 99,5) |  |
| slow_scan (H) | 145 | 86,9 % (80,4 až 91,4) | 88,3 % (82,0 až 92,5) |  |
| ssh_bruteforce | 263 | 83,3 % (78,3 až 87,3) | 90,1 % (85,9 až 93,2) |  |
| web_exploit (H) | 133 | 76,7 % (68,8 až 83,1) | 85,7 % (78,8 až 90,7) |  |

### Rodina × pásmo S

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| apt_chain | Q1 | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| apt_chain | Q2 | 7 | 100,0 % (64,6 až 100,0) | 100,0 % (64,6 až 100,0) | nedostatečná data |
| apt_chain | Q3 | 7 | 100,0 % (64,6 až 100,0) | 85,7 % (48,7 až 97,4) | nedostatečná data |
| apt_chain | Q4 | 8 | 87,5 % (52,9 až 97,8) | 100,0 % (67,6 až 100,0) | nedostatečná data |
| apt_chain | Q5 | 12 | 91,7 % (64,6 až 98,5) | 91,7 % (64,6 až 98,5) | nedostatečná data |
| c2_beacon | Q1 | 19 | 26,3 % (11,8 až 48,8) | 89,5 % (68,6 až 97,1) | nedostatečná data |
| c2_beacon | Q2 | 22 | 22,7 % (10,1 až 43,4) | 68,2 % (47,3 až 83,6) | slabé místo |
| c2_beacon | Q3 | 32 | 18,8 % (8,9 až 35,3) | 62,5 % (45,3 až 77,1) | slabé místo |
| c2_beacon | Q4 | 41 | 53,7 % (38,7 až 67,9) | 80,5 % (66,0 až 89,8) |  |
| c2_beacon | Q5 | 68 | 45,6 % (34,3 až 57,3) | 67,6 % (55,8 až 77,6) | slabé místo |
| credential_stuffing | Q1 | 12 | 83,3 % (55,2 až 95,3) | 91,7 % (64,6 až 98,5) | nedostatečná data |
| credential_stuffing | Q2 | 16 | 75,0 % (50,5 až 89,8) | 75,0 % (50,5 až 89,8) | nedostatečná data |
| credential_stuffing | Q3 | 18 | 94,4 % (74,2 až 99,0) | 94,4 % (74,2 až 99,0) | nedostatečná data |
| credential_stuffing | Q4 | 32 | 81,2 % (64,7 až 91,1) | 84,4 % (68,2 až 93,1) |  |
| credential_stuffing | Q5 | 46 | 78,3 % (64,4 až 87,7) | 82,6 % (69,3 až 90,9) |  |
| cryptomining | Q1 | 12 | 16,7 % (4,7 až 44,8) | 91,7 % (64,6 až 98,5) | nedostatečná data |
| cryptomining | Q2 | 11 | 27,3 % (9,7 až 56,6) | 90,9 % (62,3 až 98,4) | nedostatečná data |
| cryptomining | Q3 | 12 | 25,0 % (8,9 až 53,2) | 83,3 % (55,2 až 95,3) | nedostatečná data |
| cryptomining | Q4 | 15 | 53,3 % (30,1 až 75,2) | 80,0 % (54,8 až 93,0) | nedostatečná data |
| cryptomining | Q5 | 36 | 36,1 % (22,5 až 52,4) | 72,2 % (56,0 až 84,2) |  |
| ddos_volume | Q1 | 11 | 90,9 % (62,3 až 98,4) | 81,8 % (52,3 až 94,9) | nedostatečná data |
| ddos_volume | Q2 | 3 | 100,0 % (43,9 až 100,0) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| ddos_volume | Q3 | 14 | 92,9 % (68,5 až 98,7) | 92,9 % (68,5 až 98,7) | nedostatečná data |
| ddos_volume | Q4 | 8 | 62,5 % (30,6 až 86,3) | 62,5 % (30,6 až 86,3) | nedostatečná data |
| ddos_volume | Q5 | 20 | 95,0 % (76,4 až 99,1) | 95,0 % (76,4 až 99,1) |  |
| dns_tunnel | Q1 | 18 | 33,3 % (16,3 až 56,3) | 94,4 % (74,2 až 99,0) | nedostatečná data |
| dns_tunnel | Q2 | 15 | 40,0 % (19,8 až 64,3) | 80,0 % (54,8 až 93,0) | nedostatečná data |
| dns_tunnel | Q3 | 12 | 16,7 % (4,7 až 44,8) | 100,0 % (75,8 až 100,0) | nedostatečná data |
| dns_tunnel | Q4 | 19 | 36,8 % (19,1 až 59,0) | 68,4 % (46,0 až 84,6) | nedostatečná data |
| dns_tunnel | Q5 | 27 | 40,7 % (24,5 až 59,3) | 70,4 % (51,5 až 84,1) |  |
| exfiltration | Q1 | 19 | 5,3 % (0,9 až 24,6) | 73,7 % (51,2 až 88,2) | nedostatečná data |
| exfiltration | Q2 | 23 | 8,7 % (2,4 až 26,8) | 69,6 % (49,1 až 84,4) | slabé místo |
| exfiltration | Q3 | 21 | 14,3 % (5,0 až 34,6) | 85,7 % (65,4 až 95,0) |  |
| exfiltration | Q4 | 32 | 9,4 % (3,2 až 24,2) | 87,5 % (71,9 až 95,0) |  |
| exfiltration | Q5 | 53 | 13,2 % (6,5 až 24,8) | 84,9 % (72,9 až 92,1) |  |
| exploit_attempt | Q1 | 33 | 24,2 % (12,8 až 41,0) | 42,4 % (27,2 až 59,2) | SLEPÉ MÍSTO |
| exploit_attempt | Q2 | 21 | 23,8 % (10,6 až 45,1) | 42,9 % (24,5 až 63,5) | SLEPÉ MÍSTO |
| exploit_attempt | Q3 | 44 | 20,5 % (11,2 až 34,5) | 38,6 % (25,7 až 53,4) | SLEPÉ MÍSTO |
| exploit_attempt | Q4 | 46 | 21,7 % (12,3 až 35,6) | 45,7 % (32,2 až 59,8) | SLEPÉ MÍSTO |
| exploit_attempt | Q5 | 89 | 21,3 % (14,1 až 31,0) | 34,8 % (25,7 až 45,2) | SLEPÉ MÍSTO |
| fleet_beacon | Q1 | 7 | 71,4 % (35,9 až 91,8) | 71,4 % (35,9 až 91,8) | nedostatečná data |
| fleet_beacon | Q2 | 5 | 60,0 % (23,1 až 88,2) | 60,0 % (23,1 až 88,2) | nedostatečná data |
| fleet_beacon | Q3 | 4 | 75,0 % (30,1 až 95,4) | 75,0 % (30,1 až 95,4) | nedostatečná data |
| fleet_beacon | Q4 | 7 | 42,9 % (15,8 až 75,0) | 57,1 % (25,0 až 84,2) | nedostatečná data |
| fleet_beacon | Q5 | 12 | 75,0 % (46,8 až 91,1) | 83,3 % (55,2 až 95,3) | nedostatečná data |
| ics_attack | Q1 | 1 | 100,0 % (20,7 až 100,0) | 0,0 % (0,0 až 79,3) | nedostatečná data |
| ics_attack | Q2 | 1 | 100,0 % (20,7 až 100,0) | 100,0 % (20,7 až 100,0) | nedostatečná data |
| ics_attack | Q3 | 2 | 100,0 % (34,2 až 100,0) | 100,0 % (34,2 až 100,0) | nedostatečná data |
| ics_attack | Q4 | 3 | 66,7 % (20,8 až 93,9) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| ics_attack | Q5 | 1 | 100,0 % (20,7 až 100,0) | 100,0 % (20,7 až 100,0) | nedostatečná data |
| insider_hoarding | Q1 | 4 | 75,0 % (30,1 až 95,4) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| insider_hoarding | Q3 | 13 | 92,3 % (66,7 až 98,6) | 84,6 % (57,8 až 95,7) | nedostatečná data |
| insider_hoarding | Q4 | 7 | 85,7 % (48,7 až 97,4) | 85,7 % (48,7 až 97,4) | nedostatečná data |
| insider_hoarding | Q5 | 12 | 83,3 % (55,2 až 95,3) | 100,0 % (75,8 až 100,0) | nedostatečná data |
| lateral_movement | Q1 | 25 | 72,0 % (52,4 až 85,7) | 76,0 % (56,6 až 88,5) |  |
| lateral_movement | Q2 | 31 | 64,5 % (46,9 až 78,9) | 61,3 % (43,8 až 76,3) | slabé místo |
| lateral_movement | Q3 | 27 | 70,4 % (51,5 až 84,1) | 63,0 % (44,2 až 78,5) | slabé místo |
| lateral_movement | Q4 | 45 | 57,8 % (43,3 až 71,0) | 53,3 % (39,1 až 67,1) | slabé místo |
| lateral_movement | Q5 | 69 | 78,3 % (67,2 až 86,4) | 76,8 % (65,6 až 85,2) |  |
| port_scan_horizontal | Q1 | 18 | 61,1 % (38,6 až 79,7) | 83,3 % (60,8 až 94,2) | nedostatečná data |
| port_scan_horizontal | Q2 | 18 | 77,8 % (54,8 až 91,0) | 77,8 % (54,8 až 91,0) | nedostatečná data |
| port_scan_horizontal | Q3 | 23 | 73,9 % (53,5 až 87,5) | 87,0 % (67,9 až 95,5) |  |
| port_scan_horizontal | Q4 | 26 | 80,8 % (62,1 až 91,5) | 84,6 % (66,5 až 93,8) |  |
| port_scan_horizontal | Q5 | 70 | 81,4 % (70,8 až 88,8) | 75,7 % (64,5 až 84,2) |  |
| port_scan_vertical | Q1 | 24 | 54,2 % (35,1 až 72,1) | 91,7 % (74,2 až 97,7) |  |
| port_scan_vertical | Q2 | 34 | 67,6 % (50,8 až 80,9) | 91,2 % (77,0 až 97,0) |  |
| port_scan_vertical | Q3 | 20 | 50,0 % (29,9 až 70,1) | 90,0 % (69,9 až 97,2) |  |
| port_scan_vertical | Q4 | 36 | 58,3 % (42,2 až 72,9) | 83,3 % (68,1 až 92,1) |  |
| port_scan_vertical | Q5 | 81 | 44,4 % (34,1 až 55,3) | 84,0 % (74,5 až 90,4) |  |
| ransomware | Q1 | 10 | 100,0 % (72,2 až 100,0) | 100,0 % (72,2 až 100,0) | nedostatečná data |
| ransomware | Q2 | 9 | 100,0 % (70,1 až 100,0) | 100,0 % (70,1 až 100,0) | nedostatečná data |
| ransomware | Q3 | 7 | 100,0 % (64,6 až 100,0) | 100,0 % (64,6 až 100,0) | nedostatečná data |
| ransomware | Q4 | 16 | 100,0 % (80,6 až 100,0) | 100,0 % (80,6 až 100,0) | nedostatečná data |
| ransomware | Q5 | 23 | 95,7 % (79,0 až 99,2) | 100,0 % (85,7 až 100,0) |  |
| rogue_device | Q1 | 3 | 0,0 % (0,0 až 56,1) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| rogue_device | Q2 | 3 | 0,0 % (0,0 až 56,1) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| rogue_device | Q3 | 5 | 40,0 % (11,8 až 76,9) | 100,0 % (56,6 až 100,0) | nedostatečná data |
| rogue_device | Q4 | 6 | 50,0 % (18,8 až 81,2) | 83,3 % (43,6 až 97,0) | nedostatečná data |
| rogue_device | Q5 | 17 | 11,8 % (3,3 až 34,3) | 100,0 % (81,6 až 100,0) | nedostatečná data |
| slow_scan | Q1 | 27 | 85,2 % (67,5 až 94,1) | 96,3 % (81,7 až 99,3) |  |
| slow_scan | Q2 | 12 | 100,0 % (75,8 až 100,0) | 91,7 % (64,6 až 98,5) | nedostatečná data |
| slow_scan | Q3 | 22 | 86,4 % (66,7 až 95,3) | 72,7 % (51,8 až 86,8) |  |
| slow_scan | Q4 | 29 | 82,8 % (65,5 až 92,4) | 86,2 % (69,4 až 94,5) |  |
| slow_scan | Q5 | 55 | 87,3 % (76,0 až 93,7) | 90,9 % (80,4 až 96,1) |  |
| ssh_bruteforce | Q1 | 25 | 84,0 % (65,3 až 93,6) | 92,0 % (75,0 až 97,8) |  |
| ssh_bruteforce | Q2 | 31 | 80,6 % (63,7 až 90,8) | 96,8 % (83,8 až 99,4) |  |
| ssh_bruteforce | Q3 | 43 | 83,7 % (70,0 až 91,9) | 90,7 % (78,4 až 96,3) |  |
| ssh_bruteforce | Q4 | 61 | 78,7 % (66,9 až 87,1) | 90,2 % (80,2 až 95,4) |  |
| ssh_bruteforce | Q5 | 103 | 86,4 % (78,5 až 91,7) | 87,4 % (79,6 až 92,5) |  |
| web_exploit | Q1 | 22 | 72,7 % (51,8 až 86,8) | 90,9 % (72,2 až 97,5) |  |
| web_exploit | Q2 | 16 | 56,2 % (33,2 až 76,9) | 68,8 % (44,4 až 85,8) | nedostatečná data |
| web_exploit | Q3 | 26 | 96,2 % (81,1 až 99,3) | 96,2 % (81,1 až 99,3) |  |
| web_exploit | Q4 | 18 | 66,7 % (43,7 až 83,7) | 88,9 % (67,2 až 96,9) | nedostatečná data |
| web_exploit | Q5 | 51 | 78,4 % (65,4 až 87,5) | 82,4 % (69,7 až 90,4) |  |

### Rodina × osa (tempo, zdroje, objem)

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| apt_chain | objem 0.25× | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| apt_chain | objem 0.5× | 8 | 75,0 % (40,9 až 92,9) | 87,5 % (52,9 až 97,8) | nedostatečná data |
| apt_chain | objem 1× | 19 | 100,0 % (83,2 až 100,0) | 100,0 % (83,2 až 100,0) | nedostatečná data |
| apt_chain | objem 2× | 7 | 100,0 % (64,6 až 100,0) | 85,7 % (48,7 až 97,4) | nedostatečná data |
| apt_chain | tempo 0.25× | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| apt_chain | tempo 0.5× | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| apt_chain | tempo 1× | 16 | 93,8 % (71,7 až 98,9) | 100,0 % (80,6 až 100,0) | nedostatečná data |
| apt_chain | tempo 2× | 5 | 100,0 % (56,6 až 100,0) | 80,0 % (37,6 až 96,4) | nedostatečná data |
| apt_chain | tempo 4× | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| apt_chain | tempo 8× | 5 | 80,0 % (37,6 až 96,4) | 80,0 % (37,6 až 96,4) | nedostatečná data |
| apt_chain | zdroje 1 | 14 | 100,0 % (78,5 až 100,0) | 100,0 % (78,5 až 100,0) | nedostatečná data |
| apt_chain | zdroje 10 | 13 | 92,3 % (66,7 až 98,6) | 92,3 % (66,7 až 98,6) | nedostatečná data |
| apt_chain | zdroje 3 | 11 | 90,9 % (62,3 až 98,4) | 90,9 % (62,3 až 98,4) | nedostatečná data |
| c2_beacon | objem 0.25× | 28 | 53,6 % (35,8 až 70,5) | 78,6 % (60,5 až 89,8) |  |
| c2_beacon | objem 0.5× | 49 | 40,8 % (28,2 až 54,8) | 71,4 % (57,6 až 82,2) |  |
| c2_beacon | objem 1× | 79 | 32,9 % (23,6 až 43,9) | 70,9 % (60,1 až 79,7) |  |
| c2_beacon | objem 2× | 26 | 30,8 % (16,5 až 50,0) | 69,2 % (50,0 až 83,5) | slabé místo |
| c2_beacon | tempo 0.25× | 28 | 53,6 % (35,8 až 70,5) | 89,3 % (72,8 až 96,3) |  |
| c2_beacon | tempo 0.5× | 19 | 68,4 % (46,0 až 84,6) | 89,5 % (68,6 až 97,1) | nedostatečná data |
| c2_beacon | tempo 1× | 68 | 35,3 % (25,0 až 47,2) | 77,9 % (66,7 až 86,2) |  |
| c2_beacon | tempo 2× | 27 | 29,6 % (15,9 až 48,5) | 70,4 % (51,5 až 84,1) |  |
| c2_beacon | tempo 4× | 14 | 28,6 % (11,7 až 54,6) | 57,1 % (32,6 až 78,6) | nedostatečná data |
| c2_beacon | tempo 8× | 26 | 19,2 % (8,5 až 37,9) | 34,6 % (19,4 až 53,8) | SLEPÉ MÍSTO |
| c2_beacon | zdroje 1 | 79 | 30,4 % (21,3 až 41,2) | 73,4 % (62,8 až 81,9) |  |
| c2_beacon | zdroje 10 | 52 | 57,7 % (44,2 až 70,1) | 71,2 % (57,7 až 81,7) |  |
| c2_beacon | zdroje 3 | 51 | 29,4 % (18,7 až 43,0) | 70,6 % (57,0 až 81,3) |  |
| credential_stuffing | objem 0.25× | 30 | 83,3 % (66,4 až 92,7) | 86,7 % (70,3 až 94,7) |  |
| credential_stuffing | objem 0.5× | 25 | 84,0 % (65,3 až 93,6) | 88,0 % (70,0 až 95,8) |  |
| credential_stuffing | objem 1× | 45 | 80,0 % (66,2 až 89,1) | 82,2 % (68,7 až 90,7) |  |
| credential_stuffing | objem 2× | 24 | 79,2 % (59,5 až 90,8) | 83,3 % (64,1 až 93,3) |  |
| credential_stuffing | tempo 0.25× | 12 | 66,7 % (39,1 až 86,2) | 66,7 % (39,1 až 86,2) | nedostatečná data |
| credential_stuffing | tempo 0.5× | 13 | 84,6 % (57,8 až 95,7) | 84,6 % (57,8 až 95,7) | nedostatečná data |
| credential_stuffing | tempo 1× | 49 | 79,6 % (66,4 až 88,5) | 87,8 % (75,8 až 94,3) |  |
| credential_stuffing | tempo 2× | 21 | 95,2 % (77,3 až 99,2) | 95,2 % (77,3 až 99,2) |  |
| credential_stuffing | tempo 4× | 11 | 90,9 % (62,3 až 98,4) | 81,8 % (52,3 až 94,9) | nedostatečná data |
| credential_stuffing | tempo 8× | 18 | 72,2 % (49,1 až 87,5) | 77,8 % (54,8 až 91,0) | nedostatečná data |
| credential_stuffing | zdroje 1 | 47 | 87,2 % (74,8 až 94,0) | 87,2 % (74,8 až 94,0) |  |
| credential_stuffing | zdroje 10 | 43 | 74,4 % (59,8 až 85,1) | 86,0 % (72,7 až 93,4) |  |
| credential_stuffing | zdroje 3 | 34 | 82,4 % (66,5 až 91,7) | 79,4 % (63,2 až 89,7) |  |
| cryptomining | objem 0.25× | 10 | 30,0 % (10,8 až 60,3) | 70,0 % (39,7 až 89,2) | nedostatečná data |
| cryptomining | objem 0.5× | 23 | 34,8 % (18,8 až 55,1) | 78,3 % (58,1 až 90,3) |  |
| cryptomining | objem 1× | 30 | 36,7 % (21,9 až 54,5) | 86,7 % (70,3 až 94,7) |  |
| cryptomining | objem 2× | 23 | 30,4 % (15,6 až 50,9) | 78,3 % (58,1 až 90,3) |  |
| cryptomining | tempo 0.25× | 22 | 54,5 % (34,7 až 73,1) | 77,3 % (56,6 až 89,9) |  |
| cryptomining | tempo 0.5× | 5 | 20,0 % (3,6 až 62,4) | 100,0 % (56,6 až 100,0) | nedostatečná data |
| cryptomining | tempo 1× | 37 | 29,7 % (17,5 až 45,8) | 81,1 % (65,8 až 90,5) |  |
| cryptomining | tempo 2× | 12 | 25,0 % (8,9 až 53,2) | 75,0 % (46,8 až 91,1) | nedostatečná data |
| cryptomining | tempo 4× | 5 | 40,0 % (11,8 až 76,9) | 80,0 % (37,6 až 96,4) | nedostatečná data |
| cryptomining | tempo 8× | 5 | 0,0 % (0,0 až 43,4) | 80,0 % (37,6 až 96,4) | nedostatečná data |
| cryptomining | zdroje 1 | 33 | 21,2 % (10,7 až 37,8) | 84,8 % (69,1 až 93,3) |  |
| cryptomining | zdroje 10 | 23 | 56,5 % (36,8 až 74,4) | 65,2 % (44,9 až 81,2) | slabé místo |
| cryptomining | zdroje 3 | 30 | 30,0 % (16,7 až 47,9) | 86,7 % (70,3 až 94,7) |  |
| ddos_volume | objem 0.25× | 15 | 100,0 % (79,6 až 100,0) | 100,0 % (79,6 až 100,0) | nedostatečná data |
| ddos_volume | objem 0.5× | 8 | 75,0 % (40,9 až 92,9) | 75,0 % (40,9 až 92,9) | nedostatečná data |
| ddos_volume | objem 1× | 18 | 94,4 % (74,2 až 99,0) | 88,9 % (67,2 až 96,9) | nedostatečná data |
| ddos_volume | objem 2× | 15 | 80,0 % (54,8 až 93,0) | 80,0 % (54,8 až 93,0) | nedostatečná data |
| ddos_volume | tempo 0.25× | 4 | 100,0 % (51,0 až 100,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| ddos_volume | tempo 0.5× | 8 | 100,0 % (67,6 až 100,0) | 100,0 % (67,6 až 100,0) | nedostatečná data |
| ddos_volume | tempo 1× | 25 | 96,0 % (80,5 až 99,3) | 96,0 % (80,5 až 99,3) |  |
| ddos_volume | tempo 2× | 8 | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | nedostatečná data |
| ddos_volume | tempo 4× | 8 | 62,5 % (30,6 až 86,3) | 50,0 % (21,5 až 78,5) | nedostatečná data |
| ddos_volume | tempo 8× | 3 | 66,7 % (20,8 až 93,9) | 66,7 % (20,8 až 93,9) | nedostatečná data |
| ddos_volume | zdroje 1 | 27 | 92,6 % (76,6 až 97,9) | 92,6 % (76,6 až 97,9) |  |
| ddos_volume | zdroje 10 | 17 | 88,2 % (65,7 až 96,7) | 88,2 % (65,7 až 96,7) | nedostatečná data |
| ddos_volume | zdroje 3 | 12 | 83,3 % (55,2 až 95,3) | 75,0 % (46,8 až 91,1) | nedostatečná data |
| dns_tunnel | objem 0.25× | 23 | 30,4 % (15,6 až 50,9) | 78,3 % (58,1 až 90,3) |  |
| dns_tunnel | objem 0.5× | 16 | 31,2 % (14,2 až 55,6) | 75,0 % (50,5 až 89,8) | nedostatečná data |
| dns_tunnel | objem 1× | 35 | 37,1 % (23,2 až 53,7) | 91,4 % (77,6 až 97,0) |  |
| dns_tunnel | objem 2× | 17 | 41,2 % (21,6 až 64,0) | 64,7 % (41,3 až 82,7) | nedostatečná data |
| dns_tunnel | tempo 0.25× | 9 | 44,4 % (18,9 až 73,3) | 77,8 % (45,3 až 93,7) | nedostatečná data |
| dns_tunnel | tempo 0.5× | 10 | 30,0 % (10,8 až 60,3) | 80,0 % (49,0 až 94,3) | nedostatečná data |
| dns_tunnel | tempo 1× | 35 | 45,7 % (30,5 až 61,8) | 68,6 % (52,0 až 81,4) | slabé místo |
| dns_tunnel | tempo 2× | 13 | 7,7 % (1,4 až 33,3) | 84,6 % (57,8 až 95,7) | nedostatečná data |
| dns_tunnel | tempo 4× | 11 | 36,4 % (15,2 až 64,6) | 90,9 % (62,3 až 98,4) | nedostatečná data |
| dns_tunnel | tempo 8× | 13 | 30,8 % (12,7 až 57,6) | 100,0 % (77,2 až 100,0) | nedostatečná data |
| dns_tunnel | zdroje 1 | 39 | 30,8 % (18,6 až 46,4) | 87,2 % (73,3 až 94,4) |  |
| dns_tunnel | zdroje 10 | 24 | 33,3 % (18,0 až 53,3) | 62,5 % (42,7 až 78,8) | slabé místo |
| dns_tunnel | zdroje 3 | 28 | 42,9 % (26,5 až 60,9) | 85,7 % (68,5 až 94,3) |  |
| exfiltration | objem 0.25× | 32 | 6,2 % (1,7 až 20,1) | 84,4 % (68,2 až 93,1) |  |
| exfiltration | objem 0.5× | 35 | 14,3 % (6,3 až 29,4) | 80,0 % (64,1 až 90,0) |  |
| exfiltration | objem 1× | 55 | 14,5 % (7,6 až 26,2) | 81,8 % (69,7 až 89,8) |  |
| exfiltration | objem 2× | 26 | 3,8 % (0,7 až 18,9) | 80,8 % (62,1 až 91,5) |  |
| exfiltration | tempo 0.25× | 20 | 25,0 % (11,2 až 46,9) | 75,0 % (53,1 až 88,8) |  |
| exfiltration | tempo 0.5× | 16 | 18,8 % (6,6 až 43,0) | 93,8 % (71,7 až 98,9) | nedostatečná data |
| exfiltration | tempo 1× | 64 | 4,7 % (1,6 až 12,9) | 76,6 % (64,9 až 85,3) |  |
| exfiltration | tempo 2× | 17 | 11,8 % (3,3 až 34,3) | 94,1 % (73,0 až 99,0) | nedostatečná data |
| exfiltration | tempo 4× | 15 | 13,3 % (3,7 až 37,9) | 73,3 % (48,0 až 89,1) | nedostatečná data |
| exfiltration | tempo 8× | 16 | 6,2 % (1,1 až 28,3) | 93,8 % (71,7 až 98,9) | nedostatečná data |
| exfiltration | zdroje 1 | 68 | 14,7 % (8,2 až 25,0) | 76,5 % (65,1 až 85,0) |  |
| exfiltration | zdroje 10 | 43 | 11,6 % (5,1 až 24,5) | 88,4 % (75,5 až 94,9) |  |
| exfiltration | zdroje 3 | 37 | 2,7 % (0,5 až 13,8) | 83,8 % (68,9 až 92,3) |  |
| exploit_attempt | objem 0.25× | 47 | 31,9 % (20,4 až 46,2) | 48,9 % (35,3 až 62,8) | SLEPÉ MÍSTO |
| exploit_attempt | objem 0.5× | 43 | 14,0 % (6,6 až 27,3) | 48,8 % (34,6 až 63,2) | SLEPÉ MÍSTO |
| exploit_attempt | objem 1× | 103 | 20,4 % (13,7 až 29,2) | 33,0 % (24,7 až 42,6) | SLEPÉ MÍSTO |
| exploit_attempt | objem 2× | 40 | 22,5 % (12,3 až 37,5) | 35,0 % (22,1 až 50,5) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 0.25× | 27 | 25,9 % (13,2 až 44,7) | 25,9 % (13,2 až 44,7) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 0.5× | 22 | 36,4 % (19,7 až 57,0) | 50,0 % (30,7 až 69,3) | slabé místo |
| exploit_attempt | tempo 1× | 91 | 17,6 % (11,1 až 26,7) | 37,4 % (28,1 až 47,6) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 2× | 26 | 11,5 % (4,0 až 29,0) | 30,8 % (16,5 až 50,0) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 4× | 38 | 21,1 % (11,1 až 36,3) | 50,0 % (34,8 až 65,2) | slabé místo |
| exploit_attempt | tempo 8× | 29 | 31,0 % (17,3 až 49,2) | 44,8 % (28,4 až 62,5) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 1 | 95 | 29,5 % (21,2 až 39,3) | 41,1 % (31,7 až 51,1) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 10 | 68 | 17,6 % (10,4 až 28,4) | 35,3 % (25,0 až 47,2) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 3 | 70 | 15,7 % (9,0 až 26,0) | 41,4 % (30,6 až 53,1) | SLEPÉ MÍSTO |
| fleet_beacon | objem 0.25× | 9 | 77,8 % (45,3 až 93,7) | 77,8 % (45,3 až 93,7) | nedostatečná data |
| fleet_beacon | objem 0.5× | 6 | 66,7 % (30,0 až 90,3) | 66,7 % (30,0 až 90,3) | nedostatečná data |
| fleet_beacon | objem 1× | 12 | 58,3 % (32,0 až 80,7) | 66,7 % (39,1 až 86,2) | nedostatečná data |
| fleet_beacon | objem 2× | 8 | 62,5 % (30,6 až 86,3) | 75,0 % (40,9 až 92,9) | nedostatečná data |
| fleet_beacon | tempo 0.25× | 2 | 100,0 % (34,2 až 100,0) | 100,0 % (34,2 až 100,0) | nedostatečná data |
| fleet_beacon | tempo 0.5× | 5 | 100,0 % (56,6 až 100,0) | 100,0 % (56,6 až 100,0) | nedostatečná data |
| fleet_beacon | tempo 1× | 13 | 76,9 % (49,7 až 91,8) | 76,9 % (49,7 až 91,8) | nedostatečná data |
| fleet_beacon | tempo 2× | 2 | 50,0 % (9,5 až 90,5) | 50,0 % (9,5 až 90,5) | nedostatečná data |
| fleet_beacon | tempo 4× | 6 | 50,0 % (18,8 až 81,2) | 83,3 % (43,6 až 97,0) | nedostatečná data |
| fleet_beacon | tempo 8× | 7 | 28,6 % (8,2 až 64,1) | 28,6 % (8,2 až 64,1) | nedostatečná data |
| fleet_beacon | zdroje 1 | 19 | 57,9 % (36,3 až 76,9) | 52,6 % (31,7 až 72,7) | nedostatečná data |
| fleet_beacon | zdroje 10 | 9 | 55,6 % (26,7 až 81,1) | 88,9 % (56,5 až 98,0) | nedostatečná data |
| fleet_beacon | zdroje 3 | 7 | 100,0 % (64,6 až 100,0) | 100,0 % (64,6 až 100,0) | nedostatečná data |
| ics_attack | objem 0.25× | 1 | 100,0 % (20,7 až 100,0) | 100,0 % (20,7 až 100,0) | nedostatečná data |
| ics_attack | objem 0.5× | 1 | 100,0 % (20,7 až 100,0) | 100,0 % (20,7 až 100,0) | nedostatečná data |
| ics_attack | objem 1× | 2 | 100,0 % (34,2 až 100,0) | 50,0 % (9,5 až 90,5) | nedostatečná data |
| ics_attack | objem 2× | 4 | 75,0 % (30,1 až 95,4) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| ics_attack | tempo 0.5× | 2 | 100,0 % (34,2 až 100,0) | 100,0 % (34,2 až 100,0) | nedostatečná data |
| ics_attack | tempo 1× | 4 | 75,0 % (30,1 až 95,4) | 75,0 % (30,1 až 95,4) | nedostatečná data |
| ics_attack | tempo 4× | 2 | 100,0 % (34,2 až 100,0) | 100,0 % (34,2 až 100,0) | nedostatečná data |
| ics_attack | zdroje 1 | 5 | 100,0 % (56,6 až 100,0) | 80,0 % (37,6 až 96,4) | nedostatečná data |
| ics_attack | zdroje 10 | 3 | 66,7 % (20,8 až 93,9) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| insider_hoarding | objem 0.25× | 4 | 75,0 % (30,1 až 95,4) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| insider_hoarding | objem 0.5× | 9 | 77,8 % (45,3 až 93,7) | 88,9 % (56,5 až 98,0) | nedostatečná data |
| insider_hoarding | objem 1× | 14 | 85,7 % (60,1 až 96,0) | 85,7 % (60,1 až 96,0) | nedostatečná data |
| insider_hoarding | objem 2× | 9 | 100,0 % (70,1 až 100,0) | 100,0 % (70,1 až 100,0) | nedostatečná data |
| insider_hoarding | tempo 0.25× | 2 | 100,0 % (34,2 až 100,0) | 100,0 % (34,2 až 100,0) | nedostatečná data |
| insider_hoarding | tempo 0.5× | 6 | 100,0 % (61,0 až 100,0) | 100,0 % (61,0 až 100,0) | nedostatečná data |
| insider_hoarding | tempo 1× | 18 | 88,9 % (67,2 až 96,9) | 88,9 % (67,2 až 96,9) | nedostatečná data |
| insider_hoarding | tempo 2× | 6 | 83,3 % (43,6 až 97,0) | 100,0 % (61,0 až 100,0) | nedostatečná data |
| insider_hoarding | tempo 4× | 1 | 0,0 % (0,0 až 79,3) | 0,0 % (0,0 až 79,3) | nedostatečná data |
| insider_hoarding | tempo 8× | 3 | 66,7 % (20,8 až 93,9) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| insider_hoarding | zdroje 1 | 19 | 78,9 % (56,7 až 91,5) | 84,2 % (62,4 až 94,5) | nedostatečná data |
| insider_hoarding | zdroje 10 | 7 | 85,7 % (48,7 až 97,4) | 100,0 % (64,6 až 100,0) | nedostatečná data |
| insider_hoarding | zdroje 3 | 10 | 100,0 % (72,2 až 100,0) | 100,0 % (72,2 až 100,0) | nedostatečná data |
| lateral_movement | objem 0.25× | 41 | 68,3 % (53,0 až 80,4) | 70,7 % (55,5 až 82,4) |  |
| lateral_movement | objem 0.5× | 32 | 68,8 % (51,4 až 82,0) | 65,6 % (48,3 až 79,6) | slabé místo |
| lateral_movement | objem 1× | 85 | 69,4 % (59,0 až 78,2) | 65,9 % (55,3 až 75,1) | slabé místo |
| lateral_movement | objem 2× | 39 | 71,8 % (56,2 až 83,5) | 66,7 % (51,0 až 79,4) | slabé místo |
| lateral_movement | tempo 0.25× | 17 | 58,8 % (36,0 až 78,4) | 47,1 % (26,2 až 69,0) | nedostatečná data |
| lateral_movement | tempo 0.5× | 18 | 55,6 % (33,7 až 75,4) | 61,1 % (38,6 až 79,7) | nedostatečná data |
| lateral_movement | tempo 1× | 82 | 62,2 % (51,4 až 71,9) | 56,1 % (45,3 až 66,3) | slabé místo |
| lateral_movement | tempo 2× | 32 | 65,6 % (48,3 až 79,6) | 65,6 % (48,3 až 79,6) | slabé místo |
| lateral_movement | tempo 4× | 23 | 91,3 % (73,2 až 97,6) | 95,7 % (79,0 až 99,2) |  |
| lateral_movement | tempo 8× | 25 | 96,0 % (80,5 až 99,3) | 96,0 % (80,5 až 99,3) |  |
| lateral_movement | zdroje 1 | 68 | 72,1 % (60,4 až 81,3) | 70,6 % (58,9 až 80,1) |  |
| lateral_movement | zdroje 10 | 61 | 65,6 % (53,0 až 76,3) | 70,5 % (58,1 až 80,4) |  |
| lateral_movement | zdroje 3 | 68 | 70,6 % (58,9 až 80,1) | 60,3 % (48,4 až 71,1) | slabé místo |
| port_scan_horizontal | objem 0.25× | 38 | 84,2 % (69,6 až 92,6) | 84,2 % (69,6 až 92,6) |  |
| port_scan_horizontal | objem 0.5× | 34 | 79,4 % (63,2 až 89,7) | 88,2 % (73,4 až 95,3) |  |
| port_scan_horizontal | objem 1× | 53 | 77,4 % (64,5 až 86,5) | 77,4 % (64,5 až 86,5) |  |
| port_scan_horizontal | objem 2× | 30 | 66,7 % (48,8 až 80,8) | 70,0 % (52,1 až 83,3) |  |
| port_scan_horizontal | tempo 0.25× | 25 | 88,0 % (70,0 až 95,8) | 80,0 % (60,9 až 91,1) |  |
| port_scan_horizontal | tempo 0.5× | 27 | 70,4 % (51,5 až 84,1) | 74,1 % (55,3 až 86,8) |  |
| port_scan_horizontal | tempo 1× | 58 | 63,8 % (50,9 až 74,9) | 75,9 % (63,5 až 85,0) |  |
| port_scan_horizontal | tempo 2× | 19 | 89,5 % (68,6 až 97,1) | 78,9 % (56,7 až 91,5) | nedostatečná data |
| port_scan_horizontal | tempo 4× | 16 | 100,0 % (80,6 až 100,0) | 100,0 % (80,6 až 100,0) | nedostatečná data |
| port_scan_horizontal | tempo 8× | 10 | 90,0 % (59,6 až 98,2) | 90,0 % (59,6 až 98,2) | nedostatečná data |
| port_scan_horizontal | zdroje 1 | 52 | 75,0 % (61,8 až 84,8) | 80,8 % (68,1 až 89,2) |  |
| port_scan_horizontal | zdroje 10 | 59 | 81,4 % (69,6 až 89,3) | 79,7 % (67,7 až 88,0) |  |
| port_scan_horizontal | zdroje 3 | 44 | 75,0 % (60,6 až 85,4) | 79,5 % (65,5 až 88,8) |  |
| port_scan_vertical | objem 0.25× | 34 | 52,9 % (36,7 až 68,5) | 73,5 % (56,9 až 85,4) |  |
| port_scan_vertical | objem 0.5× | 34 | 52,9 % (36,7 až 68,5) | 88,2 % (73,4 až 95,3) |  |
| port_scan_vertical | objem 1× | 79 | 54,4 % (43,5 až 65,0) | 88,6 % (79,7 až 93,9) |  |
| port_scan_vertical | objem 2× | 48 | 50,0 % (36,4 až 63,6) | 91,7 % (80,4 až 96,7) |  |
| port_scan_vertical | tempo 0.25× | 28 | 46,4 % (29,5 až 64,2) | 82,1 % (64,4 až 92,1) |  |
| port_scan_vertical | tempo 0.5× | 27 | 33,3 % (18,6 až 52,2) | 85,2 % (67,5 až 94,1) |  |
| port_scan_vertical | tempo 1× | 74 | 32,4 % (22,9 až 43,7) | 86,5 % (76,9 až 92,5) |  |
| port_scan_vertical | tempo 2× | 22 | 81,8 % (61,5 až 92,7) | 90,9 % (72,2 až 97,5) |  |
| port_scan_vertical | tempo 4× | 25 | 92,0 % (75,0 až 97,8) | 92,0 % (75,0 až 97,8) |  |
| port_scan_vertical | tempo 8× | 19 | 84,2 % (62,4 až 94,5) | 84,2 % (62,4 až 94,5) | nedostatečná data |
| port_scan_vertical | zdroje 1 | 71 | 56,3 % (44,8 až 67,3) | 88,7 % (79,3 až 94,2) |  |
| port_scan_vertical | zdroje 10 | 70 | 51,4 % (40,0 až 62,8) | 88,6 % (79,0 až 94,1) |  |
| port_scan_vertical | zdroje 3 | 54 | 50,0 % (37,1 až 62,9) | 81,5 % (69,2 až 89,6) |  |
| ransomware | objem 0.25× | 14 | 100,0 % (78,5 až 100,0) | 100,0 % (78,5 až 100,0) | nedostatečná data |
| ransomware | objem 0.5× | 17 | 100,0 % (81,6 až 100,0) | 100,0 % (81,6 až 100,0) | nedostatečná data |
| ransomware | objem 1× | 21 | 100,0 % (84,5 až 100,0) | 100,0 % (84,5 až 100,0) |  |
| ransomware | objem 2× | 13 | 92,3 % (66,7 až 98,6) | 100,0 % (77,2 až 100,0) | nedostatečná data |
| ransomware | tempo 0.25× | 8 | 87,5 % (52,9 až 97,8) | 100,0 % (67,6 až 100,0) | nedostatečná data |
| ransomware | tempo 0.5× | 10 | 100,0 % (72,2 až 100,0) | 100,0 % (72,2 až 100,0) | nedostatečná data |
| ransomware | tempo 1× | 26 | 100,0 % (87,1 až 100,0) | 100,0 % (87,1 až 100,0) |  |
| ransomware | tempo 2× | 7 | 100,0 % (64,6 až 100,0) | 100,0 % (64,6 až 100,0) | nedostatečná data |
| ransomware | tempo 4× | 5 | 100,0 % (56,6 až 100,0) | 100,0 % (56,6 až 100,0) | nedostatečná data |
| ransomware | tempo 8× | 9 | 100,0 % (70,1 až 100,0) | 100,0 % (70,1 až 100,0) | nedostatečná data |
| ransomware | zdroje 1 | 34 | 100,0 % (89,8 až 100,0) | 100,0 % (89,8 až 100,0) |  |
| ransomware | zdroje 10 | 18 | 100,0 % (82,4 až 100,0) | 100,0 % (82,4 až 100,0) | nedostatečná data |
| ransomware | zdroje 3 | 13 | 92,3 % (66,7 až 98,6) | 100,0 % (77,2 až 100,0) | nedostatečná data |
| rogue_device | objem 0.25× | 7 | 0,0 % (0,0 až 35,4) | 100,0 % (64,6 až 100,0) | nedostatečná data |
| rogue_device | objem 0.5× | 8 | 25,0 % (7,1 až 59,1) | 100,0 % (67,6 až 100,0) | nedostatečná data |
| rogue_device | objem 1× | 15 | 13,3 % (3,7 až 37,9) | 93,3 % (70,2 až 98,8) | nedostatečná data |
| rogue_device | objem 2× | 4 | 75,0 % (30,1 až 95,4) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| rogue_device | tempo 0.25× | 3 | 0,0 % (0,0 až 56,1) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| rogue_device | tempo 0.5× | 3 | 0,0 % (0,0 až 56,1) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| rogue_device | tempo 1× | 16 | 0,0 % (0,0 až 19,4) | 93,8 % (71,7 až 98,9) | nedostatečná data |
| rogue_device | tempo 2× | 3 | 33,3 % (6,1 až 79,2) | 100,0 % (43,9 až 100,0) | nedostatečná data |
| rogue_device | tempo 4× | 5 | 80,0 % (37,6 až 96,4) | 100,0 % (56,6 až 100,0) | nedostatečná data |
| rogue_device | tempo 8× | 4 | 50,0 % (15,0 až 85,0) | 100,0 % (51,0 až 100,0) | nedostatečná data |
| rogue_device | zdroje 1 | 10 | 10,0 % (1,8 až 40,4) | 90,0 % (59,6 až 98,2) | nedostatečná data |
| rogue_device | zdroje 10 | 12 | 33,3 % (13,8 až 60,9) | 100,0 % (75,8 až 100,0) | nedostatečná data |
| rogue_device | zdroje 3 | 12 | 16,7 % (4,7 až 44,8) | 100,0 % (75,8 až 100,0) | nedostatečná data |
| slow_scan | objem 0.25× | 23 | 95,7 % (79,0 až 99,2) | 91,3 % (73,2 až 97,6) |  |
| slow_scan | objem 0.5× | 27 | 77,8 % (59,2 až 89,4) | 85,2 % (67,5 až 94,1) |  |
| slow_scan | objem 1× | 73 | 87,7 % (78,2 až 93,4) | 90,4 % (81,5 až 95,3) |  |
| slow_scan | objem 2× | 22 | 86,4 % (66,7 až 95,3) | 81,8 % (61,5 až 92,7) |  |
| slow_scan | tempo 0.25× | 14 | 85,7 % (60,1 až 96,0) | 100,0 % (78,5 až 100,0) | nedostatečná data |
| slow_scan | tempo 0.5× | 25 | 96,0 % (80,5 až 99,3) | 96,0 % (80,5 až 99,3) |  |
| slow_scan | tempo 1× | 50 | 68,0 % (54,2 až 79,2) | 78,0 % (64,8 až 87,2) |  |
| slow_scan | tempo 2× | 18 | 100,0 % (82,4 až 100,0) | 72,2 % (49,1 až 87,5) | nedostatečná data |
| slow_scan | tempo 4× | 16 | 100,0 % (80,6 až 100,0) | 100,0 % (80,6 až 100,0) | nedostatečná data |
| slow_scan | tempo 8× | 22 | 100,0 % (85,1 až 100,0) | 100,0 % (85,1 až 100,0) |  |
| slow_scan | zdroje 1 | 56 | 85,7 % (74,3 až 92,6) | 98,2 % (90,6 až 99,7) |  |
| slow_scan | zdroje 10 | 45 | 91,1 % (79,3 až 96,5) | 75,6 % (61,3 až 85,8) |  |
| slow_scan | zdroje 3 | 44 | 84,1 % (70,6 až 92,1) | 88,6 % (76,0 až 95,0) |  |
| ssh_bruteforce | objem 0.25× | 52 | 76,9 % (63,9 až 86,3) | 82,7 % (70,3 až 90,6) |  |
| ssh_bruteforce | objem 0.5× | 54 | 81,5 % (69,2 až 89,6) | 88,9 % (77,8 až 94,8) |  |
| ssh_bruteforce | objem 1× | 119 | 84,9 % (77,4 až 90,2) | 92,4 % (86,2 až 96,0) |  |
| ssh_bruteforce | objem 2× | 38 | 89,5 % (75,9 až 95,8) | 94,7 % (82,7 až 98,5) |  |
| ssh_bruteforce | tempo 0.25× | 35 | 85,7 % (70,6 až 93,7) | 82,9 % (67,3 až 91,9) |  |
| ssh_bruteforce | tempo 0.5× | 35 | 80,0 % (64,1 až 90,0) | 91,4 % (77,6 až 97,0) |  |
| ssh_bruteforce | tempo 1× | 101 | 85,1 % (76,9 až 90,8) | 92,1 % (85,1 až 95,9) |  |
| ssh_bruteforce | tempo 2× | 29 | 89,7 % (73,6 až 96,4) | 93,1 % (78,0 až 98,1) |  |
| ssh_bruteforce | tempo 4× | 34 | 82,4 % (66,5 až 91,7) | 94,1 % (80,9 až 98,4) |  |
| ssh_bruteforce | tempo 8× | 29 | 72,4 % (54,3 až 85,3) | 82,8 % (65,5 až 92,4) |  |
| ssh_bruteforce | zdroje 1 | 91 | 81,3 % (72,1 až 88,0) | 89,0 % (80,9 až 93,9) |  |
| ssh_bruteforce | zdroje 10 | 95 | 86,3 % (78,0 až 91,8) | 91,6 % (84,3 až 95,7) |  |
| ssh_bruteforce | zdroje 3 | 77 | 81,8 % (71,8 až 88,8) | 89,6 % (80,8 až 94,6) |  |
| web_exploit | objem 0.25× | 27 | 81,5 % (63,3 až 91,8) | 77,8 % (59,2 až 89,4) |  |
| web_exploit | objem 0.5× | 23 | 82,6 % (62,9 až 93,0) | 91,3 % (73,2 až 97,6) |  |
| web_exploit | objem 1× | 57 | 73,7 % (61,0 až 83,4) | 89,5 % (78,9 až 95,1) |  |
| web_exploit | objem 2× | 26 | 73,1 % (53,9 až 86,3) | 80,8 % (62,1 až 91,5) |  |
| web_exploit | tempo 0.25× | 16 | 81,2 % (57,0 až 93,4) | 87,5 % (64,0 až 96,5) | nedostatečná data |
| web_exploit | tempo 0.5× | 14 | 78,6 % (52,4 až 92,4) | 78,6 % (52,4 až 92,4) | nedostatečná data |
| web_exploit | tempo 1× | 59 | 79,7 % (67,7 až 88,0) | 84,7 % (73,5 až 91,8) |  |
| web_exploit | tempo 2× | 17 | 70,6 % (46,9 až 86,7) | 82,4 % (59,0 až 93,8) | nedostatečná data |
| web_exploit | tempo 4× | 17 | 64,7 % (41,3 až 82,7) | 100,0 % (81,6 až 100,0) | nedostatečná data |
| web_exploit | tempo 8× | 10 | 80,0 % (49,0 až 94,3) | 80,0 % (49,0 až 94,3) | nedostatečná data |
| web_exploit | zdroje 1 | 50 | 76,0 % (62,6 až 85,7) | 86,0 % (73,8 až 93,0) |  |
| web_exploit | zdroje 10 | 37 | 75,7 % (59,9 až 86,6) | 81,1 % (65,8 až 90,5) |  |
| web_exploit | zdroje 3 | 46 | 78,3 % (64,4 až 87,7) | 89,1 % (77,0 až 95,3) |  |

### Souběh útoku s provozní poruchou

| buňka | n | detekce legacy | detekce v3k6 | registr |
|---|---:|---:|---:|---:|
| bez souběhu | 375 | 54,7 % (49,6 až 59,6) | 77,1 % (72,5 až 81,0) |  |
| nesenzorová porucha | 1747 | 61,3 % (59,0 až 63,6) | 79,5 % (77,6 až 81,3) |  |
| s backup_failed | 216 | 76,4 % (70,3 až 81,6) | 88,4 % (83,5 až 92,0) |  |
| s batch_job | 437 | 64,3 % (59,7 až 68,7) | 84,0 % (80,2 až 87,1) |  |
| s cert_expired | 312 | 63,8 % (58,3 až 68,9) | 82,7 % (78,1 až 86,5) |  |
| s cloud_migration | 715 | 61,3 % (57,6 až 64,8) | 78,0 % (74,9 až 80,9) |  |
| s collector_replay | 377 | 69,2 % (64,4 až 73,7) | 85,4 % (81,5 až 88,6) |  |
| s device_decommission | 253 | 73,9 % (68,2 až 78,9) | 89,3 % (84,9 až 92,6) |  |
| s device_onboarding | 277 | 69,0 % (63,3 až 74,1) | 86,3 % (81,7 až 89,8) |  |
| s dhcp_renumber | 288 | 76,7 % (71,5 až 81,2) | 89,2 % (85,1 až 92,3) |  |
| s dns_outage | 254 | 73,6 % (67,9 až 78,7) | 84,6 % (79,7 až 88,6) |  |
| s link_flapping | 345 | 65,8 % (60,6 až 70,6) | 84,3 % (80,1 až 87,8) |  |
| s log_corruption | 303 | 69,3 % (63,9 až 74,2) | 85,8 % (81,4 až 89,3) |  |
| s misconfig | 258 | 69,0 % (63,1 až 74,3) | 86,4 % (81,7 až 90,1) |  |
| s patch_window | 308 | 71,8 % (66,5 až 76,5) | 85,1 % (80,7 až 88,6) |  |
| s retry_storm | 326 | 65,3 % (60,0 až 70,3) | 84,4 % (80,0 až 87,9) |  |
| s segment_power_loss | 227 | 69,6 % (63,3 až 75,2) | 85,5 % (80,3 až 89,5) |  |
| s sensor_crash | 399 | 58,1 % (53,2 až 62,9) | 75,4 % (71,0 až 79,4) |  |
| s service_crash | 472 | 66,7 % (62,4 až 70,8) | 82,0 % (78,3 až 85,2) |  |
| s vpn_reconnect_storm | 208 | 72,1 % (65,7 až 77,8) | 89,4 % (84,5 až 92,9) |  |
| senzorová porucha | 804 | 61,2 % (57,8 až 64,5) | 78,2 % (75,3 až 80,9) |  |

### Kampaně

| rameno | šablona | kampaní | aspoň jedna fáze | první fáze | všechny fáze |
|---|---:|---:|---:|---:|---:|
| legacy | K-H1 | 17 | 100,0 % (81,6 až 100,0) | 58,8 % (36,0 až 78,4) | 47,1 % (26,2 až 69,0) |
| legacy | K-H2 | 31 | 90,3 % (75,1 až 96,7) | 83,9 % (67,4 až 92,9) | 12,9 % (5,1 až 28,9) |
| legacy | K-H3 | 27 | 92,6 % (76,6 až 97,9) | 63,0 % (44,2 až 78,5) | 14,8 % (5,9 až 32,5) |
| legacy | K-T1 | 32 | 84,4 % (68,2 až 93,1) | 53,1 % (36,4 až 69,1) | 6,2 % (1,7 až 20,1) |
| legacy | K-T2 | 20 | 80,0 % (58,4 až 91,9) | 80,0 % (58,4 až 91,9) | 25,0 % (11,2 až 46,9) |
| legacy | K-T3 | 39 | 82,1 % (67,3 až 91,0) | 28,2 % (16,5 až 43,8) | 5,1 % (1,4 až 16,9) |
| legacy | vše | 166 | 87,3 % (81,4 až 91,6) | 58,4 % (50,8 až 65,7) | 15,1 % (10,4 až 21,3) |
| v3k6 | K-H1 | 17 | 100,0 % (81,6 až 100,0) | 94,1 % (73,0 až 99,0) | 88,2 % (65,7 až 96,7) |
| v3k6 | K-H2 | 31 | 96,8 % (83,8 až 99,4) | 83,9 % (67,4 až 92,9) | 38,7 % (23,7 až 56,2) |
| v3k6 | K-H3 | 27 | 92,6 % (76,6 až 97,9) | 85,2 % (67,5 až 94,1) | 44,4 % (27,6 až 62,7) |
| v3k6 | K-T1 | 32 | 90,6 % (75,8 až 96,8) | 46,9 % (30,9 až 63,6) | 18,8 % (8,9 až 35,3) |
| v3k6 | K-T2 | 20 | 95,0 % (76,4 až 99,1) | 85,0 % (64,0 až 94,8) | 55,0 % (34,2 až 74,2) |
| v3k6 | K-T3 | 39 | 100,0 % (91,0 až 100,0) | 38,5 % (24,9 až 54,1) | 23,1 % (12,6 až 38,3) |
| v3k6 | vše | 166 | 95,8 % (91,6 až 97,9) | 67,5 % (60,0 až 74,1) | 39,2 % (32,1 až 46,7) |

### Leave-one-family-out (náhrada A5), rameno `v3k6`

| rodina | vynechané typy D(X) | n | detekce všemi signály | obecná detekce | verdikt |
|---|---:|---:|---:|---:|---:|
| c2_beacon | beacon_periodic | 35 | 45,7 % (30,5 až 61,8) | 22,9 % (12,1 až 39,0) | SLEPÉ MÍSTO |
| exfiltration | egress_volume_anomaly, long_lived_tunnel | 37 | 86,5 % (72,0 až 94,1) | 0,0 % (0,0 až 9,4) | SLEPÉ MÍSTO |
| ssh_bruteforce | connection_timeout_burst, source_volume_outlier | 32 | 90,6 % (75,8 až 96,8) | 90,6 % (75,8 až 96,8) | zobecňuje |
| port_scan_vertical | connection_timeout_burst, scan_attempts | 39 | 84,6 % (70,3 až 92,8) | 5,1 % (1,4 až 16,9) | SLEPÉ MÍSTO |
| lateral_movement | multi_target_pattern, pivot_chain | 39 | 71,8 % (56,2 až 83,5) | 61,5 % (45,9 až 75,1) | zobecňuje |
| dns_tunnel | egress_volume_anomaly, source_volume_outlier | 28 | 71,4 % (52,9 až 84,7) | 46,4 % (29,5 až 64,2) | SLEPÉ MÍSTO |

### Útoky s automaticky zavřeným připsaným nálezem

| rameno | rodiny | útoků | podíl s automatickým zavřením | z toho první výskyt (A7) |
|---|---:|---:|---:|---:|
| legacy | laděné | 1678 | 0,0 % (0,0 až 0,2) | 0 |
| legacy | držené | 546 | 0,0 % (0,0 až 0,7) | 0 |
| v3k6 | laděné | 1678 | 0,9 % (0,5 až 1,5) | 1 |
| v3k6 | držené | 546 | 3,5 % (2,2 až 5,4) | 15 |

### Poruchy a lookalike: podíl výskytů s FP

| rameno | událost | výskytů | FP ve frontě podezření | zobrazené FP (i provoz) | zachycené FP | registr |
|---|---:|---:|---:|---:|---:|---:|
| legacy | authorized_scanner | 235 | 48,9 % (42,6 až 55,3) | 48,9 % (42,6 až 55,3) | 48,9 % (42,6 až 55,3) | FP SLEPÉ MÍSTO |
| legacy | backup_burst | 462 | 75,5 % (71,4 až 79,2) | 75,5 % (71,4 až 79,2) | 75,5 % (71,4 až 79,2) | FP SLEPÉ MÍSTO |
| legacy | backup_failed | 79 | 98,7 % (93,2 až 99,8) | 98,7 % (93,2 až 99,8) | 98,7 % (93,2 až 99,8) | FP SLEPÉ MÍSTO |
| legacy | batch_job | 153 | 90,8 % (85,2 až 94,5) | 90,8 % (85,2 až 94,5) | 90,8 % (85,2 až 94,5) | FP SLEPÉ MÍSTO |
| legacy | cert_expired (H) | 83 | 100,0 % (95,6 až 100,0) | 100,0 % (95,6 až 100,0) | 100,0 % (95,6 až 100,0) | FP SLEPÉ MÍSTO |
| legacy | cloud_migration (H) | 77 | 93,5 % (85,7 až 97,2) | 93,5 % (85,7 až 97,2) | 93,5 % (85,7 až 97,2) | FP SLEPÉ MÍSTO |
| legacy | collector_replay | 149 | 96,6 % (92,4 až 98,6) | 96,6 % (92,4 až 98,6) | 96,6 % (92,4 až 98,6) | FP SLEPÉ MÍSTO |
| legacy | device_decommission | 99 | 27,3 % (19,5 až 36,8) | 27,3 % (19,5 až 36,8) | 27,3 % (19,5 až 36,8) | FP SLEPÉ MÍSTO |
| legacy | device_onboarding | 108 | 1,9 % (0,5 až 6,5) | 1,9 % (0,5 až 6,5) | 1,9 % (0,5 až 6,5) |  |
| legacy | dhcp_renumber | 101 | 85,1 % (76,9 až 90,8) | 85,1 % (76,9 až 90,8) | 85,1 % (76,9 až 90,8) | FP SLEPÉ MÍSTO |
| legacy | dns_outage | 102 | 100,0 % (96,4 až 100,0) | 100,0 % (96,4 až 100,0) | 100,0 % (96,4 až 100,0) | FP SLEPÉ MÍSTO |
| legacy | flash_crowd | 489 | 80,6 % (76,8 až 83,8) | 80,6 % (76,8 až 83,8) | 80,6 % (76,8 až 83,8) | FP SLEPÉ MÍSTO |
| legacy | link_flapping | 102 | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 3,6) |  |
| legacy | log_corruption | 118 | 94,9 % (89,3 až 97,6) | 94,9 % (89,3 až 97,6) | 94,9 % (89,3 až 97,6) | FP SLEPÉ MÍSTO |
| legacy | misconfig | 92 | 89,1 % (81,1 až 94,0) | 89,1 % (81,1 až 94,0) | 89,1 % (81,1 až 94,0) | FP SLEPÉ MÍSTO |
| legacy | ntp_fanout | 223 | 26,9 % (21,5 až 33,1) | 26,9 % (21,5 až 33,1) | 26,9 % (21,5 až 33,1) | FP SLEPÉ MÍSTO |
| legacy | patch_window | 102 | 97,1 % (91,7 až 99,0) | 97,1 % (91,7 až 99,0) | 97,1 % (91,7 až 99,0) | FP SLEPÉ MÍSTO |
| legacy | retry_storm | 134 | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 2,8) |  |
| legacy | saas_adoption (H) | 87 | 36,8 % (27,4 až 47,3) | 36,8 % (27,4 až 47,3) | 36,8 % (27,4 až 47,3) | FP SLEPÉ MÍSTO |
| legacy | segment_power_loss (H) | 89 | 64,0 % (53,7 až 73,2) | 64,0 % (53,7 až 73,2) | 64,0 % (53,7 až 73,2) | FP SLEPÉ MÍSTO |
| legacy | sensor_crash | 141 | 0,0 % (0,0 až 2,7) | 0,0 % (0,0 až 2,7) | 0,0 % (0,0 až 2,7) |  |
| legacy | service_crash | 211 | 91,5 % (86,9 až 94,5) | 91,5 % (86,9 až 94,5) | 91,5 % (86,9 až 94,5) | FP SLEPÉ MÍSTO |
| legacy | software_update | 465 | 0,0 % (0,0 až 0,8) | 0,0 % (0,0 až 0,8) | 0,0 % (0,0 až 0,8) |  |
| legacy | vpn_reconnect_storm (H) | 70 | 94,3 % (86,2 až 97,8) | 94,3 % (86,2 až 97,8) | 94,3 % (86,2 až 97,8) | FP SLEPÉ MÍSTO |
| v3k6 | authorized_scanner | 235 | 92,8 % (88,7 až 95,4) | 92,8 % (88,7 až 95,4) | 94,9 % (91,3 až 97,1) | FP SLEPÉ MÍSTO |
| v3k6 | backup_burst | 462 | 36,8 % (32,5 až 41,3) | 36,8 % (32,5 až 41,3) | 68,0 % (63,6 až 72,1) | FP SLEPÉ MÍSTO |
| v3k6 | backup_failed | 79 | 97,5 % (91,2 až 99,3) | 97,5 % (91,2 až 99,3) | 98,7 % (93,2 až 99,8) | FP SLEPÉ MÍSTO |
| v3k6 | batch_job | 153 | 74,5 % (67,1 až 80,8) | 74,5 % (67,1 až 80,8) | 90,2 % (84,5 až 94,0) | FP SLEPÉ MÍSTO |
| v3k6 | cert_expired (H) | 83 | 90,4 % (82,1 až 95,0) | 90,4 % (82,1 až 95,0) | 98,8 % (93,5 až 99,8) | FP SLEPÉ MÍSTO |
| v3k6 | cloud_migration (H) | 77 | 97,4 % (91,0 až 99,3) | 97,4 % (91,0 až 99,3) | 100,0 % (95,2 až 100,0) | FP SLEPÉ MÍSTO |
| v3k6 | collector_replay | 149 | 69,8 % (62,0 až 76,6) | 69,8 % (62,0 až 76,6) | 89,9 % (84,1 až 93,8) | FP SLEPÉ MÍSTO |
| v3k6 | device_decommission | 99 | 15,2 % (9,4 až 23,5) | 15,2 % (9,4 až 23,5) | 25,3 % (17,7 až 34,6) |  |
| v3k6 | device_onboarding | 108 | 10,2 % (5,8 až 17,3) | 10,2 % (5,8 až 17,3) | 10,2 % (5,8 až 17,3) |  |
| v3k6 | dhcp_renumber | 101 | 76,2 % (67,1 až 83,5) | 76,2 % (67,1 až 83,5) | 81,2 % (72,5 až 87,6) | FP SLEPÉ MÍSTO |
| v3k6 | dns_outage | 102 | 87,3 % (79,4 až 92,4) | 87,3 % (79,4 až 92,4) | 100,0 % (96,4 až 100,0) | FP SLEPÉ MÍSTO |
| v3k6 | flash_crowd | 489 | 41,5 % (37,2 až 45,9) | 41,5 % (37,2 až 45,9) | 77,7 % (73,8 až 81,2) | FP SLEPÉ MÍSTO |
| v3k6 | link_flapping | 102 | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 3,6) |  |
| v3k6 | log_corruption | 118 | 39,8 % (31,5 až 48,8) | 39,8 % (31,5 až 48,8) | 89,0 % (82,1 až 93,4) | FP SLEPÉ MÍSTO |
| v3k6 | misconfig | 92 | 94,6 % (87,9 až 97,7) | 94,6 % (87,9 až 97,7) | 97,8 % (92,4 až 99,4) | FP SLEPÉ MÍSTO |
| v3k6 | ntp_fanout | 223 | 6,3 % (3,8 až 10,3) | 6,3 % (3,8 až 10,3) | 13,9 % (10,0 až 19,1) |  |
| v3k6 | patch_window | 102 | 94,1 % (87,8 až 97,3) | 94,1 % (87,8 až 97,3) | 97,1 % (91,7 až 99,0) | FP SLEPÉ MÍSTO |
| v3k6 | retry_storm | 134 | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 2,8) |  |
| v3k6 | saas_adoption (H) | 87 | 69,0 % (58,6 až 77,7) | 69,0 % (58,6 až 77,7) | 72,4 % (62,2 až 80,7) | FP SLEPÉ MÍSTO |
| v3k6 | segment_power_loss (H) | 89 | 62,9 % (52,5 až 72,2) | 62,9 % (52,5 až 72,2) | 76,4 % (66,6 až 84,0) | FP SLEPÉ MÍSTO |
| v3k6 | sensor_crash | 141 | 19,1 % (13,5 až 26,4) | 19,1 % (13,5 až 26,4) | 19,1 % (13,5 až 26,4) |  |
| v3k6 | service_crash | 211 | 66,8 % (60,2 až 72,8) | 66,8 % (60,2 až 72,8) | 79,1 % (73,2 až 84,1) | FP SLEPÉ MÍSTO |
| v3k6 | software_update | 465 | 1,1 % (0,5 až 2,5) | 1,1 % (0,5 až 2,5) | 1,1 % (0,5 až 2,5) |  |
| v3k6 | vpn_reconnect_storm (H) | 70 | 88,6 % (79,0 až 94,1) | 88,6 % (79,0 až 94,1) | 91,4 % (82,5 až 96,0) | FP SLEPÉ MÍSTO |

### Typy FP ve frontě podezření (rameno `v3k6`, počet výskytů s typem)

| událost | typy |
|---|---:|
| authorized_scanner | multi_target_pattern 203, scan_attempts 201, unmapped_passive_event 22, unexpected_traffic 5, connection_timeout_burst 3 |
| backup_burst | inductive_volume_anomaly 128, packet_rate_spike 125, egress_volume_anomaly 35, connection_timeout_burst 11, unmapped_passive_event 9 |
| backup_failed | connection_timeout_burst 76, inductive_volume_anomaly 49, packet_rate_spike 29, service_overload_risk 27, source_volume_outlier 13 |
| batch_job | inductive_volume_anomaly 111, packet_rate_spike 106, source_volume_outlier 38, connection_timeout_burst 10, egress_volume_anomaly 7 |
| cert_expired | inductive_volume_anomaly 68, unexpected_traffic 29, packet_rate_spike 20, source_volume_outlier 2, egress_volume_anomaly 2 |
| cloud_migration | egress_volume_anomaly 62, packet_rate_spike 60, inductive_volume_anomaly 53, connection_timeout_burst 44, scan_attempts 40 |
| collector_replay | packet_rate_spike 69, inductive_volume_anomaly 65, source_volume_outlier 25, unmapped_passive_event 14, unexpected_traffic 9 |
| device_decommission | connection_timeout_burst 8, service_unreachable 5, packet_rate_spike 2, service_overload_risk 1, inductive_volume_anomaly 1 |
| device_onboarding | unexpected_traffic 6, packet_rate_spike 3, multi_target_pattern 2 |
| dhcp_renumber | unmapped_passive_event 50, service_unreachable 47, connection_timeout_burst 24, inductive_volume_anomaly 9, packet_rate_spike 5 |
| dns_outage | service_unreachable 75, connection_timeout_burst 29, unmapped_passive_event 10, scan_attempts 8, packet_rate_spike 5 |
| flash_crowd | inductive_volume_anomaly 170, packet_rate_spike 170, unmapped_passive_event 12, connection_timeout_burst 10, unexpected_traffic 8 |
| log_corruption | packet_rate_spike 38, unmapped_passive_event 11, unexpected_traffic 4, novel_persistent_peer 3, inductive_volume_anomaly 3 |
| misconfig | connection_timeout_burst 79, unmapped_passive_event 78, multi_target_pattern 20, scan_attempts 15, packet_rate_spike 7 |
| ntp_fanout | egress_volume_anomaly 3, packet_rate_spike 3, unmapped_passive_event 3, unexpected_traffic 2, scan_attempts 1 |
| patch_window | connection_timeout_burst 76, service_unreachable 73, packet_rate_spike 38, inductive_volume_anomaly 21, scan_attempts 14 |
| saas_adoption | novel_persistent_peer 54, connection_timeout_burst 9, unexpected_traffic 9, packet_rate_spike 7, beacon_periodic 6 |
| segment_power_loss | connection_timeout_burst 32, packet_rate_spike 17, unexpected_traffic 16, service_unreachable 16, inductive_volume_anomaly 12 |
| sensor_crash | unexpected_traffic 9, packet_rate_spike 7, unmapped_passive_event 7, novel_persistent_peer 5, beacon_periodic 1 |
| service_crash | service_unreachable 109, connection_timeout_burst 63, packet_rate_spike 21, unmapped_passive_event 19, inductive_volume_anomaly 11 |
| software_update | egress_volume_anomaly 5 |
| vpn_reconnect_storm | connection_timeout_burst 61, service_overload_risk 37, inductive_volume_anomaly 36, packet_rate_spike 33, unexpected_traffic 26 |

### Útoky zobrazené jen ve frontě provoz (nezapočtené jako detekce)

| rameno | útoků | podíl |
|---|---:|---:|
| legacy | 2224 | 0,0 % (0,0 až 0,2) |
| v3k6 | 2224 | 0,0 % (0,0 až 0,2) |

### Registr slepých míst (rameno `v3k6`, automaticky podle A8)

| oblast | buňka | n | hodnota | zařazení |
|---|---:|---:|---:|---:|
| Rodiny | exploit_attempt | 233 | 39,5 % | SLEPÉ MÍSTO |
| Rodiny | lateral_movement | 197 | 67,0 % | slabé místo |
| Rodina × pásmo S | c2_beacon | Q2 | 22 | 68,2 % | slabé místo |
| Rodina × pásmo S | c2_beacon | Q3 | 32 | 62,5 % | slabé místo |
| Rodina × pásmo S | c2_beacon | Q5 | 68 | 67,6 % | slabé místo |
| Rodina × pásmo S | exfiltration | Q2 | 23 | 69,6 % | slabé místo |
| Rodina × pásmo S | exploit_attempt | Q1 | 33 | 42,4 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q2 | 21 | 42,9 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q3 | 44 | 38,6 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q4 | 46 | 45,7 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q5 | 89 | 34,8 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | lateral_movement | Q2 | 31 | 61,3 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q3 | 27 | 63,0 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q4 | 45 | 53,3 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | objem 2× | 26 | 69,2 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 8× | 26 | 34,6 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | cryptomining | zdroje 10 | 23 | 65,2 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | dns_tunnel | tempo 1× | 35 | 68,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | dns_tunnel | zdroje 10 | 24 | 62,5 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.25× | 47 | 48,9 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.5× | 43 | 48,8 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 1× | 103 | 33,0 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 2× | 40 | 35,0 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 0.25× | 27 | 25,9 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 0.5× | 22 | 50,0 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 1× | 91 | 37,4 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 2× | 26 | 30,8 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 4× | 38 | 50,0 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 8× | 29 | 44,8 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 1 | 95 | 41,1 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 10 | 68 | 35,3 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 3 | 70 | 41,4 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 0.5× | 32 | 65,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 1× | 85 | 65,9 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 2× | 39 | 66,7 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 1× | 82 | 56,1 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 2× | 32 | 65,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | zdroje 3 | 68 | 60,3 % | slabé místo |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | c2_beacon | 35 | 22,9 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | exfiltration | 37 | 0,0 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | port_scan_vertical | 39 | 5,1 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | dns_tunnel | 28 | 46,4 % | SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | authorized_scanner | 235 | 92,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | backup_burst | 462 | 36,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | backup_failed | 79 | 97,5 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | batch_job | 153 | 74,5 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | cert_expired | 83 | 90,4 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | cloud_migration | 77 | 97,4 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | collector_replay | 149 | 69,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | dhcp_renumber | 101 | 76,2 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | dns_outage | 102 | 87,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | flash_crowd | 489 | 41,5 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | log_corruption | 118 | 39,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | misconfig | 92 | 94,6 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | patch_window | 102 | 94,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | saas_adoption | 87 | 69,0 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | segment_power_loss | 89 | 62,9 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | service_crash | 211 | 66,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | vpn_reconnect_storm | 70 | 88,6 % | FP SLEPÉ MÍSTO |

### Prahy K1 až K8

| práh | hodnota | splněno |
|---|---:|---:|
| K1 | Q5/Q1 = 0,93 | ano |
| K2 | vše +18,9 p. b., Q4+Q5 +17,1 p. b. | ano |
| K3 (fronta podezření) | držené 84,0 % (79,6 až 87,6) vs laděné 69,3 % (65,0 až 73,3) | ne |
| K3 (krok 5: jakékoli zobrazení) | držené 84,0 % (79,6 až 87,6) vs laděné 69,3 % (65,0 až 73,3) | ne |
| K4 | +1,9 p. b. | ano |
| K5 | c2_beacon: 8/35, exfiltration: 0/37, ssh_bruteforce: 29/32, port_scan_vertical: 2/39, lateral_movement: 24/39, dns_tunnel: 13/28 | 2 ze 6 zobecňuje |
| K6 | 33/1320, horní mez 3,5 % | ano |
| K6b | držené 3,5 % vs laděné 0,9 % | ano |
| K7 | 95,8 % (91,6 až 97,9) | ano |
| K8 | 0 panik, 0 invariantů | ano |

