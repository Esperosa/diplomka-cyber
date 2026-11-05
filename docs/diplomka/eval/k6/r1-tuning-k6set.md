## Pokrytí, křivky skrytosti a registr slepých míst

Ramena: before, after; hodnocené rameno `after`. Detekce = kontrafaktuální zobrazená detekce na útok (Wilson 95 %; souhrny a rozdíly s bootstrapem po sítích).

Hranice pásem S (zadané předem): 0.172, 0.236, 0.305, 0.392

| rameno | sítí | útoků | detekce (bootstrap) | zobrazené FP/síť-den | zavřeno omylem (G3) | panik/invariantů |
|---|---:|---:|---:|---:|---:|---:|
| before | 120 | 3759 | 79,9 % (77,5 až 81,9) | 22,1 | 1,3 % (0,9 až 1,8) [33/2518] | 0/0 |
| after | 120 | 3759 | 79,9 % (77,5 až 81,9) | 22,1 | 1,3 % (0,9 až 1,8) [33/2518] | 0/0 |

### Párově `after` − `before`

| výběr | párů | rozdíl detekce |
|---|---:|---:|
| vše | 3759 | +0,0 p. b. (+0,0 až +0,0) |
| Q4 + Q5 | 1524 | +0,0 p. b. (+0,0 až +0,0) |
| Q5 | 763 | +0,0 p. b. (+0,0 až +0,0) |

### Párově po rodinách `after` − `before`

| rodina | párů | rozdíl detekce | B5/D1 |
|---|---:|---:|---:|
| c2_beacon | 477 | +0,0 p. b. (+0,0 až +0,0) |  |
| credential_stuffing | 323 | +0,0 p. b. (+0,0 až +0,0) |  |
| ddos_volume | 130 | +0,0 p. b. (+0,0 až +0,0) |  |
| dns_tunnel | 242 | +0,0 p. b. (+0,0 až +0,0) |  |
| exfiltration | 349 | +0,0 p. b. (+0,0 až +0,0) |  |
| exploit_attempt | 443 | +0,0 p. b. (+0,0 až +0,0) |  |
| lateral_movement | 427 | +0,0 p. b. (+0,0 až +0,0) |  |
| port_scan_horizontal | 344 | +0,0 p. b. (+0,0 až +0,0) |  |
| port_scan_vertical | 402 | +0,0 p. b. (+0,0 až +0,0) |  |
| rogue_device | 81 | +0,0 p. b. (+0,0 až +0,0) |  |
| ssh_bruteforce | 541 | +0,0 p. b. (+0,0 až +0,0) |  |

### Poměr zobrazených FP `after` / `before` (stejné sítě)

| metrika | poměr (bootstrap 95 %) |
|---|---:|
| displayed_fp | 1,000 (1,000 až 1,000) |
| displayed_fp_suspect | 1,000 (1,000 až 1,000) |

### Křivka skrytosti: pásma S

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| Q1 | 783 | 84,3 % (81,6 až 86,7) | 84,3 % (81,6 až 86,7) |  |
| Q2 | 728 | 79,1 % (76,0 až 81,9) | 79,1 % (76,0 až 81,9) |  |
| Q3 | 724 | 79,4 % (76,3 až 82,2) | 79,4 % (76,3 až 82,2) |  |
| Q4 | 761 | 78,8 % (75,8 až 81,6) | 78,8 % (75,8 až 81,6) |  |
| Q5 | 763 | 77,6 % (74,5 až 80,4) | 77,6 % (74,5 až 80,4) |  |

### Osa: intenzita

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| 0.0–0.2 | 386 | 74,6 % (70,0 až 78,7) | 74,6 % (70,0 až 78,7) |  |
| 0.2–0.4 | 833 | 80,4 % (77,6 až 83,0) | 80,4 % (77,6 až 83,0) |  |
| 0.4–0.6 | 824 | 81,1 % (78,3 až 83,6) | 81,1 % (78,3 až 83,6) |  |
| 0.6–0.8 | 872 | 80,5 % (77,7 až 83,0) | 80,5 % (77,7 až 83,0) |  |
| 0.8–1.0 | 844 | 80,0 % (77,1 až 82,5) | 80,0 % (77,1 až 82,5) |  |

### Osa: tempo

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| 0.5× | 696 | 78,6 % (75,4 až 81,5) | 78,6 % (75,4 až 81,5) |  |
| 1× | 1562 | 79,8 % (77,8 až 81,7) | 79,8 % (77,8 až 81,7) |  |
| 2× | 756 | 78,6 % (75,5 až 81,3) | 78,6 % (75,5 až 81,3) |  |
| 4× | 745 | 82,6 % (79,7 až 85,1) | 82,6 % (79,7 až 85,1) |  |

### Osa: rozptyl

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| 0 | 1519 | 80,1 % (78,0 až 82,0) | 80,1 % (78,0 až 82,0) |  |
| 0.15 | 1109 | 79,5 % (77,1 až 81,8) | 79,5 % (77,1 až 81,8) |  |
| 0.3 | 1131 | 80,0 % (77,6 až 82,2) | 80,0 % (77,6 až 82,2) |  |

### Osa: zdroje

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| 1 | 1529 | 80,1 % (78,0 až 82,0) | 80,1 % (78,0 až 82,0) |  |
| 3 | 2230 | 79,8 % (78,1 až 81,4) | 79,8 % (78,1 až 81,4) |  |

### Osa: doba

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| 0.5× | 759 | 75,5 % (72,3 až 78,4) | 75,5 % (72,3 až 78,4) |  |
| 1× | 1530 | 78,4 % (76,3 až 80,4) | 78,4 % (76,3 až 80,4) |  |
| 2× | 719 | 81,9 % (78,9 až 84,6) | 81,9 % (78,9 až 84,6) |  |
| 4× | 751 | 85,4 % (82,6 až 87,7) | 85,4 % (82,6 až 87,7) |  |

### Osa: objem

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| 0.25× | 762 | 79,9 % (76,9 až 82,6) | 79,9 % (76,9 až 82,6) |  |
| 0.5× | 772 | 78,5 % (75,5 až 81,3) | 78,5 % (75,5 až 81,3) |  |
| 1× | 1440 | 81,5 % (79,4 až 83,4) | 81,5 % (79,4 až 83,4) |  |
| 2× | 785 | 78,2 % (75,2 až 81,0) | 78,2 % (75,2 až 81,0) |  |

### Osa: mimo pracovní dobu

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| ano | 776 | 81,1 % (78,1 až 83,7) | 81,1 % (78,1 až 83,7) |  |
| ne | 2983 | 79,6 % (78,1 až 81,0) | 79,6 % (78,1 až 81,0) |  |

### Osa: míchání s provozem

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| ano | 1118 | 76,5 % (73,9 až 78,9) | 76,5 % (73,9 až 78,9) |  |
| ne | 2641 | 81,3 % (79,8 až 82,8) | 81,3 % (79,8 až 82,8) |  |

### Osa: IDS signatura

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| ano | 921 | 93,3 % (91,5 až 94,7) | 93,3 % (91,5 až 94,7) |  |
| ne | 2838 | 75,5 % (73,9 až 77,1) | 75,5 % (73,9 až 77,1) |  |

### Rodiny

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| c2_beacon | 477 | 80,9 % (77,2 až 84,2) | 80,9 % (77,2 až 84,2) |  |
| credential_stuffing | 323 | 90,4 % (86,7 až 93,2) | 90,4 % (86,7 až 93,2) |  |
| ddos_volume | 130 | 95,4 % (90,3 až 97,9) | 95,4 % (90,3 až 97,9) |  |
| dns_tunnel | 242 | 93,8 % (90,0 až 96,2) | 93,8 % (90,0 až 96,2) |  |
| exfiltration | 349 | 91,1 % (87,7 až 93,7) | 91,1 % (87,7 až 93,7) |  |
| exploit_attempt | 443 | 39,7 % (35,3 až 44,4) | 39,7 % (35,3 až 44,4) | SLEPÉ MÍSTO |
| lateral_movement | 427 | 60,4 % (55,7 až 64,9) | 60,4 % (55,7 až 64,9) | slabé místo |
| port_scan_horizontal | 344 | 78,8 % (74,2 až 82,8) | 78,8 % (74,2 až 82,8) |  |
| port_scan_vertical | 402 | 90,8 % (87,6 až 93,2) | 90,8 % (87,6 až 93,2) |  |
| rogue_device | 81 | 93,8 % (86,4 až 97,3) | 93,8 % (86,4 až 97,3) |  |
| ssh_bruteforce | 541 | 94,3 % (92,0 až 95,9) | 94,3 % (92,0 až 95,9) |  |

### Rodina × pásmo S

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| c2_beacon | Q1 | 103 | 84,5 % (76,2 až 90,2) | 84,5 % (76,2 až 90,2) |  |
| c2_beacon | Q2 | 95 | 80,0 % (70,9 až 86,8) | 80,0 % (70,9 až 86,8) |  |
| c2_beacon | Q3 | 84 | 79,8 % (70,0 až 87,0) | 79,8 % (70,0 až 87,0) |  |
| c2_beacon | Q4 | 95 | 77,9 % (68,6 až 85,1) | 77,9 % (68,6 až 85,1) |  |
| c2_beacon | Q5 | 100 | 82,0 % (73,3 až 88,3) | 82,0 % (73,3 až 88,3) |  |
| credential_stuffing | Q1 | 75 | 96,0 % (88,9 až 98,6) | 96,0 % (88,9 až 98,6) |  |
| credential_stuffing | Q2 | 52 | 92,3 % (81,8 až 97,0) | 92,3 % (81,8 až 97,0) |  |
| credential_stuffing | Q3 | 60 | 85,0 % (73,9 až 91,9) | 85,0 % (73,9 až 91,9) |  |
| credential_stuffing | Q4 | 63 | 90,5 % (80,7 až 95,6) | 90,5 % (80,7 až 95,6) |  |
| credential_stuffing | Q5 | 73 | 87,7 % (78,2 až 93,4) | 87,7 % (78,2 až 93,4) |  |
| ddos_volume | Q1 | 29 | 96,6 % (82,8 až 99,4) | 96,6 % (82,8 až 99,4) |  |
| ddos_volume | Q2 | 21 | 95,2 % (77,3 až 99,2) | 95,2 % (77,3 až 99,2) |  |
| ddos_volume | Q3 | 20 | 95,0 % (76,4 až 99,1) | 95,0 % (76,4 až 99,1) |  |
| ddos_volume | Q4 | 32 | 90,6 % (75,8 až 96,8) | 90,6 % (75,8 až 96,8) |  |
| ddos_volume | Q5 | 28 | 100,0 % (87,9 až 100,0) | 100,0 % (87,9 až 100,0) |  |
| dns_tunnel | Q1 | 48 | 95,8 % (86,0 až 98,8) | 95,8 % (86,0 až 98,8) |  |
| dns_tunnel | Q2 | 51 | 94,1 % (84,1 až 98,0) | 94,1 % (84,1 až 98,0) |  |
| dns_tunnel | Q3 | 50 | 94,0 % (83,8 až 97,9) | 94,0 % (83,8 až 97,9) |  |
| dns_tunnel | Q4 | 46 | 91,3 % (79,7 až 96,6) | 91,3 % (79,7 až 96,6) |  |
| dns_tunnel | Q5 | 47 | 93,6 % (82,8 až 97,8) | 93,6 % (82,8 až 97,8) |  |
| exfiltration | Q1 | 78 | 94,9 % (87,5 až 98,0) | 94,9 % (87,5 až 98,0) |  |
| exfiltration | Q2 | 64 | 90,6 % (81,0 až 95,6) | 90,6 % (81,0 až 95,6) |  |
| exfiltration | Q3 | 67 | 88,1 % (78,2 až 93,8) | 88,1 % (78,2 až 93,8) |  |
| exfiltration | Q4 | 66 | 89,4 % (79,7 až 94,8) | 89,4 % (79,7 až 94,8) |  |
| exfiltration | Q5 | 74 | 91,9 % (83,4 až 96,2) | 91,9 % (83,4 až 96,2) |  |
| exploit_attempt | Q1 | 80 | 43,8 % (33,4 až 54,7) | 43,8 % (33,4 až 54,7) | SLEPÉ MÍSTO |
| exploit_attempt | Q2 | 89 | 43,8 % (34,0 až 54,2) | 43,8 % (34,0 až 54,2) | SLEPÉ MÍSTO |
| exploit_attempt | Q3 | 77 | 31,2 % (21,9 až 42,2) | 31,2 % (21,9 až 42,2) | SLEPÉ MÍSTO |
| exploit_attempt | Q4 | 102 | 47,1 % (37,7 až 56,7) | 47,1 % (37,7 až 56,7) | SLEPÉ MÍSTO |
| exploit_attempt | Q5 | 95 | 31,6 % (23,1 až 41,5) | 31,6 % (23,1 až 41,5) | SLEPÉ MÍSTO |
| lateral_movement | Q1 | 84 | 65,5 % (54,8 až 74,8) | 65,5 % (54,8 až 74,8) | slabé místo |
| lateral_movement | Q2 | 79 | 58,2 % (47,2 až 68,5) | 58,2 % (47,2 až 68,5) | slabé místo |
| lateral_movement | Q3 | 93 | 62,4 % (52,2 až 71,5) | 62,4 % (52,2 až 71,5) | slabé místo |
| lateral_movement | Q4 | 89 | 60,7 % (50,3 až 70,2) | 60,7 % (50,3 až 70,2) | slabé místo |
| lateral_movement | Q5 | 82 | 54,9 % (44,1 až 65,2) | 54,9 % (44,1 až 65,2) | slabé místo |
| port_scan_horizontal | Q1 | 63 | 88,9 % (78,8 až 94,5) | 88,9 % (78,8 až 94,5) |  |
| port_scan_horizontal | Q2 | 76 | 72,4 % (61,4 až 81,2) | 72,4 % (61,4 až 81,2) |  |
| port_scan_horizontal | Q3 | 72 | 79,2 % (68,4 až 86,9) | 79,2 % (68,4 až 86,9) |  |
| port_scan_horizontal | Q4 | 66 | 80,3 % (69,2 až 88,1) | 80,3 % (69,2 až 88,1) |  |
| port_scan_horizontal | Q5 | 67 | 74,6 % (63,1 až 83,5) | 74,6 % (63,1 až 83,5) |  |
| port_scan_vertical | Q1 | 88 | 89,8 % (81,7 až 94,5) | 89,8 % (81,7 až 94,5) |  |
| port_scan_vertical | Q2 | 86 | 89,5 % (81,3 až 94,4) | 89,5 % (81,3 až 94,4) |  |
| port_scan_vertical | Q3 | 78 | 94,9 % (87,5 až 98,0) | 94,9 % (87,5 až 98,0) |  |
| port_scan_vertical | Q4 | 89 | 89,9 % (81,9 až 94,6) | 89,9 % (81,9 až 94,6) |  |
| port_scan_vertical | Q5 | 61 | 90,2 % (80,2 až 95,4) | 90,2 % (80,2 až 95,4) |  |
| rogue_device | Q1 | 14 | 92,9 % (68,5 až 98,7) | 92,9 % (68,5 až 98,7) | nedostatečná data |
| rogue_device | Q2 | 22 | 90,9 % (72,2 až 97,5) | 90,9 % (72,2 až 97,5) |  |
| rogue_device | Q3 | 15 | 93,3 % (70,2 až 98,8) | 93,3 % (70,2 až 98,8) | nedostatečná data |
| rogue_device | Q4 | 15 | 100,0 % (79,6 až 100,0) | 100,0 % (79,6 až 100,0) | nedostatečná data |
| rogue_device | Q5 | 15 | 93,3 % (70,2 až 98,8) | 93,3 % (70,2 až 98,8) | nedostatečná data |
| ssh_bruteforce | Q1 | 121 | 95,0 % (89,6 až 97,7) | 95,0 % (89,6 až 97,7) |  |
| ssh_bruteforce | Q2 | 93 | 95,7 % (89,5 až 98,3) | 95,7 % (89,5 až 98,3) |  |
| ssh_bruteforce | Q3 | 108 | 97,2 % (92,1 až 99,1) | 97,2 % (92,1 až 99,1) |  |
| ssh_bruteforce | Q4 | 98 | 90,8 % (83,5 až 95,1) | 90,8 % (83,5 až 95,1) |  |
| ssh_bruteforce | Q5 | 121 | 92,6 % (86,5 až 96,0) | 92,6 % (86,5 až 96,0) |  |

### Rodina × osa (tempo, zdroje, objem)

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| c2_beacon | objem 0.25× | 93 | 82,8 % (73,9 až 89,1) | 82,8 % (73,9 až 89,1) |  |
| c2_beacon | objem 0.5× | 99 | 73,7 % (64,3 až 81,4) | 73,7 % (64,3 až 81,4) |  |
| c2_beacon | objem 1× | 180 | 86,1 % (80,3 až 90,4) | 86,1 % (80,3 až 90,4) |  |
| c2_beacon | objem 2× | 105 | 77,1 % (68,2 až 84,1) | 77,1 % (68,2 až 84,1) |  |
| c2_beacon | tempo 0.5× | 76 | 92,1 % (83,8 až 96,3) | 92,1 % (83,8 až 96,3) |  |
| c2_beacon | tempo 1× | 197 | 89,3 % (84,3 až 92,9) | 89,3 % (84,3 až 92,9) |  |
| c2_beacon | tempo 2× | 99 | 78,8 % (69,7 až 85,7) | 78,8 % (69,7 až 85,7) |  |
| c2_beacon | tempo 4× | 105 | 59,0 % (49,5 až 68,0) | 59,0 % (49,5 až 68,0) | slabé místo |
| c2_beacon | zdroje 1 | 201 | 80,1 % (74,0 až 85,0) | 80,1 % (74,0 až 85,0) |  |
| c2_beacon | zdroje 3 | 276 | 81,5 % (76,5 až 85,7) | 81,5 % (76,5 až 85,7) |  |
| credential_stuffing | objem 0.25× | 65 | 90,8 % (81,3 až 95,7) | 90,8 % (81,3 až 95,7) |  |
| credential_stuffing | objem 0.5× | 72 | 87,5 % (77,9 až 93,3) | 87,5 % (77,9 až 93,3) |  |
| credential_stuffing | objem 1× | 114 | 94,7 % (89,0 až 97,6) | 94,7 % (89,0 až 97,6) |  |
| credential_stuffing | objem 2× | 72 | 86,1 % (76,3 až 92,3) | 86,1 % (76,3 až 92,3) |  |
| credential_stuffing | tempo 0.5× | 59 | 76,3 % (64,0 až 85,3) | 76,3 % (64,0 až 85,3) |  |
| credential_stuffing | tempo 1× | 135 | 95,6 % (90,6 až 97,9) | 95,6 % (90,6 až 97,9) |  |
| credential_stuffing | tempo 2× | 58 | 87,9 % (77,1 až 94,0) | 87,9 % (77,1 až 94,0) |  |
| credential_stuffing | tempo 4× | 71 | 94,4 % (86,4 až 97,8) | 94,4 % (86,4 až 97,8) |  |
| credential_stuffing | zdroje 1 | 126 | 89,7 % (83,1 až 93,9) | 89,7 % (83,1 až 93,9) |  |
| credential_stuffing | zdroje 3 | 197 | 90,9 % (86,0 až 94,1) | 90,9 % (86,0 až 94,1) |  |
| ddos_volume | objem 0.25× | 24 | 100,0 % (86,2 až 100,0) | 100,0 % (86,2 až 100,0) |  |
| ddos_volume | objem 0.5× | 29 | 93,1 % (78,0 až 98,1) | 93,1 % (78,0 až 98,1) |  |
| ddos_volume | objem 1× | 52 | 96,2 % (87,0 až 98,9) | 96,2 % (87,0 až 98,9) |  |
| ddos_volume | objem 2× | 25 | 92,0 % (75,0 až 97,8) | 92,0 % (75,0 až 97,8) |  |
| ddos_volume | tempo 0.5× | 20 | 100,0 % (83,9 až 100,0) | 100,0 % (83,9 až 100,0) |  |
| ddos_volume | tempo 1× | 55 | 94,5 % (85,1 až 98,1) | 94,5 % (85,1 až 98,1) |  |
| ddos_volume | tempo 2× | 25 | 92,0 % (75,0 až 97,8) | 92,0 % (75,0 až 97,8) |  |
| ddos_volume | tempo 4× | 30 | 96,7 % (83,3 až 99,4) | 96,7 % (83,3 až 99,4) |  |
| ddos_volume | zdroje 1 | 48 | 95,8 % (86,0 až 98,8) | 95,8 % (86,0 až 98,8) |  |
| ddos_volume | zdroje 3 | 82 | 95,1 % (88,1 až 98,1) | 95,1 % (88,1 až 98,1) |  |
| dns_tunnel | objem 0.25× | 43 | 97,7 % (87,9 až 99,6) | 97,7 % (87,9 až 99,6) |  |
| dns_tunnel | objem 0.5× | 48 | 93,8 % (83,2 až 97,9) | 93,8 % (83,2 až 97,9) |  |
| dns_tunnel | objem 1× | 95 | 93,7 % (86,9 až 97,1) | 93,7 % (86,9 až 97,1) |  |
| dns_tunnel | objem 2× | 56 | 91,1 % (80,7 až 96,1) | 91,1 % (80,7 až 96,1) |  |
| dns_tunnel | tempo 0.5× | 51 | 90,2 % (79,0 až 95,7) | 90,2 % (79,0 až 95,7) |  |
| dns_tunnel | tempo 1× | 84 | 91,7 % (83,8 až 95,9) | 91,7 % (83,8 až 95,9) |  |
| dns_tunnel | tempo 2× | 58 | 98,3 % (90,9 až 99,7) | 98,3 % (90,9 až 99,7) |  |
| dns_tunnel | tempo 4× | 49 | 95,9 % (86,3 až 98,9) | 95,9 % (86,3 až 98,9) |  |
| dns_tunnel | zdroje 1 | 104 | 94,2 % (88,0 až 97,3) | 94,2 % (88,0 až 97,3) |  |
| dns_tunnel | zdroje 3 | 138 | 93,5 % (88,1 až 96,5) | 93,5 % (88,1 až 96,5) |  |
| exfiltration | objem 0.25× | 65 | 86,2 % (75,7 až 92,5) | 86,2 % (75,7 až 92,5) |  |
| exfiltration | objem 0.5× | 63 | 95,2 % (86,9 až 98,4) | 95,2 % (86,9 až 98,4) |  |
| exfiltration | objem 1× | 148 | 91,2 % (85,6 až 94,8) | 91,2 % (85,6 až 94,8) |  |
| exfiltration | objem 2× | 73 | 91,8 % (83,2 až 96,2) | 91,8 % (83,2 až 96,2) |  |
| exfiltration | tempo 0.5× | 50 | 92,0 % (81,2 až 96,8) | 92,0 % (81,2 až 96,8) |  |
| exfiltration | tempo 1× | 156 | 91,0 % (85,5 až 94,6) | 91,0 % (85,5 až 94,6) |  |
| exfiltration | tempo 2× | 65 | 89,2 % (79,4 až 94,7) | 89,2 % (79,4 až 94,7) |  |
| exfiltration | tempo 4× | 78 | 92,3 % (84,2 až 96,4) | 92,3 % (84,2 až 96,4) |  |
| exfiltration | zdroje 1 | 141 | 88,7 % (82,4 až 92,9) | 88,7 % (82,4 až 92,9) |  |
| exfiltration | zdroje 3 | 208 | 92,8 % (88,4 až 95,6) | 92,8 % (88,4 až 95,6) |  |
| exploit_attempt | objem 0.25× | 101 | 42,6 % (33,4 až 52,3) | 42,6 % (33,4 až 52,3) | SLEPÉ MÍSTO |
| exploit_attempt | objem 0.5× | 81 | 37,0 % (27,3 až 47,9) | 37,0 % (27,3 až 47,9) | SLEPÉ MÍSTO |
| exploit_attempt | objem 1× | 166 | 39,2 % (32,1 až 46,7) | 39,2 % (32,1 až 46,7) | SLEPÉ MÍSTO |
| exploit_attempt | objem 2× | 95 | 40,0 % (30,7 až 50,1) | 40,0 % (30,7 až 50,1) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 0.5× | 89 | 37,1 % (27,8 až 47,5) | 37,1 % (27,8 až 47,5) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 1× | 185 | 42,7 % (35,8 až 49,9) | 42,7 % (35,8 až 49,9) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 2× | 90 | 36,7 % (27,4 až 47,0) | 36,7 % (27,4 až 47,0) | SLEPÉ MÍSTO |
| exploit_attempt | tempo 4× | 79 | 39,2 % (29,2 až 50,3) | 39,2 % (29,2 až 50,3) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 1 | 178 | 41,0 % (34,0 až 48,4) | 41,0 % (34,0 až 48,4) | SLEPÉ MÍSTO |
| exploit_attempt | zdroje 3 | 265 | 38,9 % (33,2 až 44,9) | 38,9 % (33,2 až 44,9) | SLEPÉ MÍSTO |
| lateral_movement | objem 0.25× | 91 | 59,3 % (49,1 až 68,9) | 59,3 % (49,1 až 68,9) | slabé místo |
| lateral_movement | objem 0.5× | 87 | 51,7 % (41,4 až 61,9) | 51,7 % (41,4 až 61,9) | slabé místo |
| lateral_movement | objem 1× | 162 | 66,7 % (59,1 až 73,5) | 66,7 % (59,1 až 73,5) | slabé místo |
| lateral_movement | objem 2× | 87 | 58,6 % (48,1 až 68,4) | 58,6 % (48,1 až 68,4) | slabé místo |
| lateral_movement | tempo 0.5× | 66 | 48,5 % (36,8 až 60,3) | 48,5 % (36,8 až 60,3) | SLEPÉ MÍSTO |
| lateral_movement | tempo 1× | 184 | 48,4 % (41,3 až 55,5) | 48,4 % (41,3 až 55,5) | SLEPÉ MÍSTO |
| lateral_movement | tempo 2× | 88 | 60,2 % (49,8 až 69,8) | 60,2 % (49,8 až 69,8) | slabé místo |
| lateral_movement | tempo 4× | 89 | 94,4 % (87,5 až 97,6) | 94,4 % (87,5 až 97,6) |  |
| lateral_movement | zdroje 1 | 160 | 60,6 % (52,9 až 67,9) | 60,6 % (52,9 až 67,9) | slabé místo |
| lateral_movement | zdroje 3 | 267 | 60,3 % (54,3 až 66,0) | 60,3 % (54,3 až 66,0) | slabé místo |
| port_scan_horizontal | objem 0.25× | 71 | 83,1 % (72,7 až 90,1) | 83,1 % (72,7 až 90,1) |  |
| port_scan_horizontal | objem 0.5× | 63 | 77,8 % (66,1 až 86,3) | 77,8 % (66,1 až 86,3) |  |
| port_scan_horizontal | objem 1× | 138 | 79,0 % (71,4 až 85,0) | 79,0 % (71,4 až 85,0) |  |
| port_scan_horizontal | objem 2× | 72 | 75,0 % (63,9 až 83,6) | 75,0 % (63,9 až 83,6) |  |
| port_scan_horizontal | tempo 0.5× | 75 | 77,3 % (66,7 až 85,3) | 77,3 % (66,7 až 85,3) |  |
| port_scan_horizontal | tempo 1× | 139 | 74,8 % (67,0 až 81,3) | 74,8 % (67,0 až 81,3) |  |
| port_scan_horizontal | tempo 2× | 78 | 75,6 % (65,1 až 83,8) | 75,6 % (65,1 až 83,8) |  |
| port_scan_horizontal | tempo 4× | 52 | 96,2 % (87,0 až 98,9) | 96,2 % (87,0 až 98,9) |  |
| port_scan_horizontal | zdroje 1 | 148 | 79,7 % (72,5 až 85,4) | 79,7 % (72,5 až 85,4) |  |
| port_scan_horizontal | zdroje 3 | 196 | 78,1 % (71,8 až 83,3) | 78,1 % (71,8 až 83,3) |  |
| port_scan_vertical | objem 0.25× | 83 | 91,6 % (83,6 až 95,9) | 91,6 % (83,6 až 95,9) |  |
| port_scan_vertical | objem 0.5× | 91 | 92,3 % (85,0 až 96,2) | 92,3 % (85,0 až 96,2) |  |
| port_scan_vertical | objem 1× | 148 | 90,5 % (84,7 až 94,3) | 90,5 % (84,7 až 94,3) |  |
| port_scan_vertical | objem 2× | 80 | 88,8 % (80,0 až 94,0) | 88,8 % (80,0 až 94,0) |  |
| port_scan_vertical | tempo 0.5× | 82 | 91,5 % (83,4 až 95,8) | 91,5 % (83,4 až 95,8) |  |
| port_scan_vertical | tempo 1× | 168 | 89,9 % (84,4 až 93,6) | 89,9 % (84,4 až 93,6) |  |
| port_scan_vertical | tempo 2× | 77 | 94,8 % (87,4 až 98,0) | 94,8 % (87,4 až 98,0) |  |
| port_scan_vertical | tempo 4× | 75 | 88,0 % (78,7 až 93,6) | 88,0 % (78,7 až 93,6) |  |
| port_scan_vertical | zdroje 1 | 171 | 91,8 % (86,7 až 95,1) | 91,8 % (86,7 až 95,1) |  |
| port_scan_vertical | zdroje 3 | 231 | 90,0 % (85,5 až 93,3) | 90,0 % (85,5 až 93,3) |  |
| rogue_device | objem 0.25× | 15 | 93,3 % (70,2 až 98,8) | 93,3 % (70,2 až 98,8) | nedostatečná data |
| rogue_device | objem 0.5× | 28 | 100,0 % (87,9 až 100,0) | 100,0 % (87,9 až 100,0) |  |
| rogue_device | objem 1× | 29 | 93,1 % (78,0 až 98,1) | 93,1 % (78,0 až 98,1) |  |
| rogue_device | objem 2× | 9 | 77,8 % (45,3 až 93,7) | 77,8 % (45,3 až 93,7) | nedostatečná data |
| rogue_device | tempo 0.5× | 13 | 92,3 % (66,7 až 98,6) | 92,3 % (66,7 až 98,6) | nedostatečná data |
| rogue_device | tempo 1× | 38 | 94,7 % (82,7 až 98,5) | 94,7 % (82,7 až 98,5) |  |
| rogue_device | tempo 2× | 13 | 92,3 % (66,7 až 98,6) | 92,3 % (66,7 až 98,6) | nedostatečná data |
| rogue_device | tempo 4× | 17 | 94,1 % (73,0 až 99,0) | 94,1 % (73,0 až 99,0) | nedostatečná data |
| rogue_device | zdroje 1 | 31 | 93,5 % (79,3 až 98,2) | 93,5 % (79,3 až 98,2) |  |
| rogue_device | zdroje 3 | 50 | 94,0 % (83,8 až 97,9) | 94,0 % (83,8 až 97,9) |  |
| ssh_bruteforce | objem 0.25× | 111 | 94,6 % (88,7 až 97,5) | 94,6 % (88,7 až 97,5) |  |
| ssh_bruteforce | objem 0.5× | 111 | 91,9 % (85,3 až 95,7) | 91,9 % (85,3 až 95,7) |  |
| ssh_bruteforce | objem 1× | 208 | 93,3 % (89,0 až 95,9) | 93,3 % (89,0 až 95,9) |  |
| ssh_bruteforce | objem 2× | 111 | 98,2 % (93,7 až 99,5) | 98,2 % (93,7 až 99,5) |  |
| ssh_bruteforce | tempo 0.5× | 115 | 95,7 % (90,2 až 98,1) | 95,7 % (90,2 až 98,1) |  |
| ssh_bruteforce | tempo 1× | 221 | 95,9 % (92,4 až 97,8) | 95,9 % (92,4 až 97,8) |  |
| ssh_bruteforce | tempo 2× | 105 | 92,4 % (85,7 až 96,1) | 92,4 % (85,7 až 96,1) |  |
| ssh_bruteforce | tempo 4× | 100 | 91,0 % (83,8 až 95,2) | 91,0 % (83,8 až 95,2) |  |
| ssh_bruteforce | zdroje 1 | 221 | 93,7 % (89,6 až 96,2) | 93,7 % (89,6 až 96,2) |  |
| ssh_bruteforce | zdroje 3 | 320 | 94,7 % (91,7 až 96,7) | 94,7 % (91,7 až 96,7) |  |

### Souběh útoku s provozní poruchou

| buňka | n | detekce before | detekce after | registr |
|---|---:|---:|---:|---:|
| bez souběhu | 964 | 78,9 % (76,3 až 81,4) | 78,9 % (76,3 až 81,4) |  |
| nesenzorová porucha | 2535 | 81,7 % (80,1 až 83,2) | 81,7 % (80,1 až 83,2) |  |
| s backup_failed | 450 | 85,8 % (82,2 až 88,7) | 85,8 % (82,2 až 88,7) |  |
| s batch_job | 502 | 87,1 % (83,8 až 89,7) | 87,1 % (83,8 až 89,7) |  |
| s collector_replay | 476 | 84,0 % (80,5 až 87,0) | 84,0 % (80,5 až 87,0) |  |
| s device_decommission | 332 | 85,2 % (81,0 až 88,7) | 85,2 % (81,0 až 88,7) |  |
| s device_onboarding | 284 | 82,7 % (77,9 až 86,7) | 82,7 % (77,9 až 86,7) |  |
| s dhcp_renumber | 475 | 84,6 % (81,1 až 87,6) | 84,6 % (81,1 až 87,6) |  |
| s dns_outage | 468 | 88,0 % (84,8 až 90,7) | 88,0 % (84,8 až 90,7) |  |
| s link_flapping | 691 | 81,9 % (78,9 až 84,6) | 81,9 % (78,9 až 84,6) |  |
| s log_corruption | 410 | 84,4 % (80,6 až 87,6) | 84,4 % (80,6 až 87,6) |  |
| s misconfig | 499 | 86,6 % (83,3 až 89,3) | 86,6 % (83,3 až 89,3) |  |
| s patch_window | 411 | 83,0 % (79,0 až 86,3) | 83,0 % (79,0 až 86,3) |  |
| s retry_storm | 499 | 85,6 % (82,2 až 88,4) | 85,6 % (82,2 až 88,4) |  |
| s sensor_crash | 505 | 64,8 % (60,5 až 68,8) | 64,8 % (60,5 až 68,8) | slabé místo |
| s service_crash | 601 | 82,5 % (79,3 až 85,4) | 82,5 % (79,3 až 85,4) |  |
| senzorová porucha | 1119 | 76,4 % (73,8 až 78,8) | 76,4 % (73,8 až 78,8) |  |

### Kampaně

| rameno | šablona | kampaní | aspoň jedna fáze | první fáze | všechny fáze |
|---|---:|---:|---:|---:|---:|
| before | K-T1 | 121 | 99,2 % (95,5 až 99,9) | 62,0 % (53,1 až 70,1) | 33,9 % (26,1 až 42,7) |
| before | K-T2 | 96 | 97,9 % (92,7 až 99,4) | 88,5 % (80,6 až 93,5) | 72,9 % (63,3 až 80,8) |
| before | K-T3 | 132 | 97,0 % (92,5 až 98,8) | 44,7 % (36,5 až 53,2) | 18,2 % (12,5 až 25,6) |
| before | vše | 349 | 98,0 % (95,9 až 99,0) | 62,8 % (57,6 až 67,7) | 38,7 % (33,7 až 43,9) |
| after | K-T1 | 121 | 99,2 % (95,5 až 99,9) | 62,0 % (53,1 až 70,1) | 33,9 % (26,1 až 42,7) |
| after | K-T2 | 96 | 97,9 % (92,7 až 99,4) | 88,5 % (80,6 až 93,5) | 72,9 % (63,3 až 80,8) |
| after | K-T3 | 132 | 97,0 % (92,5 až 98,8) | 44,7 % (36,5 až 53,2) | 18,2 % (12,5 až 25,6) |
| after | vše | 349 | 98,0 % (95,9 až 99,0) | 62,8 % (57,6 až 67,7) | 38,7 % (33,7 až 43,9) |

### Leave-one-family-out (náhrada A5), rameno `after`

| rodina | vynechané typy D(X) | n | detekce všemi signály | obecná detekce | verdikt |
|---|---:|---:|---:|---:|---:|
| c2_beacon | beacon_periodic | 76 | 68,4 % (57,3 až 77,8) | 27,6 % (18,8 až 38,6) | SLEPÉ MÍSTO |
| exfiltration | egress_volume_anomaly, long_lived_tunnel | 66 | 89,4 % (79,7 až 94,8) | 3,0 % (0,8 až 10,4) | SLEPÉ MÍSTO |
| ssh_bruteforce | connection_timeout_burst, source_volume_outlier | 56 | 96,4 % (87,9 až 99,0) | 96,4 % (87,9 až 99,0) | zobecňuje |
| port_scan_vertical | connection_timeout_burst, scan_attempts | 60 | 93,3 % (84,1 až 97,4) | 1,7 % (0,3 až 8,9) | SLEPÉ MÍSTO |
| lateral_movement | multi_target_pattern, pivot_chain | 72 | 66,7 % (55,2 až 76,5) | 50,0 % (38,7 až 61,3) | zobecňuje |
| dns_tunnel | egress_volume_anomaly, source_volume_outlier | 64 | 90,6 % (81,0 až 95,6) | 54,7 % (42,6 až 66,3) | zobecňuje |

### Útoky s automaticky zavřeným připsaným nálezem

| rameno | rodiny | útoků | podíl s automatickým zavřením | z toho první výskyt (A7) |
|---|---:|---:|---:|---:|
| before | laděné | 3759 | 0,5 % (0,3 až 0,8) | 9 |
| before | držené | 0 | – % (0,0 až 100,0) | 0 |
| after | laděné | 3759 | 0,5 % (0,3 až 0,8) | 9 |
| after | držené | 0 | – % (0,0 až 100,0) | 0 |

### Poruchy a lookalike: podíl výskytů s FP

| rameno | událost | výskytů | FP ve frontě podezření | zobrazené FP (i provoz) | zachycené FP | registr |
|---|---:|---:|---:|---:|---:|---:|
| before | authorized_scanner | 523 | 93,9 % (91,5 až 95,6) | 93,9 % (91,5 až 95,6) | 95,6 % (93,5 až 97,1) | FP SLEPÉ MÍSTO |
| before | backup_burst | 1026 | 41,8 % (38,8 až 44,9) | 41,8 % (38,8 až 44,9) | 62,6 % (59,6 až 65,5) | FP SLEPÉ MÍSTO |
| before | backup_failed | 305 | 91,1 % (87,4 až 93,8) | 91,1 % (87,4 až 93,8) | 95,4 % (92,4 až 97,2) | FP SLEPÉ MÍSTO |
| before | batch_job | 311 | 71,1 % (65,8 až 75,8) | 71,1 % (65,8 až 75,8) | 87,5 % (83,3 až 90,7) | FP SLEPÉ MÍSTO |
| before | collector_replay | 321 | 80,4 % (75,7 až 84,3) | 80,4 % (75,7 až 84,3) | 95,6 % (92,8 až 97,4) | FP SLEPÉ MÍSTO |
| before | device_decommission | 204 | 18,6 % (13,9 až 24,5) | 18,6 % (13,9 až 24,5) | 27,0 % (21,3 až 33,4) |  |
| before | device_onboarding | 217 | 12,4 % (8,7 až 17,5) | 12,4 % (8,7 až 17,5) | 14,3 % (10,3 až 19,6) |  |
| before | dhcp_renumber | 333 | 79,0 % (74,3 až 83,0) | 79,0 % (74,3 až 83,0) | 82,6 % (78,1 až 86,3) | FP SLEPÉ MÍSTO |
| before | dns_outage | 354 | 86,2 % (82,2 až 89,4) | 86,2 % (82,2 až 89,4) | 98,0 % (96,0 až 99,0) | FP SLEPÉ MÍSTO |
| before | flash_crowd | 1037 | 35,3 % (32,4 až 38,3) | 35,3 % (32,4 až 38,3) | 74,1 % (71,3 až 76,6) | FP SLEPÉ MÍSTO |
| before | link_flapping | 365 | 0,0 % (0,0 až 1,0) | 0,0 % (0,0 až 1,0) | 0,0 % (0,0 až 1,0) |  |
| before | log_corruption | 240 | 47,9 % (41,7 až 54,2) | 47,9 % (41,7 až 54,2) | 90,0 % (85,6 až 93,2) | FP SLEPÉ MÍSTO |
| before | misconfig | 360 | 96,9 % (94,6 až 98,3) | 96,9 % (94,6 až 98,3) | 98,9 % (97,2 až 99,6) | FP SLEPÉ MÍSTO |
| before | ntp_fanout | 500 | 7,0 % (5,1 až 9,6) | 7,0 % (5,1 až 9,6) | 16,8 % (13,8 až 20,3) |  |
| before | patch_window | 260 | 92,7 % (88,9 až 95,3) | 92,7 % (88,9 až 95,3) | 96,2 % (93,1 až 97,9) | FP SLEPÉ MÍSTO |
| before | retry_storm | 340 | 0,0 % (0,0 až 1,1) | 0,0 % (0,0 až 1,1) | 0,0 % (0,0 až 1,1) |  |
| before | sensor_crash | 278 | 33,8 % (28,5 až 39,6) | 33,8 % (28,5 až 39,6) | 33,8 % (28,5 až 39,6) | FP SLEPÉ MÍSTO |
| before | service_crash | 450 | 66,0 % (61,5 až 70,2) | 66,0 % (61,5 až 70,2) | 76,4 % (72,3 až 80,1) | FP SLEPÉ MÍSTO |
| before | software_update | 1022 | 1,6 % (1,0 až 2,5) | 1,6 % (1,0 až 2,5) | 1,8 % (1,1 až 2,8) |  |
| after | authorized_scanner | 523 | 93,9 % (91,5 až 95,6) | 93,9 % (91,5 až 95,6) | 95,6 % (93,5 až 97,1) | FP SLEPÉ MÍSTO |
| after | backup_burst | 1026 | 41,8 % (38,8 až 44,9) | 41,8 % (38,8 až 44,9) | 62,6 % (59,6 až 65,5) | FP SLEPÉ MÍSTO |
| after | backup_failed | 305 | 91,1 % (87,4 až 93,8) | 91,1 % (87,4 až 93,8) | 95,4 % (92,4 až 97,2) | FP SLEPÉ MÍSTO |
| after | batch_job | 311 | 71,1 % (65,8 až 75,8) | 71,1 % (65,8 až 75,8) | 87,5 % (83,3 až 90,7) | FP SLEPÉ MÍSTO |
| after | collector_replay | 321 | 80,4 % (75,7 až 84,3) | 80,4 % (75,7 až 84,3) | 95,6 % (92,8 až 97,4) | FP SLEPÉ MÍSTO |
| after | device_decommission | 204 | 18,6 % (13,9 až 24,5) | 18,6 % (13,9 až 24,5) | 27,0 % (21,3 až 33,4) |  |
| after | device_onboarding | 217 | 12,4 % (8,7 až 17,5) | 12,4 % (8,7 až 17,5) | 14,3 % (10,3 až 19,6) |  |
| after | dhcp_renumber | 333 | 79,0 % (74,3 až 83,0) | 79,0 % (74,3 až 83,0) | 82,6 % (78,1 až 86,3) | FP SLEPÉ MÍSTO |
| after | dns_outage | 354 | 86,2 % (82,2 až 89,4) | 86,2 % (82,2 až 89,4) | 98,0 % (96,0 až 99,0) | FP SLEPÉ MÍSTO |
| after | flash_crowd | 1037 | 35,3 % (32,4 až 38,3) | 35,3 % (32,4 až 38,3) | 74,1 % (71,3 až 76,6) | FP SLEPÉ MÍSTO |
| after | link_flapping | 365 | 0,0 % (0,0 až 1,0) | 0,0 % (0,0 až 1,0) | 0,0 % (0,0 až 1,0) |  |
| after | log_corruption | 240 | 47,9 % (41,7 až 54,2) | 47,9 % (41,7 až 54,2) | 90,0 % (85,6 až 93,2) | FP SLEPÉ MÍSTO |
| after | misconfig | 360 | 96,9 % (94,6 až 98,3) | 96,9 % (94,6 až 98,3) | 98,9 % (97,2 až 99,6) | FP SLEPÉ MÍSTO |
| after | ntp_fanout | 500 | 7,0 % (5,1 až 9,6) | 7,0 % (5,1 až 9,6) | 16,8 % (13,8 až 20,3) |  |
| after | patch_window | 260 | 92,7 % (88,9 až 95,3) | 92,7 % (88,9 až 95,3) | 96,2 % (93,1 až 97,9) | FP SLEPÉ MÍSTO |
| after | retry_storm | 340 | 0,0 % (0,0 až 1,1) | 0,0 % (0,0 až 1,1) | 0,0 % (0,0 až 1,1) |  |
| after | sensor_crash | 278 | 33,8 % (28,5 až 39,6) | 33,8 % (28,5 až 39,6) | 33,8 % (28,5 až 39,6) | FP SLEPÉ MÍSTO |
| after | service_crash | 450 | 66,0 % (61,5 až 70,2) | 66,0 % (61,5 až 70,2) | 76,4 % (72,3 až 80,1) | FP SLEPÉ MÍSTO |
| after | software_update | 1022 | 1,6 % (1,0 až 2,5) | 1,6 % (1,0 až 2,5) | 1,8 % (1,1 až 2,8) |  |

### Typy FP ve frontě podezření (rameno `after`, počet výskytů s typem)

| událost | typy |
|---|---:|
| authorized_scanner | scan_attempts 462, multi_target_pattern 456, unmapped_passive_event 48, unexpected_traffic 13, packet_rate_spike 11 |
| backup_burst | inductive_volume_anomaly 348, packet_rate_spike 339, egress_volume_anomaly 63, source_volume_outlier 26, unexpected_traffic 25 |
| backup_failed | connection_timeout_burst 258, inductive_volume_anomaly 152, packet_rate_spike 74, service_overload_risk 58, source_volume_outlier 47 |
| batch_job | inductive_volume_anomaly 210, packet_rate_spike 200, source_volume_outlier 34, connection_timeout_burst 23, service_overload_risk 18 |
| collector_replay | packet_rate_spike 204, inductive_volume_anomaly 169, unmapped_passive_event 58, source_volume_outlier 51, unexpected_traffic 37 |
| device_decommission | connection_timeout_burst 23, service_unreachable 11, unmapped_passive_event 4, unexpected_traffic 4, packet_rate_spike 3 |
| device_onboarding | unexpected_traffic 10, inductive_volume_anomaly 10, packet_rate_spike 6, multi_target_pattern 5, unmapped_passive_event 2 |
| dhcp_renumber | unmapped_passive_event 202, service_unreachable 175, connection_timeout_burst 68, inductive_volume_anomaly 30, packet_rate_spike 22 |
| dns_outage | service_unreachable 266, connection_timeout_burst 97, scan_attempts 34, packet_rate_spike 28, unmapped_passive_event 27 |
| flash_crowd | inductive_volume_anomaly 326, packet_rate_spike 302, suricata_alert 14, unmapped_passive_event 11, connection_timeout_burst 10 |
| log_corruption | packet_rate_spike 69, unmapped_passive_event 37, unexpected_traffic 27, inductive_volume_anomaly 11, novel_persistent_peer 10 |
| misconfig | unmapped_passive_event 340, connection_timeout_burst 291, multi_target_pattern 62, packet_rate_spike 22, scan_attempts 19 |
| ntp_fanout | unexpected_traffic 11, unmapped_passive_event 8, inductive_volume_anomaly 5, source_volume_outlier 5, connection_timeout_burst 4 |
| patch_window | connection_timeout_burst 174, service_unreachable 160, packet_rate_spike 93, inductive_volume_anomaly 54, unmapped_passive_event 31 |
| sensor_crash | unmapped_passive_event 43, unexpected_traffic 33, packet_rate_spike 15, novel_persistent_peer 6, connection_timeout_burst 5 |
| service_crash | service_unreachable 206, connection_timeout_burst 185, packet_rate_spike 27, unmapped_passive_event 26, inductive_volume_anomaly 19 |
| software_update | egress_volume_anomaly 16 |

### Útoky zobrazené jen ve frontě provoz (nezapočtené jako detekce)

| rameno | útoků | podíl |
|---|---:|---:|
| before | 3759 | 0,0 % (0,0 až 0,1) |
| after | 3759 | 0,0 % (0,0 až 0,1) |

### Registr slepých míst (rameno `after`, automaticky podle A8)

| oblast | buňka | n | hodnota | zařazení |
|---|---:|---:|---:|---:|
| Rodiny | exploit_attempt | 443 | 39,7 % | SLEPÉ MÍSTO |
| Rodiny | lateral_movement | 427 | 60,4 % | slabé místo |
| Rodina × pásmo S | exploit_attempt | Q1 | 80 | 43,8 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q2 | 89 | 43,8 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q3 | 77 | 31,2 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q4 | 102 | 47,1 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | exploit_attempt | Q5 | 95 | 31,6 % | SLEPÉ MÍSTO |
| Rodina × pásmo S | lateral_movement | Q1 | 84 | 65,5 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q2 | 79 | 58,2 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q3 | 93 | 62,4 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q4 | 89 | 60,7 % | slabé místo |
| Rodina × pásmo S | lateral_movement | Q5 | 82 | 54,9 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | c2_beacon | tempo 4× | 105 | 59,0 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.25× | 101 | 42,6 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 0.5× | 81 | 37,0 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 1× | 166 | 39,2 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | objem 2× | 95 | 40,0 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 0.5× | 89 | 37,1 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 1× | 185 | 42,7 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 2× | 90 | 36,7 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | tempo 4× | 79 | 39,2 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 1 | 178 | 41,0 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | exploit_attempt | zdroje 3 | 265 | 38,9 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 0.25× | 91 | 59,3 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 0.5× | 87 | 51,7 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 1× | 162 | 66,7 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | objem 2× | 87 | 58,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 0.5× | 66 | 48,5 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 1× | 184 | 48,4 % | SLEPÉ MÍSTO |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | tempo 2× | 88 | 60,2 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | zdroje 1 | 160 | 60,6 % | slabé místo |
| Rodina × osa (tempo, zdroje, objem) | lateral_movement | zdroje 3 | 267 | 60,3 % | slabé místo |
| Souběh útoku s provozní poruchou | s sensor_crash | 505 | 64,8 % | slabé místo |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | c2_beacon | 76 | 27,6 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | exfiltration | 66 | 3,0 % | SLEPÉ MÍSTO |
| LOFO (první útok rodiny, bez signatury, bez vlastních typů) | port_scan_vertical | 60 | 1,7 % | SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | authorized_scanner | 523 | 93,9 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | backup_burst | 1026 | 41,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | backup_failed | 305 | 91,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | batch_job | 311 | 71,1 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | collector_replay | 321 | 80,4 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | dhcp_renumber | 333 | 79,0 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | dns_outage | 354 | 86,2 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | flash_crowd | 1037 | 35,3 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | log_corruption | 240 | 47,9 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | misconfig | 360 | 96,9 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | patch_window | 260 | 92,7 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | sensor_crash | 278 | 33,8 % | FP SLEPÉ MÍSTO |
| Poruchy a lookalike (FP ve frontě podezření) | service_crash | 450 | 66,0 % | FP SLEPÉ MÍSTO |

