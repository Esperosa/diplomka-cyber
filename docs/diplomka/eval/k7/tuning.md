## Krok 7, ladicí seedy 20261701 a 20261801

| rameno | sítí | útoků | detekce mikro | detekce makro | FP/síť-den | zobrazeno/síť-den | zavřeno omylem (G3) | útoky s omylem zavřeným nálezem | omylem zavřených nálezů |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| v3k6 | 80 | 2224 | 78,4 (74,8 až 81,8) | 82,4 (79,0 až 85,3) | 13,1 | 116,6 | 2,5 % (1,8 až 3,5) [33/1320] | 34 | 197 |
| v3k7A | 80 | 2224 | 78,5 (74,9 až 81,9) | 82,6 (79,1 až 85,7) | 13,4 | 118,2 | 2,6 % (1,7 až 3,9) [21/807] | 23 | 144 |
| b1 | 80 | 2224 | 78,5 (74,9 až 81,9) | 82,6 (79,1 až 85,7) | 13,4 | 118,2 | 2,6 % (1,7 až 3,9) [21/807] | 23 | 144 |
| b2 | 80 | 2224 | 80,6 (77,1 až 84,0) | 84,3 (81,1 až 87,2) | 14,1 | 127,7 | 1,4 % (0,8 až 2,3) [14/1031] | 15 | 34 |
| b3a | 80 | 2224 | 78,9 (75,3 až 82,2) | 82,9 (79,4 až 85,9) | 14,2 | 120,5 | 4,0 % (2,8 až 5,6) [31/773] | 16 | 139 |
| b3b | 80 | 2224 | 79,8 (76,2 až 83,3) | 83,8 (80,2 až 86,9) | 13,7 | 137,0 | 4,1 % (2,9 až 5,7) [33/806] | 19 | 132 |
| b4 | 78 | 1788 | 79,8 (75,7 až 83,7) | 83,8 (79,9 až 87,3) | 432,5 | 743,8 | 7,8 % (5,4 až 11,2) [26/332] | 17 | 115 |
| b5 | 80 | 2224 | 78,5 (74,9 až 81,9) | 82,7 (79,1 až 85,7) | 13,4 | 118,1 | 2,6 % (1,7 až 3,9) [21/820] | 23 | 144 |

| rameno | viditelnost po 1. zobrazení | ztráta viditelnosti (příčina: útoků) | habituace | latence medián / p90 (cykly) | chráněných zobrazeno / automaticky zavřeno | ops-only útoky | útoky s provozní anotací |
|---|---:|---|---:|---:|---:|---:|---:|
| v3k6 | 92,1 % | evicted: 1, ladder: 9, quiet: 36 | 109 | 0 / 7 | 0 / 0 | 0 | 0 |
| v3k7A | 93,7 % | ladder: 6, quiet: 31 | 109 | 0 / 6 | 5138 / 0 | 0 | 0 |
| b1 | 93,7 % | ladder: 6, quiet: 31 | 109 | 0 / 6 | 5138 / 0 | 0 | 133 |
| b2 | 95,7 % | evicted: 1, ladder: 4, quiet: 28 | 108 | 0 / 6 | 10525 / 0 | 0 | 0 |
| b3a | 93,6 % | ladder: 4, quiet: 31 | 109 | 0 / 6 | 6025 / 0 | 0 | 0 |
| b3b | 95,2 % | evicted: 1, ladder: 4, quiet: 28 | 108 | 0 / 6 | 15157 / 0 | 0 | 0 |
| b4 | 99,0 % | ladder: 1, quiet: 6 | 80 | 0 / 6 | 339692 / 0 | 0 | 0 |
| b5 | 93,6 % | ladder: 8, quiet: 30 | 109 | 0 / 6 | 5124 / 0 | 0 | 0 |

### Párově proti `v3k6`

| rameno | detekce (p. b.) | FP poměr | zobrazeno poměr | nejhorší rodina n ≥ 100 (p. b.) |
|---|---:|---:|---:|---|
| v3k7A | +0,1 (-0,1 až +0,3) | 1,022 (1,015 až 1,031) | 1,014 (1,010 až 1,020) | c2_beacon -0,5 |
| b1 | +0,1 (-0,1 až +0,3) | 1,022 (1,015 až 1,031) | 1,014 (1,010 až 1,020) | c2_beacon -0,5 |
| b2 | +2,2 (+1,6 až +2,9) | 1,073 (1,036 až 1,125) | 1,095 (1,073 až 1,123) | slow_scan +0,0 |
| b3a | +0,5 (+0,2 až +0,9) | 1,084 (1,059 až 1,121) | 1,034 (1,024 až 1,048) | exploit_attempt -0,4 |
| b3b | +1,4 (+0,8 až +2,0) | 1,041 (1,031 až 1,055) | 1,175 (1,095 až 1,235) | exfiltration +0,0 |
| b4 | +1,4 (+0,7 až +2,3) | 35,695 (19,166 až 54,278) | 7,267 (4,313 až 10,972) | ssh_bruteforce -1,4 |
| b5 | +0,1 (-0,1 až +0,4) | 1,019 (1,012 až 1,030) | 1,013 (1,009 až 1,019) | c2_beacon -0,5 |

### Rodiny

| rodina | n | v3k6 | v3k7A | b1 | b2 | b3a | b3b | b4 | b5 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| apt_chain | 38 | 94,7 % (82,7 až 98,5) | 94,7 % (82,7 až 98,5) | 94,7 % (82,7 až 98,5) | 97,4 % (86,5 až 99,5) | 94,7 % (82,7 až 98,5) | 94,7 % (82,7 až 98,5) | 93,5 % (79,3 až 98,2) | 94,7 % (82,7 až 98,5) |
| c2_beacon | 182 | 72,0 % (65,1 až 78,0) | 71,4 % (64,5 až 77,5) | 71,4 % (64,5 až 77,5) | 74,2 % (67,4 až 80,0) | 74,7 % (67,9 až 80,5) | 72,5 % (65,6 až 78,5) | 70,5 % (62,7 až 77,3) | 71,4 % (64,5 až 77,5) |
| credential_stuffing | 124 | 84,7 % (77,3 až 90,0) | 84,7 % (77,3 až 90,0) | 84,7 % (77,3 až 90,0) | 84,7 % (77,3 až 90,0) | 84,7 % (77,3 až 90,0) | 84,7 % (77,3 až 90,0) | 89,1 % (81,5 až 93,8) | 84,7 % (77,3 až 90,0) |
| cryptomining | 86 | 80,2 % (70,6 až 87,3) | 81,4 % (71,9 až 88,2) | 81,4 % (71,9 až 88,2) | 82,6 % (73,2 až 89,1) | 82,6 % (73,2 až 89,1) | 81,4 % (71,9 až 88,2) | 82,7 % (72,6 až 89,6) | 81,4 % (71,9 až 88,2) |
| ddos_volume | 56 | 87,5 % (76,4 až 93,8) | 87,5 % (76,4 až 93,8) | 87,5 % (76,4 až 93,8) | 87,5 % (76,4 až 93,8) | 87,5 % (76,4 až 93,8) | 87,5 % (76,4 až 93,8) | 88,6 % (76,0 až 95,0) | 87,5 % (76,4 až 93,8) |
| dns_tunnel | 91 | 80,2 % (70,9 až 87,1) | 80,2 % (70,9 až 87,1) | 80,2 % (70,9 až 87,1) | 84,6 % (75,8 až 90,6) | 80,2 % (70,9 až 87,1) | 83,5 % (74,6 až 89,7) | 85,5 % (75,9 až 91,7) | 80,2 % (70,9 až 87,1) |
| exfiltration | 148 | 81,8 % (74,8 až 87,1) | 81,8 % (74,8 až 87,1) | 81,8 % (74,8 až 87,1) | 81,8 % (74,8 až 87,1) | 83,1 % (76,3 až 88,3) | 81,8 % (74,8 až 87,1) | 81,5 % (73,7 až 87,3) | 81,8 % (74,8 až 87,1) |
| exploit_attempt | 233 | 39,5 % (33,4 až 45,9) | 39,5 % (33,4 až 45,9) | 39,5 % (33,4 až 45,9) | 39,9 % (33,8 až 46,3) | 39,1 % (33,0 až 45,4) | 39,5 % (33,4 až 45,9) | 51,1 % (43,9 až 58,2) | 39,5 % (33,4 až 45,9) |
| fleet_beacon | 35 | 71,4 % (54,9 až 83,7) | 74,3 % (57,9 až 85,8) | 74,3 % (57,9 až 85,8) | 74,3 % (57,9 až 85,8) | 74,3 % (57,9 až 85,8) | 80,0 % (64,1 až 90,0) | 77,8 % (59,2 až 89,4) | 74,3 % (57,9 až 85,8) |
| ics_attack | 8 | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) | 87,5 % (52,9 až 97,8) |
| insider_hoarding | 36 | 91,7 % (78,2 až 97,1) | 91,7 % (78,2 až 97,1) | 91,7 % (78,2 až 97,1) | 94,4 % (81,9 až 98,5) | 91,7 % (78,2 až 97,1) | 91,7 % (78,2 až 97,1) | 88,9 % (71,9 až 96,1) | 91,7 % (78,2 až 97,1) |
| lateral_movement | 197 | 67,0 % (60,2 až 73,2) | 67,0 % (60,2 až 73,2) | 67,0 % (60,2 až 73,2) | 82,7 % (76,9 až 87,4) | 67,5 % (60,7 až 73,7) | 76,6 % (70,3 až 82,0) | 66,9 % (59,3 až 73,7) | 67,5 % (60,7 až 73,7) |
| port_scan_horizontal | 155 | 80,0 % (73,0 až 85,5) | 80,6 % (73,7 až 86,1) | 80,6 % (73,7 až 86,1) | 81,9 % (75,1 až 87,2) | 80,6 % (73,7 až 86,1) | 82,6 % (75,8 až 87,7) | 80,0 % (72,1 až 86,1) | 80,6 % (73,7 až 86,1) |
| port_scan_vertical | 195 | 86,7 % (81,2 až 90,7) | 86,7 % (81,2 až 90,7) | 86,7 % (81,2 až 90,7) | 86,7 % (81,2 až 90,7) | 86,7 % (81,2 až 90,7) | 86,7 % (81,2 až 90,7) | 85,8 % (79,4 až 90,4) | 86,7 % (81,2 až 90,7) |
| ransomware | 65 | 100,0 % (94,4 až 100,0) | 100,0 % (94,4 až 100,0) | 100,0 % (94,4 až 100,0) | 100,0 % (94,4 až 100,0) | 100,0 % (94,4 až 100,0) | 100,0 % (94,4 až 100,0) | 100,0 % (92,0 až 100,0) | 100,0 % (94,4 až 100,0) |
| rogue_device | 34 | 97,1 % (85,1 až 99,5) | 97,1 % (85,1 až 99,5) | 97,1 % (85,1 až 99,5) | 97,1 % (85,1 až 99,5) | 97,1 % (85,1 až 99,5) | 97,1 % (85,1 až 99,5) | 100,0 % (86,7 až 100,0) | 97,1 % (85,1 až 99,5) |
| slow_scan | 145 | 88,3 % (82,0 až 92,5) | 88,3 % (82,0 až 92,5) | 88,3 % (82,0 až 92,5) | 88,3 % (82,0 až 92,5) | 88,3 % (82,0 až 92,5) | 89,0 % (82,8 až 93,1) | 87,2 % (80,2 až 92,0) | 88,3 % (82,0 až 92,5) |
| ssh_bruteforce | 263 | 90,1 % (85,9 až 93,2) | 90,1 % (85,9 až 93,2) | 90,1 % (85,9 až 93,2) | 90,9 % (86,8 až 93,8) | 90,1 % (85,9 až 93,2) | 90,1 % (85,9 až 93,2) | 88,7 % (83,7 až 92,3) | 90,1 % (85,9 až 93,2) |
| web_exploit | 133 | 85,7 % (78,8 až 90,7) | 85,7 % (78,8 až 90,7) | 85,7 % (78,8 až 90,7) | 85,7 % (78,8 až 90,7) | 85,7 % (78,8 až 90,7) | 85,7 % (78,8 až 90,7) | 86,9 % (78,8 až 92,2) | 85,7 % (78,8 až 90,7) |

### Poruchy a lookalike (fronta podezření)

| porucha | varianta | n | FP v3k6 | FP v3k7A | FP b1 | FP b2 | FP b3a | FP b3b | FP b4 | FP b5 | položek/výskyt b5 | anotace b5 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| authorized_scanner | - | 235 | 92,8 % (88,7 až 95,4) | 92,8 % (88,7 až 95,4) | 92,8 % (88,7 až 95,4) | 92,8 % (88,7 až 95,4) | 92,8 % (88,7 až 95,4) | 92,8 % (88,7 až 95,4) | 95,4 % (91,5 až 97,6) | 92,8 % (88,7 až 95,4) | 2.37 | 0 |
| backup_burst | - | 462 | 36,8 % (32,5 až 41,3) | 38,1 % (33,8 až 42,6) | 38,1 % (33,8 až 42,6) | 44,8 % (40,3 až 49,4) | 37,4 % (33,2 až 41,9) | 39,6 % (35,3 až 44,1) | 55,2 % (50,2 až 60,1) | 38,1 % (33,8 až 42,6) | 1.15 | 0 |
| backup_failed | - | 79 | 97,5 % (91,2 až 99,3) | 97,5 % (91,2 až 99,3) | 97,5 % (91,2 až 99,3) | 98,7 % (93,2 až 99,8) | 97,5 % (91,2 až 99,3) | 98,7 % (93,2 až 99,8) | 98,5 % (91,9 až 99,7) | 97,5 % (91,2 až 99,3) | 4.30 | 0 |
| batch_job | - | 153 | 74,5 % (67,1 až 80,8) | 75,8 % (68,5 až 81,9) | 75,8 % (68,5 až 81,9) | 83,0 % (76,3 až 88,1) | 75,8 % (68,5 až 81,9) | 76,5 % (69,2 až 82,5) | 75,4 % (67,2 až 82,1) | 75,8 % (68,5 až 81,9) | 5.28 | 0 |
| cert_expired | - | 83 | 90,4 % (82,1 až 95,0) | 90,4 % (82,1 až 95,0) | 90,4 % (82,1 až 95,0) | 92,8 % (85,1 až 96,6) | 90,4 % (82,1 až 95,0) | 90,4 % (82,1 až 95,0) | 100,0 % (94,7 až 100,0) | 90,4 % (82,1 až 95,0) | 2.16 | 0 |
| cloud_migration | - | 77 | 97,4 % (91,0 až 99,3) | 97,4 % (91,0 až 99,3) | 97,4 % (91,0 až 99,3) | 98,7 % (93,0 až 99,8) | 97,4 % (91,0 až 99,3) | 97,4 % (91,0 až 99,3) | 98,5 % (91,8 až 99,7) | 97,4 % (91,0 až 99,3) | 101.45 | 0 |
| collector_replay | - | 149 | 69,8 % (62,0 až 76,6) | 70,5 % (62,7 až 77,2) | 70,5 % (62,7 až 77,2) | 71,8 % (64,1 až 78,4) | 70,5 % (62,7 až 77,2) | 75,8 % (68,4 až 82,0) | 85,0 % (77,8 až 90,2) | 70,5 % (62,7 až 77,2) | 5.07 | 0 |
| device_decommission | - | 99 | 15,2 % (9,4 až 23,5) | 17,2 % (11,0 až 25,8) | 17,2 % (11,0 až 25,8) | 17,2 % (11,0 až 25,8) | 17,2 % (11,0 až 25,8) | 19,2 % (12,6 až 28,0) | 25,8 % (17,9 až 35,8) | 17,2 % (11,0 až 25,8) | 0.29 | 0 |
| device_onboarding | - | 108 | 10,2 % (5,8 až 17,3) | 10,2 % (5,8 až 17,3) | 10,2 % (5,8 až 17,3) | 10,2 % (5,8 až 17,3) | 10,2 % (5,8 až 17,3) | 26,9 % (19,4 až 35,9) | 55,6 % (45,3 až 65,4) | 10,2 % (5,8 až 17,3) | 0.10 | 0 |
| dhcp_renumber | - | 101 | 76,2 % (67,1 až 83,5) | 77,2 % (68,1 až 84,3) | 77,2 % (68,1 až 84,3) | 79,2 % (70,3 až 86,0) | 77,2 % (68,1 až 84,3) | 79,2 % (70,3 až 86,0) | 89,5 % (81,3 až 94,4) | 77,2 % (68,1 až 84,3) | 1.97 | 0 |
| dns_outage | - | 102 | 87,3 % (79,4 až 92,4) | 87,3 % (79,4 až 92,4) | 87,3 % (79,4 až 92,4) | 84,3 % (76,0 až 90,1) | 87,3 % (79,4 až 92,4) | 87,3 % (79,4 až 92,4) | 95,3 % (88,5 až 98,2) | 85,3 % (77,1 až 90,9) | 2.27 | 0 |
| flash_crowd | - | 489 | 41,5 % (37,2 až 45,9) | 41,5 % (37,2 až 45,9) | 41,5 % (37,2 až 45,9) | 44,2 % (39,8 až 48,6) | 41,5 % (37,2 až 45,9) | 43,8 % (39,4 až 48,2) | 75,9 % (71,5 až 79,7) | 41,5 % (37,2 až 45,9) | 1.16 | 0 |
| link_flapping | - | 102 | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 3,6) | 0,0 % (0,0 až 4,1) | 0,0 % (0,0 až 3,6) | 0.00 | 0 |
| log_corruption | - | 118 | 39,8 % (31,5 až 48,8) | 41,5 % (33,0 až 50,5) | 41,5 % (33,0 až 50,5) | 56,8 % (47,8 až 65,4) | 42,4 % (33,8 až 51,4) | 50,8 % (41,9 až 59,7) | 76,1 % (66,4 až 83,6) | 41,5 % (33,0 až 50,5) | 1.12 | 0 |
| misconfig | - | 92 | 94,6 % (87,9 až 97,7) | 94,6 % (87,9 až 97,7) | 94,6 % (87,9 až 97,7) | 94,6 % (87,9 až 97,7) | 94,6 % (87,9 až 97,7) | 94,6 % (87,9 až 97,7) | 94,9 % (87,7 až 98,0) | 94,6 % (87,9 až 97,7) | 19.67 | 0 |
| ntp_fanout | - | 223 | 6,3 % (3,8 až 10,3) | 6,3 % (3,8 až 10,3) | 6,3 % (3,8 až 10,3) | 9,4 % (6,2 až 14,0) | 6,3 % (3,8 až 10,3) | 6,7 % (4,1 až 10,8) | 19,8 % (14,7 až 26,1) | 6,3 % (3,8 až 10,3) | 0.07 | 0 |
| patch_window | - | 102 | 94,1 % (87,8 až 97,3) | 94,1 % (87,8 až 97,3) | 94,1 % (87,8 až 97,3) | 94,1 % (87,8 až 97,3) | 94,1 % (87,8 až 97,3) | 94,1 % (87,8 až 97,3) | 96,6 % (90,3 až 98,8) | 94,1 % (87,8 až 97,3) | 11.99 | 0 |
| retry_storm | - | 134 | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 2,8) | 0,0 % (0,0 až 3,3) | 0,0 % (0,0 až 2,8) | 0.00 | 0 |
| saas_adoption | - | 87 | 69,0 % (58,6 až 77,7) | 69,0 % (58,6 až 77,7) | 69,0 % (58,6 až 77,7) | 74,7 % (64,7 až 82,7) | 70,1 % (59,8 až 78,7) | 74,7 % (64,7 až 82,7) | 79,7 % (68,8 až 87,5) | 69,0 % (58,6 až 77,7) | 3.41 | 0 |
| segment_power_loss | - | 89 | 62,9 % (52,5 až 72,2) | 64,0 % (53,7 až 73,2) | 64,0 % (53,7 až 73,2) | 76,4 % (66,6 až 84,0) | 64,0 % (53,7 až 73,2) | 67,4 % (57,1 až 76,3) | 94,9 % (87,7 až 98,0) | 64,0 % (53,7 až 73,2) | 6.57 | 0 |
| sensor_crash | - | 141 | 19,1 % (13,5 až 26,4) | 7,8 % (4,4 až 13,4) | 7,8 % (4,4 až 13,4) | 7,8 % (4,4 až 13,4) | 7,8 % (4,4 až 13,4) | 7,8 % (4,4 až 13,4) | 6,7 % (3,4 až 12,7) | 7,8 % (4,4 až 13,4) | 0.09 | 0 |
| service_crash | - | 211 | 66,8 % (60,2 až 72,8) | 72,0 % (65,6 až 77,7) | 72,0 % (65,6 až 77,7) | 73,0 % (66,6 až 78,5) | 71,6 % (65,1 až 77,2) | 73,0 % (66,6 až 78,5) | 85,0 % (79,2 až 89,4) | 72,0 % (65,6 až 77,7) | 2.53 | 0 |
| software_update | - | 465 | 1,1 % (0,5 až 2,5) | 1,1 % (0,5 až 2,5) | 1,1 % (0,5 až 2,5) | 1,1 % (0,5 až 2,5) | 1,1 % (0,5 až 2,5) | 1,1 % (0,5 až 2,5) | 1,0 % (0,4 až 2,7) | 1,1 % (0,5 až 2,5) | 0.02 | 0 |
| vpn_reconnect_storm | - | 70 | 88,6 % (79,0 až 94,1) | 88,6 % (79,0 až 94,1) | 88,6 % (79,0 až 94,1) | 88,6 % (79,0 až 94,1) | 88,6 % (79,0 až 94,1) | 88,6 % (79,0 až 94,1) | 91,7 % (81,9 až 96,4) | 88,6 % (79,0 až 94,1) | 3.40 | 0 |

### Kategorie buněk (`b5`)

Buněk celkem 442. Bez korekce: (a) 192, (b) 70, (c) 180. S Holmovou korekcí: (a) 101, (b) 161, (c) 180.

Buňky v (b) s n ≥ 20 (vedené s mírou a mitigací):

| dimenze | buňka | n | detekce (Wilson) | kategorie bez korekce |
|---|---|---:|---:|---|
| rodina | exploit_attempt | 233 | 39,5 % (33,4 až 45,9) | b |
| rodina | lateral_movement | 197 | 67,5 % (60,7 až 73,7) | b |
| rodina | c2_beacon | 182 | 71,4 % (64,5 až 77,5) | a |
| rodina | fleet_beacon | 35 | 74,3 % (57,9 až 85,8) | b |
| rodina × duration | exploit_attempt 2.0 | 68 | 32,4 % (22,4 až 44,2) | b |
| rodina × duration | exploit_attempt 0.5 | 42 | 33,3 % (21,0 až 48,4) | b |
| rodina × duration | exploit_attempt 1.0 | 85 | 44,7 % (34,6 až 55,3) | b |
| rodina × duration | exploit_attempt 4.0 | 38 | 47,4 % (32,5 až 62,7) | b |
| rodina × duration | c2_beacon 0.5 | 33 | 51,5 % (35,2 až 67,5) | b |
| rodina × duration | lateral_movement 1.0 | 83 | 61,4 % (50,7 až 71,2) | b |
| rodina × duration | lateral_movement 0.5 | 39 | 61,5 % (45,9 až 75,1) | b |
| rodina × duration | lateral_movement 2.0 | 37 | 67,6 % (51,5 až 80,4) | b |
| rodina × duration | c2_beacon 1.0 | 73 | 69,9 % (58,6 až 79,2) | b |
| rodina × duration | exfiltration 0.5 | 30 | 70,0 % (52,1 až 83,3) | b |
| rodina × duration | port_scan_horizontal 0.5 | 22 | 72,7 % (51,8 až 86,8) | b |
| rodina × duration | dns_tunnel 1.0 | 43 | 74,4 % (59,8 až 85,1) | b |
| rodina × duration | c2_beacon 2.0 | 36 | 75,0 % (58,9 až 86,2) | b |
| rodina × duration | credential_stuffing 0.5 | 26 | 76,9 % (57,9 až 89,0) | b |
| rodina × duration | port_scan_horizontal 1.0 | 66 | 77,3 % (65,8 až 85,7) | a |
| rodina × duration | web_exploit 1.0 | 51 | 78,4 % (65,4 až 87,5) | a |
| rodina × duration | port_scan_horizontal 2.0 | 28 | 78,6 % (60,5 až 89,8) | a |
| rodina × duration | exfiltration 1.0 | 66 | 80,3 % (69,2 až 88,1) | a |
| rodina × duration | port_scan_vertical 0.5 | 46 | 80,4 % (66,8 až 89,3) | a |
| rodina × duration | port_scan_vertical 1.0 | 67 | 80,6 % (69,6 až 88,3) | a |
| rodina × duration | slow_scan 0.5 | 22 | 81,8 % (61,5 až 92,7) | a |
| rodina × duration | slow_scan 1.0 | 55 | 81,8 % (69,7 až 89,8) | a |
| rodina × duration | credential_stuffing 2.0 | 23 | 82,6 % (62,9 až 93,0) | a |
| rodina × duration | cryptomining 1.0 | 35 | 82,9 % (67,3 až 91,9) | a |
| rodina × duration | credential_stuffing 4.0 | 25 | 84,0 % (65,3 až 93,6) | a |
| rodina × duration | web_exploit 0.5 | 27 | 85,2 % (67,5 až 94,1) | a |
| rodina × duration | exfiltration 4.0 | 21 | 85,7 % (65,4 až 95,0) | a |
| rodina × duration | lateral_movement 4.0 | 38 | 86,8 % (72,7 až 94,2) | a |
| rodina × duration | ddos_volume 1.0 | 23 | 87,0 % (67,9 až 95,5) | a |
| rodina × duration | dns_tunnel 4.0 | 20 | 90,0 % (69,9 až 97,2) | a |
| rodina × duration | cryptomining 4.0 | 22 | 90,9 % (72,2 až 97,5) | a |
| rodina × duration | web_exploit 4.0 | 22 | 95,5 % (78,2 až 99,2) | a |
| rodina × jitter | exploit_attempt 0.15 | 56 | 33,9 % (22,9 až 47,0) | b |
| rodina × jitter | exploit_attempt 0.5 | 44 | 38,6 % (25,7 až 53,4) | b |
| rodina × jitter | exploit_attempt 0.0 | 81 | 40,7 % (30,7 až 51,6) | b |
| rodina × jitter | exploit_attempt 0.3 | 52 | 44,2 % (31,6 až 57,7) | b |
| rodina × jitter | c2_beacon 0.5 | 35 | 45,7 % (30,5 až 61,8) | b |
| rodina × jitter | lateral_movement 0.15 | 43 | 65,1 % (50,2 až 77,6) | b |
| rodina × jitter | lateral_movement 0.3 | 48 | 66,7 % (52,5 až 78,3) | b |
| rodina × jitter | lateral_movement 0.5 | 37 | 67,6 % (51,5 až 80,4) | b |
| rodina × jitter | lateral_movement 0.0 | 69 | 69,6 % (57,9 až 79,2) | b |
| rodina × jitter | cryptomining 0.15 | 21 | 71,4 % (50,0 až 86,2) | b |
| rodina × jitter | port_scan_horizontal 0.3 | 26 | 73,1 % (53,9 až 86,3) | b |
| rodina × jitter | port_scan_horizontal 0.5 | 27 | 74,1 % (55,3 až 86,8) | b |
| rodina × jitter | web_exploit 0.15 | 35 | 74,3 % (57,9 až 85,8) | b |
| rodina × jitter | exfiltration 0.3 | 28 | 75,0 % (56,6 až 87,3) | b |
| rodina × jitter | c2_beacon 0.0 | 77 | 76,6 % (66,0 až 84,7) | a |
| rodina × jitter | c2_beacon 0.15 | 36 | 77,8 % (61,9 až 88,3) | a |
| rodina × jitter | credential_stuffing 0.0 | 46 | 78,3 % (64,4 až 87,7) | a |
| rodina × jitter | dns_tunnel 0.0 | 37 | 78,4 % (62,8 až 88,6) | a |
| rodina × jitter | port_scan_horizontal 0.15 | 28 | 78,6 % (60,5 až 89,8) | a |
| rodina × jitter | c2_beacon 0.3 | 34 | 79,4 % (63,2 až 89,7) | a |
| rodina × jitter | cryptomining 0.0 | 34 | 79,4 % (63,2 až 89,7) | a |
| rodina × jitter | exfiltration 0.15 | 30 | 80,0 % (62,7 až 90,5) | a |
| rodina × jitter | exfiltration 0.0 | 64 | 81,2 % (70,0 až 88,9) | a |
| rodina × jitter | dns_tunnel 0.15 | 23 | 82,6 % (62,9 až 93,0) | a |
| rodina × jitter | port_scan_vertical 0.3 | 42 | 83,3 % (69,4 až 91,7) | a |
| rodina × jitter | port_scan_vertical 0.15 | 37 | 83,8 % (68,9 až 92,3) | a |
| rodina × jitter | credential_stuffing 0.5 | 26 | 84,6 % (66,5 až 93,8) | a |
| rodina × jitter | ddos_volume 0.0 | 29 | 86,2 % (69,4 až 94,5) | a |
| rodina × jitter | slow_scan 0.15 | 30 | 86,7 % (70,3 až 94,7) | a |
| rodina × jitter | credential_stuffing 0.15 | 25 | 88,0 % (70,0 až 95,8) | a |
| rodina × jitter | slow_scan 0.3 | 27 | 88,9 % (71,9 až 96,1) | a |
| rodina × jitter | web_exploit 0.3 | 24 | 91,7 % (74,2 až 97,7) | a |
| rodina × jitter | exfiltration 0.5 | 26 | 92,3 % (75,9 až 97,9) | a |
| rodina × jitter | credential_stuffing 0.3 | 27 | 92,6 % (76,6 až 97,9) | a |
| rodina × sources | exploit_attempt 10 | 68 | 35,3 % (25,0 až 47,2) | b |
| rodina × sources | exploit_attempt 1 | 95 | 41,1 % (31,7 až 51,1) | b |
| rodina × sources | exploit_attempt 3 | 70 | 41,4 % (30,6 až 53,1) | b |
| rodina × sources | lateral_movement 3 | 68 | 61,8 % (49,9 až 72,4) | b |
| rodina × sources | dns_tunnel 10 | 24 | 62,5 % (42,7 až 78,8) | b |
| rodina × sources | cryptomining 10 | 23 | 65,2 % (44,9 až 81,2) | b |
| rodina × sources | c2_beacon 10 | 52 | 69,2 % (55,7 až 80,1) | b |
| rodina × sources | lateral_movement 10 | 61 | 70,5 % (58,1 až 80,4) | b |
| rodina × sources | c2_beacon 3 | 51 | 70,6 % (57,0 až 81,3) | b |
| rodina × sources | lateral_movement 1 | 68 | 70,6 % (58,9 až 80,1) | b |
| rodina × sources | c2_beacon 1 | 79 | 73,4 % (62,8 až 81,9) | a |
| rodina × sources | slow_scan 10 | 45 | 75,6 % (61,3 až 85,8) | a |
| rodina × sources | exfiltration 1 | 68 | 76,5 % (65,1 až 85,0) | a |
| rodina × sources | credential_stuffing 3 | 34 | 79,4 % (63,2 až 89,7) | a |
| rodina × sources | port_scan_horizontal 10 | 59 | 79,7 % (67,7 až 88,0) | a |
| rodina × sources | port_scan_horizontal 1 | 52 | 80,8 % (68,1 až 89,2) | a |
| rodina × sources | web_exploit 10 | 37 | 81,1 % (65,8 až 90,5) | a |
| rodina × sources | port_scan_vertical 3 | 54 | 81,5 % (69,2 až 89,6) | a |
| rodina × sources | port_scan_horizontal 3 | 44 | 81,8 % (68,0 až 90,5) | a |
| rodina × sources | exfiltration 3 | 37 | 83,8 % (68,9 až 92,3) | a |
| rodina × sources | dns_tunnel 3 | 28 | 85,7 % (68,5 až 94,3) | a |
| rodina × sources | credential_stuffing 10 | 43 | 86,0 % (72,7 až 93,4) | a |
| rodina × sources | cryptomining 3 | 30 | 86,7 % (70,3 až 94,7) | a |
| rodina × sources | dns_tunnel 1 | 39 | 87,2 % (73,3 až 94,4) | a |
| rodina × sources | cryptomining 1 | 33 | 87,9 % (72,7 až 95,2) | a |
| rodina × sources | ddos_volume 1 | 27 | 92,6 % (76,6 až 97,9) | a |
| rodina × tempo | exploit_attempt 0.25 | 27 | 25,9 % (13,2 až 44,7) | b |
| rodina × tempo | exploit_attempt 2.0 | 26 | 30,8 % (16,5 až 50,0) | b |
| rodina × tempo | c2_beacon 8.0 | 26 | 34,6 % (19,4 až 53,8) | b |
| rodina × tempo | exploit_attempt 1.0 | 91 | 37,4 % (28,1 až 47,6) | b |
| rodina × tempo | exploit_attempt 8.0 | 29 | 44,8 % (28,4 až 62,5) | b |
| rodina × tempo | exploit_attempt 4.0 | 38 | 50,0 % (34,8 až 65,2) | b |
| rodina × tempo | exploit_attempt 0.5 | 22 | 50,0 % (30,7 až 69,3) | b |
| rodina × tempo | lateral_movement 1.0 | 82 | 56,1 % (45,3 až 66,3) | b |
| rodina × tempo | dns_tunnel 1.0 | 35 | 68,6 % (52,0 až 81,4) | b |
| rodina × tempo | lateral_movement 2.0 | 32 | 68,8 % (51,4 až 82,0) | b |
| rodina × tempo | c2_beacon 2.0 | 27 | 70,4 % (51,5 až 84,1) | b |
| rodina × tempo | port_scan_horizontal 0.5 | 27 | 74,1 % (55,3 až 86,8) | b |
| rodina × tempo | exfiltration 0.25 | 20 | 75,0 % (53,1 až 88,8) | b |
| rodina × tempo | c2_beacon 1.0 | 68 | 76,5 % (65,1 až 85,0) | a |
| rodina × tempo | exfiltration 1.0 | 64 | 76,6 % (64,9 až 85,3) | a |
| rodina × tempo | port_scan_horizontal 1.0 | 58 | 77,6 % (65,3 až 86,4) | a |
| rodina × tempo | slow_scan 1.0 | 50 | 78,0 % (64,8 až 87,2) | a |
| rodina × tempo | port_scan_horizontal 0.25 | 25 | 80,0 % (60,9 až 91,1) | a |
| rodina × tempo | cryptomining 1.0 | 37 | 81,1 % (65,8 až 90,5) | a |
| rodina × tempo | cryptomining 0.25 | 22 | 81,8 % (61,5 až 92,7) | a |
| rodina × tempo | port_scan_vertical 0.25 | 28 | 82,1 % (64,4 až 92,1) | a |
| rodina × tempo | ssh_bruteforce 8.0 | 29 | 82,8 % (65,5 až 92,4) | a |
| rodina × tempo | ssh_bruteforce 0.25 | 35 | 82,9 % (67,3 až 91,9) | a |
| rodina × tempo | port_scan_vertical 0.5 | 27 | 85,2 % (67,5 až 94,1) | a |
| rodina × tempo | c2_beacon 0.25 | 28 | 89,3 % (72,8 až 96,3) | a |
| rodina × tempo | port_scan_vertical 2.0 | 22 | 90,9 % (72,2 až 97,5) | a |
| rodina × tempo | port_scan_vertical 4.0 | 25 | 92,0 % (75,0 až 97,8) | a |
| rodina × tempo | credential_stuffing 2.0 | 21 | 95,2 % (77,3 až 99,2) | a |
| rodina × volume | exploit_attempt 1.0 | 103 | 33,0 % (24,7 až 42,6) | b |
| rodina × volume | exploit_attempt 2.0 | 40 | 35,0 % (22,1 až 50,5) | b |
| rodina × volume | exploit_attempt 0.5 | 43 | 48,8 % (34,6 až 63,2) | b |
| rodina × volume | exploit_attempt 0.25 | 47 | 48,9 % (35,3 až 62,8) | b |
| rodina × volume | lateral_movement 0.5 | 32 | 65,6 % (48,3 až 79,6) | b |
| rodina × volume | lateral_movement 1.0 | 85 | 65,9 % (55,3 až 75,1) | b |
| rodina × volume | lateral_movement 2.0 | 39 | 66,7 % (51,0 až 79,4) | b |
| rodina × volume | c2_beacon 2.0 | 26 | 69,2 % (50,0 až 83,5) | b |
| rodina × volume | c2_beacon 0.5 | 49 | 69,4 % (55,5 až 80,5) | b |
| rodina × volume | c2_beacon 1.0 | 79 | 70,9 % (60,1 až 79,7) | a |
| rodina × volume | lateral_movement 0.25 | 41 | 73,2 % (58,1 až 84,3) | b |
| rodina × volume | port_scan_horizontal 2.0 | 30 | 73,3 % (55,6 až 85,8) | b |
| rodina × volume | port_scan_vertical 0.25 | 34 | 73,5 % (56,9 až 85,4) | b |
| rodina × volume | port_scan_horizontal 1.0 | 53 | 77,4 % (64,5 až 86,5) | a |
| rodina × volume | web_exploit 0.25 | 27 | 77,8 % (59,2 až 89,4) | b |
| rodina × volume | cryptomining 0.5 | 23 | 78,3 % (58,1 až 90,3) | b |
| rodina × volume | cryptomining 2.0 | 23 | 78,3 % (58,1 až 90,3) | b |
| rodina × volume | dns_tunnel 0.25 | 23 | 78,3 % (58,1 až 90,3) | b |
| rodina × volume | c2_beacon 0.25 | 28 | 78,6 % (60,5 až 89,8) | a |
| rodina × volume | exfiltration 0.5 | 35 | 80,0 % (64,1 až 90,0) | a |
| rodina × volume | exfiltration 2.0 | 26 | 80,8 % (62,1 až 91,5) | a |
| rodina × volume | web_exploit 2.0 | 26 | 80,8 % (62,1 až 91,5) | a |
| rodina × volume | slow_scan 2.0 | 22 | 81,8 % (61,5 až 92,7) | a |
| rodina × volume | exfiltration 1.0 | 55 | 81,8 % (69,7 až 89,8) | a |
| rodina × volume | credential_stuffing 1.0 | 45 | 82,2 % (68,7 až 90,7) | a |
| rodina × volume | ssh_bruteforce 0.25 | 52 | 82,7 % (70,3 až 90,6) | a |
| rodina × volume | credential_stuffing 2.0 | 24 | 83,3 % (64,1 až 93,3) | a |
| rodina × volume | port_scan_horizontal 0.25 | 38 | 84,2 % (69,6 až 92,6) | a |
| rodina × volume | exfiltration 0.25 | 32 | 84,4 % (68,2 až 93,1) | a |
| rodina × volume | slow_scan 0.5 | 27 | 85,2 % (67,5 až 94,1) | a |
| rodina × volume | credential_stuffing 0.25 | 30 | 86,7 % (70,3 až 94,7) | a |
| rodina × volume | credential_stuffing 0.5 | 25 | 88,0 % (70,0 až 95,8) | a |
| rodina × volume | port_scan_vertical 0.5 | 34 | 88,2 % (73,4 až 95,3) | a |
| rodina × volume | port_scan_horizontal 0.5 | 34 | 88,2 % (73,4 až 95,3) | a |
| rodina × volume | cryptomining 1.0 | 30 | 90,0 % (74,4 až 96,5) | a |
| rodina × volume | slow_scan 0.25 | 23 | 91,3 % (73,2 až 97,6) | a |
| rodina × volume | web_exploit 0.5 | 23 | 91,3 % (73,2 až 97,6) | a |

