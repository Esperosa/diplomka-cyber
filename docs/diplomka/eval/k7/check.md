## Krok 7, kontrola sestavy na seedech 20261401 a 20261501

| rameno | sítí | útoků | detekce mikro | detekce makro | FP/síť-den | zobrazeno/síť-den | zavřeno omylem (G3) | útoky s omylem zavřeným nálezem | omylem zavřených nálezů |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| v3k6 | 80 | 2858 | 78,8 (75,8 až 82,0) | 81,4 (79,2 až 84,4) | 14,7 | 106,0 | 1,4 % (1,0 až 2,0) [29/2083] | 27 | 30 |
| v3k7 | 80 | 2858 | 81,0 (77,9 až 84,0) | 83,2 (80,9 až 86,0) | 16,3 | 133,4 | 1,2 % (0,7 až 2,2) [12/962] | 16 | 16 |

| rameno | viditelnost po 1. zobrazení | ztráta viditelnosti (příčina: útoků) | habituace | latence medián / p90 (cykly) | chráněných zobrazeno / automaticky zavřeno | ops-only útoky | útoky s provozní anotací |
|---|---:|---|---:|---:|---:|---:|---:|
| v3k6 | 96,7 % | context: 1, ladder: 13, quiet: 51 | 139 | 0 / 7 | 0 / 0 | 0 | 0 |
| v3k7 | 98,6 % | ladder: 4, quiet: 35 | 128 | 0 / 5 | 25645 / 0 | 0 | 0 |

### Párově proti `v3k6`

| rameno | detekce (p. b.) | FP poměr | zobrazeno poměr | nejhorší rodina n ≥ 100 (p. b.) |
|---|---:|---:|---:|---|
| v3k7 | +2,1 (+1,5 až +2,8) | 1,106 (1,063 až 1,187) | 1,258 (1,175 až 1,327) | port_scan_vertical +0,0 |

### Rodiny

| rodina | n | v3k6 | v3k7 |
|---|---:|---:|---:|
| apt_chain | 59 | 100,0 % (93,9 až 100,0) | 100,0 % (93,9 až 100,0) |
| c2_beacon | 262 | 64,5 % (58,5 až 70,1) | 67,6 % (61,7 až 72,9) |
| credential_stuffing | 159 | 79,2 % (72,3 až 84,8) | 81,8 % (75,0 až 87,0) |
| cryptomining | 125 | 81,6 % (73,9 až 87,4) | 81,6 % (73,9 až 87,4) |
| ddos_volume | 83 | 85,5 % (76,4 až 91,5) | 85,5 % (76,4 až 91,5) |
| dns_tunnel | 117 | 79,5 % (71,3 až 85,8) | 83,8 % (76,0 až 89,4) |
| exfiltration | 206 | 85,0 % (79,4 až 89,2) | 85,4 % (80,0 až 89,6) |
| exploit_attempt | 271 | 50,6 % (44,6 až 56,5) | 50,9 % (45,0 až 56,8) |
| fleet_beacon | 34 | 76,5 % (60,0 až 87,6) | 79,4 % (63,2 až 89,7) |
| ics_attack | 3 | 66,7 % (20,8 až 93,9) | 66,7 % (20,8 až 93,9) |
| insider_hoarding | 53 | 92,5 % (82,1 až 97,0) | 94,3 % (84,6 až 98,1) |
| lateral_movement | 239 | 71,1 % (65,1 až 76,5) | 83,7 % (78,5 až 87,8) |
| port_scan_horizontal | 194 | 82,0 % (75,9 až 86,7) | 83,0 % (77,1 až 87,6) |
| port_scan_vertical | 233 | 82,8 % (77,5 až 87,1) | 82,8 % (77,5 až 87,1) |
| ransomware | 82 | 97,6 % (91,5 až 99,3) | 96,3 % (89,8 až 98,7) |
| rogue_device | 63 | 95,2 % (86,9 až 98,4) | 96,8 % (89,1 až 99,1) |
| slow_scan | 202 | 84,2 % (78,5 až 88,5) | 87,6 % (82,4 až 91,5) |
| ssh_bruteforce | 285 | 90,5 % (86,6 až 93,4) | 90,9 % (87,0 až 93,7) |
| web_exploit | 188 | 81,9 % (75,8 až 86,8) | 81,9 % (75,8 až 86,8) |

### Poruchy a lookalike (fronta podezření)

| porucha | varianta | n | FP v3k6 | FP v3k7 | položek/výskyt v3k7 | anotace v3k7 |
|---|---|---:|---:|---:|---:|---:|
| authorized_scanner | - | 273 | 92,7 % (89,0 až 95,2) | 93,0 % (89,4 až 95,5) | 2.24 | 0 |
| backup_burst | - | 667 | 39,3 % (35,6 až 43,0) | 46,2 % (42,4 až 50,0) | 1.78 | 0 |
| backup_failed | - | 99 | 83,8 % (75,3 až 89,8) | 84,8 % (76,5 až 90,6) | 3.75 | 0 |
| batch_job | - | 169 | 66,9 % (59,5 až 73,5) | 77,5 % (70,6 až 83,2) | 9.70 | 0 |
| cert_expired | - | 112 | 90,2 % (83,3 až 94,4) | 96,4 % (91,2 až 98,6) | 15.38 | 0 |
| cloud_migration | - | 108 | 93,5 % (87,2 až 96,8) | 94,4 % (88,4 až 97,4) | 121.42 | 0 |
| collector_replay | - | 212 | 69,8 % (63,3 až 75,6) | 75,5 % (69,3 až 80,8) | 19.51 | 0 |
| device_decommission | - | 124 | 17,7 % (12,0 až 25,4) | 22,6 % (16,1 až 30,7) | 0.47 | 0 |
| device_onboarding | - | 130 | 20,8 % (14,7 až 28,5) | 34,6 % (27,0 až 43,1) | 0.55 | 0 |
| dhcp_renumber | - | 105 | 72,4 % (63,2 až 80,0) | 77,1 % (68,2 až 84,1) | 2.53 | 0 |
| dns_outage | - | 112 | 89,3 % (82,2 až 93,8) | 92,9 % (86,5 až 96,3) | 2.54 | 0 |
| flash_crowd | - | 618 | 40,9 % (37,1 až 44,9) | 46,9 % (43,0 až 50,9) | 1.46 | 0 |
| link_flapping | - | 123 | 0,0 % (0,0 až 3,0) | 0,0 % (0,0 až 3,0) | 0.00 | 0 |
| log_corruption | - | 148 | 42,6 % (34,9 až 50,6) | 68,2 % (60,4 až 75,2) | 5.47 | 0 |
| misconfig | - | 109 | 94,5 % (88,5 až 97,5) | 94,5 % (88,5 až 97,5) | 19.93 | 0 |
| ntp_fanout | - | 335 | 6,0 % (3,9 až 9,0) | 9,9 % (7,1 až 13,5) | 0.27 | 0 |
| patch_window | - | 143 | 88,1 % (81,8 až 92,4) | 88,1 % (81,8 až 92,4) | 10.83 | 0 |
| retry_storm | - | 182 | 0,0 % (0,0 až 2,1) | 0,0 % (0,0 až 2,1) | 0.00 | 0 |
| saas_adoption | - | 104 | 83,7 % (75,4 až 89,5) | 87,5 % (79,8 až 92,5) | 7.58 | 0 |
| segment_power_loss | - | 141 | 57,4 % (49,2 až 65,3) | 73,8 % (65,9 až 80,3) | 8.13 | 0 |
| sensor_crash | - | 203 | 19,2 % (14,4 až 25,2) | 12,3 % (8,5 až 17,5) | 0.16 | 0 |
| service_crash | - | 312 | 56,7 % (51,2 až 62,1) | 62,5 % (57,0 až 67,7) | 2.13 | 0 |
| software_update | - | 635 | 1,4 % (0,7 až 2,7) | 1,4 % (0,7 až 2,7) | 0.02 | 0 |
| vpn_reconnect_storm | - | 84 | 88,1 % (79,5 až 93,4) | 89,3 % (80,9 až 94,3) | 3.62 | 0 |

### Kategorie buněk (`v3k7`)

Buněk celkem 435. Bez korekce: (a) 244, (b) 68, (c) 123. S Holmovou korekcí: (a) 146, (b) 166, (c) 123.

Buňky v (b) s n ≥ 20 (vedené s mírou a mitigací):

| dimenze | buňka | n | detekce (Wilson) | kategorie bez korekce |
|---|---|---:|---:|---|
| rodina | exploit_attempt | 271 | 50,9 % (45,0 až 56,8) | b |
| rodina | c2_beacon | 262 | 67,6 % (61,7 až 72,9) | b |
| rodina | fleet_beacon | 34 | 79,4 % (63,2 až 89,7) | a |
| rodina × duration | exploit_attempt 0.5 | 48 | 33,3 % (21,7 až 47,5) | b |
| rodina × duration | c2_beacon 0.5 | 51 | 39,2 % (27,0 až 52,9) | b |
| rodina × duration | exploit_attempt 1.0 | 100 | 53,0 % (43,3 až 62,5) | b |
| rodina × duration | exploit_attempt 4.0 | 69 | 53,6 % (42,0 až 64,9) | b |
| rodina × duration | exploit_attempt 2.0 | 54 | 59,3 % (46,0 až 71,3) | b |
| rodina × duration | credential_stuffing 0.5 | 30 | 63,3 % (45,5 až 78,1) | b |
| rodina × duration | dns_tunnel 0.5 | 31 | 67,7 % (50,1 až 81,4) | b |
| rodina × duration | c2_beacon 1.0 | 92 | 68,5 % (58,4 až 77,1) | b |
| rodina × duration | slow_scan 0.5 | 30 | 70,0 % (52,1 až 83,3) | b |
| rodina × duration | lateral_movement 0.5 | 36 | 72,2 % (56,0 až 84,2) | b |
| rodina × duration | web_exploit 0.5 | 35 | 74,3 % (57,9 až 85,8) | b |
| rodina × duration | c2_beacon 2.0 | 63 | 74,6 % (62,7 až 83,7) | a |
| rodina × duration | cryptomining 2.0 | 20 | 75,0 % (53,1 až 88,8) | b |
| rodina × duration | cryptomining 0.5 | 21 | 76,2 % (54,9 až 89,4) | b |
| rodina × duration | port_scan_vertical 2.0 | 41 | 78,0 % (63,3 až 88,0) | a |
| rodina × duration | port_scan_horizontal 1.0 | 80 | 78,8 % (68,6 až 86,3) | a |
| rodina × duration | ddos_volume 1.0 | 35 | 80,0 % (64,1 až 90,0) | a |
| rodina × duration | cryptomining 1.0 | 62 | 80,6 % (69,1 až 88,6) | a |
| rodina × duration | port_scan_horizontal 2.0 | 38 | 81,6 % (66,6 až 90,8) | a |
| rodina × duration | ssh_bruteforce 2.0 | 56 | 82,1 % (70,2 až 90,0) | a |
| rodina × duration | port_scan_vertical 0.5 | 45 | 82,2 % (68,7 až 90,7) | a |
| rodina × duration | port_scan_horizontal 0.5 | 34 | 82,4 % (66,5 až 91,7) | a |
| rodina × duration | exfiltration 0.5 | 34 | 82,4 % (66,5 až 91,7) | a |
| rodina × duration | web_exploit 2.0 | 35 | 82,9 % (67,3 až 91,9) | a |
| rodina × duration | credential_stuffing 4.0 | 30 | 83,3 % (66,4 až 92,7) | a |
| rodina × duration | dns_tunnel 4.0 | 26 | 84,6 % (66,5 až 93,8) | a |
| rodina × duration | web_exploit 4.0 | 43 | 86,0 % (72,7 až 93,4) | a |
| rodina × duration | exfiltration 2.0 | 38 | 86,8 % (72,7 až 94,2) | a |
| rodina × duration | credential_stuffing 2.0 | 35 | 88,6 % (74,0 až 95,5) | a |
| rodina × duration | dns_tunnel 2.0 | 23 | 91,3 % (73,2 až 97,6) | a |
| rodina × duration | insider_hoarding 1.0 | 20 | 95,0 % (76,4 až 99,1) | a |
| rodina × duration | cryptomining 4.0 | 22 | 95,5 % (78,2 až 99,2) | a |
| rodina × jitter | exploit_attempt 0.0 | 101 | 43,6 % (34,3 až 53,3) | b |
| rodina × jitter | exploit_attempt 0.5 | 50 | 52,0 % (38,5 až 65,2) | b |
| rodina × jitter | c2_beacon 0.5 | 58 | 53,4 % (40,8 až 65,7) | b |
| rodina × jitter | exploit_attempt 0.3 | 64 | 54,7 % (42,6 až 66,3) | b |
| rodina × jitter | exploit_attempt 0.15 | 56 | 58,9 % (45,9 až 70,8) | b |
| rodina × jitter | cryptomining 0.5 | 22 | 59,1 % (38,7 až 76,7) | b |
| rodina × jitter | c2_beacon 0.15 | 50 | 62,0 % (48,2 až 74,1) | b |
| rodina × jitter | c2_beacon 0.3 | 43 | 62,8 % (47,9 až 75,6) | b |
| rodina × jitter | credential_stuffing 0.15 | 25 | 68,0 % (48,4 až 82,8) | b |
| rodina × jitter | ddos_volume 0.5 | 20 | 75,0 % (53,1 až 88,8) | b |
| rodina × jitter | dns_tunnel 0.15 | 29 | 75,9 % (57,9 až 87,8) | b |
| rodina × jitter | port_scan_horizontal 0.3 | 42 | 76,2 % (61,5 až 86,5) | a |
| rodina × jitter | web_exploit 0.3 | 38 | 76,3 % (60,8 až 87,0) | a |
| rodina × jitter | dns_tunnel 0.3 | 26 | 76,9 % (57,9 až 89,0) | b |
| rodina × jitter | web_exploit 0.5 | 40 | 77,5 % (62,5 až 87,7) | a |
| rodina × jitter | exfiltration 0.3 | 41 | 78,0 % (63,3 až 88,0) | a |
| rodina × jitter | lateral_movement 0.15 | 54 | 79,6 % (67,1 až 88,2) | a |
| rodina × jitter | credential_stuffing 0.3 | 36 | 80,6 % (65,0 až 90,2) | a |
| rodina × jitter | credential_stuffing 0.5 | 43 | 81,4 % (67,4 až 90,3) | a |
| rodina × jitter | port_scan_vertical 0.5 | 54 | 81,5 % (69,2 až 89,6) | a |
| rodina × jitter | lateral_movement 0.5 | 45 | 82,2 % (68,7 až 90,7) | a |
| rodina × jitter | web_exploit 0.15 | 35 | 82,9 % (67,3 až 91,9) | a |
| rodina × jitter | port_scan_horizontal 0.15 | 41 | 82,9 % (68,7 až 91,5) | a |
| rodina × jitter | lateral_movement 0.3 | 53 | 83,0 % (70,8 až 90,8) | a |
| rodina × jitter | cryptomining 0.3 | 24 | 83,3 % (64,1 až 93,3) | a |
| rodina × jitter | port_scan_vertical 0.15 | 32 | 84,4 % (68,2 až 93,1) | a |
| rodina × jitter | exfiltration 0.5 | 40 | 85,0 % (70,9 až 92,9) | a |
| rodina × jitter | ddos_volume 0.0 | 31 | 87,1 % (71,1 až 94,9) | a |
| rodina × jitter | port_scan_horizontal 0.5 | 33 | 87,9 % (72,7 až 95,2) | a |
| rodina × jitter | insider_hoarding 0.0 | 21 | 90,5 % (71,1 až 97,3) | a |
| rodina × jitter | cryptomining 0.15 | 24 | 91,7 % (74,2 až 97,7) | a |
| rodina × jitter | rogue_device 0.0 | 20 | 95,0 % (76,4 až 99,1) | a |
| rodina × sources | exploit_attempt 10 | 69 | 47,8 % (36,5 až 59,4) | b |
| rodina × sources | exploit_attempt 1 | 122 | 51,6 % (42,9 až 60,3) | b |
| rodina × sources | exploit_attempt 3 | 80 | 52,5 % (41,7 až 63,1) | b |
| rodina × sources | dns_tunnel 10 | 42 | 64,3 % (49,2 až 77,0) | b |
| rodina × sources | c2_beacon 10 | 93 | 64,5 % (54,4 až 73,5) | b |
| rodina × sources | cryptomining 10 | 41 | 65,9 % (50,5 až 78,4) | b |
| rodina × sources | c2_beacon 1 | 97 | 66,0 % (56,1 až 74,6) | b |
| rodina × sources | c2_beacon 3 | 72 | 73,6 % (62,4 až 82,4) | a |
| rodina × sources | exfiltration 1 | 96 | 75,0 % (65,5 až 82,6) | a |
| rodina × sources | port_scan_horizontal 10 | 56 | 76,8 % (64,2 až 85,9) | a |
| rodina × sources | slow_scan 10 | 65 | 76,9 % (65,4 až 85,5) | a |
| rodina × sources | port_scan_vertical 10 | 61 | 77,0 % (65,1 až 85,8) | a |
| rodina × sources | web_exploit 3 | 58 | 77,6 % (65,3 až 86,4) | a |
| rodina × sources | credential_stuffing 3 | 52 | 78,8 % (66,0 až 87,8) | a |
| rodina × sources | web_exploit 10 | 53 | 79,2 % (66,5 až 88,0) | a |
| rodina × sources | credential_stuffing 1 | 63 | 81,0 % (69,6 až 88,8) | a |
| rodina × sources | ddos_volume 1 | 32 | 84,4 % (68,2 až 93,1) | a |
| rodina × sources | ddos_volume 3 | 26 | 84,6 % (66,5 až 93,8) | a |
| rodina × sources | cryptomining 3 | 39 | 87,2 % (73,3 až 94,4) | a |
| rodina × sources | ddos_volume 10 | 25 | 88,0 % (70,0 až 95,8) | a |
| rodina × sources | ransomware 10 | 22 | 95,5 % (78,2 až 99,2) | a |
| rodina × sources | insider_hoarding 1 | 22 | 95,5 % (78,2 až 99,2) | a |
| rodina × tempo | exploit_attempt 8.0 | 31 | 38,7 % (23,7 až 56,2) | b |
| rodina × tempo | exploit_attempt 4.0 | 29 | 41,4 % (25,5 až 59,3) | b |
| rodina × tempo | exploit_attempt 1.0 | 105 | 45,7 % (36,5 až 55,2) | b |
| rodina × tempo | c2_beacon 8.0 | 39 | 46,2 % (31,6 až 61,4) | b |
| rodina × tempo | c2_beacon 4.0 | 38 | 50,0 % (34,8 až 65,2) | b |
| rodina × tempo | c2_beacon 2.0 | 22 | 54,5 % (34,7 až 73,1) | b |
| rodina × tempo | exploit_attempt 0.25 | 32 | 59,4 % (42,3 až 74,5) | b |
| rodina × tempo | exfiltration 0.5 | 20 | 60,0 % (38,7 až 78,1) | b |
| rodina × tempo | exploit_attempt 0.5 | 38 | 60,5 % (44,7 až 74,4) | b |
| rodina × tempo | port_scan_horizontal 2.0 | 26 | 61,5 % (42,5 až 77,6) | b |
| rodina × tempo | credential_stuffing 0.5 | 21 | 61,9 % (40,9 až 79,2) | b |
| rodina × tempo | web_exploit 0.25 | 29 | 62,1 % (44,0 až 77,3) | b |
| rodina × tempo | exploit_attempt 2.0 | 36 | 66,7 % (50,3 až 79,8) | b |
| rodina × tempo | cryptomining 4.0 | 23 | 73,9 % (53,5 až 87,5) | b |
| rodina × tempo | port_scan_vertical 4.0 | 27 | 74,1 % (55,3 až 86,8) | b |
| rodina × tempo | c2_beacon 1.0 | 104 | 76,0 % (66,9 až 83,2) | a |
| rodina × tempo | slow_scan 2.0 | 21 | 76,2 % (54,9 až 89,4) | b |
| rodina × tempo | c2_beacon 0.5 | 31 | 77,4 % (60,2 až 88,6) | a |
| rodina × tempo | port_scan_horizontal 1.0 | 72 | 77,8 % (66,9 až 85,8) | a |
| rodina × tempo | exfiltration 4.0 | 23 | 78,3 % (58,1 až 90,3) | b |
| rodina × tempo | web_exploit 0.5 | 28 | 78,6 % (60,5 až 89,8) | a |
| rodina × tempo | port_scan_vertical 0.25 | 29 | 79,3 % (61,6 až 90,2) | a |
| rodina × tempo | credential_stuffing 8.0 | 20 | 80,0 % (58,4 až 91,9) | b |
| rodina × tempo | lateral_movement 2.0 | 20 | 80,0 % (58,4 až 91,9) | b |
| rodina × tempo | port_scan_vertical 0.5 | 20 | 80,0 % (58,4 až 91,9) | b |
| rodina × tempo | dns_tunnel 1.0 | 52 | 80,8 % (68,1 až 89,2) | a |
| rodina × tempo | lateral_movement 0.5 | 37 | 81,1 % (65,8 až 90,5) | a |
| rodina × tempo | ddos_volume 1.0 | 36 | 83,3 % (68,1 až 92,1) | a |
| rodina × tempo | ssh_bruteforce 8.0 | 30 | 83,3 % (66,4 až 92,7) | a |
| rodina × tempo | port_scan_vertical 8.0 | 31 | 83,9 % (67,4 až 92,9) | a |
| rodina × tempo | port_scan_vertical 2.0 | 34 | 85,3 % (69,9 až 93,6) | a |
| rodina × tempo | lateral_movement 0.25 | 29 | 86,2 % (69,4 až 94,5) | a |
| rodina × tempo | credential_stuffing 4.0 | 22 | 86,4 % (66,7 až 95,3) | a |
| rodina × tempo | slow_scan 0.5 | 22 | 86,4 % (66,7 až 95,3) | a |
| rodina × tempo | cryptomining 1.0 | 38 | 86,8 % (72,7 až 94,2) | a |
| rodina × tempo | port_scan_horizontal 0.5 | 24 | 87,5 % (69,0 až 95,7) | a |
| rodina × tempo | exfiltration 2.0 | 26 | 88,5 % (71,0 až 96,0) | a |
| rodina × tempo | exfiltration 8.0 | 28 | 89,3 % (72,8 až 96,3) | a |
| rodina × tempo | c2_beacon 0.25 | 28 | 89,3 % (72,8 až 96,3) | a |
| rodina × tempo | web_exploit 4.0 | 20 | 90,0 % (69,9 až 97,2) | a |
| rodina × tempo | port_scan_horizontal 0.25 | 20 | 90,0 % (69,9 až 97,2) | a |
| rodina × tempo | port_scan_horizontal 4.0 | 25 | 92,0 % (75,0 až 97,8) | a |
| rodina × tempo | ransomware 1.0 | 27 | 92,6 % (76,6 až 97,9) | a |
| rodina × tempo | slow_scan 0.25 | 22 | 95,5 % (78,2 až 99,2) | a |
| rodina × volume | exploit_attempt 0.5 | 56 | 42,9 % (30,8 až 55,9) | b |
| rodina × volume | exploit_attempt 0.25 | 60 | 48,3 % (36,2 až 60,7) | b |
| rodina × volume | exploit_attempt 2.0 | 52 | 53,8 % (40,5 až 66,7) | b |
| rodina × volume | exploit_attempt 1.0 | 103 | 55,3 % (45,7 až 64,6) | b |
| rodina × volume | c2_beacon 0.25 | 63 | 61,9 % (49,6 až 72,9) | b |
| rodina × volume | c2_beacon 2.0 | 38 | 65,8 % (49,9 až 78,8) | b |
| rodina × volume | c2_beacon 1.0 | 107 | 69,2 % (59,9 až 77,1) | b |
| rodina × volume | port_scan_vertical 2.0 | 53 | 71,7 % (58,4 až 82,0) | b |
| rodina × volume | c2_beacon 0.5 | 54 | 72,2 % (59,1 až 82,4) | b |
| rodina × volume | web_exploit 0.5 | 29 | 72,4 % (54,3 až 85,3) | b |
| rodina × volume | lateral_movement 0.25 | 35 | 74,3 % (57,9 až 85,8) | b |
| rodina × volume | cryptomining 0.25 | 20 | 75,0 % (53,1 až 88,8) | b |
| rodina × volume | dns_tunnel 0.25 | 25 | 76,0 % (56,6 až 88,5) | b |
| rodina × volume | port_scan_horizontal 0.5 | 41 | 78,0 % (63,3 až 88,0) | a |
| rodina × volume | exfiltration 2.0 | 42 | 78,6 % (64,1 až 88,3) | a |
| rodina × volume | web_exploit 2.0 | 42 | 78,6 % (64,1 až 88,3) | a |
| rodina × volume | cryptomining 1.0 | 47 | 78,7 % (65,1 až 88,0) | a |
| rodina × volume | port_scan_horizontal 2.0 | 40 | 80,0 % (65,2 až 89,5) | a |
| rodina × volume | credential_stuffing 2.0 | 20 | 80,0 % (58,4 až 91,9) | b |
| rodina × volume | credential_stuffing 0.5 | 38 | 81,6 % (66,6 až 90,8) | a |
| rodina × volume | port_scan_horizontal 0.25 | 38 | 81,6 % (66,6 až 90,8) | a |
| rodina × volume | dns_tunnel 1.0 | 45 | 82,2 % (68,7 až 90,7) | a |
| rodina × volume | slow_scan 0.25 | 34 | 82,4 % (66,5 až 91,7) | a |
| rodina × volume | slow_scan 2.0 | 41 | 82,9 % (68,7 až 91,5) | a |
| rodina × volume | exfiltration 0.25 | 42 | 83,3 % (69,4 až 91,7) | a |
| rodina × volume | port_scan_vertical 0.5 | 43 | 83,7 % (70,0 až 91,9) | a |
| rodina × volume | ddos_volume 1.0 | 45 | 84,4 % (71,2 až 92,3) | a |
| rodina × volume | cryptomining 2.0 | 33 | 84,8 % (69,1 až 93,3) | a |
| rodina × volume | dns_tunnel 0.5 | 28 | 85,7 % (68,5 až 94,3) | a |
| rodina × volume | credential_stuffing 0.25 | 29 | 86,2 % (69,4 až 94,5) | a |
| rodina × volume | cryptomining 0.5 | 25 | 88,0 % (70,0 až 95,8) | a |
| rodina × volume | port_scan_vertical 0.25 | 35 | 88,6 % (74,0 až 95,5) | a |
| rodina × volume | rogue_device 1.0 | 27 | 92,6 % (76,6 až 97,9) | a |

