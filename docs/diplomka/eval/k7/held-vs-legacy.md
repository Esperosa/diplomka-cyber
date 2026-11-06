## Krok 7, držené seedy, párově proti legacy

| rameno | sítí | útoků | detekce mikro | detekce makro | FP/síť-den | zobrazeno/síť-den | zavřeno omylem (G3) | útoky s omylem zavřeným nálezem | omylem zavřených nálezů |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| legacy | 80 | 2934 | 62,6 (59,5 až 65,5) | 65,5 (62,2 až 69,0) | 919,0 | 8993,1 | – % (0,0 až 100,0) [0/0] | 0 | 0 |
| v3k6 | 80 | 2934 | 77,9 (74,7 až 81,2) | 80,3 (76,3 až 83,6) | 28,4 | 153,8 | 1,4 % (1,0 až 2,0) [30/2153] | 31 | 35 |
| v3k7 | 80 | 2934 | 80,3 (77,2 až 83,2) | 82,9 (79,8 až 85,7) | 29,9 | 183,7 | 1,4 % (0,9 až 2,2) [17/1232] | 27 | 31 |

| rameno | viditelnost po 1. zobrazení | ztráta viditelnosti (příčina: útoků) | habituace | latence medián / p90 (cykly) | chráněných zobrazeno / automaticky zavřeno | ops-only útoky | útoky s provozní anotací |
|---|---:|---|---:|---:|---:|---:|---:|
| legacy | – % | 0 | 0 | None / None | 0 / 0 | 0 | 0 |
| v3k6 | 94,4 % | context: 1, ladder: 15, quiet: 63 | 168 | 0 / 8 | 0 / 0 | 0 | 0 |
| v3k7 | 97,0 % | ladder: 14, quiet: 39 | 160 | 0 / 6 | 27947 / 0 | 0 | 0 |

### Párově proti `legacy`

| rameno | detekce (p. b.) | FP poměr | zobrazeno poměr | nejhorší rodina n ≥ 100 (p. b.) |
|---|---:|---:|---:|---|
| v3k6 | +15,3 (+13,1 až +17,9) | 0,031 (0,018 až 0,044) | 0,017 (0,013 až 0,021) | slow_scan -3,7 |
| v3k7 | +17,7 (+15,5 až +20,2) | 0,033 (0,020 až 0,045) | 0,020 (0,016 až 0,025) | slow_scan -2,7 |

### Rodiny

| rodina | n | legacy | v3k6 | v3k7 |
|---|---:|---:|---:|---:|
| apt_chain | 59 | 96,6 % (88,5 až 99,1) | 94,9 % (86,1 až 98,3) | 94,9 % (86,1 až 98,3) |
| c2_beacon | 257 | 35,8 % (30,2 až 41,8) | 67,7 % (61,8 až 73,1) | 71,2 % (65,4 až 76,4) |
| credential_stuffing | 183 | 86,3 % (80,6 až 90,6) | 86,9 % (81,2 až 91,0) | 87,4 % (81,8 až 91,5) |
| cryptomining | 118 | 41,5 % (33,0 až 50,5) | 83,9 % (76,2 až 89,4) | 86,4 % (79,1 až 91,5) |
| ddos_volume | 73 | 83,6 % (73,4 až 90,3) | 84,9 % (75,0 až 91,4) | 84,9 % (75,0 až 91,4) |
| dns_tunnel | 120 | 44,2 % (35,6 až 53,1) | 73,3 % (64,8 až 80,4) | 76,7 % (68,3 až 83,3) |
| exfiltration | 202 | 18,8 % (14,0 až 24,8) | 89,1 % (84,1 až 92,7) | 88,6 % (83,5 až 92,3) |
| exploit_attempt | 276 | 25,4 % (20,6 až 30,8) | 33,0 % (27,7 až 38,7) | 35,5 % (30,1 až 41,3) |
| fleet_beacon | 46 | 63,0 % (48,6 až 75,5) | 73,9 % (59,7 až 84,4) | 80,4 % (66,8 až 89,3) |
| ics_attack | 10 | 80,0 % (49,0 až 94,3) | 70,0 % (39,7 až 89,2) | 80,0 % (49,0 až 94,3) |
| insider_hoarding | 45 | 86,7 % (73,8 až 93,7) | 88,9 % (76,5 až 95,2) | 91,1 % (79,3 až 96,5) |
| lateral_movement | 220 | 72,7 % (66,5 až 78,2) | 72,7 % (66,5 až 78,2) | 86,8 % (81,7 až 90,7) |
| port_scan_horizontal | 224 | 77,7 % (71,8 až 82,6) | 75,4 % (69,4 až 80,6) | 77,2 % (71,3 až 82,2) |
| port_scan_vertical | 240 | 52,9 % (46,6 až 59,1) | 86,7 % (81,8 až 90,4) | 87,5 % (82,7 až 91,1) |
| ransomware | 86 | 89,5 % (81,3 až 94,4) | 89,5 % (81,3 až 94,4) | 89,5 % (81,3 až 94,4) |
| rogue_device | 45 | 33,3 % (21,4 až 47,9) | 95,6 % (85,2 až 98,8) | 95,6 % (85,2 až 98,8) |
| slow_scan | 188 | 87,8 % (82,3 až 91,7) | 84,0 % (78,1 až 88,6) | 85,1 % (79,3 až 89,5) |
| ssh_bruteforce | 341 | 89,4 % (85,7 až 92,3) | 92,4 % (89,1 až 94,7) | 93,0 % (89,7 až 95,2) |
| web_exploit | 201 | 79,6 % (73,5 až 84,6) | 82,6 % (76,7 až 87,2) | 83,1 % (77,3 až 87,6) |

### Poruchy a lookalike (fronta podezření)

| porucha | varianta | n | FP legacy | FP v3k6 | FP v3k7 | položek/výskyt v3k7 | anotace v3k7 |
|---|---|---:|---:|---:|---:|---:|---:|
| authorized_scanner | - | 302 | 48,3 % (42,8 až 54,0) | 95,0 % (92,0 až 97,0) | 95,4 % (92,4 až 97,2) | 2.87 | 0 |
| backup_burst | - | 649 | 69,2 % (65,5 až 72,6) | 36,2 % (32,6 až 40,0) | 44,2 % (40,4 až 48,1) | 1.74 | 0 |
| backup_failed | - | 74 | 97,2 % (92,2 až 99,1) | 95,9 % (88,7 až 98,6) | 97,3 % (90,7 až 99,3) | 5.26 | 0 |
| backup_failed | low | 35 | – | 97,1 % (85,5 až 99,5) | 97,1 % (85,5 až 99,5) | 4.03 | 0 |
| batch_job | - | 177 | 86,4 % (80,6 až 90,7) | 71,8 % (64,7 až 77,9) | 81,4 % (75,0 až 86,4) | 10.12 | 0 |
| cert_expired | - | 16 | 98,8 % (93,5 až 99,8) | 93,8 % (71,7 až 98,9) | 93,8 % (71,7 až 98,9) | 10.12 | 0 |
| cert_expired | cert_8443 | 52 | – | 100,0 % (93,1 až 100,0) | 100,0 % (93,1 až 100,0) | 11.73 | 0 |
| cert_expired | low | 15 | – | 93,3 % (70,2 až 98,8) | 93,3 % (70,2 až 98,8) | 18.07 | 0 |
| cloud_migration | - | 57 | 94,7 % (88,9 až 97,5) | 96,5 % (88,1 až 99,0) | 98,2 % (90,7 až 99,7) | 145.26 | 0 |
| cloud_migration | low | 56 | – | 100,0 % (93,6 až 100,0) | 100,0 % (93,6 až 100,0) | 289.29 | 0 |
| collector_replay | - | 197 | 92,9 % (88,4 až 95,7) | 77,2 % (70,8 až 82,5) | 82,2 % (76,3 až 86,9) | 18.04 | 0 |
| device_decommission | - | 105 | 22,9 % (15,9 až 31,8) | 13,3 % (8,1 až 21,1) | 15,2 % (9,6 až 23,3) | 0.30 | 0 |
| device_onboarding | - | 143 | 4,2 % (1,9 až 8,9) | 14,7 % (9,8 až 21,4) | 32,9 % (25,7 až 40,9) | 0.84 | 0 |
| dhcp_renumber | - | 85 | 75,0 % (66,7 až 81,8) | 57,6 % (47,0 až 67,6) | 60,0 % (49,4 až 69,8) | 2.46 | 0 |
| dhcp_renumber | low | 39 | – | 79,5 % (64,5 až 89,2) | 84,6 % (70,3 až 92,8) | 3.87 | 0 |
| dns_outage | - | 70 | 99,1 % (94,8 až 99,8) | 80,0 % (69,2 až 87,7) | 80,0 % (69,2 až 87,7) | 1.79 | 0 |
| dns_outage | low | 36 | – | 88,9 % (74,7 až 95,6) | 91,7 % (78,2 až 97,1) | 2.39 | 0 |
| flash_crowd | - | 625 | 85,1 % (82,1 až 87,7) | 45,1 % (41,3 až 49,0) | 49,4 % (45,5 až 53,4) | 1.61 | 0 |
| link_flapping | - | 61 | 0,0 % (0,0 až 3,4) | 0,0 % (0,0 až 5,9) | 0,0 % (0,0 až 5,9) | 0.00 | 0 |
| link_flapping | low | 47 | – | 0,0 % (0,0 až 7,6) | 0,0 % (0,0 až 7,6) | 0.00 | 0 |
| log_corruption | - | 149 | 92,6 % (87,3 až 95,8) | 45,0 % (37,2 až 53,0) | 60,4 % (52,4 až 67,9) | 3.99 | 0 |
| misconfig | - | 67 | 94,6 % (88,7 až 97,5) | 97,0 % (89,8 až 99,2) | 97,0 % (89,8 až 99,2) | 22.67 | 0 |
| misconfig | low | 44 | – | 100,0 % (92,0 až 100,0) | 100,0 % (92,0 až 100,0) | 24.27 | 0 |
| ntp_fanout | - | 302 | 24,2 % (19,7 až 29,3) | 6,3 % (4,1 až 9,6) | 11,3 % (8,2 až 15,3) | 0.32 | 0 |
| patch_window | - | 147 | 98,0 % (94,2 až 99,3) | 93,9 % (88,8 až 96,7) | 94,6 % (89,6 až 97,2) | 15.24 | 0 |
| retry_storm | - | 177 | 0,0 % (0,0 až 2,1) | 0,0 % (0,0 až 2,1) | 0,0 % (0,0 až 2,1) | 0.00 | 0 |
| saas_adoption | - | 32 | 49,5 % (40,1 až 59,0) | 71,9 % (54,6 až 84,4) | 75,0 % (57,9 až 86,7) | 5.19 | 0 |
| saas_adoption | low | 15 | – | 80,0 % (54,8 až 93,0) | 86,7 % (62,1 až 96,3) | 2.87 | 0 |
| saas_adoption | saas_group | 56 | – | 75,0 % (62,3 až 84,5) | 85,7 % (74,3 až 92,6) | 20.77 | 0 |
| segment_power_loss | - | 64 | 57,4 % (48,0 až 66,3) | 62,5 % (50,3 až 73,3) | 70,3 % (58,2 až 80,1) | 14.56 | 0 |
| segment_power_loss | low | 44 | – | 50,0 % (35,8 až 64,2) | 63,6 % (48,9 až 76,2) | 7.50 | 0 |
| sensor_crash | - | 201 | 0,0 % (0,0 až 1,9) | 15,9 % (11,5 až 21,6) | 10,0 % (6,5 až 14,9) | 0.13 | 0 |
| service_crash | - | 303 | 87,1 % (82,9 až 90,4) | 58,1 % (52,5 až 63,5) | 64,4 % (58,8 až 69,5) | 2.63 | 0 |
| software_update | - | 646 | 0,0 % (0,0 až 0,6) | 1,2 % (0,6 až 2,4) | 1,2 % (0,6 až 2,4) | 0.02 | 0 |
| vpn_reconnect_storm | - | 66 | 97,0 % (91,6 až 99,0) | 95,5 % (87,5 až 98,4) | 95,5 % (87,5 až 98,4) | 3.88 | 0 |
| vpn_reconnect_storm | low | 35 | – | 91,4 % (77,6 až 97,0) | 91,4 % (77,6 až 97,0) | 3.57 | 0 |

### Kategorie buněk (`v3k7`)

Buněk celkem 598. Bez korekce: (a) 261, (b) 76, (c) 261. S Holmovou korekcí: (a) 141, (b) 196, (c) 261.

Buňky v (b) s n ≥ 20 (vedené s mírou a mitigací):

| dimenze | buňka | n | detekce (Wilson) | kategorie bez korekce |
|---|---|---:|---:|---|
| rodina | exploit_attempt | 276 | 35,5 % (30,1 až 41,3) | b |
| rodina | c2_beacon | 257 | 71,2 % (65,4 až 76,4) | a |
| rodina | fleet_beacon | 46 | 80,4 % (66,8 až 89,3) | a |
| rodina × duration | exploit_attempt 8.0 | 43 | 23,3 % (13,2 až 37,7) | b |
| rodina × duration | exploit_attempt 4.0 | 26 | 34,6 % (19,4 až 53,8) | b |
| rodina × duration | exploit_attempt 1.0 | 93 | 36,6 % (27,5 až 46,7) | b |
| rodina × duration | exploit_attempt 0.5 | 42 | 38,1 % (25,0 až 53,2) | b |
| rodina × duration | exploit_attempt 0.25 | 35 | 40,0 % (25,6 až 56,4) | b |
| rodina × duration | exploit_attempt 2.0 | 37 | 40,5 % (26,3 až 56,5) | b |
| rodina × duration | port_scan_horizontal 0.5 | 27 | 48,1 % (30,7 až 66,0) | b |
| rodina × duration | c2_beacon 0.25 | 33 | 54,5 % (38,0 až 70,2) | b |
| rodina × duration | c2_beacon 0.5 | 25 | 60,0 % (40,7 až 76,6) | b |
| rodina × duration | slow_scan 0.25 | 23 | 60,9 % (40,8 až 77,8) | b |
| rodina × duration | dns_tunnel 1.0 | 40 | 62,5 % (47,0 až 75,8) | b |
| rodina × duration | port_scan_horizontal 0.25 | 25 | 64,0 % (44,5 až 79,8) | b |
| rodina × duration | c2_beacon 1.0 | 109 | 68,8 % (59,6 až 76,7) | b |
| rodina × duration | port_scan_vertical 0.25 | 32 | 71,9 % (54,6 až 84,4) | b |
| rodina × duration | web_exploit 0.25 | 31 | 74,2 % (56,8 až 86,3) | b |
| rodina × duration | slow_scan 0.5 | 20 | 75,0 % (53,1 až 88,8) | b |
| rodina × duration | lateral_movement 0.25 | 24 | 75,0 % (55,1 až 88,0) | b |
| rodina × duration | exfiltration 0.5 | 25 | 76,0 % (56,6 až 88,5) | b |
| rodina × duration | port_scan_horizontal 1.0 | 94 | 76,6 % (67,1 až 84,0) | a |
| rodina × duration | lateral_movement 0.5 | 35 | 77,1 % (61,0 až 87,9) | a |
| rodina × duration | cryptomining 1.0 | 42 | 78,6 % (64,1 až 88,3) | a |
| rodina × duration | web_exploit 1.0 | 82 | 79,3 % (69,3 až 86,6) | a |
| rodina × duration | web_exploit 4.0 | 25 | 80,0 % (60,9 až 91,1) | a |
| rodina × duration | c2_beacon 2.0 | 31 | 80,6 % (63,7 až 90,8) | a |
| rodina × duration | ddos_volume 1.0 | 34 | 82,4 % (66,5 až 91,7) | a |
| rodina × duration | c2_beacon 4.0 | 30 | 83,3 % (66,4 až 92,7) | a |
| rodina × duration | c2_beacon 8.0 | 29 | 86,2 % (69,4 až 94,5) | a |
| rodina × duration | port_scan_horizontal 2.0 | 29 | 86,2 % (69,4 až 94,5) | a |
| rodina × duration | dns_tunnel 4.0 | 23 | 87,0 % (67,9 až 95,5) | a |
| rodina × duration | ransomware 1.0 | 31 | 87,1 % (71,1 až 94,9) | a |
| rodina × duration | credential_stuffing 8.0 | 24 | 87,5 % (69,0 až 95,7) | a |
| rodina × duration | credential_stuffing 0.25 | 26 | 88,5 % (71,0 až 96,0) | a |
| rodina × duration | exfiltration 2.0 | 31 | 90,3 % (75,1 až 96,7) | a |
| rodina × duration | slow_scan 2.0 | 22 | 90,9 % (72,2 až 97,5) | a |
| rodina × duration | web_exploit 0.5 | 23 | 91,3 % (73,2 až 97,6) | a |
| rodina × duration | lateral_movement 2.0 | 20 | 95,0 % (76,4 až 99,1) | a |
| rodina × duration | port_scan_horizontal 4.0 | 21 | 95,2 % (77,3 až 99,2) | a |
| rodina × duration | slow_scan 8.0 | 22 | 95,5 % (78,2 až 99,2) | a |
| rodina × jitter | exploit_attempt 0.7 | 36 | 33,3 % (20,2 až 49,7) | b |
| rodina × jitter | exploit_attempt 0.5 | 45 | 35,6 % (23,2 až 50,2) | b |
| rodina × jitter | exploit_attempt 0.0 | 123 | 35,8 % (27,9 až 44,6) | b |
| rodina × jitter | exploit_attempt 0.15 | 36 | 36,1 % (22,5 až 52,4) | b |
| rodina × jitter | exploit_attempt 0.3 | 36 | 36,1 % (22,5 až 52,4) | b |
| rodina × jitter | c2_beacon 0.15 | 44 | 65,9 % (51,1 až 78,1) | b |
| rodina × jitter | c2_beacon 0.7 | 39 | 69,2 % (53,6 až 81,4) | b |
| rodina × jitter | c2_beacon 0.3 | 27 | 70,4 % (51,5 až 84,1) | b |
| rodina × jitter | slow_scan 0.7 | 24 | 70,8 % (50,8 až 85,1) | b |
| rodina × jitter | port_scan_horizontal 0.15 | 35 | 71,4 % (54,9 až 83,7) | b |
| rodina × jitter | web_exploit 0.3 | 35 | 71,4 % (54,9 až 83,7) | b |
| rodina × jitter | c2_beacon 0.5 | 39 | 71,8 % (56,2 až 83,5) | b |
| rodina × jitter | dns_tunnel 0.5 | 23 | 73,9 % (53,5 až 87,5) | b |
| rodina × jitter | c2_beacon 0.0 | 108 | 74,1 % (65,1 až 81,4) | a |
| rodina × jitter | port_scan_horizontal 0.0 | 82 | 74,4 % (64,0 až 82,6) | a |
| rodina × jitter | port_scan_horizontal 0.3 | 24 | 75,0 % (55,1 až 88,0) | b |
| rodina × jitter | dns_tunnel 0.0 | 43 | 76,7 % (62,3 až 86,8) | a |
| rodina × jitter | exfiltration 0.15 | 32 | 78,1 % (61,2 až 89,0) | a |
| rodina × jitter | slow_scan 0.3 | 23 | 78,3 % (58,1 až 90,3) | b |
| rodina × jitter | port_scan_horizontal 0.5 | 47 | 78,7 % (65,1 až 88,0) | a |
| rodina × jitter | web_exploit 0.5 | 33 | 78,8 % (62,2 až 89,3) | a |
| rodina × jitter | lateral_movement 0.5 | 34 | 79,4 % (63,2 až 89,7) | a |
| rodina × jitter | port_scan_vertical 0.5 | 44 | 81,8 % (68,0 až 90,5) | a |
| rodina × jitter | ddos_volume 0.0 | 33 | 81,8 % (65,6 až 91,4) | a |
| rodina × jitter | credential_stuffing 0.3 | 22 | 81,8 % (61,5 až 92,7) | a |
| rodina × jitter | ssh_bruteforce 0.7 | 56 | 82,1 % (70,2 až 90,0) | a |
| rodina × jitter | web_exploit 0.7 | 29 | 82,8 % (65,5 až 92,4) | a |
| rodina × jitter | cryptomining 0.0 | 53 | 83,0 % (70,8 až 90,8) | a |
| rodina × jitter | dns_tunnel 0.7 | 24 | 83,3 % (64,1 až 93,3) | a |
| rodina × jitter | lateral_movement 0.7 | 32 | 84,4 % (68,2 až 93,1) | a |
| rodina × jitter | slow_scan 0.5 | 33 | 84,8 % (69,1 až 93,3) | a |
| rodina × jitter | web_exploit 0.15 | 20 | 85,0 % (64,0 až 94,8) | a |
| rodina × jitter | exfiltration 0.7 | 34 | 85,3 % (69,9 až 93,6) | a |
| rodina × jitter | lateral_movement 0.15 | 34 | 85,3 % (69,9 až 93,6) | a |
| rodina × jitter | port_scan_vertical 0.15 | 28 | 85,7 % (68,5 až 94,3) | a |
| rodina × jitter | cryptomining 0.7 | 22 | 86,4 % (66,7 až 95,3) | a |
| rodina × jitter | insider_hoarding 0.0 | 22 | 86,4 % (66,7 až 95,3) | a |
| rodina × jitter | credential_stuffing 0.5 | 30 | 86,7 % (70,3 až 94,7) | a |
| rodina × jitter | port_scan_vertical 0.3 | 39 | 87,2 % (73,3 až 94,4) | a |
| rodina × jitter | port_scan_horizontal 0.7 | 36 | 88,9 % (74,7 až 95,6) | a |
| rodina × jitter | ransomware 0.0 | 32 | 90,6 % (75,8 až 96,8) | a |
| rodina × jitter | rogue_device 0.0 | 26 | 92,3 % (75,9 až 97,9) | a |
| rodina × jitter | credential_stuffing 0.15 | 27 | 92,6 % (76,6 až 97,9) | a |
| rodina × jitter | cryptomining 0.5 | 20 | 95,0 % (76,4 až 99,1) | a |
| rodina × sources | exploit_attempt 3 | 49 | 24,5 % (14,6 až 38,1) | b |
| rodina × sources | exploit_attempt 1 | 122 | 36,9 % (28,8 až 45,7) | b |
| rodina × sources | exploit_attempt 10 | 59 | 37,3 % (26,1 až 50,0) | b |
| rodina × sources | exploit_attempt 30 | 46 | 41,3 % (28,3 až 55,7) | b |
| rodina × sources | dns_tunnel 10 | 31 | 58,1 % (40,8 až 73,6) | b |
| rodina × sources | c2_beacon 10 | 50 | 64,0 % (50,1 až 75,9) | b |
| rodina × sources | c2_beacon 30 | 42 | 64,3 % (49,2 až 77,0) | b |
| rodina × sources | dns_tunnel 3 | 26 | 69,2 % (50,0 až 83,5) | b |
| rodina × sources | port_scan_horizontal 10 | 47 | 70,2 % (56,0 až 81,3) | b |
| rodina × sources | port_scan_horizontal 3 | 39 | 71,8 % (56,2 až 83,5) | b |
| rodina × sources | c2_beacon 1 | 107 | 73,8 % (64,8 až 81,2) | a |
| rodina × sources | port_scan_horizontal 30 | 51 | 74,5 % (61,1 až 84,5) | a |
| rodina × sources | web_exploit 10 | 44 | 75,0 % (60,6 až 85,4) | a |
| rodina × sources | cryptomining 10 | 28 | 75,0 % (56,6 až 87,3) | b |
| rodina × sources | slow_scan 30 | 35 | 77,1 % (61,0 až 87,9) | a |
| rodina × sources | c2_beacon 3 | 58 | 77,6 % (65,3 až 86,4) | a |
| rodina × sources | web_exploit 3 | 39 | 79,5 % (64,5 až 89,2) | a |
| rodina × sources | credential_stuffing 30 | 45 | 80,0 % (66,2 až 89,1) | a |
| rodina × sources | slow_scan 10 | 44 | 81,8 % (68,0 až 90,5) | a |
| rodina × sources | dns_tunnel 30 | 22 | 81,8 % (61,5 až 92,7) | a |
| rodina × sources | web_exploit 30 | 41 | 82,9 % (68,7 až 91,5) | a |
| rodina × sources | lateral_movement 3 | 41 | 82,9 % (68,7 až 91,5) | a |
| rodina × sources | ddos_volume 1 | 30 | 83,3 % (66,4 až 92,7) | a |
| rodina × sources | slow_scan 3 | 38 | 84,2 % (69,6 až 92,6) | a |
| rodina × sources | ransomware 1 | 38 | 84,2 % (69,6 až 92,6) | a |
| rodina × sources | port_scan_vertical 10 | 39 | 84,6 % (70,3 až 92,8) | a |
| rodina × sources | fleet_beacon 1 | 20 | 85,0 % (64,0 až 94,8) | a |
| rodina × sources | credential_stuffing 10 | 31 | 87,1 % (71,1 až 94,9) | a |
| rodina × sources | cryptomining 3 | 26 | 88,5 % (71,0 až 96,0) | a |
| rodina × sources | lateral_movement 10 | 36 | 88,9 % (74,7 až 95,6) | a |
| rodina × sources | apt_chain 1 | 21 | 95,2 % (77,3 až 99,2) | a |
| rodina × sources | ransomware 3 | 22 | 95,5 % (78,2 až 99,2) | a |
| rodina × tempo | exploit_attempt 1.0 | 123 | 32,5 % (24,9 až 41,2) | b |
| rodina × tempo | exploit_attempt 8.0 | 26 | 34,6 % (19,4 až 53,8) | b |
| rodina × tempo | exploit_attempt 4.0 | 25 | 36,0 % (20,2 až 55,5) | b |
| rodina × tempo | c2_beacon 4.0 | 27 | 37,0 % (21,5 až 55,8) | b |
| rodina × tempo | exploit_attempt 0.5 | 24 | 37,5 % (21,2 až 57,3) | b |
| rodina × tempo | exploit_attempt 2.0 | 26 | 42,3 % (25,5 až 61,1) | b |
| rodina × tempo | slow_scan 2.0 | 21 | 57,1 % (36,5 až 75,5) | b |
| rodina × tempo | c2_beacon 8.0 | 24 | 58,3 % (38,8 až 75,5) | b |
| rodina × tempo | port_scan_horizontal 0.5 | 21 | 61,9 % (40,9 až 79,2) | b |
| rodina × tempo | port_scan_horizontal 1.0 | 84 | 69,0 % (58,5 až 77,9) | b |
| rodina × tempo | port_scan_horizontal 2.0 | 20 | 70,0 % (48,1 až 85,5) | b |
| rodina × tempo | dns_tunnel 1.0 | 49 | 73,5 % (59,7 až 83,8) | b |
| rodina × tempo | web_exploit 4.0 | 20 | 80,0 % (58,4 až 91,9) | b |
| rodina × tempo | c2_beacon 0.25 | 31 | 80,6 % (63,7 až 90,8) | a |
| rodina × tempo | port_scan_vertical 4.0 | 27 | 81,5 % (63,3 až 91,8) | a |
| rodina × tempo | c2_beacon 0.125 | 23 | 82,6 % (62,9 až 93,0) | a |
| rodina × tempo | ransomware 1.0 | 32 | 84,4 % (68,2 až 93,1) | a |
| rodina × tempo | lateral_movement 0.25 | 20 | 85,0 % (64,0 až 94,8) | a |
| rodina × tempo | port_scan_vertical 0.25 | 20 | 85,0 % (64,0 až 94,8) | a |
| rodina × tempo | lateral_movement 0.5 | 27 | 85,2 % (67,5 až 94,1) | a |
| rodina × tempo | port_scan_vertical 16.0 | 21 | 85,7 % (65,4 až 95,0) | a |
| rodina × tempo | lateral_movement 4.0 | 21 | 85,7 % (65,4 až 95,0) | a |
| rodina × tempo | ssh_bruteforce 16.0 | 21 | 85,7 % (65,4 až 95,0) | a |
| rodina × tempo | slow_scan 0.125 | 21 | 85,7 % (65,4 až 95,0) | a |
| rodina × tempo | ddos_volume 1.0 | 29 | 86,2 % (69,4 až 94,5) | a |
| rodina × tempo | port_scan_horizontal 0.125 | 23 | 87,0 % (67,9 až 95,5) | a |
| rodina × tempo | ssh_bruteforce 0.25 | 32 | 90,6 % (75,8 až 96,8) | a |
| rodina × tempo | port_scan_horizontal 8.0 | 23 | 91,3 % (73,2 až 97,6) | a |
| rodina × tempo | port_scan_vertical 2.0 | 25 | 92,0 % (75,0 až 97,8) | a |
| rodina × tempo | ssh_bruteforce 8.0 | 28 | 92,9 % (77,4 až 98,0) | a |
| rodina × tempo | exfiltration 4.0 | 21 | 95,2 % (77,3 až 99,2) | a |
| rodina × tempo | slow_scan 16.0 | 22 | 95,5 % (78,2 až 99,2) | a |
| rodina × volume | exploit_attempt 0.125 | 28 | 25,0 % (12,7 až 43,4) | b |
| rodina × volume | exploit_attempt 0.5 | 32 | 28,1 % (15,6 až 45,4) | b |
| rodina × volume | exploit_attempt 1.0 | 111 | 31,5 % (23,6 až 40,7) | b |
| rodina × volume | exploit_attempt 0.25 | 48 | 37,5 % (25,2 až 51,6) | b |
| rodina × volume | exploit_attempt 4.0 | 28 | 42,9 % (26,5 až 60,9) | b |
| rodina × volume | exploit_attempt 2.0 | 29 | 58,6 % (40,7 až 74,5) | b |
| rodina × volume | c2_beacon 2.0 | 32 | 59,4 % (42,3 až 74,5) | b |
| rodina × volume | port_scan_horizontal 0.5 | 27 | 63,0 % (44,2 až 78,5) | b |
| rodina × volume | c2_beacon 0.5 | 30 | 70,0 % (52,1 až 83,3) | b |
| rodina × volume | c2_beacon 0.125 | 24 | 70,8 % (50,8 až 85,1) | b |
| rodina × volume | credential_stuffing 0.125 | 21 | 71,4 % (50,0 až 86,2) | b |
| rodina × volume | c2_beacon 1.0 | 107 | 72,0 % (62,8 až 79,6) | a |
| rodina × volume | web_exploit 0.25 | 22 | 72,7 % (51,8 až 86,8) | b |
| rodina × volume | port_scan_horizontal 0.25 | 23 | 73,9 % (53,5 až 87,5) | b |
| rodina × volume | c2_beacon 4.0 | 28 | 75,0 % (56,6 až 87,3) | b |
| rodina × volume | port_scan_horizontal 2.0 | 32 | 75,0 % (57,9 až 86,7) | b |
| rodina × volume | dns_tunnel 1.0 | 48 | 75,0 % (61,2 až 85,1) | a |
| rodina × volume | port_scan_horizontal 4.0 | 26 | 76,9 % (57,9 až 89,0) | b |
| rodina × volume | lateral_movement 2.0 | 22 | 77,3 % (56,6 až 89,9) | b |
| rodina × volume | c2_beacon 0.25 | 36 | 77,8 % (61,9 až 88,3) | a |
| rodina × volume | slow_scan 1.0 | 84 | 78,6 % (68,7 až 86,0) | a |
| rodina × volume | port_scan_horizontal 1.0 | 90 | 78,9 % (69,4 až 86,0) | a |
| rodina × volume | ddos_volume 1.0 | 29 | 79,3 % (61,6 až 90,2) | a |
| rodina × volume | exfiltration 0.125 | 25 | 80,0 % (60,9 až 91,1) | a |
| rodina × volume | web_exploit 0.125 | 20 | 80,0 % (58,4 až 91,9) | b |
| rodina × volume | exfiltration 0.25 | 22 | 81,8 % (61,5 až 92,7) | a |
| rodina × volume | port_scan_vertical 4.0 | 29 | 82,8 % (65,5 až 92,4) | a |
| rodina × volume | web_exploit 0.5 | 21 | 85,7 % (65,4 až 95,0) | a |
| rodina × volume | lateral_movement 0.125 | 28 | 85,7 % (68,5 až 94,3) | a |
| rodina × volume | credential_stuffing 0.5 | 21 | 85,7 % (65,4 až 95,0) | a |
| rodina × volume | slow_scan 4.0 | 22 | 86,4 % (66,7 až 95,3) | a |
| rodina × volume | lateral_movement 0.5 | 31 | 87,1 % (71,1 až 94,9) | a |
| rodina × volume | ssh_bruteforce 0.25 | 39 | 87,2 % (73,3 až 94,4) | a |
| rodina × volume | lateral_movement 4.0 | 24 | 87,5 % (69,0 až 95,7) | a |
| rodina × volume | port_scan_vertical 0.125 | 33 | 87,9 % (72,7 až 95,2) | a |
| rodina × volume | slow_scan 2.0 | 25 | 88,0 % (70,0 až 95,8) | a |
| rodina × volume | credential_stuffing 2.0 | 29 | 89,7 % (73,6 až 96,4) | a |
| rodina × volume | port_scan_vertical 0.5 | 30 | 90,0 % (74,4 až 96,5) | a |
| rodina × volume | lateral_movement 0.25 | 30 | 90,0 % (74,4 až 96,5) | a |
| rodina × volume | rogue_device 1.0 | 25 | 92,0 % (75,0 až 97,8) | a |
| rodina × volume | port_scan_vertical 0.25 | 25 | 92,0 % (75,0 až 97,8) | a |
| rodina × volume | web_exploit 2.0 | 25 | 92,0 % (75,0 až 97,8) | a |
| rodina × volume | web_exploit 4.0 | 26 | 92,3 % (75,9 až 97,9) | a |
| rodina × volume | port_scan_horizontal 0.125 | 26 | 92,3 % (75,9 až 97,9) | a |
| rodina × volume | exfiltration 4.0 | 27 | 92,6 % (76,6 až 97,9) | a |
| rodina × volume | port_scan_vertical 2.0 | 27 | 92,6 % (76,6 až 97,9) | a |
| rodina × volume | slow_scan 0.125 | 20 | 95,0 % (76,4 až 99,1) | a |

