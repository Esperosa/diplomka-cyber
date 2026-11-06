## Krok 7, ICS seed 20262101

| rameno | sítí | útoků | detekce mikro | detekce makro | FP/síť-den | zobrazeno/síť-den | zavřeno omylem (G3) | útoky s omylem zavřeným nálezem | omylem zavřených nálezů |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ics-v3k6 | 40 | 916 | 74,8 (71,1 až 77,9) | 77,8 (73,1 až 81,7) | 22,5 | 157,5 | 0,4 % (0,1 až 0,9) [4/1119] | 7 | 7 |
| ics-v3k7 | 40 | 916 | 77,8 (74,1 až 81,1) | 80,7 (76,1 až 84,3) | 26,6 | 204,8 | 0,6 % (0,2 až 1,3) [5/863] | 4 | 5 |

| rameno | viditelnost po 1. zobrazení | ztráta viditelnosti (příčina: útoků) | habituace | latence medián / p90 (cykly) | chráněných zobrazeno / automaticky zavřeno | ops-only útoky | útoky s provozní anotací |
|---|---:|---|---:|---:|---:|---:|---:|
| ics-v3k6 | 95,2 % | ladder: 9, quiet: 23 | 45 | 0 / 11 | 0 / 0 | 0 | 0 |
| ics-v3k7 | 97,5 % | ladder: 6, quiet: 20 | 43 | 0 / 8 | 13569 / 0 | 0 | 0 |

### Párově proti `ics-v3k6`

| rameno | detekce (p. b.) | FP poměr | zobrazeno poměr | nejhorší rodina n ≥ 100 (p. b.) |
|---|---:|---:|---:|---|
| ics-v3k7 | +3,1 (+2,0 až +4,3) | 1,186 (1,133 až 1,240) | 1,301 (1,204 až 1,406) | – |

### Rodiny

| rodina | n | ics-v3k6 | ics-v3k7 |
|---|---:|---:|---:|
| apt_chain | 14 | 100,0 % (78,5 až 100,0) | 100,0 % (78,5 až 100,0) |
| c2_beacon | 84 | 64,3 % (53,6 až 73,7) | 67,9 % (57,3 až 76,9) |
| credential_stuffing | 56 | 80,4 % (68,2 až 88,7) | 80,4 % (68,2 až 88,7) |
| cryptomining | 27 | 70,4 % (51,5 až 84,1) | 81,5 % (63,3 až 91,8) |
| ddos_volume | 23 | 87,0 % (67,9 až 95,5) | 87,0 % (67,9 až 95,5) |
| dns_tunnel | 33 | 66,7 % (49,6 až 80,2) | 78,8 % (62,2 až 89,3) |
| exfiltration | 55 | 80,0 % (67,6 až 88,4) | 80,0 % (67,6 až 88,4) |
| exploit_attempt | 79 | 35,4 % (25,8 až 46,4) | 38,0 % (28,1 až 49,0) |
| fleet_beacon | 12 | 58,3 % (32,0 až 80,7) | 58,3 % (32,0 až 80,7) |
| ics_attack | 78 | 65,4 % (54,3 až 75,0) | 69,2 % (58,3 až 78,4) |
| insider_hoarding | 23 | 91,3 % (73,2 až 97,6) | 91,3 % (73,2 až 97,6) |
| lateral_movement | 76 | 72,4 % (61,4 až 81,2) | 85,5 % (75,9 až 91,7) |
| port_scan_horizontal | 60 | 81,7 % (70,1 až 89,4) | 81,7 % (70,1 až 89,4) |
| port_scan_vertical | 58 | 86,2 % (75,1 až 92,8) | 87,9 % (77,1 až 94,0) |
| ransomware | 23 | 82,6 % (62,9 až 93,0) | 87,0 % (67,9 až 95,5) |
| rogue_device | 16 | 100,0 % (80,6 až 100,0) | 100,0 % (80,6 až 100,0) |
| slow_scan | 56 | 82,1 % (70,2 až 90,0) | 83,9 % (72,2 až 91,3) |
| ssh_bruteforce | 84 | 86,9 % (78,1 až 92,5) | 86,9 % (78,1 až 92,5) |
| web_exploit | 59 | 88,1 % (77,5 až 94,1) | 88,1 % (77,5 až 94,1) |

### Poruchy a lookalike (fronta podezření)

| porucha | varianta | n | FP ics-v3k6 | FP ics-v3k7 | položek/výskyt ics-v3k7 | anotace ics-v3k7 |
|---|---|---:|---:|---:|---:|---:|
| authorized_scanner | - | 114 | 97,4 % (92,5 až 99,1) | 97,4 % (92,5 až 99,1) | 2.71 | 0 |
| backup_burst | - | 187 | 67,4 % (60,4 až 73,7) | 82,4 % (76,3 až 87,1) | 3.50 | 0 |
| backup_failed | - | 24 | 95,8 % (79,8 až 99,3) | 95,8 % (79,8 až 99,3) | 4.29 | 0 |
| backup_failed | low | 15 | 80,0 % (54,8 až 93,0) | 80,0 % (54,8 až 93,0) | 3.07 | 0 |
| batch_job | - | 52 | 96,2 % (87,0 až 98,9) | 98,1 % (89,9 až 99,7) | 15.83 | 0 |
| cert_expired | - | 15 | 86,7 % (62,1 až 96,3) | 86,7 % (62,1 až 96,3) | 17.60 | 0 |
| cert_expired | cert_8443 | 22 | 95,5 % (78,2 až 99,2) | 95,5 % (78,2 až 99,2) | 27.77 | 0 |
| cert_expired | low | 2 | 100,0 % (34,2 až 100,0) | 100,0 % (34,2 až 100,0) | 80.50 | 0 |
| cloud_migration | - | 25 | 100,0 % (86,7 až 100,0) | 100,0 % (86,7 až 100,0) | 215.80 | 0 |
| cloud_migration | low | 9 | 100,0 % (70,1 až 100,0) | 100,0 % (70,1 až 100,0) | 203.56 | 0 |
| collector_replay | - | 69 | 72,5 % (61,0 až 81,6) | 79,7 % (68,8 až 87,5) | 33.29 | 0 |
| device_decommission | - | 29 | 37,9 % (22,7 až 56,0) | 44,8 % (28,4 až 62,5) | 1.38 | 0 |
| device_onboarding | - | 37 | 0,0 % (0,0 až 9,4) | 8,1 % (2,8 až 21,3) | 0.14 | 0 |
| dhcp_renumber | - | 32 | 68,8 % (51,4 až 82,0) | 71,9 % (54,6 až 84,4) | 2.53 | 0 |
| dhcp_renumber | low | 16 | 56,2 % (33,2 až 76,9) | 56,2 % (33,2 až 76,9) | 2.00 | 0 |
| dns_outage | - | 28 | 75,0 % (56,6 až 87,3) | 75,0 % (56,6 až 87,3) | 4.11 | 0 |
| dns_outage | low | 19 | 78,9 % (56,7 až 91,5) | 78,9 % (56,7 až 91,5) | 2.58 | 0 |
| flash_crowd | - | 220 | 45,0 % (38,6 až 51,6) | 49,1 % (42,6 až 55,7) | 1.42 | 0 |
| link_flapping | - | 29 | 0,0 % (0,0 až 11,7) | 0,0 % (0,0 až 11,7) | 0.00 | 0 |
| link_flapping | low | 14 | 0,0 % (0,0 až 21,5) | 0,0 % (0,0 až 21,5) | 0.00 | 0 |
| log_corruption | - | 65 | 43,1 % (31,8 až 55,2) | 49,2 % (37,5 až 61,1) | 1.85 | 0 |
| misconfig | - | 29 | 93,1 % (78,0 až 98,1) | 93,1 % (78,0 až 98,1) | 28.93 | 0 |
| misconfig | low | 11 | 100,0 % (74,1 až 100,0) | 100,0 % (74,1 až 100,0) | 41.27 | 0 |
| ntp_fanout | - | 97 | 5,2 % (2,2 až 11,5) | 6,2 % (2,9 až 12,8) | 0.33 | 0 |
| patch_window | - | 39 | 97,4 % (86,8 až 99,5) | 97,4 % (86,8 až 99,5) | 32.15 | 0 |
| retry_storm | - | 61 | 0,0 % (0,0 až 5,9) | 0,0 % (0,0 až 5,9) | 0.00 | 0 |
| saas_adoption | - | 3 | 66,7 % (20,8 až 93,9) | 100,0 % (43,9 až 100,0) | 25.33 | 0 |
| saas_adoption | low | 6 | 83,3 % (43,6 až 97,0) | 83,3 % (43,6 až 97,0) | 6.17 | 0 |
| saas_adoption | saas_group | 21 | 61,9 % (40,9 až 79,2) | 76,2 % (54,9 až 89,4) | 10.24 | 0 |
| segment_power_loss | - | 32 | 100,0 % (89,3 až 100,0) | 100,0 % (89,3 až 100,0) | 32.28 | 0 |
| segment_power_loss | low | 14 | 100,0 % (78,5 až 100,0) | 100,0 % (78,5 až 100,0) | 41.93 | 0 |
| sensor_crash | - | 88 | 6,8 % (3,2 až 14,1) | 5,7 % (2,5 až 12,6) | 0.07 | 0 |
| service_crash | - | 90 | 53,3 % (43,1 až 63,3) | 53,3 % (43,1 až 63,3) | 1.76 | 0 |
| software_update | - | 224 | 0,4 % (0,1 až 2,5) | 0,4 % (0,1 až 2,5) | 0.00 | 0 |
| vpn_reconnect_storm | - | 33 | 90,9 % (76,4 až 96,9) | 90,9 % (76,4 až 96,9) | 4.94 | 0 |
| vpn_reconnect_storm | low | 17 | 88,2 % (65,7 až 96,7) | 88,2 % (65,7 až 96,7) | 3.94 | 0 |

### Kategorie buněk (`ics-v3k7`)

Buněk celkem 585. Bez korekce: (a) 80, (b) 26, (c) 479. S Holmovou korekcí: (a) 33, (b) 73, (c) 479.

Buňky v (b) s n ≥ 20 (vedené s mírou a mitigací):

| dimenze | buňka | n | detekce (Wilson) | kategorie bez korekce |
|---|---|---:|---:|---|
| duration | 0.5 | 110 | 71,8 % (62,8 až 79,4) | a |
| duration | 0.25 | 86 | 74,4 % (64,3 až 82,5) | a |
| jitter | 0.5 | 128 | 69,5 % (61,1 až 76,8) | b |
| jitter | 0.7 | 139 | 74,1 % (66,2 až 80,7) | a |
| jitter | 0.15 | 138 | 75,4 % (67,6 až 81,8) | a |
| rodina | exploit_attempt | 79 | 38,0 % (28,1 až 49,0) | b |
| rodina | c2_beacon | 84 | 67,9 % (57,3 až 76,9) | b |
| rodina | ics_attack | 78 | 69,2 % (58,3 až 78,4) | b |
| rodina | dns_tunnel | 33 | 78,8 % (62,2 až 89,3) | a |
| rodina | exfiltration | 55 | 80,0 % (67,6 až 88,4) | a |
| rodina | credential_stuffing | 56 | 80,4 % (68,2 až 88,7) | a |
| rodina | cryptomining | 27 | 81,5 % (63,3 až 91,8) | a |
| rodina | port_scan_horizontal | 60 | 81,7 % (70,1 až 89,4) | a |
| rodina | slow_scan | 56 | 83,9 % (72,2 až 91,3) | a |
| rodina | ransomware | 23 | 87,0 % (67,9 až 95,5) | a |
| rodina | ddos_volume | 23 | 87,0 % (67,9 až 95,5) | a |
| rodina | insider_hoarding | 23 | 91,3 % (73,2 až 97,6) | a |
| rodina × duration | exploit_attempt 1.0 | 33 | 39,4 % (24,7 až 56,3) | b |
| rodina × duration | c2_beacon 1.0 | 41 | 58,5 % (43,4 až 72,2) | b |
| rodina × duration | ics_attack 1.0 | 42 | 64,3 % (49,2 až 77,0) | b |
| rodina × duration | credential_stuffing 1.0 | 23 | 73,9 % (53,5 až 87,5) | b |
| rodina × duration | exfiltration 1.0 | 24 | 75,0 % (55,1 až 88,0) | b |
| rodina × duration | web_exploit 1.0 | 25 | 80,0 % (60,9 až 91,1) | a |
| rodina × duration | lateral_movement 1.0 | 20 | 80,0 % (58,4 až 91,9) | b |
| rodina × duration | port_scan_vertical 1.0 | 22 | 81,8 % (61,5 až 92,7) | a |
| rodina × duration | port_scan_horizontal 1.0 | 29 | 82,8 % (65,5 až 92,4) | a |
| rodina × duration | ssh_bruteforce 1.0 | 41 | 82,9 % (68,7 až 91,5) | a |
| rodina × duration | slow_scan 1.0 | 28 | 85,7 % (68,5 až 94,3) | a |
| rodina × jitter | exploit_attempt 0.0 | 32 | 46,9 % (30,9 až 63,6) | b |
| rodina × jitter | c2_beacon 0.0 | 37 | 73,0 % (57,0 až 84,6) | b |
| rodina × jitter | exfiltration 0.0 | 30 | 76,7 % (59,1 až 88,2) | b |
| rodina × jitter | port_scan_horizontal 0.0 | 25 | 80,0 % (60,9 až 91,1) | a |
| rodina × jitter | ics_attack 0.0 | 31 | 80,6 % (63,7 až 90,8) | a |
| rodina × jitter | credential_stuffing 0.0 | 23 | 87,0 % (67,9 až 95,5) | a |
| rodina × jitter | port_scan_vertical 0.0 | 26 | 88,5 % (71,0 až 96,0) | a |
| rodina × jitter | web_exploit 0.0 | 22 | 90,9 % (72,2 až 97,5) | a |
| rodina × jitter | slow_scan 0.0 | 21 | 95,2 % (77,3 až 99,2) | a |
| rodina × sources | exploit_attempt 1 | 29 | 31,0 % (17,3 až 49,2) | b |
| rodina × sources | ics_attack 10 | 25 | 72,0 % (52,4 až 85,7) | b |
| rodina × sources | c2_beacon 1 | 29 | 75,9 % (57,9 až 87,8) | b |
| rodina × sources | ics_attack 1 | 30 | 76,7 % (59,1 až 88,2) | b |
| rodina × sources | exfiltration 1 | 20 | 80,0 % (58,4 až 91,9) | b |
| rodina × sources | lateral_movement 1 | 25 | 80,0 % (60,9 až 91,1) | a |
| rodina × sources | ssh_bruteforce 1 | 35 | 85,7 % (70,6 až 93,7) | a |
| rodina × sources | lateral_movement 30 | 24 | 87,5 % (69,0 až 95,7) | a |
| rodina × sources | ssh_bruteforce 3 | 23 | 91,3 % (73,2 až 97,6) | a |
| rodina × sources | port_scan_vertical 1 | 21 | 95,2 % (77,3 až 99,2) | a |
| rodina × sources | slow_scan 1 | 23 | 95,7 % (79,0 až 99,2) | a |
| rodina × tempo | exploit_attempt 1.0 | 30 | 33,3 % (19,2 až 51,2) | b |
| rodina × tempo | port_scan_horizontal 1.0 | 22 | 68,2 % (47,3 až 83,6) | b |
| rodina × tempo | ics_attack 1.0 | 29 | 79,3 % (61,6 až 90,2) | a |
| rodina × tempo | lateral_movement 1.0 | 28 | 82,1 % (64,4 až 92,1) | a |
| rodina × tempo | exfiltration 1.0 | 23 | 82,6 % (62,9 až 93,0) | a |
| rodina × tempo | credential_stuffing 1.0 | 23 | 82,6 % (62,9 až 93,0) | a |
| rodina × tempo | c2_beacon 1.0 | 33 | 84,8 % (69,1 až 93,3) | a |
| rodina × tempo | web_exploit 1.0 | 23 | 87,0 % (67,9 až 95,5) | a |
| rodina × tempo | port_scan_vertical 1.0 | 23 | 87,0 % (67,9 až 95,5) | a |
| rodina × tempo | ssh_bruteforce 1.0 | 32 | 87,5 % (71,9 až 95,0) | a |
| rodina × volume | exploit_attempt 1.0 | 34 | 38,2 % (23,9 až 55,0) | b |
| rodina × volume | ics_attack 1.0 | 31 | 67,7 % (50,1 až 81,4) | b |
| rodina × volume | c2_beacon 1.0 | 36 | 69,4 % (53,1 až 82,0) | b |
| rodina × volume | port_scan_horizontal 1.0 | 25 | 72,0 % (52,4 až 85,7) | b |
| rodina × volume | exfiltration 1.0 | 24 | 79,2 % (59,5 až 90,8) | b |
| rodina × volume | lateral_movement 1.0 | 27 | 81,5 % (63,3 až 91,8) | a |
| rodina × volume | web_exploit 1.0 | 29 | 86,2 % (69,4 až 94,5) | a |
| rodina × volume | port_scan_vertical 1.0 | 23 | 87,0 % (67,9 až 95,5) | a |
| rodina × volume | credential_stuffing 1.0 | 20 | 90,0 % (69,9 až 97,2) | a |
| rodina × volume | slow_scan 1.0 | 21 | 95,2 % (77,3 až 99,2) | a |
| tempo | 16.0 | 73 | 65,8 % (54,3 až 75,6) | b |
| tempo | 0.25 | 97 | 72,2 % (62,5 až 80,1) | a |
| tempo | 8.0 | 78 | 74,4 % (63,7 až 82,7) | a |
| volume | 0.25 | 94 | 71,3 % (61,4 až 79,4) | a |
| volume | 0.125 | 116 | 75,0 % (66,4 až 82,0) | a |

