## Krok 8, vyhodnocení (5 seedů x 40 sítí)

| rameno | sítí | útoků | detekce | FP/síť-den | zobrazeno/síť-den | zavřeno omylem | útoky s omylem zavřeným nálezem |
|---|---:|---:|---:|---:|---:|---:|---:|
| off | 200 | 6362 | 83,9 (82,9 až 84,8) | 15,1 | 140,4 | 1,4 % (1,1 až 1,9) | 41 |
| on100 | 200 | 6362 | 90,7 (89,9 až 91,4) | 16,0 | 145,2 | 1,1 % (0,8 až 1,6) | 25 |
| on60 | 200 | 6362 | 88,2 (87,3 až 88,9) | 15,7 | 143,1 | 1,8 % (1,3 až 2,3) | 44 |
| on30 | 200 | 6362 | 86,5 (85,6 až 87,3) | 15,3 | 141,4 | 2,3 % (1,9 až 2,8) | 62 |
| comp-silent | 200 | 6362 | 83,9 (82,9 až 84,8) | 15,3 | 140,6 | 1,4 % (1,1 až 1,9) | 45 |
| comp-ok | 200 | 6362 | 83,9 (83,0 až 84,8) | 16,0 | 142,0 | 1,6 % (1,2 až 2,1) | 50 |

### Párově proti `off`

| rameno | detekce souhrn (p. b.) | exploit (p. b.) | lateral (p. b.) | c2_beacon (p. b.) | c2 pomalé tempo ≤ 0,5× (p. b.) | FP poměr | zobrazeno poměr |
|---|---:|---:|---:|---:|---:|---:|---:|
| on100 | +6,8 (+6,1 až +7,5) | +33,6 (+29,5 až +37,8) | +11,3 (+9,0 až +13,9) | +8,7 (+6,4 až +11,0) | +5,0 (+1,3 až +9,4) | 1,060 (1,049 až 1,072) | 1,034 (1,030 až 1,039) |
| on60 | +4,3 (+3,8 až +4,8) | +20,3 (+16,9 až +23,5) | +10,2 (+7,8 až +12,8) | +5,3 (+3,4 až +7,4) | +1,4 (+0,0 až +3,6) | 1,035 (1,028 až 1,042) | 1,019 (1,016 až 1,022) |
| on30 | +2,6 (+2,2 až +3,0) | +11,9 (+9,1 až +14,6) | +6,7 (+5,1 až +8,6) | +2,9 (+1,6 až +4,2) | +0,0 (+0,0 až +0,0) | 1,009 (0,993 až 1,020) | 1,007 (1,002 až 1,012) |
| comp-silent | +0,0 (+0,0 až +0,0) | +0,0 (+0,0 až +0,0) | +0,0 (+0,0 až +0,0) | +0,0 (+0,0 až +0,0) | +0,0 (+0,0 až +0,0) | 1,008 (1,006 až 1,011) | 1,001 (1,001 až 1,002) |
| comp-ok | +0,0 (+0,0 až +0,1) | +0,0 (+0,0 až +0,0) | +0,0 (+0,0 až +0,0) | +0,0 (+0,0 až +0,0) | +0,0 (+0,0 až +0,0) | 1,060 (1,050 až 1,072) | 1,011 (1,006 až 1,016) |

### Počítadla koncové telemetrie a ochrany

| počítadlo | off | on100 | on60 | on30 | comp-silent | comp-ok |
|---|---:|---:|---:|---:|---:|---:|
| endpoint_alerts | 0 | 180200 | 105205 | 52366 | 2549 | 28401 |
| endpoint_benign_refuted | 0 | 76 | 49 | 24 | 6 | 74 |
| endpoint_covered_host_cycles | 0 | 17416320 | 10471183 | 5329647 | 1714212 | 17417819 |
| endpoint_host_cycles | 0 | 17478810 | 17478810 | 17478810 | 17478810 | 17478810 |
| endpoint_ind_encoded_or_download_cmd | 0 | 10289 | 5933 | 2848 | 811 | 10289 |
| endpoint_ind_lateral_remote_exec | 0 | 64064 | 38542 | 19209 | 1738 | 18112 |
| endpoint_ind_logon_failures | 0 | 6485 | 3475 | 1347 | 0 | 0 |
| endpoint_ind_periodic_unsigned_connection | 0 | 94221 | 53153 | 26171 | 0 | 764 |
| endpoint_ind_persistence_writable | 0 | 3576 | 2028 | 1086 | 0 | 0 |
| endpoint_ind_remote_exec_tool | 0 | 18112 | 10339 | 5039 | 1738 | 18112 |
| endpoint_ind_service_unsigned | 0 | 64294 | 39303 | 20030 | 0 | 0 |
| endpoint_ind_unsigned_from_writable_path | 0 | 3801 | 2154 | 1138 | 0 | 0 |
| endpoint_ind_web_shell_spawn | 0 | 17123 | 9878 | 5516 | 0 | 0 |
| endpoint_step_benign | 0 | 416 | 255 | 146 | 66 | 620 |
| endpoint_step_malicious | 0 | 14483 | 8163 | 4091 | 143 | 2286 |
| endpoint_step_unavailable | 0 | 7118 | 38742 | 73906 | 118728 | 7090 |
| endpoint_step_undetermined | 0 | 121182 | 94433 | 61039 | 16947 | 129249 |
| endpoint_suspicious_confirmed | 0 | 4689 | 2328 | 1266 | 3 | 241 |
| protected_displayed | 56677 | 62021 | 59729 | 58231 | 56812 | 58118 |

### Prahy (E1 až E11; E12 až E14 viz test a ověření determinismu)

| práh | hodnota | výsledek |
|---|---|---|
| E1 | exploit_attempt on100 − off = +33.6 p. b. (dolní mez +29.5) | **splněno** |
| E2 | lateral_movement on100 − off = +11.3 p. b. (dolní mez +9.0) | **splněno** |
| E3 | c2_beacon on100 − off = +8.7 p. b. (dolní mez +6.4) | **splněno** |
| E4 | detekce souhrn +6.8 p. b. | **splněno** |
| E5 | FP poměr 1.060 | **splněno** |
| E6 | zobrazeno poměr 1.034 | **splněno** |
| E7 | útoky s omylem zavřeným nálezem 25 proti 41 | **splněno** |
| E8 | comp-ok: útoků s omylem zavřeným nálezem 50 proti 41 (+9, limit 1 % útoků = 63.6), detekce +0.0 p. b. | **splněno** |
| E9 | comp-silent: detekce +0.0 p. b. | **splněno** |
| E10 | chráněná zavření (všechna ramena) 0 | **splněno** |
| E11 | souhrn on100 +6.8, on60 +4.3, on30 +2.6 p. b. | **splněno** |
