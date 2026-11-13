# Ablace B a C — temporal windowing a graph-linking (Deliverable 3)

**Status: implementováno, testováno, naměřeno (29. 10. 2026).** Nový modul `src/correlation_v2.rs`, VEDLE `passive::anomaly`/`correlation.rs` (ablace A beze změny). Reprodukce: `cargo test --lib eval::dataset_replay::tests::ablation_b_c_vs_a_on_iot23_malware_scenario -- --nocapture`.

## Co bylo postaveno

- **Ablace B (`detect_windowed_anomalies`)**: stejné heuristiky a prahy jako `passive::anomaly::detect_connection_anomalies` (timeout burst, packet rate spike, packet loss, overload risk), ale agregované po **tumbling oknech** `time_window_s` místo přes celý capture. Okno je ukotvené na čas prvního pozorování v datasetu (ne na Unix epoch 0).
- **Ablace C (`detect_windowed_anomalies_linked`)**: B + jednoduché graph-linking — anomálie se stejným `src_ip` napříč ≥2 různými `(dst_ip,proto,port)` cíli ve stejném okně se spojí do `multi_target_pattern` nálezu (signál skenu/lateral movementu).
- Vědomé zjednodušení: induktivní z-score outlier detektor z `anomaly.rs` v této verzi vynechán (okna na malých scénářích mají často <4 aktivních klíčů, takže by stejně nikdy nevystřelil).

## Naměřeno na IoT-23 scénáři 44-1 (`time_window_s=300`)

| Ablace | Events | Precision | Recall | F1 | Findings |
|---|---|---|---|---|---|
| A (baseline) | 27 | 0.250 | 0.667 | 0.364 | 27 |
| B (windowed) | 39 | 0.250 | 0.667 | 0.364 | 39 |
| C (B + linking) | 48 | 0.250 | 0.667 | 0.364 | 48 |

**Honest nulový výsledek pro precision/recall:** na tomto konkrétním scénáři se confusion matrix mezi A/B/C **neliší** — celý malicious burst (25 ze 26 flows) se vejde do jednoho 300s okna s velkou rezervou (trvá ~178 s), takže windowing nerozdělí signál, ale ani nic nepřidá k přesnosti rozpoznávání na úrovni `(dst_ip,proto,port)` klíčů. B a C produkují **víc events/findings** (39, 48 vs. 27) bez zlepšení confusion matrix — to je důležité samo o sobě: okénkování může nafouknout triage queue operátora, aniž by zlepšilo detekci, pokud je okno zvolené špatně vzhledem k délce reálného incidentu.

## Konkrétní, potvrzený false-positive nález (ablace C)

Test `multi_target_pattern_on_iot23_malware_scenario_is_mostly_ntp_false_positive` (projde, dokumentuje známou limitaci, ne skrývá ji): naivní multi-target heuristika na infikovaném hostu `192.168.1.199` vyprodukovala 9 `multi_target_pattern` nálezů. Většina z nich (8 z 9) je **čistě legitimní periodický NTP fan-out** (`udp/123` ke standardním NTP serverům každých ~30 s) — jen první okno obsahuje i skutečný C2 cíl (`46.101.251.172/tcp/80`) smíchaný se 4 NTP cíli. Toto přesně odpovídá tomu, co předpověděla nezávislá revize před implementací: scénář s jedním infikovaným hostem a benigním NTP fan-outem je nevhodný pro čistou validaci multi-target detekce a ukazuje naopak reálné riziko FP z běžné síťové hygieny.

**Závěr není "graph-linking nefunguje"** — je to přesně ten typ nálezu, který ablační metodika má odhalit: naivní heuristika bez znalosti "co je legitimně periodické" (baseline/allowlist) je příliš hrubá. Následující krok (ne v tomto deliverable): odečítat od multi-target skóre cíle, které jsou stabilně periodické a málo objemné (typický NTP vzorec), než se heuristika bude považovat za použitelnou v produkci.

## Co to znamená pro další postup

1. **Tento scénář (44-1, 237 flows) je na testování temporal windowingu příliš krátký/kompaktní** — potřeba scénář s delším rozpětím útoku nebo menším `time_window_s`, aby se ukázal rozdíl mezi A a B. Zapsáno jako otevřená otázka pro vlnu 1 datasetů (CTU-13 má delší/vícestupňové C2 scénáře).
2. **Graph-linking potřebuje baseline-awareness** (odlišit periodický/known-good provoz od skutečného multi-target scanu) dřív, než bude use-ready — přesně shoda s tím, co risk-auditor v debatě o lokálním AI systému nazval "cirkulární past bez baseline".
3. Žádná z těchto ablací nezasáhla do `correlation.rs`/`decision.rs`/`report.rs` — ablace A zůstává nezměněná referenční cesta.
