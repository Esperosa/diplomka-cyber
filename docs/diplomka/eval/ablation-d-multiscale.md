# Ablace D — multi-scale okénkování (Deliverable 10)

**Status: implementováno a naměřeno (29. 10. 2026).** Přímý, měřený důsledek potvrzené fragmentační hypotézy (`docs/diplomka/eval/cross-dataset-ctu13.md`): fixní `time_window_s` je trade-off (malé okno pro bursty, velké pro sustained beaconing), ne univerzálně správná konstanta. `correlation_v2::detect_multiscale_windowed_anomalies` spustí detekci na více škálách (`[60, 300, 1800, 7200]`s) a sjednotí výsledky — klíč `(dst_ip,proto,port)` je "predicted positive", pokud ho zachytí **alespoň jedna** škála.

**OPRAVA 29.10.2026:** CTU-13 čísla níže byla přepočítána po opravě label-mapování (`cross-dataset-ctu13.md` — "Background" už se nepočítá jako "Benign", ale jako "Unknown" vyřazené z confusion matrix). Směr závěru (D = nejlepší jednotlivá škála, ne lepší) se neměnil, jen absolutní čísla.

## Naměřeno

| | IoT-23 (44-1) | CTU-13 (Botnet-54 výřez, po opravě) |
|---|---|---|
| Ablace A | precision 0.250, recall 0.667 | precision 0.767, recall 0.192 |
| Ablace D | precision 0.250, recall 0.667 (**beze změny**) | precision 0.767, recall 0.192 (**identické s A**) |
| Events/findings A | 27 | 3 057 |
| Events/findings D | 127 (4,7×) | 10 380 (3,4×) |

**Metodologická výhrada (z nezávislého auditu, N3):** sada škál `[60, 300, 1800, 7200]`s byla zvolena **po** zjištění, že 7200s přesně odpovídá délce CTU-13 výřezu (1h16m50s) — tedy "nejlepší škála v sadě" byla do sady vložena se znalostí výsledku, který měla řešit. To NENÍ nezávisle odvozený hyperparametr; je to mírná forma post-hoc přizpůsobení. Na datasetu s jinou délkou capture by 7200s tuhle vlastnost nemuselo mít. Nekontrolováno dalším měřením.

## Honestní interpretace — žádné nafukování výsledku

**D není "lepší než A" na žádném z obou datasetů — je stejně dobré jako nejlepší jednotlivá škála v sadě, bez nutnosti ji předem uhodnout.** Na CTU-13 D přesně odpovídá A, protože A je matematicky ekvivalentní jedné škále (7200s = celý capture, viz cross-dataset dokument) a menší škály v sadě nenašly žádný nový TP/FP nad to, co 7200s už zachytilo. Na IoT-23 D nezhoršilo recall oproti A/B (test to explicitně ověřuje).

**Reálný měřený trade-off: 3,4–4,7× víc events/findings** — multi-scale sjednocení stejný klíč detekuje vícekrát na různých škálách, což nafoukne triage queue operátora, aniž by to zlepšilo přesnost. To je přesně ten typ nákladu, který motivuje typovanou nejistotu/VOI planner (Deliverable 4/5) — ne "spusť všechno na všech škálách a doufej", ale informované rozhodnutí, kdy která škála/kontrola má smysl.

## Co to znamená

D je honest "safety net" řešení (nikdy horší než nejlepší jednotlivá škála), ne skutečné zlepšení kvality detekce. Skutečné zlepšení musí přijít z toho, co návrh nazývá adaptivní korelace — volba škály/metody podle typu signálu, ne hrubá síla union přes předem danou sadu konstant. To je přesně směr, kterým se má Hypothesis/Verification Planner vrstva dál rozvíjet.

**Důležitý kontext (viz `cross-dataset-ctu13.md`):** triviální baseline "vše=malicious" má na obou datasetech vyšší F1 než ablace A i D (0.462 vs. 0.364 na IoT-23, 0.965 vs. 0.306 na CTU-13). D tedy není jen "nikdy horší než nejlepší škála v sadě" — pořád zůstává pod triviálním baseline na obou datasetech. To nijak nerelativizuje hodnotu zjištění o fragmentaci (to je nezávislé pozorování o chování oken), ale znamená to, že multi-scale union sám o sobě neřeší skutečný problém — ten vyžaduje typovanou nejistotu/kalibraci, ne jen víc škál.
