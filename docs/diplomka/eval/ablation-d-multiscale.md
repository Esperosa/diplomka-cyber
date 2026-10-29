# Ablace D — multi-scale okénkování (Deliverable 10)

**Status: implementováno a naměřeno (29. 10. 2026).** Přímý, měřený důsledek potvrzené fragmentační hypotézy (`docs/diplomka/eval/cross-dataset-ctu13.md`): fixní `time_window_s` je trade-off (malé okno pro bursty, velké pro sustained beaconing), ne univerzálně správná konstanta. `correlation_v2::detect_multiscale_windowed_anomalies` spustí detekci na více škálách (`[60, 300, 1800, 7200]`s) a sjednotí výsledky — klíč `(dst_ip,proto,port)` je "predicted positive", pokud ho zachytí **alespoň jedna** škála.

## Naměřeno

| | IoT-23 (44-1) | CTU-13 (Botnet-54 výřez) |
|---|---|---|
| Ablace A | precision 0.250, recall 0.667 | precision 0.083, recall 0.192 |
| Ablace D | precision 0.250, recall 0.667 (**beze změny**) | precision 0.083, recall 0.192 (**identické s A**) |
| Events/findings A | 27 | 3 057 |
| Events/findings D | 127 (4,7×) | 10 380 (3,4×) |

## Honestní interpretace — žádné nafukování výsledku

**D není "lepší než A" na žádném z obou datasetů — je stejně dobré jako nejlepší jednotlivá škála v sadě, bez nutnosti ji předem uhodnout.** Na CTU-13 D přesně odpovídá A, protože A je matematicky ekvivalentní jedné škále (7200s = celý capture, viz cross-dataset dokument) a menší škály v sadě nenašly žádný nový TP/FP nad to, co 7200s už zachytilo. Na IoT-23 D nezhoršilo recall oproti A/B (test to explicitně ověřuje).

**Reálný měřený trade-off: 3,4–4,7× víc events/findings** — multi-scale sjednocení stejný klíč detekuje vícekrát na různých škálách, což nafoukne triage queue operátora, aniž by to zlepšilo přesnost. To je přesně ten typ nákladu, který motivuje typovanou nejistotu/VOI planner (Deliverable 4/5) — ne "spusť všechno na všech škálách a doufej", ale informované rozhodnutí, kdy která škála/kontrola má smysl.

## Co to znamená

D je honest "safety net" řešení (nikdy horší než nejlepší jednotlivá škála), ne skutečné zlepšení kvality detekce. Skutečné zlepšení musí přijít z toho, co návrh nazývá adaptivní korelace — volba škály/metody podle typu signálu, ne hrubá síla union přes předem danou sadu konstant. To je přesně směr, kterým se má Hypothesis/Verification Planner vrstva dál rozvíjet.
