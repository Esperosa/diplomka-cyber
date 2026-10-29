# Jádro: proč ablace A ztrácí, a jak ji reálně zlepšit (Deliverable 28)

**Status: naměřeno (29. 10. 2026).** Reakce na přímý požadavek: negativní výsledek ("ablace A prohrává s triviálním baseline na všech 3 scénářích", Deliverable 18/20) se nemá jen honestně zdokumentovat — má se zjistit, **jestli a jak se dá reálně zlepšit**. Tohle je ta diagnóza a první konkrétní, měřený krok ke zlepšení.

## Diagnostická otázka

Je slabý výsledek způsoben **špatně zvoleným prahem** (score≥3.2 byl odhad z Deliverable 3, nikdy netrénovaný), nebo **samotný signál nemá rozlišovací silu** na tomhle datasetu? To jsou dvě zcela odlišné diagnózy s odlišnou léčbou — první řeší kalibrace/lepší práh, druhá vyžaduje lepší detektor.

## Nástroj: PR-AUC (`src/eval/stats.rs::pr_auc`)

Plocha pod precision-recall křivkou, počítaná ze (skóre, label) dvojic **bez vazby na konkrétní práh** — měří, jestli skóre má užitečnou informaci, nezávisle na tom, kde se later nastaví hranice rozhodnutí. Náhodný/konstantní klasifikátor má PR-AUC = prevalence (podíl pozitivních) — to je správný "nulový" baseline, analogicky 0.5 u ROC-AUC. Ověřeno na ručně spočítaném referenčním příkladu (shoda se standardním scikit-learn `average_precision_score` dokumentačním příkladem, AP=5/6).

## Naměřeno — první diagnóza (existující destinace-centrické skóre)

```
Botnet-54: PR-AUC=0.5784 prevalence=0.7670 rozdil=-0.1886
Botnet-51: PR-AUC=0.1957 prevalence=0.1791 rozdil=+0.0165
Botnet-42: PR-AUC=0.3844 prevalence=0.5086 rozdil=-0.1242
```

**Diagnóza: na 2 ze 3 scénářů je PR-AUC POD prevalencí — signál je hůř než náhodný, ne jen špatně prahovaný.** Žádná kalibrace ani jiný práh tohle nemůže opravit — problém je v tom, CO se měří, ne KDE se škáluje.

## Hypotéza: špatná jednotka analýzy

`score_connection_keys` agreguje podle **CÍLE** `(dst_ip, proto, port)` — odpovídá otázce "je tahle SLUŽBA anomální". CTU-13 ground truth je ale definovaná podle **ZDROJE** — bot je infikovaný HOST, ne anomální služba. To je fundamentálně jiná jednotka analýzy, a destinace-centrické skóre na ni ani nemůže dobře odpovídat.

## Nový nástroj: `score_source_hosts` (`src/passive/anomaly.rs`)

Stejná robust z-score logika, ale agregovaná podle `src_ip`, plus nový rys: **počet distinktních cílů** (typický indikátor C2/scanning chování infikovaného hosta, který destinace-centrické skóre vůbec nezachycuje).

## Naměřeno — srovnání

```
Botnet-54: DESTINACE PR-AUC=0.5784 prevalence=0.7670 LIFT=0.75x | ZDROJ PR-AUC=0.0093 prevalence=0.0004 LIFT=24.21x
Botnet-51: DESTINACE PR-AUC=0.1957 prevalence=0.1791 LIFT=1.09x | ZDROJ PR-AUC=0.0128 prevalence=0.0041 LIFT=3.09x
Botnet-42: DESTINACE PR-AUC=0.3844 prevalence=0.5086 LIFT=0.76x | ZDROJ PR-AUC=0.0323 prevalence=0.0004 LIFT=89.97x
```

**Klíčové: LIFT (PR-AUC / prevalence) je jediná korektní srovnávací metrika mezi dvěma jednotkami analýzy s úplně jinou základní sazbou** — zdrojová prevalence je o 2-3 řády nižší (pár botů mezi tisíci hostů), takže raw PR-AUC čísla samotná nejsou přímo srovnatelná; LIFT je scale-invariant.

| Scénář | Destinace-centrický LIFT | Zdroj-centrický LIFT |
|---|---|---|
| Botnet-54 | 0.75× (hůř než náhoda) | **24.21×** |
| Botnet-51 | 1.09× (téměř náhoda) | **3.09×** |
| Botnet-42 | 0.76× (hůř než náhoda) | **89.97×** |

## Interpretace

**Přesun z "je tahle služba anomální" na "je tenhle host anomální" dramaticky a konzistentně zlepšuje rozlišovací silu na všech 3 reálných scénářích/2 rodinách.** To je reálná, měřená cesta ke zlepšení — ne naděje, že se to časem spraví. Destinace-centrické skóre (dosavadní `score_connection_keys`, jádro ablace A) je skutečně slabé, protože měří špatnou věc pro tento typ hrozby (botnet C2), ne protože je implementace chybná.

## Co z tohoto plyne — konkrétní další krok

1. **Toto je zatím diagnostický nástroj, ne zapojený detektor.** `score_source_hosts` běží jen v testu, ne v `detect_connection_anomalies`/produkčním rozhodování.
2. **Další krok**: zapojit zdroj-centrické skóre do produkční detekce (nová ablace, nebo rozšíření existující), přepočítat ablace A/confusion matrix na zdroj-centrické predikce místo destinace-centrických, a změřit, jestli **F1/precision/recall** (ne jen PR-AUC) zdroj-centrické ablace konečně překoná triviální baseline — to je ten test, který by potvrdil skutečné zlepšení, ne jen lepší ranking.
3. **Ground truth na úrovni zdroje vyžaduje jinou definici "known evidence"** — aktuální `GroundTruthLabel`/confusion matrix logika je psaná pro destinace-centrické klíče; přepis na zdroj-centrické vyžaduje paralelní, ne nahrazující, evaluační cestu (žádná regrese v existujících ablacích A-D).

## Honestní omezení

- **PR-AUC lift neznamená automaticky, že výsledná klasifikace (při nějakém prahu) porazí triviální baseline** — jen že RANKING skóre je mnohem lepší než náhodný. Krok 2 výše je nutný k ověření skutečného zlepšení F1.
- **"Počet distinktních cílů" je 1 nový rys** přidaný ad-hoc na základě domény (typický botnet indikátor) — nebyl systematicky srovnáván proti jiným možným rysům (velikost paketů, periodicita, entropie portů), takže zbývá prostor pro další zlepšení.
- **3 scénáře, 2 rodiny** — stejné omezení jako u všech ostatních CTU-13 měření v tomhle projektu.
