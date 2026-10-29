# Statistický aparát: bootstrap confidence intervaly (Deliverable 20)

**Status: naměřeno (29. 10. 2026).** Reakce na audit finding N4 ("chybějící statistický aparát — CI, significance testy, PR-AUC/Brier/ECE"). Design doc (sekce 9.1) žádá `confidence interval` jako jednu z povinných metrik, dosud nikde nepočítanou. Toto NENÍ formální significance test mezi scénáři/ablacemi — na to N=3 scénáře (Deliverable 18) nestačí (Wilcoxon potřebuje n≥6 na jakoukoliv smysluplnou sílu, viz `dalsi-postup-master-plan.md`). Je to nejistota **uvnitř** jednoho měření — kolik by se číslo změnilo na jiném vzorku stejné populace klíčů.

## Co bylo postaveno

- **`BaselineResult::per_key_predictions: Vec<(bool, bool)>`** — (predicted, actual) dvojice pro každý "known evidence" klíč, přesně ty, co vstupují do `confusion` matrix. Žádná změna existující detekční logiky — jen zachycení dat, která se už počítala.
- **`src/eval/stats.rs`** — `bootstrap_metric_ci()`: percentilová metoda, resampling s navrácením, seedovaný `StdRng` (reprodukovatelnost je vyžadovaná vlastnost, ne vedlejší efekt — stejný požadavek jako u ostatních eval testů v projektu).

## Naměřeno

```
CTU-13 ablace A F1 95% bootstrap CI: 0.306 [0.271, 0.342] (n=885, 2000 resamplu, seed=42)
```

## Interpretace

**Interval [0.271, 0.342] nikde ani vzdáleně nedosahuje triviálního baseline F1 0.965** (viz `cross-dataset-ctu13.md`). To potvrzuje, že "ablace A prohrává s triviálním baseline" nezávisí na tom, že padl zrovna nešťastný point-estimate — je to robustní napříč rozumnou nejistotou uvnitř tohoto scénáře samotného.

## Honestní omezení

- **Tohle je CI uvnitř JEDNOHO scénáře** (Botnet-54, n=885 known klíčů) — neříká nic o tom, jak by se číslo lišilo na jiném scénáři/jiné malware rodině (na to slouží Deliverable 18's rozsah [0.273, 0.306] přes 3 scénáře, jiný typ nejistoty).
- **Resamplování je na úrovni klíčů `(dst_ip,proto,port)`, ne flows** — klíče uvnitř jednoho scénáře nejsou nutně nezávislé (shared infrastruktura, korelovaný provoz), takže i tenhle interval může být užší, než by odpovídalo "skutečné" nezávislosti vzorků. Zapsáno jako limitace, ne skryto.
- **Jen pro ablaci A na CTU-13** — rozšíření na IoT-23 a ostatní ablace (B/C/D) je mechanické (stejná funkce, jiný vstup), ale zatím neudělané — žádné tvrzení se o nich nedělá.
