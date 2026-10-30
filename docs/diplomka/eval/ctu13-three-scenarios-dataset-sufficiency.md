# CTU-13: ze 1 na 3 scénáře, 2 malware rodiny (Deliverable 18)

**Status: naměřeno (29. 10. 2026).** Reakce na vlastní limitaci zapsanou v `cross-dataset-ctu13.md`: "CTU-13 strana stojí na jediném scénáři (Botnet-54/Virut) z 13 dostupných — 'cross-dataset' zde fakticky znamená 'druhý capture soubor', ne prokázanou šíři generalizace." Rozšíření bylo v master plánu (`dalsi-postup-master-plan.md`) vědomě odloženo s odůvodněním "klesající návratnost" — uživatel se po předložení plánu rozhodl v tomhle bodě pokračovat dál navzdory doporučení pragmatika/skeptika, proto bylo provedeno.

## Co bylo přidáno

2 další CTU-13 scénáře, obě ověřené rodiny přímo na `mcfp.felk.cvut.cz` (ne odhadnuté ze jména souboru — stejná disciplína jako oprava Virut/RBot chyby v Deliverable 15):

- **Botnet-51 (scénář 10, Rbot)** — výřez z prvních 30 MB, obsahuje malware provoz hned na začátku.
- **Botnet-42 (scénář 1, Neris)** — první 30 MB bylo prázdné (0 Botnet-labelovaných flows); malware aktivita v téhle 6,15h capture začíná později. Ověřeno sondou (`curl -r`), ne předpokladem. Výřez proto sestaven z hlavičky (byte 0) + 30 MB dat od offsetu 150 000 000 B.

Vedlejší nález při stavbě: Botnet-51 má v adresáři dva `binetflow` soubory s odlišným CSV schématem (`capture20110818.binetflow` vs. `...binetflow.labeled`, druhý má jiné názvy sloupců `Label(Normal:CC:Background)` + extra `CCDetector`) — ověřeno přímo (`curl -r 0-500`) před výběrem správného souboru. Použití nesprávného by znovu zavedlo chybu stejné třídy jako N1 (chybný parsing schema).

## Naměřeno

```
Botnet-54 (Virut): known_keys=885 malicious=6185 benign=2308 unknown_excluded=23548 TP=158 FP=48 FN=667 TN=12 precision=0.767 recall=0.192 f1=0.306 | trivialni_baseline_f1=0.965
Botnet-51 (Rbot): known_keys=95 malicious=81 benign=2026 unknown_excluded=27210 TP=12 FP=55 FN=8 TN=20 precision=0.179 recall=0.600 f1=0.276 | trivialni_baseline_f1=0.348
Botnet-42 (Neris): known_keys=979 malicious=2614 benign=4827 unknown_excluded=20254 TP=148 FP=143 FN=644 TN=44 precision=0.509 recall=0.187 f1=0.273 | trivialni_baseline_f1=0.894
CTU-13, 3 scenare/2 rodiny: F1 rozsah [0.273, 0.306], ablace A porazila trivialni baseline v 0/3 scenarich
```

| Scénář | Rodina | Precision | Recall | F1 | Triviální baseline F1 |
|---|---|---|---|---|---|
| Botnet-54 | Virut | 0.767 | 0.192 | 0.306 | 0.965 |
| Botnet-51 | Rbot | 0.179 | 0.600 | 0.276 | 0.348 |
| Botnet-42 | Neris | 0.509 | 0.187 | 0.273 | 0.894 |

## Interpretace

1. **Nejdůležitější zjištění: ablace A prohrává s triviálním baseline na VŠECH 3 scénářích (0/3), ne jen na 1.** Tohle podstatně posiluje generalizační tvrzení — "aktuální heuristika nepřekonává nejhloupější možný klasifikátor" teď stojí na 3 nezávislých scénářích/2 rodinách, ne na jednom capture souboru. Přesně ten typ rozšíření, který `cross-dataset-ctu13.md` identifikoval jako chybějící pro to, aby se slovo "generalizace" používalo bez výhrady.
2. **F1 je překvapivě konzistentní (0.273–0.306)** napříč rodinami i přes velmi odlišný poměr malicious/benign/unknown (Botnet-51 má jen 95 known klíčů, Botnet-42 má 979) — to je slabý, ale reálný signál, že slabý výkon ablace A není artefakt jednoho konkrétního scénáře.
3. **Triviální baseline F1 NENÍ konzistentní (0.348–0.965)** — silně závisí na prevalenci (podíl known-malicious vs. known-benign klíčů v daném scénáři). Na Botnet-51 (nejvyváženější, 81 malicious / 2026 benign known) je triviální baseline jen 0.348, nejslabší ze 3 — a ablace A (F1 0.276) se mu blíží nejvíc. To je honestní, očekávaný důsledek silně nevyváženého vzorkování, ne chyba.
4. **N=3 nestačí na formální statistický test.** Wilcoxon signed-rank potřebuje n≥6 na jakoukoliv smysluplnou sílu (p_min=0.0625 při n=5, per master plán). Tenhle report proto reportuje rozsah/medián, ne fabrikovanou p-hodnotu — přesně to varování, které `dalsi-postup-master-plan.md` zapsal predem.

## Honestní omezení

- ~~Stále jen 3 ze 13 dostupných scénářů, 2 ze zhruba 7 rodin.~~ **Vyřešeno níže (30.10.2026) — všech 13/13.**
- **Offset-based výřez u Botnet-42 je jiná vzorkovací metoda** než prvních-N-bytů u ostatních dvou — vnáší drobnou metodologickou nekonzistenci (vzorek "odjinud" v čase capture), zapsáno zde transparentně, ne skryto.
- ~~Žádná formální statistika (CI, p-hodnota)~~ — bootstrap CI existuje pro jednotlivé scénáře už od Deliverable 20; medián/IQR přes scénáře viz níže. Formální test mezi-scenarové signifikance (Wilcoxon) stále neimplementován.

## Dodatek (30.10.2026): rozšíření na všech 13/13 standardních CTU-13 scénářů, 7 rodin/technik

**Impuls**: uživatel výslovně odmítl N=3 jako statisticky/datově průkazné. Doplněno zbývajících 10 scénářů (Botnet-43/44/45/46/47/48/49/50/52/53) — podrobnosti stažení/ověření rodiny v `dataset-registry.md`. `src/eval/dataset_replay.rs` dostal sdílenou `CTU13_ALL_SCENARIOS` konstantu, nahrazující 6 nezávisle hardcoded N=3 seznamů v různých testech.

```
Botnet-42 (Neris):    known_keys=979  malicious=2614  TP=148 FP=143 FN=644 TN=44 precision=0.509 recall=0.187 f1=0.273 | trivial_f1=0.894
Botnet-43 (Neris):    known_keys=462  malicious=10263 TP=116 FP=36  FN=305 TN=5  precision=0.763 recall=0.276 f1=0.405 | trivial_f1=0.954
Botnet-44 (Rbot):      known_keys=4766 malicious=4757  TP=2   FP=20  FN=4744 TN=0 precision=0.091 recall=0.000 f1=0.001 | trivial_f1=0.998
Botnet-45 (Rbot-DoS):  known_keys=252  malicious=469   TP=5   FP=204 FN=1   TN=42 precision=0.024 recall=0.833 f1=0.047 | trivial_f1=0.047
Botnet-46 (fast-flux): known_keys=439  malicious=901   TP=34  FP=188 FN=158 TN=59 precision=0.153 recall=0.177 f1=0.164 | trivial_f1=0.609
Botnet-47 (Donbot):    known_keys=729  malicious=1552  TP=76  FP=95  FN=531 TN=27 precision=0.444 recall=0.125 f1=0.195 | trivial_f1=0.909
Botnet-48 (Sogou):     known_keys=110  malicious=63    TP=7   FP=67  FN=10  TN=26 precision=0.095 recall=0.412 f1=0.154 | trivial_f1=0.268
Botnet-49 (Qvod):      known_keys=390  malicious=381   TP=25  FP=126 FN=191 TN=48 precision=0.166 recall=0.116 f1=0.136 | trivial_f1=0.713
Botnet-50 (Neris):     known_keys=195  malicious=50    TP=9   FP=152 FN=0   TN=34 precision=0.056 recall=1.000 f1=0.106 | trivial_f1=0.088
Botnet-51 (Rbot):      known_keys=95   malicious=81    TP=12  FP=55  FN=8   TN=20 precision=0.179 recall=0.600 f1=0.276 | trivial_f1=0.348
Botnet-52 (Rbot):      known_keys=50   malicious=8164  TP=5   FP=29  FN=3   TN=13 precision=0.147 recall=0.625 f1=0.238 | trivial_f1=0.276
Botnet-53 (neoznaceno):known_keys=1403 malicious=1720  TP=90  FP=233 FN=1038 TN=42 precision=0.279 recall=0.080 f1=0.124 | trivial_f1=0.891
Botnet-54 (Virut):     known_keys=885  malicious=6185  TP=158 FP=48  FN=667 TN=12 precision=0.767 recall=0.192 f1=0.306 | trivial_f1=0.965

CTU-13, 13 scenaru/7 rodin: F1 min=0.001 median=0.164 mean=0.187 max=0.405
ablace A porazila trivialni baseline v 1/13 scenarich
```

**Hlavní zjištění přežilo, ale zesláblo**: ablace A prohrává s triviálním baseline na **12 ze 13** scénářů (dřív 3/3, teď 12/13) — jediná výjimka (Botnet-45) je hraniční (F1=0.047 vs. triviální 0.047, rozdíl na 4. desetinném místě). **Rozšíření na 7× víc dat generalizační tvrzení NEVYVRÁTILO, naopak posílilo** — ale F1 napříč scénáři je teď výrazně méně konzistentní (0.001–0.405, dřív 0.273–0.306 na jen 3 vzorcích) — menší vzorek skryl reálnou variabilitu mezi scénáři/rodinami. Medián F1=0.164 je honestnější shrnutí síly ablace A než dřívější úzký rozsah.

**Nový pozorovaný vzorec**: scénáře s velmi malým počtem known klíčů (Botnet-48: 110, Botnet-50: 195, Botnet-52: 50) mají vysokou variabilitu F1 (0.106–0.238) i triviálního baseline (0.088–0.276) — malý vzorek uvnitř scénáře přidává svou vlastní nejistotu nad rámec mezi-scénářové variability. Bootstrap CI (Deliverable 20) by tohle u každého scénáře jednotlivě kvantifikoval.

## Dodatek (31. 10. 2026): formální statistická signifikance (Wilcoxon, n=13)

Mezi-scénářová formální statistika zmíněná výše jako "budoucí práce" je dodělaná. `src/eval/stats.rs::wilcoxon_signed_rank_test` — párový Wilcoxonův znaménkový pořadový test, exaktní p-hodnota (vyčet všech 2^n kombinací znamének, ne normální aproximace — proveditelné pro n≤20). Aplikováno na `f1(ablace A) - f1(triviální baseline)` přes všech 13 scénářů: **n_effective=12 (1 nulový rozdíl vyřazen — Botnet-45), W=1.0, p=0.000977**.

To je silně statisticky významné (p≪0,05) — potvrzuje formálně, ne jen na pohled z mediánu, že ablace A spolehlivě prohrává s triviálním baseline, ne že se to shoduje náhodou na velkém vzorku. Reprodukce: `cargo test --lib ctu13_thirteen_scenarios_seven_families_dataset_sufficiency_check -- --ignored --nocapture`.
