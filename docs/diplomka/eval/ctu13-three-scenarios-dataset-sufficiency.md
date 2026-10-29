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

- **Stále jen 3 ze 13 dostupných scénářů, 2 ze zhruba 7 rodin.** Zobecnění na "CTU-13 obecně" nebo na botnet provoz obecně je dál opatrné — tohle je oproti 1 scénáři výrazně silnější, ne vyčerpávající důkaz.
- **Offset-based výřez u Botnet-42 je jiná vzorkovací metoda** než prvních-N-bytů u ostatních dvou — vnáší drobnou metodologickou nekonzistenci (vzorek "odjinud" v čase capture), zapsáno zde transparentně, ne skryto.
- **Žádná formální statistika (CI, p-hodnota)** — vědomě, kvůli nedostatečnému N, ne protože by to bylo zapomenuto.
