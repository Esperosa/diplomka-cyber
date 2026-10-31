# Case Memory a historie ověření (návrh sekce 5.6)

**Stav: hotovo (31. 10. 2026).** Uzavírá položky „plný Case Memory“ a „ostatní 2 kandidáti zůstávají ruční odhad“ z dashboardu.

## Co to je

`src/case_memory.rs` – verzovaná paměť **ověřených** případů (potvrzený / vyvrácený / neprůkazný nález). Z ní se odhaduje, jak často je daný typ nálezu skutečný, a odhad plní `SecurityHypothesis.probability`.

- **Odhad:** Beta(1,1) prior + vážené případy → posteriorní střed = pravděpodobnost, 95% credible interval z regularizované neúplné beta funkce (ověřeno proti uzavřeným tvarům Beta(1,1), (2,1), (1,3), (2,2) a proti nezávislému binomickému vzorci pro Beta(10,3)). Pod 5 efektivními případy **žádný odhad** (`None`) – nic se nefabrikuje.
- **Napojení:** `probability` = střed, `uncertainty.epistemic` = šířka intervalu (hi95 − lo95), `model_version` nese verzi paměti. Bez odhadu je výstup bajtově shodný s dřívějším (golden snapshot beze změny).
- **Zdroje případů:** (1) automatické ověření (`verification_exec`, váha 0,8) přes konzervativní mapování – jen HTTP < 400 / chyba / žádný webový port u expozičních nálezů a CVSS ≥ 7 / 0 CVE u CVE nálezů, vše ostatní se nezapisuje; (2) verdikt operátora `POST /api/runs/{run}/findings/{finding}/verdict` (váha 1,0, permission `findings.write`, CSRF, audit); (3) schválení/zamítnutí zásahu s `finding_id` (váha 0,5).
- **Persistence:** `case-memory.json` atomicky + posledních 20 snapshotů `case-memory/v{N}.json`; verze roste monotónně, `rollback_to(N)` obnoví starší obsah jako **novou** verzi. Zápisy z pipeline i serveru jdou pod souborovým zámkem.

## Ochrana proti otrávení (každý mantinel ověřen rozbij → spadne → vrať → projde)

| Mantinel | Chování |
|---|---|
| Rate limit | max 30 záznamů/h/zdroj, nadlimitní do karantény |
| Strop jednoho zdroje | pozdní zdroj max 50 % váhy typu po ≥ 10 efektivních případech (zakládající zdroj vyjmut; typ s jediným zdrojem to neblokuje – `Estimate.distinct_sources`) |
| Kontradikce | záznam proti robustnímu konsenzu (≥ 10 případů, střed > 0,85 / < 0,15, měřený **bez** záznamů posuzovaného zdroje) od zdroje s > 60 % rozporných posledních záznamů (min. 3) → karanténa, zdroj označen, jeho dřívější rozporné záznamy zpětně do karantény |
| Neprůkazné | nikdy se nepočítají |
| Neplatná váha | NaN/∞ → karanténa, jinak oříznutí na 0..1 |

Karanténa se nemaže (`quarantine_list()`). Prahy jsou konstanty v modulu.

## Historie ověření (část B)

`verification-history.json` (posledních 200 vzorků na metodu, atomicky pod zámkem) drží skutečné běhy vykonaných kontrol: `runtime_ms`, `network_cost` = 0,01 × počet HTTP požadavků, `information_gain` (zjednodušený proxy: 1,0 = kontrola dala verdikt tam, kde paměť žádný odhad neměla, nebo odporující dosavadní většině; 0,0 = jen potvrdila známé). `candidates_with_history` pro metody s ≥ 3 vzorky nahradí ruční odhady průměry z historie (`derive_candidate_from_samples`); `disruption_risk` a `requires_approval` zůstávají z katalogu – bezpečnostní rozhodnutí se neučí z rychlosti. Metody bez dost vzorků zůstávají na kuratorských konstantách. S prázdnou historií je katalog i plán bajtově shodný.

## Omezení (poctivě)

- Mapování výsledků na případy je úzké záměrně; dokud neběží ostré ověřování, paměť se plní hlavně operátorem.
- Cyklický případ: `cve_intel_relookup` čte data, ze kterých nález vznikl – má proto váhu automatického zdroje a nikdy sám nepřekročí strop pozdního zdroje.
- Kalibrace pravděpodobnosti proti skutečnému provozu se dá měřit až na dlouhém soak/replay běhu; zde je ověřena matematika a mantinely.
