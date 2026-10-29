# Verification Planner: EVOI vstupy odvozené z reálných měření (Deliverable 23)

**Status: naměřeno (29. 10. 2026).** Adresuje audit finding N6: `VerificationCandidate.estimated_information_gain`/`estimated_network_cost`/`estimated_runtime_ms` byly od Deliverable 5 vždy konstanty napsané v testu, ne odvozené z dat. Tohle je **cílený, omezený fix**, ne postavení plného Case Memory, které návrh (sekce 5.6) definuje s verzováním a poisoning guardem pro UČENÍ KLASIFIKACE — tu investici master plán vědomě nepostavil jako neúměrnou jedné hypotéze (`dalsi-postup-master-plan.md`). Důvod, proč je tenhle fix přesto bezpečný bez poisoning guardu: jde o statistiku **nákladu/času jedné konkrétní akce**, ne o učení "je tohle malicious/benign" — chybný odhad nákladu vede nanejvýš k horšímu plánování, ne k tichému zfalšování bezpečnostního rozhodnutí (riziko #8 v návrhu sekci 12 cílí na tu druhou kategorii).

## Co bylo postaveno

- **`src/case_history.rs`** — `ExecutionSample { runtime_ms, network_cost, information_gain }`, `derive_candidate_from_samples()`: průměr z `N` reálných měření nahrazuje konstantu. Panikne na prázdném vstupu — "odvodit z dat" bez dat je kontradikce, ne případ k tichému defaultu.
- **Test** `verification_candidate_derived_from_repeated_real_measurements_not_a_guessed_constant`: `execute_inspect_metrics_content` (Deliverable 11) zavoláno **5×** proti reálnému Juice Shop labu, každé volání časované (`Instant::now()`), `information_gain` odvozen z reálného počtu nalezených citlivých metrik, `network_cost` z reálné velikosti odpovědi (řádky).

## Naměřeno

```
Deliverable 23: 5 realnych mereni, runtime_ms=2 (jednotliva: [3, 2, 2, 2, 2]) network_cost=0.0020 information_gain=0.70 | puvodni rucne zvolena konstanta (D8/D11): 500ms/0.02/0.6
```

| | Původní ruční konstanta (D8/D11) | Odvozeno z 5 reálných měření (D23) |
|---|---|---|
| `estimated_runtime_ms` | 500 | **2** |
| `estimated_network_cost` | 0.02 | **0.0020** |
| `estimated_information_gain` | 0.6 | **0.70** |

## Interpretace

**Původní ruční odhad runtime byl ~250× vyšší než realita.** To je přesně ten typ chyby, který EVOI-z-dat má opravit — planner by s chybným, přehnaně konzervativním odhadem nákladu/času mohl v jiném scénáři (kde rozdíl mezi kandidáty je menší) zvolit horší akci jen kvůli nepřesnému vstupu, ne kvůli chybné utility funkci samotné. V tomhle konkrétním testu planner zvolil správně i s původní konstantou (`inspect_metrics_content` byl nejlevnější v obou verzích) — hodnota tohoto fixu je v **přesnosti vstupu**, ne ve změně výsledného rozhodnutí na tomhle jednom příkladu.

## Honestní omezení

- **Jen 1 ze 3 kandidátů je teď data-driven.** `broad_nuclei_rescan_full_template_set`/`escalate_to_human_review` zůstávají ruční odhady — žádná historie pro ně ještě nebyla naměřena. Zapsáno explicitně, ne zamlčeno.
- **5 opakování na 1 statické stránce** — `information_gain` je identický ve všech 5 (stejná statická odpověď), takže ukazuje jen variabilitu `runtime_ms` (síťový jitter), ne variabilitu informačního přínosu. Skutečná variabilita gain by vyžadovala měnící se cíl mezi opakováními.
- **Žádná persistence mezi běhy testu** — historie se staví a zahazuje uvnitř jednoho testu, ne v trvalém úložišti napříč spuštěními. To je vědomě užší než Case Memory, ne jeho zjednodušená verze se stejnými zárukami.
