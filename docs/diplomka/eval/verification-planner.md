# Verification Planner — VOI selekce (Deliverable 5)

**Status: implementováno a testováno (29. 10. 2026).** Nový modul `src/verification_planner.rs`, VEDLE `decision.rs` (pravidlová `TriageAction` generace) a `verification.rs` (porovnání výsledku běhu proti `ScenarioManifest` — jiný koncept, test-harness, ne výběr akce).

## Co bylo postaveno

Výběr nejlepší další ověřovací kontroly podle Expected Value of Information (návrh sekce 5.4):

```
utility(action) = expected_decision_loss_reduction - execution_cost - network_overhead - disruption_risk - delay_penalty
```

`expected_decision_loss_reduction = estimated_information_gain * hypothesis.potential_impact` — informace o hypotéze s vysokým dopadem je cennější snížit než o hypotéze s nízkým dopadem. `plan_verification()` seřadí kandidáty podle utility a **explicitně** vystaví `chosen_requires_approval()` — kandidát vyžadující schválení nikdy není tiše automaticky vykonán jen proto, že vyhrál v pořadí.

## Rozsah: jen SELEKCE, ne EXEKUCE

`deadline`/`budget`/`rate limit`/`max retries`/`idempotency key` z návrhu (sekce 5.4) jsou exekuční omezení — vyžadují skutečné spouštění akcí (Mininet/Containerlab lab, sekce 8.2), která je samostatná infrastrukturní investice. Vědomě vynecháno a zdokumentováno, ne fabrikováno — stejný princip jako u Deliverables 1-4. **Žádné volání `nmap.rs`/`webscan.rs` ani aktivní sken.**

`TypedUncertainty` z Deliverable 4 se vědomě NEpoužívá k váze utility — zprůměrování identity/observation/state os do jednoho čísla by bylo přesně to "falešně přesné" míchání, které Deliverable 4 zakazuje. `estimated_information_gain` je vstup od volajícího.

## Testováno (5 testů, syntetické scénáře)

- Vyšší information gain vyhrává při stejných nákladech.
- Vysoké `disruption_risk` prohraje proti bezpečnější alternativě s nižším gain.
- Kandidát vyžadující schválení **vyhraje v pořadí, ale je explicitně flagnutý** — test ověřuje obě věci zvlášť.
- Prázdná sada kandidátů → žádná vybraná akce (ne panic/default).
- Stejný kandidát má vyšší utilitu pro hypotézu s vyšším `potential_impact`.
