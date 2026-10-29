# Hypothesis/Uncertainty vrstva (Deliverable 4) — typovaná nejistota

**Status: implementováno a testováno (29. 10. 2026).** Nový modul `src/hypothesis.rs`, VEDLE `decision.rs` — `rank_finding`/`RankedDecision` se nemění. Napojení na rozhodování (nahrazení ad-hoc scoringu v `rank_finding`) je navazující, samostatný krok.

## Problém

`model.rs::Confidence` (`Low|Medium|High`, pevná `weight()`) je jediná míra "jistoty" v celém systému — slučuje do jednoho čísla úplně odlišné věci (spolehlivost korelace, kvalita identity, stav zařízení). Návrh (sekce 5.3) explicitně zakazuje "směšovat důvěru v identitu s pravděpodobností kompromitace ani s prioritou incidentu" a chce 6 typů nejistoty: aleatorickou, epistemickou, identity, observation, state, interpretation.

## Řešení

`TypedUncertainty` — explicitní `Option<f64>` pole (ne `BTreeMap`, viz zdůvodnění v kódu: mapa by tiše schovala rozdíl mezi "záměrně nepočítáno" a "zapomenuto naplnit"), `SecurityHypothesis` obohacující `Finding` o `uncertainty`, `potential_impact`, `probability` (vždy `None`, `supporting_evidence`/`contradicting_evidence`.

**Derivováno z existujících Deliverables 2/3 signálů:**
- `identity` — z `IdentityMatch` (Same=0.1, New=0.5, Ambiguous=0.85).
- `observation` — z `Confidence`, PŘEBITO na 0.95 když `CorrelationInfo.method == "unmapped"` (nevíme, ke kterému assetu událost patří — to je horší než jen nízká confidence na známém assetu).
- `state` — z `InventoryRecord` (potvrzená verze + High confidence = nízká nejistota; chybějící verze nebo nízká confidence = vysoká).

**Vědomě NEpočítáno** (vrací `None`, ne fiktivní číslo):
- `aleatoric`, `epistemic`, `interpretation` — vyžadují historickou baseline/Case Memory (sekce 5.6), která v systému ještě neexistuje.
- `probability` — žádný placeholder odvozený z `Confidence::weight()`. To by jen přesunulo přesně ten problém, který návrh zakazuje ("raději ordinální skóre než falešně přesné procento"), o jednu vrstvu dál.
- `contradicting_evidence` — vždy prázdné, žádný mechanismus na detekci rozporujících důkazů dnes neexistuje.

## Testováno

5 testů na syntetických kombinacích `Finding`/`CorrelationInfo`/`IdentityMatch`/`InventoryRecord` (ne nový dataset — jde o korektnost derivace, stejná kategorie jako testování Identity vrstvy): identity nejistota roste Same→New→Ambiguous, observation nejistota roste s klesající confidence a `unmapped` ji přebíjí na maximum, state nejistota rozlišuje potvrzenou vs. neznámou verzi, a **regresní test** potvrzující, že aleatorická/epistemická/interpretační nejistota a `probability` zůstávají `None` — pokud tento test v budoucnu začne padat, je to záměrná změna (Case Memory implementováno), ne regrese k opravení zpět.

## Omezení (explicitně)

Tohle je typová struktura + částečná heuristická derivace, ne kalibrovaný probabilistický model. Kalibrace (ověření, že `probability` odpovídá skutečné frekvenci výskytu) vyžaduje Case Memory a historická data, která projekt ještě nemá — to je budoucí práce (Verification Planner, sekce 5.4-5.6 návrhu), ne tvrzení o současné vyřešenosti.
