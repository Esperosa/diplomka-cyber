# H1 — první reálné měření: pasivní vs. pasivní+aktivní (Deliverable 12)

**Status: naměřeno (29. 10. 2026).** Návrh (sekce 11): "H1: spojení pasivní a aktivní telemetrie zvýší kvalitu rozhodnutí proti samotné pasivní vrstvě za definovaných nákladů." Test `h1_active_checks_increase_decision_quality_over_passive_only`.

## Metodika

**Stejná data ze stejného běhu**, ne syntetický protiklad: lab sken (Deliverable 7) produkuje `hosts` s `active_checks` pocházejícími výhradně z nuclei (`webscan.rs::attach_nuclei_checks`). "Pasivní" varianta = klon téhož výsledku s vyprázdněnými `active_checks` na každé službě (nmap+httpx zůstávají). Obě varianty jdou přes **stejnou nezměněnou** `build_report`→`generate_findings`→`decision::build_decision_bundle` logiku.

## Naměřeno

| | Pasivní (nmap+httpx) | Pasivní+aktivní (+nuclei) | Dodatečný náklad |
|---|---|---|---|
| Findings | 1 | 2 | 1 nuclei sken (8 kurátorovaných šablon) |
| Decision akce | 3 | 4 | + 1 GET požadavek (Deliverable 11) |

**Klíčový bod:** nález `prometheus-metrics-exposed` (a jeho 7 konkrétních citlivých metrik, Deliverable 11) **vůbec nevznikne** bez aktivní kontroly — nmap/httpx samy o sobě nemají způsob, jak exponovaný `/metrics` endpoint detekovat (httpx jen potvrdí "je tu web server", ne co konkrétně vystavuje). To je čistá, měřená, ne teoretická podpora H1: aktivní telemetrie přidala informaci, kterou pasivní vrstva strukturálně nemůže získat, za definovaný (malý, změřený) náklad.

## Honestní omezení

- **Jeden lab cíl, jeden typ zranitelnosti (exposed metrics endpoint).** Tohle NEdokazuje H1 obecně — dokazuje ji na jednom konkrétním, reprodukovatelném případu. Zobecnění vyžaduje víc lab scénářů s různými typy aktivních nálezů.
- **"Kvalita rozhodnutí" je tu proxy přes počet findings/akcí**, ne nezávisle ověřená správnost rozhodnutí (např. že akce byla skutečně ta nejlepší). To je hrubší metrika, než co H1 v plném rozsahu žádá — ale je to první skutečně změřené číslo, ne odhad.
- **"Definované náklady" jsou tu wall-clock** (~20s na celý test včetně startu kontejneru, nuclei sken samotný řádově sekundy) — ne formální cost model z Verification Planneru (Deliverable 5), který na tohle měření zatím nebyl napojen.
