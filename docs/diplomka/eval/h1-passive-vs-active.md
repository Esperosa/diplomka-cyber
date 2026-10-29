# H1 — první reálné měření: lehké vs. hlubší aktivní ověření (Deliverable 12)

**OPRAVA 29.10.2026 (nezávislý audit, N8):** původní verze tohoto dokumentu nazývala nmap+httpx variantu "pasivní". To je terminologicky nepřesné — nmap a httpx jsou aktivní nástroje (posílají pakety/HTTP požadavky cíli), ne pasivní odposlech (Zeek/Suricata), který návrh (sekce 5.1, 11) myslí "pasivní telemetrií". Přejmenováno na "lehký aktivní sken (nmap+httpx)" vs. "+ hlubší aktivní ověření (nuclei)". **Co tento test ve skutečnosti měří**: ne "pasivní vs. pasivní+aktivní" v doslovném znění H1, ale užší, přesto hodnotný dílčí nález — že hlubší aktivní kontrola (nuclei) najde to, co lehčí aktivní sken (nmap/httpx) nemůže, strukturálně. **H1 v doslovném znění** (skutečná pasivní telemetrie z Zeek/Suricata vs. +aktivní) zatím nebyla změřena vůbec — vyžaduje to lab s pasivním Zeek/Suricata snímkem vedle aktivního skenu (viz plán dalšího postupu).

**Status: naměřeno (29. 10. 2026), ale užší dílčí nález než H1 v doslovném znění.** Návrh (sekce 11): "H1: spojení pasivní a aktivní telemetrie zvýší kvalitu rozhodnutí proti samotné pasivní vrstvě za definovaných nákladů." Test `h1_active_checks_increase_decision_quality_over_passive_only` (název testu zůstává nezměněn kvůli zpětné kompatibilitě referencí, i když přesnější by bylo "light_active_vs_deeper_active").

## Metodika

**Stejná data ze stejného běhu**, ne syntetický protiklad: lab sken (Deliverable 7) produkuje `hosts` s `active_checks` pocházejícími výhradně z nuclei (`webscan.rs::attach_nuclei_checks`). "Lehká aktivní" varianta = klon téhož výsledku s vyprázdněnými `active_checks` na každé službě (nmap+httpx zůstávají — obě jsou aktivní nástroje, žádná skutečná pasivní telemetrie tu nefiguruje). Obě varianty jdou přes **stejnou nezměněnou** `build_report`→`generate_findings`→`decision::build_decision_bundle` logiku.

## Naměřeno

| | Lehký aktivní sken (nmap+httpx) | + hlubší aktivní ověření (nuclei) | Dodatečný náklad |
|---|---|---|---|
| Findings | 1 | 2 | 1 nuclei sken (8 kurátorovaných šablon) |
| Decision akce | 3 | 4 | + 1 GET požadavek (Deliverable 11) |

**Klíčový bod:** nález `prometheus-metrics-exposed` (a jeho 7 konkrétních citlivých metrik, Deliverable 11) **vůbec nevznikne** bez aktivní kontroly — nmap/httpx samy o sobě nemají způsob, jak exponovaný `/metrics` endpoint detekovat (httpx jen potvrdí "je tu web server", ne co konkrétně vystavuje). To je čistá, měřená, ne teoretická podpora H1: aktivní telemetrie přidala informaci, kterou pasivní vrstva strukturálně nemůže získat, za definovaný (malý, změřený) náklad.

## Honestní omezení

- **Toto NENÍ měření H1 v doslovném znění** — žádná skutečná pasivní telemetrie (Zeek/Suricata) tu nefiguruje, obě varianty jsou aktivní (lehký vs. hlubší sken). H1 jak je navržen zůstává nezměřen, dokud nebude existovat lab s paralelním pasivním snímkem.
- **Jeden lab cíl, jeden typ zranitelnosti (exposed metrics endpoint).** Tohle NEdokazuje ani tenhle užší nález obecně — dokazuje ho na jednom konkrétním, reprodukovatelném případu. Zobecnění vyžaduje víc lab scénářů s různými typy aktivních nálezů.
- **"Kvalita rozhodnutí" je tu proxy přes počet findings/akcí**, ne nezávisle ověřená správnost rozhodnutí (např. že akce byla skutečně ta nejlepší). To je hrubší metrika, než co H1 v plném rozsahu žádá — ale je to první skutečně změřené číslo, ne odhad.
- **"Definované náklady" jsou tu wall-clock** (~20s na celý test včetně startu kontejneru, nuclei sken samotný řádově sekundy) — ne formální cost model z Verification Planneru (Deliverable 5), který na tohle měření zatím nebyl napojen.
