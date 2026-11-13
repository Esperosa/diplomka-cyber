# H3 — první skutečné měření: VOI-informovaný výběr vs. plošný ("blanket") sken (Deliverable 15)

**Status: naměřeno (29. 10. 2026).** Odblokovává `docs/diplomka/eval/h3-measurement-difficulty.md`, který identifikoval přesný chybějící předpoklad: lab/dataset s reálným aktivním inventářem **a** více nálezy různé jistoty současně, kde je navíc pasivní signál dostupný PŘED aktivní kontrolou (ne cirkulární znalost výsledku).

## Lab (`start_multiservice_lab`, `src/lab.rs`)

4 cíle, všechny ověřené ručně (`docker run` + `curl`) proti reálným výchozím obrazům PŘED zapsáním do kódu — stejná disciplína jako nález prometheus endpointu v Deliverable 7:

| Port | Image | Očekávaný nález (manifest napsaný před skenem) |
|---|---|---|
| 3000 | `bkimminich/juice-shop` | `salticus-prometheus-metrics-exposed` |
| 3001 | `grafana/grafana-oss:11.3.0` | `salticus-grafana-login-exposed` |
| 8000 | `python:3-alpine` (`python3 -m http.server 8000`) | `salticus-directory-listing-exposed` |
| 3003 | `nginx:alpine` (výchozí stránka) | žádný (čistý kontrolní cíl) |

Port 8000 (ne libovolný jiný) je zvolen záměrně — `webscan.rs::is_http_candidate` pozná HTTP cíl buď podle jména služby z nmap `-sV` detekce, nebo podle pevného seznamu známých webových portů. Pythonův `http.server` má nestandardní banner, který nmap `-sV` nerozpozná jménem jako "http" — ověřeno přímo (na portu 3002 httpx cíl vůbec neoskenoval). Port 8000 je na pevném seznamu, takže stejný obraz na tomto portu už httpx/nuclei správně zacílí.

## Metodika

**Blanket** = všech 8 kurátorovaných šablon (`resources/nuclei-templates/controlled/`) na všech 4 službách — to, co reálně proběhlo v jednom skenu (`run_active_scan_against_multiservice_lab`). **VOI-informovaný výběr** = funkce `voi_predict_template_from_passive_title()`, která z httpx titulku (dostupného PŘED jakoukoliv aktivní kontrolou) predikuje jednu konkrétní šablonu podle obecného pravidla ("titulek zmiňuje Grafana → zkontroluj grafana-login", "titulek zmiňuje directory listing → zkontroluj directory-listing"), ne podle zpětně odvozené znalosti výsledku tohoto konkrétního labu.

## Naměřeno

```
H3: blanket=4/4 spravne za 32 kontrol (spurious navic nalezy: [(3001, "salticus-prometheus-metrics-exposed"), (3001, "salticus-actuator-health-exposed")]) | VOI=2/3 spravne za 2 kontroly (chybi porty: [3000])
```

| | Blanket (8 šablon × 4 služby) | VOI-informovaný výběr |
|---|---|---|
| Správně rozlišené cíle | 4/4 | 2/3 (zranitelné cíle) |
| Počet provedených kontrol | 32 | 2 |
| Chybějící nález | žádný | Juice Shop (port 3000) |

## Interpretace

1. **VOI použil 16× méně kontrol (2 vs. 32) a správně zacílil 2 ze 3 reálných nálezů** — přesně tam, kde httpx titulek nesl specifickou, netriviální stopu (titulek "Grafana", titulek "Directory listing for /"). To je měřená, ne teoretická podpora H3: typovaná nejistota založená na levném pasivním signálu umí nahradit část plošného skenování bez ztráty přesnosti na informativních cílech.
2. **VOI správně minul Juice Shop** — přesně ten případ, který `h3-measurement-difficulty.md` předem identifikoval jako strukturálně neinformativní (httpx titulek "OWASP Juice Shop" nenese žádnou stopu k tomu, že appka vystavuje neautentizovaný Prometheus `/metrics`). Tohle NENÍ chyba VOI predikce — je to honestní, předem očekávaná mez levného pasivního signálu. Plná H3 claim by vyžadovala, aby VOI aspoň LEVNĚ ověřil i nejisté případy (např. jednu rychlou sondu), což tady není implementováno — VOI je zjednodušen na "specifická stopa → 1 cílená kontrola, jinak 0 kontrol", ne plný planner s fallbackem.
3. **Nečekaný, ale honestně zaznamenaný vedlejší nález**: blanket sken na Grafaně navíc spustil `salticus-actuator-health-exposed` (nízká závažnost) — falešně pozitivní nález. Grafana nemá reálný Spring Boot actuator endpoint; její SPA routing vrací na libovolnou neznámou cestu (`/actuator/health`) stejný app-shell se statusem 200, jehož JS bundle (slova: 3047) obsahuje slovo "status" naprosto triviálně. Šablona s jediným slovním matcherem (`words: ["status"]`) bez striktnější strukturální podmínky (např. JSON content-type) na tohle naskočí. Stejná třída chyby jako NTP false-positive nález z Deliverable 3 — plošné skenování není jen dražší, je i náchylnější k falešným poplachům, což je další, nezávislý argument pro VOI/typovanou nejistotu nad blanket sken, ne jen argument o nákladu.
4. **Grafana skutečně vystavuje i svůj vlastní `/metrics` endpoint** (Prometheus formát) — potvrzený, reálný druhý nález na stejné službě, ne artefakt testu. Nepočítá se do VOI/blanket skórování výše (manifest definuje jen 1 očekávaný nález per cíl), ale je zaznamenán jako spurious-navic nález pro úplnost.

## Honestní omezení

- **VOI heuristika je zjednodušená na 2 pravidla** (Grafana, directory listing) — neimplementuje skutečný EVOI vzorec z `verification_planner.rs` (ten pracuje s `estimated_information_gain` jako vstupním parametrem od volajícího, ne odvozeným z pasivního titulku). Tohle měření dokazuje, že princip "pasivní signál → cílená kontrola" funguje, ne že `verification_planner.rs` sám o sobě už tohle dělá.
- **4 cíle, 1 lab prostředí.** Zobecnění na jiné kombinace produktů/zranitelností vyžaduje víc labů nebo víc cílů v tomto — tohle je první měření, ne vyčerpávající důkaz.
- **"VOI correct" vyžaduje přesnou shodu s manifestem** — Grafanin vedlejší nález (`/metrics`) by naivní "cokoliv najde = úspěch" metrika počítala jako další bonus, zde se nepočítá, aby skóre zůstalo porovnatelné s předem definovaným očekáváním.
