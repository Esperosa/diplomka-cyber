# H3 — proč jednoduché "VOI vs. blanket scan" měření na Juice Shop labu nestačí

**Status: metodologický nález (29. 10. 2026), ne vyřešeno.** Při návrhu přímého testu H3 ("typovaná nejistota a VOI-based planner dosáhne stejné či vyšší přesnosti s menším počtem aktivních kontrol oproti pravidelnému plošnému skenu") na existujícím Juice Shop labu (Deliverable 7/8/11/12) jsem narazil na reálný problém, ne na otázku implementace.

## Problém

Juice Shop v tomto labu vystavuje přesně **1 z 8** kurátorovaných nuclei kontrol (prometheus-metrics-exposed). Aby "VOI-informed výběr podmnožiny kontrol" byl smysluplný test (ne cirkulární), potřeboval by se opřít o **pasivní signál dostupný PŘED aktivní kontrolou**, který by racionálně napověděl, kterou z 8 kontrol vybrat jako první. Zkontrolováno: httpx u tohoto cíle vrací jen titulek "OWASP Juice Shop" a standardní HTTP headery — nic, co by odlišilo "pravděpodobně má exponované Prometheus metriky" od "pravděpodobně má exponovaný Swagger/Grafana/Kibana/Actuator panel". Kdybych teď napsal test, který "informovaně" vybere prometheus-metrics-exposed jako první, byl by to cirkulární podvod — vím to jen proto, že jsem už viděl výsledek v Deliverable 7.

## Druhý pokus (varianta 2) — a proč je taky blokovaná, potvrzeno v kódu

Zvažoval jsem přerámování H3 na binární "escalovat na aktivní ověření, nebo ne" rozhodnutí podle `hypothesis.rs`'s `observation` nejistoty, testované na existujících IoT-23/CTU-13 findings (ne na labu). **Ověřeno přímo v `src/correlation.rs::correlate_events()` (řádky 3-33): v CELÉM současném eval harnessu (ablace A-D) se volá vždy s `hosts: &[]`** (žádný aktivní inventář nikdy neexistuje pro passive-only datasety). `hosts.iter().find_map(...)`/`hosts.iter().find(...)` nad prázdným slice vždy vrátí `None` — **každý jediný korelovaný event tedy vždy spadne do `else` větve: `method="unmapped"`, `confidence=Confidence::Low`, bez jediné výjimky.** V `observation` nejistotě (Deliverable 4) proto není v tomhle harnessu ŽÁDNÁ variance, na které by se dalo postavit escalate/ne-escalate rozhodnutí — je to konstanta, ne signál.

Na Juice Shop labu je to naopak: tam `hosts` reálný inventář MÁ (z nmap skenu) a confidence variance by teoreticky existovala, ale je tam jen **1 finding** (Deliverable 7/8) — žádná variace k porovnání policy proti.

## Skutečný požadavek na infrastrukturu (potvrzeno, ne jen domněnka)

Smysluplný test H3 vyžaduje **dataset/lab s PÁROVANÝM aktivním inventářem (reálný `hosts: &[HostReport]`, ne prázdný slice) A VÍCE nálezy s různou confidence** současně. Žádný z dosavadních zdrojů (IoT-23, CTU-13 — čistě pasivní; Juice Shop lab — aktivní, ale jen 1 nález) tuhle kombinaci nemá. To je konkrétní, zdůvodněný požadavek na další krok (víc lab cílů NEBO dataset s párovaným active+passive snímkem), ne vágní "potřebuje to víc infrastruktury".

## Proč to zapisuji, ne tiše zahazuji

Vynucený test by tu nutně byl buď cirkulární (Juice Shop) nebo degenerovaný na konstantu (IoT-23/CTU-13 harness) — vypadal by jako potvrzení, ale byl by to artefakt návrhu testu, ne skutečný důkaz. Přesně to je důvod, proč se v tomto projektu dělá ablační/honest měření místo tvrzení "funguje".
