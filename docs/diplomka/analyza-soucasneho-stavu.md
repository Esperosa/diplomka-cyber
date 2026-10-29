# Analýza současného stavu — Bakula (service-fingerprinting-passive-analysis)

**Datum:** 29. října 2026
**Status:** nezávislá analýza kódu (ne jen statická inspekce z chatu) — doplňuje a na místech opravuje sekci 2 a 2.1 dokumentu `BAKULA_kompletni_technicky_navrh_diplomova_prace.md`.

---

## 1. Backend — architektura a jádro

### 1.1 Celková struktura
- `main.rs` (117 KB) je monolitický CLI dispatcher — všechny subsystémy (nmap, passive import, server, simulation, evaluation, pentest) se volají přímo z `main()`. Odpovídá to „integrační pipeline", ne nasaditelné služby.
- `server.rs`: Axum HTTP server, jedna `AppState`, autorizace přes `authorize_for(&["permission"])`.
- `lib.rs`: jen deklarace modulů.

### 1.2 Autentizace — horší, než popisoval původní návrh
`src/server.rs:474-523`, `SecurityConfig::default()`:
- `require_api_token` je **výchozí `false`**, a to i v commitnuté konfiguraci `workspace_thesis_verify_current/bakula.toml` — jde o reálně používanou demo konfiguraci, ne jen teoretickou větev.
- Bez `platform_db`: každý request dostává `anonymous-admin` (plné `*` oprávnění).
- **Nový nález:** i při `auth_required = true` (bez platform DB) projdou čtecí endpointy (`*.read`, `metrics.read`) bez tokenu jako `anonymous-readonly`. Čtecí API je tedy fakticky vždy neautentizované, dokud není zapnutý `platform.enabled`.

### 1.3 Korelační a rozhodovací jádro — jádro budoucí diplomky je prázdné
- **`correlation.rs` `correlate_events()`**: 3 case `match` — `(ip,port,proto)` shoda → High, jen IP → Low, jinak unmapped. Časové okno (`time_window_s`) se jen kopíruje jako metadata, **nikdy neomezuje matching**. Žádný graf, žádná kauzalita, žádný stav mezi běhy.
- **`model.rs` `Confidence`**: `Low|Medium|High` s pevnou váhou (0.5/0.75/1.0). Žádné rozlišení typů nejistoty.
- **`report.rs`**: `host_key = host.ip` — identita hosta je čistě IP, bez kontinuity při DHCP/NAT změně. `score_services()` je čistě multiplikativní heuristika s ručně vymyšlenými konstantami (`exploit_floor=9.0`, `cpe_weight` 1.0/0.85/0.45/0.2...). `infer_asset_type()` dělá substring match na hostname (`"unifi"`, `"usw"`) — funguje jen pro demo síť s UniFi konvencí.
- **`decision.rs` `rank_finding()`**: start skóre 0.62/0.42/0.18 podle severity + přičítání konstant (CVE +0.16, plaintext +0.15, traffic +0.14...). `clamp(0,1)` jen navenek vypadá jako pravděpodobnost. Existuje netriviální `inference_graph_evidence` (deduction/induction/abduction kategorizace) — strukturovanější než prosté sčítání, ale pořád string-matching na `finding_type`.
- **`automation.rs` "konsensus"**: `neural_score()` — název navozuje ML, realita je lineární váhovaný průměr (váhy 0.30/0.34/0.36 ručně napsané) protažený sigmoidou. Pevné prahy 0.82/0.62/0.44 pro strong/review/weak.

**Zásadní zjištění pro diplomku:** přesně ta část, která má být hlavní inovací (`Observation → Hypothesis → Uncertainty → VOI → Learning`), v kódu **neexistuje ani v náznaku**. Current state = heuristický scoring. To je dobrá zpráva pro diplomku — čistý prostor bez nutnosti bourat něco funkčního, ale znamená to, že "lepší korelace než konkurence" je skutečně celý výzkumný úkol od nuly, ne vylepšení existujícího.

### 1.4 Pasivní sběr
- `passive/suricata.rs`, `passive/zeek.rs`, `lanes.rs`: všechno `fs::read_to_string()` celého souboru najednou, žádný streaming/checkpoint/rotace. `lanes.rs` čte JSON snapshoty (ntopng, Greenbone, Wazuh, SNMP, LibreNMS, Meraki, UniFi...) — jde o jednorázový import, ne živý collector.

### 1.5 Perzistence a broker — reprodukovatelné bugy, ne jen teoretická rizika
- **`platform.rs::claim_due_job`** (ř. 878-917): `WHERE status IN ('queued','scheduled','failed')` — `'running'` v seznamu chybí. Po pádu workeru mezi claim a dokončením job **zůstane navždy zaseknutý** v `running`. Reprodukovatelné worker-kill testem.
- **`broker.rs`**: `XREADGROUP`/`XACK`, bez `XAUTOCLAIM`, DLQ, idempotence. Pád konzumenta mezi claim a ack → zpráva navždy uvízne v pending entries.
- `storage.rs` (souborový workspace) + `external_sql.rs` (SQLite/Postgres) jsou dvě nekonzistentní persistence vrstvy vedle sebe.

### 1.6 Co návrh nezmiňoval, a existuje
- `ai.rs` + `assistant.rs` (~90 KB): lokální LLM copilot (Ollama `qwen3:8b`, finetune `bakula-skoky`) nad kontextem reportu — UI asistent, nesouvisí s detekčním jádrem.
- `evaluation.rs` / `verification.rs`: zárodek `ScenarioManifest`/`EvaluationSummary` — základ pro `bakula-evaluation` z návrhu už částečně existuje.
- `readiness.rs`: `ProductionReadinessReport` — projekt si už sám měří gap vůči produkci.
- `pentest.rs`, `simulation.rs`: interní pentest runner a syntetická data pro škálovací testy.

### 1.7 Testy a CI
- 44 `#[test]` v `src/`, 7 `#[ignore]` (chybí fixtures na čistém klonu), `tests/e2e.rs` (12 scénářů), `tests/mas_deep.rs`.
- CI: `cargo fmt`, `cargo clippy` (**`continue-on-error: true` — lint neblokuje**), `cargo test`, `npm run build:ui`. Žádný `cargo audit`/`npm audit`, žádné failure/chaos/perf testy, žádný security scan.

### 1.8 Bezpečnostní nálezy nad rámec návrhu
1. Anonymous-readonly bypass i při `auth_required=true` — horší než popsáno.
2. `claim_due_job` nikdy nezotaví `running` joby — reálný bug.
3. Broker bez pending-recovery/DLQ/idempotence.
4. CI clippy kosmetický, nic nebrzdí merge na lint findings.
5. Žádná automatická kontrola CVE v závislostech.
6. Identita hosta = IP bez historie/merge → fragmentace při DHCP.

---

## 2. Frontend/UI — koncept dobrý, dekorace je problém

### 2.1 Stack
Vanilla TypeScript + esbuild (žádný framework), `ui/app.js` (3515 řádků), `lucide` ikony (ne emoji), ruční CSS + téměř nevyužívaný Tailwind. Jedna stránka, žádný router, globální `state` + manuální re-render.

### 2.2 Rozvržení — zachovat koncept
Tři plochy: **left-rail** (status/ovládání/data/diagnostika/export/historie běhů) — **center-stage** (topologie graf nebo reader mode) — **right-stage** (hero metriky → taby Rizika/Stanice/Sběr/Kroky/Změny → detail, nebo AI chat). Dva focus režimy zvětší jednu plochu a ztlumí druhou (`opacity:0.34`), žádné modály.

**Co je reálně dobré a zůstává:**
- Klávesové zkratky (`Esc`, `r`, `s`, `l`, `p`, `a/m/v/c`, `+/-/0`, šipky, `/`) — skutečná profesionální ovládací vrstva.
- Stavový model s historií běhů a diffem proti předchozímu běhu.
- Žádný scroll, cockpit přístup — správný instinkt pro monitoring nástroj.
- Žádné emoji, lorem placeholdery, "hero + 3 kartičky" marketingové klišé.

### 2.3 Konkrétní AI-slop nálezy
- **Mrtvý kód** `tailwind.config.cjs:5-33`: nepoužívaná paleta `emeraldfx/violetfx/magentafx` (fialovo-magenta) + animace `floaty/pulseflow/breathe` — typický opuštěný "AI generated SaaS dashboard" scaffold. Nikde v `ui-src` se nepoužívá — **smazat bez rizika**.
- **`.panel-shell`** (`base.css:169-193, 303-313`) na **každém** panelu: `backdrop-filter: blur()`, gradient pozadí, dvojitý box-shadow, inset highlight, `::before` gradient vrstva navrch — klasický glassmorphism recept nasazený univerzálně.
- `.brand-mark` s gradient-glow bublinou, scrollbar s gradient thumbem, `radius-chip: 62.4375rem` (plné pill tvary všude).
- Glow na **každém** uzlu topologie (`graph.ts` `nodeGlow`/`hubGlow` radial gradienty + extra glow circle) — neonový dojem místo klidného technického diagramu.
- Font `Inter` — bez vlastní identity, nejběžnější "default" volba.
- Nekonzistentní proměnná `--violet: #38bdf8` (ve skutečnosti modrá) — matoucí pro údržbu.

### 2.4 Chybí pro produkční nástroj
Filtrování/vyhledávání v tabulkách nálezů, hromadné akce (bulk triage), řazení sloupců, `aria-live` region pro nové incidenty, čitelnější labely v diagnostickém panelu (`"C 72% / P 88% / Q 40 / B 2"` je nejasné bez legendy).

---

## 3. Syntéza — kde je skutečná příležitost

1. **Korelační jádro je prázdná plocha, ne něco k vylepšení.** Design doc kapitola 5 (Uncertainty-Driven Security Intelligence Engine) je přesně ten výzkumný prostor, který diplomka má zaplnit — a je to i jediná cesta, jak být měřitelně jinde než konkurence (Fortinet/Splunk/Wazuh dělají scoring/pravidla, ne typovanou nejistotu + VOI-driven verification planning).
2. **UI redesign je z větší části odstraňování, ne tvorba od nuly.** IA (tři plochy, klávesové zkratky, stavový audit trail) je solidně navržená a profesionální — "unslop" průchod = smazat dekorativní vrstvu (blur/gradient/glow) a doplnit chybějící pracovní nástroje (filtry, bulk akce), ne redesignovat rozvržení.
3. **Produkční bezpečnost má konkrétní, opravitelné díry dřív, než cokoliv jde do produkce**: anonymous-readonly bypass, zaseknuté joby, broker bez recovery. Tyto 3 věci jsou malé, izolované opravy (P0), ne architektonický přepis.
4. **Testovací matice (sekce 9 návrhu) je z 90 % nenaplněná** — existující testy ověřují jen funkční jednotkovou/e2e vrstvu nad statickými fixturami, nic k výkonu, chaosu, bezpečnosti nebo multi-tenant izolaci.
