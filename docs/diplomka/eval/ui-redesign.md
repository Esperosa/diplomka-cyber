# Nové UI (31. 10. 2026)

Náhrada původního UI z bakalářky (`ui-src/` a sestavený `ui/`). Zadání: silné zjednodušení, žádný AI vzhled, jasně oddělené plochy, k tomu Nothing OS 5.0 s organickým minimalismem.

## Princip

- Monochrom (teplá šedá a černá), jediná signální červená. Červená znamená "tady je něco, co čeká na člověka" (vysoká závažnost, zásah ke schválení, narušený audit). Nikde není jako dekorace.
- Velká čísla jsou tečkomaticová (5×7). Glyfy jsou nakreslené v `ui-src/dotmatrix.ts` jako SVG kruhy, žádný cizí font se nedodává (`@font-face` v bundlu není, kontroluje to `npm run test:ui`).
- Data jsou monospace, texty systémové písmo. Kvůli češtině se nespoléhá na žádný stažený font.
- Organická vrstva: hlavní plochy mají záměrně nesymetrické rohy, widgety jsou pilulky a kruhy, stanice jsou oblázky v poli s vrstevnicemi. Tvar oblázku je deterministický z klíče stanice (stejná stanice vypadá stejně v každém běhu).

## Plochy

| Plocha | Obsah |
|---|---|
| Přehled | Pole stanic (velikost = význam, tečky na obvodu = riziko, přerušení obrysu = nejistota), souhrn běhu, tečkomaticové údaje |
| Hostitelé | Seznam a detail stanice, služby, CVE, CPE, události; záložka síťových aktiv |
| Nálezy | Nálezy s hypotézou. Šest os nejistoty. Osa, kterou model nepočítá, je "neznámé" (přerušovaný meter), nikdy 0 % |
| Ověřování | `verification_plans` (pořadí kandidátů, užitečnost, schválení, vyřazení mimo rozsah) a `verification_results` |
| Zásahy | Návrh, schválení a zamítnutí blokace IP. Banner režimu (zkušební/ostrý), odpočet TTL, srozumitelná hlášení `ProtectedRange`, `TtlExceedsMaximum`, `UnparseableIp`, `AlreadyActive`, 403 vypne tlačítka s vysvětlením |
| Audit | Záznam jen pro čtení a odznak integrity hash řetězce (`/api/audit/verify`) |
| Automat | Stav autopilota, připravenost, schopnosti, spuštění a vynulování běhu |
| Asistent | Panel zprava, streamovaná odpověď, kontext vybraného nálezu nebo stanice |

## Poctivost dat

UI nic nedopočítává. Pole, která server nepošle, se ukážou jako "neznámé". Endpointy, které server nemá (404), mají prázdný stav s vysvětlením, ne falešná data. Mock data žijí jen v `scripts/mock-server.mjs`.

## Bezpečnostní drobnosti

- Token se drží v `sessionStorage` (starý z `localStorage` se jednorázově převezme a smaže).
- Všechny mutace posílají `X-Bakula-Csrf: 1`. Starý `ui-src` tuhle hlavičku nikdy neposílal (opravu dělal jen sestavený `ui/app.js`).
- Souběžné 401 otevřou jediný dialog pro token.
- Schválení zásahu a spuštění agresivního běhu jdou přes potvrzovací dialog.

## Přístupnost a pohyb

Kontrast tokenů se počítá v `scripts/ui-smoke.mjs` (AA, oba režimy). Celé UI jde ovládat klávesnicí, fokus je vidět, dotykové cíle mají 44 px, stránka se nescrolluje (posouvají se jen vnitřní plochy), na telefonu přejde dok dolů a seznam/detail se střídají. `prefers-reduced-motion` vypne drift oblázků i dýchání stavové tečky. Dýchá jen malá tečka a jen když autopilot opravdu běží.

## Co se vědomě nedělalo

- Žádné logo ani maskot. Název je text "Bakula".
- Žádný framework, žádný Tailwind (`tailwind.config.cjs` zůstává jako prázdný stub jen kvůli `COPY` v `Dockerfile`).
- Role se neodhaduje předem. UI se dozví o chybějícím oprávnění až z 403 a tlačítka vypne.

## Příkazy

```
npm ci && npm run build:ui     # sestavení do ui/
npm run typecheck:ui           # TypeScript
npm run test:ui                # statické kontroly + e2e (Edge headless)
npm run mock:ui                # maketa API na http://127.0.0.1:8787/
npm run shots:ui               # snímky všech ploch (světlý/tmavý, desktop/tablet/telefon)
```

Varianty makety: `MOCK_ROLE=analyst`, `MOCK_AUTH=1`, `MOCK_EMPTY=1`, `MOCK_MODE=enforce`, `MOCK_CHAIN_BAD=1`, `MOCK_RUNNING=1`.
