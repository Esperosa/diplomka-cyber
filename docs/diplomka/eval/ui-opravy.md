# Oprava UI Skákavky: stav po bodech 1–18

Stav k 2026-11-01. Změny nejsou commitnuté. Mock server běží na portu 8851 (showcase).
Snímky jsou v `C:\Users\Creator\.t3\userdata\browser-artifacts\`. Náhled prohlížeče je v nich zmenšený na 1280 px, takže drobný text na nich není čitelný. Důkazem jsou proto hlavně měření přes `preview_evaluate`.

Legenda stavu: **Hotovo** = opraveno a změřeno. **Částečně** = opraveno jen část nebo bez úplného ověření. **Nesplněno** = nezačato.

## Tabulka

| Bod | Stav | Příčina | Změna (soubory) | Ověření | Co se nepodařilo |
|---|---|---|---|---|---|
| 1. Zbytečný text a místo | **Hotovo** | Filtry byly řada čipů nad mapou (`barHtml` v `mapctl.ts`), nadpis „Mapa sítě“ byl viditelný `paneHead`. | `ui-src/mapctl.ts` (`barHtml`, `syncBar`), `ui-src/views/overview.ts` (skrytý `<h1>`, odebrán `side-hint`), `ui-src/styles/netmap.css` (blok „filtry“ přepsán na levý výsuvný panel, mobilní pravidla vyčištěna). | Před: `…/browser-screenshot-…-mvy6b3yg-e6d1f296.png`. Po, zavřeno: `…-mvy6dotd-cf5a2ec2.png` (mapa 797 px vysoká, řada čipů pryč). Po, otevřeno: `…-mvy6dwpi-d56618ba.png`. Měřeno: `.mb-body` má po otevření `visibility: visible`, `aria-expanded=true`, sekce „Hledat / Závažnost / Podsíť-VLAN / Typ zařízení“ s počty. | Neověřen vizuální stav „Zobrazeno N z M“ při aktivním filtru (kód existuje, netestováno klikem). |
| 2. Žádné hranaté označení | **Hotovo** | Prohlížeč kreslí u SVG `<g tabindex>` obdélníkový outline (`auto 5px`) po kliku, protože `:focus` neměl `outline: none`. | `ui-src/styles/base.css` (`:focus { outline: none }` před `:focus-visible`, globální `-webkit-tap-highlight-color`). | Před klikem na zónu: `outline: auto 5px` na `g.zbub`. Po: `none` (u zóny, uzlu `.node` i dokové položky `A`). Měřeno `getComputedStyle`, ne snímkem. | Neměřeny čipy, položky seznamu a tlačítka zvlášť (pravidlo je globální, ale neklikal jsem na ně). |
| 3. Žádný vodorovný scroll | **Hotovo** | Původní řada čipů (zrušena bodem 1). Jediný zbylý přetok: `ASIDE.side` 348/341 px při 2000 px. | `ui-src/styles/views.css` (`.side { overflow-x: hidden }`), `ui-src/styles/netmap.css` (čipy se zalamují, `.chiprow` bez `overflow-x`). | Měření všech 7 sekcí při 2000, 1440, 1280, 1024, 390 px: 0 prvků s `overflow-x` auto/scroll a `scrollWidth > clientWidth+1`; `documentElement.scrollWidth` = `innerWidth` všude. | Test kontroluje jen `auto/scroll`, prvky s `hidden` nezkoumám. |
| 4. Ikony v mapě vždy | **Částečně** | `.nicon` byl `display:none`, dokud `show-icons` (scale ≥ 0,95). Uzly v zavřených zónách mají `visibility: hidden`, takže přehled ikony uzlů neukazuje (ikony čtyř největších skupin v zóně už byly). | `ui-src/styles/netmap.css` (`.nicon` vždy `inline`, `.nk` pro minimální velikost), `ui-src/netmap.ts` (obal `<g class="nk">`), `ui-src/mapview.ts` (`--nk = max(1, 7 px / (r_min · s))`, `MIN_NODE_PX = 7`). | Otevřená zóna, oddálení třemi kroky: nejmenší bublina 7,0 px na obrazovce, 49/49 ikon viditelných. Snímek: `…-mvy6j03h-f7f97526.png`. | Nebylo uděláno: zjednodušená varianta ikony při malé velikosti, a ověření při plném oddálení s otevřenými všemi zónami. Ikona „web“ (17b) nezměněna. |
| 5. Plynulost a blikání | **Částečně** | `renderStage` každou obnovu (každých 15 s a po každé akci) přepisoval `stage.innerHTML`, takže se mapa znovu stavěla i beze změny dat. | `ui-src/main.ts` (`renderStage` porovnává `section + html` s posledním vykreslením; `renderShell` resetuje). | Tři vynucené obnovy (`visibilitychange`, 8 API dotazů každá) s nezměněnými daty: **0 mutací** a stejný uzel `svg.netmap`. Srovnání „před“: starý přepis by znovu postavil 2473 prvků (nasimulováno přepsáním `innerHTML`). | Když se data změní, celá sekce se pořád přepíše (není inkrementální aktualizace po uzlech). Zoom a výběr při změně dat nejsou ověřeny. |
| 6. Scroll v seznamech | **Částečně** | `data-keep` byl na `<nav>` uvnitř `.split-list`, ale posouvá se `.split-list` (`overflow: auto`). Obnova `scrollTop` se tak netýkala posuvného prvku. | `ui-src/views/hosts.ts` a `ui-src/views/findings.ts` (`data-keep` přesunut na `.split-list`). | Stanice: `scrollTop` 400 před kliknutím, 400 po kliknutí, řádek vybrán, detail zobrazen. | Nálezy opraveny stejným způsobem, ale neměřeny. Další seznamy (audit, automat, verifikace) neprověřeny. |
| 7. Goo přechody stránek | **Nesplněno** | Nezkoumáno do hloubky, nic neimplementováno. | — | — | Vlastní dvouvrstvý přechod, zvlněná hrana a měření snímků v čase nejsou hotové. |
| 8. Tlačítka a přepínače | **Nesplněno** | Nezkoumáno, nic neimplementováno. | — | — | Goo stisk, přelévání bubliny u segmentů a nahrávka snímků nejsou hotové. |
| 9. Okraj mapy neořezávat tvrdě | **Částečně** | Obsah SVG se ořezával hranou pole. | `ui-src/styles/netmap.css` (`.netmap`: `mask-image` ze dvou gradientů, `--edge: 18px`). | Build a testy zelené. Vizuálně neověřeno. | Rozostření u okraje nebylo implementováno. Snímek uzlů u okraje nepořízen. |
| 10. Scroll/zoom mezi úrovněmi | **Nesplněno** | Nezkoumáno. | — | — | Prah pro návrat na „celou síť“ a hystereze nejsou hotové. |
| 11. Odznaky a popisky bez kolizí | **Nesplněno** | Nezkoumáno. | — | — | Umístění bez kolizí a měření překryvů nejsou hotové. |
| 12. Rozestupy uzlů | **Nesplněno** | Nezkoumáno (konstanty `SPACING` a rozložení v `netmodel.ts`). | — | — | Změna rozestupů a měření minimální vzdálenosti nejsou hotové. |
| 13. Toky provozu mezi zařízeními | **Nesplněno** | Funkce neexistuje. | — | — | Typ `trafficEdges`, vykreslení, částice, mock data a legenda „provoz není v datech“ nejsou hotové. |
| 14. Text z teček (dotmatrix) | **Nesplněno** | Nezkoumáno. | — | — | Kostra písmen, SVG path a zkušební stránka nejsou hotové. |
| 15. Napojení bublin (metaball) | **Nesplněno** | Na přiloženém snímku je vidět ostrá hrana na místě napojení mostu a kruhu. Mosty se skládají z oddělených tvarů (`bridgePath`, `gooArc`, `dock`). | — | Prohlédnut přiložený snímek `…-ce674e98….png`. | Jediná souvislá křivka (G1 napojení, numerický test tečen, zoom 400 %) nebyla implementována. |
| 16. Okraje mapy se usekávají brzo | **Částečně** | Měkké mizení bylo 32 px dovnitř. | `ui-src/styles/netmap.css` (`--edge: 18px`). | Build a testy zelené. Snímek čárkované cesty u okrajů nepořízen. | Vnitřní odsazení nebylo odstraněno a neověřil jsem, že SVG vyplňuje celé pole. |
| 17. Odsazení v oknech panelů | **Nesplněno** | Proměnná `--pane-pad` nebyla zavedena, odsazení neměřeno. | — | — | Jednotné odsazení, měření `getBoundingClientRect` a kontrola všech panelů nejsou hotové. |
| 17b. Ikona „web“ podobná kameře | **Nesplněno** | Ikona nebyla překreslena. | — | — | Nová ikona, porovnávací stránka a její smazání nejsou hotové. |
| 18. Rozbalení asistenta (FLIP) | **Nesplněno** | Nezkoumáno, nic neimplementováno. | — | — | Animace přes transform, vzorkování rAF a snímky v čase nejsou hotové. |

## Testy a kontroly

- `npx tsc -p tsconfig.ui.json`: bez chyb (několikrát, po každé větší změně).
- `npm run build:ui`: úspěšně.
- `node scripts/ui-smoke.mjs`: v pořádku.
- `npm run test:ui` jako celek **nespustil**. Výchozí `E2E_PORT_BASE=8800` obsadí porty 8801–8806, které patří cizím procesům. Spustil jsem proto ekvivalent s `E2E_PORT_BASE=8870`: smoke a `ui-e2e.mjs`, výsledek **34/34**.
- Tři E2E testy jsem upravil, protože popisovaly odstraněný stav (`scripts/ui-e2e.mjs`):
  - „Mapa (filtry)“ a „Mapa (statistika)“: před kliknutím na čip nově otevřou panel tlačítkem Filtry. Čipy jsou od bodu 1 uvnitř zavřeného panelu.
  - „Mapa (mobil 390)“: původně vyžadoval, aby se čipy vodorovně scrollovaly. Podle bodu 3 má být vodorovný scroll pryč, proto test nově kontroluje, že čipy nepřetékají. Název testu je upraven stejně.
- Soubor `ui-src/styles/netmap.css` se během práce změnil i mimo mou relaci. Tuto změnu jsem neprohlížel a nevracel jsem ji. Poslední běh testů proběhl až po ní.

## Co zbývá (poctivě)

Splněno je bod 1, 2, 3 a z velké části 4, 5 a 6. Body 7, 8, 10, 11, 12, 13, 14, 15, 17, 17b a 18 jsou nesplněné, stejně jako úplné dokončení 9 a 16 (neověřené vizuálně). Každý z nich je samostatný kus práce, který si zaslouží vlastní krok s měřením.
