# H1 v doslovném znění: skutečný Zeek passive capture vs. passive+active (Deliverable 21)

**Status: naměřeno (29. 10. 2026).** Opravuje mezeru zapsanou v Deliverable 15/N8: dosavadní "H1 měření" (Deliverable 12) porovnávalo dvě aktivní varianty (nmap+httpx vs. +nuclei), ne skutečnou pasivní telemetrii. Tohle je první měření s **reálným Zeek** (verze 9.0.1, offline analýza reálně zachyceného provozu), ne s nmap/httpx jako náhradou.

## Jak to funguje

1. Juice Shop lab (Deliverable 7) běží jako obvykle.
2. `tcpdump` sidecar kontejner (`corfr/tcpdump`) sdílí network namespace s Juice Shop kontejnerem (`docker run --network container:<jméno>`) — vidí přesně ten samý provoz, jaký by viděl síťový tap, bez nutnosti host-network módu (který Docker Desktop na Windows neumí).
3. Aktivní sken (nmap+httpx+nuclei) proběhne jako obvykle — tcpdump zachytí jeho provoz do `.pcap`.
4. `zeek/zeek:9.0.1` zpracuje `.pcap` OFFLINE (`zeek -C -r`) — stejná binárka, co by běžela v produkci, ne nahrada. Produkuje reálný `conn.log` (ověřeno ručně, obsahuje skutečná pole: `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`).
5. `passive::zeek::parse_zeek_dir` (nezměněná produkční funkce) naparsuje `conn.log` na `ConnectionObservation`.
6. **Pasivní-only varianta**: `detect_connection_anomalies` → `correlate_events(&[], ...)` (žádný aktivní inventář — stejná konvence jako eval harness, aby srovnání nebylo kontaminované).
7. **Pasivní+aktivní varianta**: stejné Zeek události, ale `correlate_events(&real_hosts, ...)` s reálným nmap+nuclei inventářem — Zeek signál se teprve teď páruje s otevřenými porty/službami.

## Naměřeno

```
H1 doslovne: realny Zeek zachytil 18 connections -> 3 udalosti | pasivni-only findings=3 | pasivni+aktivni findings=5
```

| | Pasivní-only (reálný Zeek) | Pasivní+aktivní (Zeek + nmap/httpx/nuclei) |
|---|---|---|
| Zachycené connections | 18 | 18 (stejná data) |
| Anomaly události | 3 | 3 |
| Findings | 3 | 5 |
| `prometheus-metrics-exposed` | **ne** | **ano** |

## Interpretace

**Poprvé opravdu měřeno, ne nahrazeno.** Reálná pasivní telemetrie (Zeek `conn.log` — jen metadata toku: trvání, bajty, stav spojení) nevidí a nemůže vidět obsah HTTP odpovědi na `/metrics`. Kombinace s aktivním ověřením (nuclei) přidala konkrétní, strukturně nedosažitelný nález — přesně to, co H1 tvrdí, teď poprvé s reálným pasivním nástrojem, ne s aktivním nástrojem (nmap/httpx) nesprávně nazvaným "pasivní" (oprava N8, Deliverable 15).

**Vedlejší zjištění**: protože aktivní inventář (hosts) byl k dispozici i pro pasivní-only variantu kódu (ale vědomě NEpoužit, aby zůstala čistá), pasivní+aktivní varianta navíc profitovala z toho, že Zeek signál se správně napáruje s otevřeným portem/službou (confidence není konstantní `Low`, jak to vždy je v eval harnessu s `hosts: &[]`, viz `h3-measurement-difficulty.md`) — to je přesně ta kombinace "reálný aktivní inventář + reálná pasivní telemetrie", kterou H3-měření identifikovalo jako chybějící, teď dostupná i pro budoucí H3 experimenty na reálné síti (ne jen v syntetickém labu).

## Honestní omezení

- **1 lab cíl, krátký capture** (jen během jednoho skenu, ne delší provoz) — 18 connections je málo na statistické tvrzení, dost na strukturní demonstraci.
- **`http.log`, který Zeek také produkuje, se vědomě NEpoužívá** — obsahuje URI cesty (`/metrics`), což by částečně prozrazovalo aktivní nález a dělalo srovnání cirkulární. Jen `conn.log` (čistá metadata toku) vstupuje do pasivní-only varianty, konzistentně s tím, co `passive::zeek` v produkci skutečně dělá.
- **Tcpdump sidecar vidí provoz podle interní docker-bridge IP kontejneru** (např. `172.17.0.2`), ne `127.0.0.1` — scope pro `parse_zeek_dir` je proto `0.0.0.0/0`, ne `127.0.0.1/32` jako jinde v labu. Zdokumentováno, ne skryto.
