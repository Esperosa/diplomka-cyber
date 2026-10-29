# Identity vrstva na reálné síti: DHCP renewal a NAT/swap (Deliverable 22)

**Status: naměřeno (29. 10. 2026).** Opravuje limitaci zapsanou v `src/identity.rs` i `docs/diplomka/eval/identity-layer.md`: "ověřeno na autorsky vytvořených (ne reálně zachycených) sekvencích běhů". Tohle je první test na **reálné síti s reálným ARP objevováním**, ne na ručně napsaných `HostReport` strukturách.

## Jak to funguje

1. Vlastní Docker bridge síť (`docker network create --subnet ...`) — kontejnery na ní mají skutečné virtuální MAC adresy, ověřeno ručně (`ping` + `ip neigh show`) před zapsáním do kódu.
2. Scanner kontejner (`nicolaka/netshoot`, `--cap-add NET_ADMIN`) na stejné síti provádí reálné ARP objevování: `ip neigh flush all` (zahodí stará data) → `ping` (vynutí čerstvé ARP rozeslání) → `ip neigh show <ip>` (přečte aktuální (IP, MAC) pár).
3. 3 kola, časování řízené testem (síť a ARP jsou reálné, jen pořadí vytváření/odstraňování kontejnerů je deterministické, ne čekání na skutečnou vícedenní síť):
   - **Kolo 1**: host s MAC `a1` na IP `.10`.
   - **Kolo 2 (DHCP renewal)**: host odstraněn, nový se **stejnou** MAC `a1` na **jiné** IP `.20`.
   - **Kolo 3 (NAT/výměna HW)**: host odstraněn, nový s **jinou** MAC `b2` na **původní** IP `.10`.
4. Všechny 3 (IP, MAC) páry jdou nezměněné do `IdentityResolver::resolve()`.

## Naměřeno

```
Deliverable 22: round1 ip=172.31.9.10 mac=02:42:ac:11:09:a1 | round2 (DHCP renewal) ip=172.31.9.20 mac=02:42:ac:11:09:a1 | round3 (NAT/swap) ip=172.31.9.10 mac=02:42:ac:11:09:b2
```

| Kolo | Scénář | Reálně naměřeno | `IdentityResolver` vrátil |
|---|---|---|---|
| 1 | nový host | IP `.10`, MAC `a1` | `New` |
| 2 | DHCP renewal | IP `.20`, **stejná** MAC `a1` | `Same` (stejný asset jako kolo 1) |
| 3 | NAT/výměna HW | **stejná** IP `.10`, nová MAC `b2` | `Ambiguous` (ne tiché sloučení) |

Stabilní přes 3 opakované běhy (žádná flakiness po opravě popsané níže).

## Skutečný problém narazený při stavbě (zapsáno, ne zamlčeno)

První verze testu bez `NET_ADMIN` capability na scanneru **padala v kole 3 se 100% packet loss**. Příčina: Linuxová ARP cache (`ip neigh`) si "pamatuje" starou MAC adresu pro IP `.10` z kola 1 jako `REACHABLE` (platnou po nějakou dobu bez re-verifikace) — nový `ping` tak šel na starou, už neexistující MAC adresu místo vynucení čerstvého ARP rozeslání, a tichě spadl. Opraveno: `--cap-add NET_ADMIN` na scanneru + `ip neigh flush all` před každým lookupem. Tohle je přesně ten typ "measure, don't assume" nálezu, co tenhle projekt dělá soustavně — ne jen naplánovaný krok, co prostě proběhl.

## Honestní omezení

- **3 kola, 1 síť, krátký časový úsek** — simuluje DHCP renewal/NAT časování řízeně, ne skutečnou vícedenní síť s organickým provozem. Potvrzuje, že resolver logika správně reaguje na správně formátovaná reálná data, ne že zvládne šum skutečné produkční sítě (duplicitní ARP odpovědi, flapping, atd.).
- **Žádné služby/porty** — `HostReport.services` je prázdný `Vec` (resolver je testuje jen podle `ip`/`mac`, services nejsou relevantní pro tuhle vrstvu).
- **Docker bridge síť ≠ skutečná podniková síť** (VLAN, switch porty, skutečný DHCP server) — další krok ke skutečnému zobecnění by byl vícero VLAN segmentů nebo delší capture, ne jen jedna plochá podsíť.
