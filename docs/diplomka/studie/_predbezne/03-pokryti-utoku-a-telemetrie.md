# Studie 03: Pokrytí útoků a chování, telemetrie a simulace pro Skákavku

Stav: návrh ke schválení, bez změn zdrojového kódu. Datum: 2026-10-31.
Rozsah: co má Skákavka v síti detekovat, z jaké telemetrie, jak to simulovat v soak harnessu a jak měřit.
Označení: **[zdroj]** = ověřeno u citovaného zdroje (přes vyhledávání, ne vždy plným čtením); **[odhad]** = můj odhad bez měření; **[návrh]** = návrh parametru k ladění na datech.
Pravidlo studie: žádný funkční škodlivý kód ani postup útoku. Popisuji jen to, co je třeba pro detekci a pro syntetické toky v paměti nebo izolovaném labu.

---

## 1. Shrnutí

1. Dnešních 19 rodin pokrývá hlavně hlasité objemové jevy (sken, DDoS, brute-force, DNS tunel) a jeden řetěz (`ApChain`). Podle `soak-findings.md` a průběžného `status.md` (run-v2-72h, 3,25 h) engine tyto jevy drží (DNS tunel 99,8 %, DDoS 96 %, APT řetěz 100 %), ale selhává na pomalých a tichých (`c2_beacon` 12,8 %, `cryptomining` 25 %, `rogue_device` v1 0,2 %) a na typování (`exploit_attempt` 0 % správný typ).
2. Chybí celá třída "interaktivní kanál": reverse shell, bind shell, SSH/HTTP/ICMP tunel, SOCKS pivot. V toku je to dlouhá obousměrná relace s malými pakety a nepravidelnými pauzami; D3FEND D3-RTSD to popisuje přímo [zdroj].
3. Chybí řetězení hostů (A→B→C). Dnešní `Lateral` je zdroj s fan-outem, ne kauzální cesta s hloubkou. Bez toho nelze měřit "správný pivot".
4. Klíčový signál pivotu není objem, ale časová a kauzální návaznost hran: host B se stane cílem v čase t a do sekund až minut z něj vede nová hrana na C.
5. Z pasivního toku lze získat periodicitu a jitter, délku, poměr bajtů, histogram velikostí, nové hrany, nestandardní porty. Nelze obsah, identitu uživatele, proces, úspěch přihlášení, DoH uvnitř TLS ani důkaz pass-the-hash.
6. Největší přínos nové telemetrie (odhad): Zeek `ssl` s JA4, `dns`, `ssh`, `kerberos`/`ntlm`/`smb`/`dce_rpc` a DHCP/ARP. Auth logy a EDR dávají identitu, kterou tok nemá.
7. Produkční Zeek parser zahazuje toky s cílem mimo scope. Pro reverse shell, tunely a C2 je cíl vždy externí, takže jsou v produkci slepé. To je priorita 1.
8. Navrhuji 30 nových scénářů (sekce 4) a 5 kombinačních režimů; každý má ground truth (IP, časy, řetěz) a lookalike protějšek.
9. Metriky: recall po rodinách a hloubce řetězu, latence, přesnost přiřazení, kvalita řetězu, FP na síť-den, FP při překryvu. Dnešní FP 210,7 / síť-den (v1) je limitující už před přidáním rodin.
10. Simulace není důkaz. Ověření mimo ni: CTU-13, LANL, DARPA OpTC, Security-Datasets, vlastní izolovaný lab s Atomic Red Team.
11. Doporučené pořadí: (a) scope filtr, (b) beaconing s jitterem, (c) interaktivní relace, (d) graf řetězení, (e) JA4/DNS/SSH zásuvky, (f) lookalike sady.
12. Nejistoty: reálné rozdělení paketů konkrétních nástrojů (chisel, ligolo, Sliver) jsem v ověřitelném zdroji nenašel; parametry jsou **[návrh]** a patří do kalibrace v labu.
13. Odhady v pp slouží jen k řazení priorit.
14. Studie nemění kód; implementace patří do navazujících kroků.
15. Zdroje jsou v sekci 10, u každého rok a stav ověření.

---

## 2. Taxonomie

Legenda signálů: PER = periodicita+jitter; DUR = délka relace; RAT = poměr bajtů; EDGE = nová hrana/směr v grafu; PORT = neobvyklý port/protokol; FP = JA3/JA4; ENT = entropie DNS; NX = počet NXDOMAIN; SZ = histogram velikostí paketů/toků.
Priorita pro malou a střední síť: A = nutné, B = vhodné, C = okrajové.
Texty technik T1572 a T1095 jsem ověřil na attack.mitre.org [zdroj, stránky 2024-2025]; ostatní ID jsou z obecné znalosti a před obhajobou je potvrdit na attack.mitre.org (ID jsou stabilní napříč v15+, ale neověřoval jsem každé zvlášť).

| Taktika | Technika (ATT&CK) | Pozorovatelné v síťové telemetrii | Signál / metrika | Nepozorovatelné v toku, potřebný zdroj | Maskování / lookalike pro FP | Pri. |
|---|---|---|---|---|---|---|
| TA0043 Recon | T1595 aktivní skenování | SYN bez odpovědi, mnoho cílů/portů | fan-out, podíl S0/REJ, PORT | pomalý sken pod prahem | autorizovaný skener, monitoring | A (už je) |
| TA0001 Initial Access | T1190 exploit veřejné aplikace | HTTP(S) na vystavený server, IDS alert | Suricata sid, URI délka, 4xx/5xx | šifrovaný payload; WAF log | pentest, crawler, vuln. skener | A |
| TA0001 | T1078 platné účty (VPN/RDP/SSH) | přihlášení z nového zdroje/času | EDGE, nový zdroj, čas | úspěch/neúspěch bez auth logu | home-office, cestování | A |
| TA0001 | T1133 externí vzdálené služby | příchozí RDP/SSH/VPN z internetu | PORT, cizí zdroj, DUR | identita uživatele | admin z domova, MSP | A |
| TA0001 | T1195 dodavatelský řetězec | mnoho stanic na jednu novou adresu | fan-out dovnitř, nový cíl, PER (dnes `FleetBeacon`) | podpis balíčku, hash | legitimní update, CDN | B |
| TA0001 | Wi-Fi / rogue AP, T1557 | nové MAC, cizí DHCP server, duplicitní ARP | anomálie ARP/DHCP | rádiová vrstva (WIDS) | hosté, BYOD | B |
| TA0002 Execution | T1059 skripty, T1047 WMI | DCOM/RPC volání na cíl | DCE-RPC operace, nový klient→server | příkazová řádka, proces | admin skripty, SCCM | B |
| TA0003 Persistence | T1053 úlohy, T1543 služby, T1098 účty | nepřímo: nová periodicita po restartu | PER vázaná na boot | registr, služby, plánovač | cron, backup, AV update | C |
| TA0004 Priv. esc. | T1068, T1548 | téměř neviditelné | – | EDR | – | C |
| TA0005 Defense evasion | T1090 proxy, T1572 tunel, T1573 šifrovaný kanál, T1036, LOTL | tunel na povoleném portu, TLS na neobvyklém místě | SZ+DUR+PORT, FP/JA4 | obsah uvnitř tunelu | VPN, SSH admin, ZTNA, remote support | A |
| TA0006 Credential access | T1110 brute force/spraying, T1003 dump, T1558 Kerberoasting, T1557 AitM | opakované pokusy, TGS na SPN, NTLM relay | počty/okno, `kerberos.log`, NTLM fan-out | LSASS dump (jen EDR) | zapomenuté heslo, skript s expirovaným heslem | A |
| TA0007 Discovery | T1046, T1018, T1087, T1135 | ARP/ICMP/SMB enumerace, LDAP | vnitřní fan-out, SMB tree_connect na mnoho hostů | cache AD | inventarizace, NAC | A |
| TA0008 Lateral movement | T1021 (.001 RDP, .002 SMB, .004 SSH, .006 WinRM), T1550.002 PtH, T1570 přenos nástrojů | nová vnitřní hrana, SMB zápis ADMIN$/IPC$, DCE-RPC svcctl | EDGE, řetězení, `smb`, `dce_rpc` | zda jde o PtH (NTLM vs. Kerberos) bez logu | admin, patch management, backup | A |
| TA0009 Collection | T1039, T1005 | velké SMB čtení z jednoho klienta | RAT, objem čtení | obsah | backup, antivir, indexace | A |
| TA0011 C&C | T1071.001/.004, T1095, T1572, T1090 (.003 multi-hop), T1102, T1568 DGA, T1573 | periodické spojení, DoH, ICMP s daty | PER, jitter, SZ, ENT, NX, DUR, FP | obsah, proces | telemetrie, NTP, cloud sync, AV, heartbeat aplikace | A |
| TA0010 Exfiltration | T1041, T1048, T1567, T1030 | upload > download, dlouhé relace | RAT, objem/den proti baseline | co se odeslalo | cloud backup, e-mail, sync | A |
| TA0040 Impact | T1486, T1496, T1498/9 | masivní SMB zápis, stratum, volumetrie | SMB write fan-out, DUR+port, pps | šifrování na disku (EDR) | AV scan, backup, kompilace | A |
| ICS | ICS ATT&CK T0855 neautorizovaný příkaz | Modbus/S7 write | zápis z nepovoleného zdroje | log PLC | engineering workstation | B |
| Cloud/kontejnery | T1078.004, T1610 | API z nové adresy, metadata endpoint | EDGE, user-agent, JA4 | CloudTrail, K8s audit | CI/CD, autoscaling | B |
| Vnitřní hrozba | T1074, T1567, T1052 | hromadění + odeslání | RAT per host + čas | USB, tisk | uzávěrka, HR | B |

Poznámky:
- Obsah šifrovaných kanálů (TLS 1.3, SSH, DoH) je z toku nepřístupný; zbývají metadata (JA3/JA4, SNI, velikosti, časy) [zdroj: FoxIO JA4+, 2023-2025].
- Zeek zapisuje spojení do `conn.log` až po jeho ukončení [zdroj: Active Countermeasures, Long Connection Detection]; dlouhé relace jsou vidět se zpožděním.
- LOTL (Volt Typhoon) je opsán jako maskování cizí aktivity jako běžné správy [zdroj: CISA/partneři, 2023 a 2024]; v toku je to nejhorší případ, signál je jen v grafu hran a rolích.

---

## 3. Reverse shelly, bind shelly, tunely a pivoting

### 3.1 Jak vypadají na úrovni toku (bez návodu)

| Varianta | Směr navázání | Typický obraz v toku | Poznámka |
|---|---|---|---|
| Reverse shell (netcat-like, meterpreter-like, vlastní implantát) | oběť → externí | jedno dlouhé TCP, malé pakety obousměrně, nepravidelné pauzy (člověk), často 443/80 nebo vzácný port | D3-RTSD: interval mezi pakety, kadence, směr zahájení vs. směr řízení, objem k řídicímu hostu [zdroj D3FEND] |
| Bind shell | externí nebo vnitřní → oběť | příchozí spojení na port, který host dosud neposlouchal | nová služba oproti nmap inventáři; za NAT/FW vzácnější |
| SSH reverse (`-R`), dynamic (`-D`), local (`-L`) | oběť → externí SSH | dlouhé SSH, keepalive, výbuchy při použití; FoxIO uvádí JA4SSH příklad pro reverse SSH shell [zdroj] | SSH ven z hostu bez admin role; resp>orig |
| HTTP(S)/WebSocket tunel (chisel-like, ligolo-like) | oběť → externí | dlouhé TLS/HTTP2, mnoho malých rámců | JA4 klienta mimo flotilu, nová doména |
| DNS tunel (iodine-like, dnscat-like) | oběť → resolver | mnoho dotazů na doménu, dlouhé subdomény, TXT/NULL, vysoká entropie, NX | už pokryto |
| DoH C2 | oběť → veřejný DoH | po prvním rozlišení jen TLS na DoH endpoint, periodicky, malé [zdroj: Outflank 2018, Black Hills ~2020] | seznam DoH resolverů + host, který jinak používá interní DNS |
| ICMP tunel | oběť ↔ externí | echo s nenulovou datovou částí, konstantní velikost | T1095 [zdroj MITRE] |
| SOCKS pivot / port forward | vnitřní → vnitřní přes B | B přijímá od A a zároveň otevírá na C se zrcadleným objemem | grafový signál, 3.3 |
| Multi-hop proxy | A→B→C→ven | časově sladěné relace | T1090.003 [zdroj MITRE] |

O konkrétních nástrojích (chisel, ligolo-ng, Sliver) jsem nenašel ověřitelný zdroj s naměřenými vzory paketů; hodnoty ve scénářích jsou **[návrh]** k kalibraci v labu.

### 3.2 Metriky příznaků

1. **Interaktivita**: `duration > 60 s`, medián velikosti paketu pod ~150 B v obou směrech, poměr paketů orig:resp 0,3-3, variační koeficient mezičasů > 1 (lidské pauzy) **[návrh]**. Beacon má CV < 0,3.
2. **Obrácený objem**: u spojení iniciovaného zevnitř resp_bytes/orig_bytes > 5 při nízkém celku (SSH/TLS na cizí cíl).
3. **Dlouhé spojení**: `duration > 1 h` na externí IP mimo whitelist (VPN, streaming, vzdálená podpora). Kvůli zápisu na konci spojení potřeba průběžného stavu v parseru.
4. **Beaconing s jitterem**: nepoužívat jen směrodatnou odchylku. Robustnější je MAD, šikmost histogramu mezičasů a frekvenční analýza (FFT nad kbelíky) [zdroj: Active Countermeasures "Understanding C2 Beacons"; DEV.to cgivre, FFT]. Jitter 33 % na 5 s se může vyhnout detektorům čekajícím pevný interval [zdroj: ACM Saefko].
5. **Stejná velikost dat**: nízká variance bytes/spojení při periodicitě svědčí o stroji [zdroj: ACM].
6. **Nová hrana + nová doména/JA4**: první spojení dvojice (cíl, JA4) v historii hostu.
7. **Plochý hodinový profil**: stejný počet spojení v noci i o víkendu (24-72h pomalé C2).

### 3.3 Pivoting: grafové signály

Model: orientovaný časový graf; hrana = (src, dst, port/proto, čas, bajty).

| Signál | Definice | Parametr [návrh] | Očekávané FP [odhad] |
|---|---|---|---|
| Nová hrana na admin protokol | RDP/SMB/WinRM/SSH/RPC (3389, 445, 5985/6, 22, 135) pro dvojici mimo baseline 14 dní | váha podle role cíle | 2-8 / síť-den, méně s whitelistem rolí |
| Řetěz A→B→C | hrana B→C začne do T_chain po začátku A→B; B dosud nebylo zdrojem na C | T_chain 10 s - 15 min; hloubka ≥ 2 | bastion, CI/CD |
| Zrcadlení objemu | bajty přijaté z A ≈ bajty odeslané na C (±20 %) v překryvu | korelace > 0,8 | proxy, NAT, load balancer |
| Fan-out po průniku | po první nové hraně do B roste počet unikátních cílů z B proti baseline | z-skóre > 3 | skenery, inventář |
| Změna role | server začne iniciovat na klienty, stanice na stanice | porušení role matice | patch management |
| Vnější vstup → vnitřní hrana | příchozí VPN/RDP, pak do 30 min nová vnitřní hrana | ≤ 30 min | VPN uživatel s legit. RDP |
| Pass-the-hash | NTLM bez předchozího Kerberos TGT u hostu, který běžně používá Kerberos | vyžaduje `ntlm.log`, `kerberos.log` | staré aplikace s NTLM |
| Nástroj před spuštěním | SMB zápis do ADMIN$/C$ a pak DCE-RPC svcctl/atsvc | `smb_files` + `dce_rpc` | instalace admina přes PsExec |

Zeek logy `rdp`, `ssh`, `smb_mapping`, `smb_files`, `dce_rpc`, `ntlm`, `kerberos` jsou součástí Zeek [zdroj: docs.zeek.org, aktuální vydání]. Corelight SSH/RDP Inferences jsou komerční [zdroj: Corelight, 2023-2024], takže pro open source je potřeba vlastní odvození z velikostí.

### 3.4 Návrh detektorů

| Detektor | Vstup | Logika | Parametry [návrh] | Očekávané FP [odhad] |
|---|---|---|---|---|
| D1 Interaktivní relace ven | conn.log (+history) | dlouhá malopaketová obousměrná relace s lidskou nepravidelností, cíl mimo whitelist | dur > 120 s; stř. paket < 200 B; CV > 1 | 1-5 / síť-den (SSH admin, remote support, hry) |
| D2 Reverse SSH | conn+ssh | SSH ven z hostu bez admin role; dlouhé; resp>orig | dur > 30 min | < 1 / síť-den s whitelistem |
| D3 Beacon s jitterem | conn | MAD+šikmost+FFT per (src,dst,port) | ≥ 12 spojení; skóre > 0,7; okno 6-72 h | 3-15 / síť-den bez allowlistu; JA4 flotily snižuje |
| D4 Nová admin hrana | conn+role | viz 3.3 | baseline 14 d | 2-8 / síť-den |
| D5 Řetěz hran | graf | viz 3.3 | hloubka ≥ 2 | 0,2-1 / síť-den |
| D6 Tunel na povoleném portu | conn+ssl | 443 s JA4 mimo flotilu, dlouhé, malé pakety, nová doména | věk domény < 30 d (pDNS), dur > 10 min | 2-6 / síť-den |
| D7 DoH | conn+ssl+dns | TLS na známý DoH u hostu s interním DNS | seznam DoH + role | 1-3 / síť-den (prohlížeče) |
| D8 ICMP tunel | conn (icmp) | konstantní velikost > 64 B, > 100/h | per cíl | < 0,5 / síť-den |
| D9 Nová listening služba | tok + nmap | spojení na port, který v inventáři nebyl | 1 spojení z jiného hostu | 1-3 / síť-den |
| D10 PtH / Kerberoasting | ntlm/kerberos | NTLM bez TGT; TGS s RC4 na SPN | okno 10 min per uživatel | nízké s whitelistem |

---

## 4. Scénáře pro simulaci

Společné principy pro `src/soak/traffic.rs`:
- Nová hodnota `Family` (nebo `ScenarioSpec` s parametry), fáze podle dnešního `ApChain`, ground truth jako dnes (klíčové IP, okno, +2 cykly).
- Nová položka ground truth: `chain: Vec<(host, t_start)>` pro skórování pivotu.
- Jen syntetické `conn`-like záznamy v paměti; žádné payloady.
- Zkratky: LN lognormální, EXP exponenciální, U rovnoměrné, cyc = 30 virt. minut, PS velikost paketu. Všechny parametry **[návrh]**.

| ID | Scénář (ATT&CK) | Fáze a generované toky | Ground truth | Lookalike | Skórování |
|---|---|---|---|---|---|
| N01 | Reverse shell za NAT na 443 (T1071.001, T1095) | 1) příchozí exploit (4-40 kB) 2) za 5-60 s odchozí TCP/443 na novou IP; trvání LN(2 h); PS ~ LN(60 B, σ 0,6) obousměrně; mezičasy směs EXP(3 s) a pauz 20-300 s | oběť, C2 IP, čas navázání; dvojice exploit→spojení | SSH admin na 443; vzdálená podpora | nález s `host_key`=oběť; latence od navázání; správný typ "interaktivní kanál" |
| N02 | Reverse shell na vzácném portu (4444-like, 8443, 1337) | jako N01, port ze vzácné množiny, bez TLS | stejné | admin nástroje na vlastních portech (RDP gateway 8443) | detekce + FP v sítích s vlastními porty |
| N03 | Bind shell (T1059 + nová služba) | příchozí spojení z vnitřního hostu na dosud neposlouchaný port; relace 5-45 min | oběť, zdroj, port | nová aplikace nasazená adminem | nález "nová služba + spojení" do 1 cyc; FP u onboardingu |
| N04 | SSH reverse tunnel `-R` z vnitřního stroje | SSH ven 4-48 h, keepalive 30-60 s (PS 52-90 B), výbuchy 10 s - 2 min, resp>orig | host, cíl, tunelované vnitřní cíle | SSH admin na VPS, git push, rsync | D2; správný typ; podíl tunelovaného provozu |
| N05 | SSH dynamic `-D` použitý k průzkumu | SSH relace + současný fan-out z koncového bodu na vnitřní porty | pivot host, cíle, čas | SSH bastion | pivot host správně pojmenován |
| N06 | HTTP(S)/WebSocket tunel | 1 dlouhé TLS (dur LN 3 h), JA4 mimo flotilu, PS LN(120 B), bursty 20-200 kB, nové SNI | host, doména, JA4 | VPN přes 443, Teams/Zoom | D6; FP vůči VPN/Teams |
| N07 | Tunel přes UDP/53 (ne DNS) | velké pakety bez DNS struktury, 10-60 min | host, cíl | DNS over TCP, velké DNSSEC | detekce; odlišení od DNS tunelu |
| N08 | ICMP tunel (T1095) | echo 128-1024 B, interval EXP(2 s) 5-30 min, pak 3 h klid, opakování | host, cíl | ping monitoring (64 B, 1 s, 24/7), MTU probe | D8; FP u monitoringu |
| N09 | DoH C2 | po rozlišení TLS na DoH IP každých 30-120 s ± 30 %, PS 200-600 B, 24-72 h | host, resolver | prohlížeč s DoH | D7 + PER; odlišení od lidského DoH |
| N10 | Pivot hloubka 2 (A→B→C) | A kompromitován (N01-like); A→B SMB/RDP t+3 min; B→C RDP t+9 min | A, B, C, časy hran | admin přes bastion | recall hloubky 2; pořadí správně |
| N11 | Pivot hloubka 3 | A→B SSH, B→C WinRM, C→D SMB, mezery 2-20 min | A..D | patch management, Ansible | plné pořadí hran; F1 hran |
| N12 | Pivot hloubka 4 přes SOCKS na B | A tuneluje přes B na C a D; zrcadlený objem na B | A,B,C,D, pivot B | proxy, bastion, load balancer | B označen jako pivot |
| N13 | Pivot hloubka 5, pomalý | 5 hostů, skok každých 6-30 h | všech 5 + časy | rozložené okno údržby | recall při velkém intervalu; ztráta řetězu |
| N14 | Extern → DMZ → DB → file server | exploit na DMZ web, pak DB, pak file server | 4 hosty | legitimní třívrstvá aplikace web→app→DB | odlišení od legit. řetězu (kritická FP kategorie) |
| N15 | Fan-out po průniku (T1046, T1135) | z B 40-250 cílů na 445/139/3389/22 za 2-30 min; pomalá varianta 1-5/min | B, cíle | inventarizace, autorizovaný skener (už je) | recall rychlý i pomalý |
| N16 | Pass-the-hash / NTLM (T1550.002) | NTLM SMB na 3-8 serverů bez TGT; 5-80 kB | zdroj, cíle | staré tiskárny/NAS | vyžaduje `ntlm.log`; recall, FP |
| N17 | Kerberoasting (T1558.003) | 20-100 TGS na SPN za 2 min z klienta, RC4 | klient, SPN | vyhledávání služeb při loginu | vyžaduje `kerberos.log` |
| N18 | Password spraying (T1110.003) | 1-3 pokusy/účet, stovky účtů, 1-6 h; jeden nebo více zdrojů | zdroje, počet účtů | zapomenutá hesla po dovolené | detekce nízké rychlosti; FP |
| N19 | Pomalé nízkoobjemové C2 24-72 h | 1 spojení / 5-30 min, PS 200-700 B, jitter 10-50 %, pracovní doba + nepravidelné víkendy | host, cíl | NTP, telemetrie, AV, cloud sync | recall podle doby (24/48/72 h); latence |
| N20 | Náhodný beacon bez periodicity | mezičasy LN(σ 1,0), medián 10 min | host, cíl | SaaS pull uživatelů | ukáže limit D3 (RITA skóre blízké 0 u LN, viz nejistoty bod 5) |
| N21 | Periodický beacon, jitter 0/10/25/50 % | intervaly 60 s a 300 s | host, cíl | monitoring agenti | křivka recall vs. jitter |
| N22 | C2 přes CDN / fronting (T1090.004) | TLS na velké CDN IP s neshodným SNI/Host | host, CDN IP | skutečné CDN (video, update) | ukáže slepotu bez JA4/SNI |
| N23 | Perzistence: periodicita po bootu (T1053) | beacon začíná do 90 s po bootu hostu | host, čas bootu | aplikace startující po bootu | vyžaduje DHCP/boot; korelace |
| N24 | Exfiltrace přes cloud (T1567) | upload 2-20 GB v 03:00 | host, objem | OneDrive/backup | odlišení od backupu |
| N25 | Exfiltrace po částech (T1030) | 50-200 MB × 40 nocí pod prahem | host, kumulativ | uživatelský sync | kumulativní baseline; recall po dnech |
| N26 | Rogue AP + AitM (T1557) | nový DHCP server, duplicitní ARP brány, neznámé MAC | MAC, IP | druhé AP po instalaci | vyžaduje ARP/DHCP; dnešní `RogueDevice` ~0 % |
| N27 | Cloud/kontejner: metadata a API z nového zdroje | spojení na metadata endpoint a cloudové API z kontejneru, nový user-agent | host, API | CI/CD, autoscaling | odlišení od autoscalingu |
| N28 | Supply chain: kompromitovaný build agent | build server → nová externí IP + podepsaný update do flotily (rozšíření `FleetBeacon`) | build server, flotila | legitimní update | latence od prvního beaconu |
| N29 | ICS: pivot IT → OT (T0855) | IT host → jump server → PLC write Modbus/S7 | 3 hosty | inženýr s povoleným zdrojem | povolený vs. nepovolený zdroj |
| N30 | Vnitřní hrozba: pomalý sběr | SMB čtení 30 GB/týden + malé uploady | uživatel, objem | uzávěrka, indexace | recall po týdnech; FP u sezónních špiček |

### 4.1 Kombinace a šum

| ID | Režim | Popis | Měří |
|---|---|---|---|
| K1 | Více útoků na jednom hostu | např. N19 + N15 + N25 na stejné oběti | rozdělení nálezů do incidentů, přesnost přiřazení |
| K2 | Překryv s lookalike | scénář ve stejném okně jako Backup/FlashCrowd/AuthorizedScanner | FP při překryvu, potlačení signálu |
| K3 | Šum 10×, 50× | násobení benigního provozu | křivka recall vs. šum |
| K4 | Výpadek telemetrie | 5-30 % cyklů chybí uprostřed řetězu | odolnost kauzálního řetězu |
| K5 | Větvený řetěz | B pivotuje na C a D souběžně | kvalita stromu, ne jen lineárního řetězu |

### 4.2 Nové lookalike protějšky

SSH admin session (dlouhá, malé pakety, i na 443), vzdálená podpora (TeamViewer/AnyDesk-like), VPN klient (dlouhé UDP/443), Teams/Zoom (dlouhé TLS), streaming, bastion/jump host, CI/CD (git, artefakty, registry), Ansible (admin SSH z jednoho zdroje na mnoho), monitoring ping, DoH prohlížeč, backup s dlouhými relacemi, tisková služba (NTLM), třívrstvá aplikace web→app→DB. Bez nich není recall srovnatelný s FP, takže jsou povinné.

### 4.3 Poznámky k implementaci harnessu

1. `Family` rozšířit po balících (shell/tunel, pivot, identita, skryté kanály) nebo zavést `ScenarioSpec`.
2. Ground truth doplnit o `chain`, `pivot_host`, `depth`, `phase_times`.
3. Jedna deterministická funkce `sample_iat(kind, jitter, rng)` pro PER/EXP/LN/mix; zachovat bitovou reprodukovatelnost podle seedu jako dnes.
4. Nová telemetrie (JA4, DNS, ntlm, kerberos, DHCP/ARP) vyžaduje rozšíření pozorování v soak modelu. Do té doby jsou N16, N17, N22, N23, N26 "ground truth bez detektoru", což je užitečné: ukáže strop dnešní telemetrie.

---

## 5. Matice telemetrie

Přínos: +++ vysoký, ++ střední, + nízký, – žádný. Subjektivní odhad.

| Rodina \ zdroj | conn.log (dnes) | Suricata ET Open | Zeek ssl+JA4 | Zeek dns | Zeek ssh | Zeek smb/dce_rpc/ntlm/kerberos | DHCP/ARP | auth logy | NetFlow/IPFIX | proxy | EDR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Reverse/bind shell | ++ | + | ++ | – | + | – | – | – | + | + | +++ |
| SSH/HTTP tunel | ++ | + | +++ | + | ++ | – | – | – | + | ++ | ++ |
| DNS/DoH tunel/C2 | ++ | + | ++ | +++ | – | – | – | – | – | ++ | + |
| ICMP tunel | ++ | + | – | – | – | – | – | – | + | – | – |
| Pivot / lateral | ++ | + | – | – | + | +++ | + | ++ | ++ | – | +++ |
| Credential (spraying, Kerberoast, PtH) | + | + | – | – | – | +++ | – | +++ | – | – | ++ |
| Pomalé C2 | + | + | ++ | + | – | – | – | – | + | ++ | ++ |
| Exfiltrace | ++ | – | + | + | – | ++ | – | – | ++ | ++ | + |
| Rogue / Wi-Fi | – | – | – | – | – | – | +++ | + | – | – | + |
| ICS | + | ++ | – | – | – | – | + | – | + | – | – |
| Cloud/kontejner | + | – | ++ | + | – | – | – | +++ | + | ++ | ++ |
| Supply chain | + | + | ++ | ++ | – | – | – | – | – | +++ | ++ |
| Vnitřní hrozba | + | – | – | – | – | ++ | – | ++ | + | ++ | ++ |

### 5.1 Co dopojit (podle poměru přínos/náročnost)

| # | Zdroj | Co přidat | Přínos [odhad] | Náročnost [odhad] | Korelace |
|---|---|---|---|---|---|
| 1 | Oprava scope filtru Zeek parseru | držet externí cíle pro toky z vnitřních zdrojů | exfiltrace z 0 % na 42,1 % zdrojového pořadí už ukázalo měření v1; odblokuje C2 a tunely | nízká | beze změny klíče |
| 2 | Zeek `ssl` + JA4 (JA4 TLS klient je BSD-3, ostatní JA4+ pod FoxIO License 1.1 [zdroj FoxIO]) | JA4, SNI, ALPN, certifikát | C2/tunel +10-20 pp; menší FP díky flotile | střední | `uid`, `community_id` |
| 3 | Zeek `dns` + pasivní DNS | entropie, délka, NX, TTL, TXT/NULL, stáří domény | DNS/DoH/DGA +5-15 pp | střední | `uid`, dotaz→IP v krátkém okně |
| 4 | Zeek `ssh` | HASSH/JA4SSH, počet pokusů, délka | reverse SSH +10-20 pp | nízká | `uid` |
| 5 | Zeek `smb`, `dce_rpc`, `ntlm`, `kerberos`, `rdp` | pivot, PtH, Kerberoast, enumerace | typování lateral +15-30 pp (dnes 12,5 % v1, 64,8 % ve v2) | střední-vysoká | uid; identita = uživatel+host |
| 6 | DHCP/ARP | identita, rogue, čas bootu | rogue +50 pp; FP identity (dnes falešné rozdělení 8,7 %) | střední | MAC↔IP↔čas |
| 7 | Suricata ET Open + oprava typu | typ nálezu ze `sid`/kategorie | exploit_attempt správný typ z 0 % o +50 pp | nízká | `community_id` |
| 8 | Auth logy (AD 4624/4625/4768/4769, SSH, VPN) | spraying, nové přihlášení | credential +20 pp | střední | uživatel↔host↔čas |
| 9 | NetFlow/IPFIX | pokrytí bez Zeek, dlouhé relace | +10 pp v sítích bez SPAN | střední | 5-tuple + čas |
| 10 | Proxy / EDR | obsah, proces | nejvyšší, ale mimo pasivní dosah | vysoká | host_id, proces→tok |

Korelace: `community_id` je standardní hash 5-tuple sjednocující Zeek a Suricata (specifikace Corelight, 2018; v této studii nepotvrzeno, ověřit). Identitu zařízení držet přes MAC→IP→hostname z DHCP s okny platnosti, jinak se řetězy při změně adresy rozpadají.

---

## 6. Metriky a datasety

### 6.1 Metriky

| Metrika | Definice | Z harnessu |
|---|---|---|
| Recall po rodinách | detekováno / pozorovatelné, Wilson 95 % | už je |
| Recall po hloubce řetězu | N10-N14: podíl řetězů s odhalenými všemi hranami do hloubky d | nové: `chain` |
| Latence | čas od prvního pozorovatelného toku do nálezu (median, p90) | už je (median) |
| Přesnost přiřazení | nálezy připsané správnému incidentu / všechny nálezy incidentu | K1 |
| Kvalita řetězu | F1 orientovaných hran, Kendall tau nad pořadím, správný pivot host | nové |
| FP / síť-den | nálezy bez příčiny, členěné podle `finding_type` | už je (v1: 210,7) |
| FP při překryvu | FP v oknech lookalike + útok vs. jen útok | K2 |
| Odolnost | recall při výpadku telemetrie (K4) a šumu 10× (K3) | nové |
| Správný typ | shoda typu nálezu (dnes selhává u exploit, lateral) | už je |
| Přínos zdroje | rozdíl recallu se zdrojem a bez (ablace) | nové, pro sekci 5 |

Reportovat zvlášť "jakýkoli nález" a "správný typ + správný host". Pro řetězy hodnotit hranu, ne jen nález. U n < 30 uvádět počty, ne procenta.

### 6.2 Datasety mimo simulaci

| Zdroj | Obsah | Použití | Omezení | Rok / stav |
|---|---|---|---|---|
| CTU-13 | botnet captures, labely toků | beaconing, C2 | 2011, starý malware, bez moderních shellů | 2011; z přehledové tabulky |
| Stratosphere / MCFP | pcap vzorků malware | Zeek→Skákavka | kontrola licence | nepotvrzeno v této studii |
| Malware-Traffic-Analysis.net | pcap cvičení s popisem | C2, exploit kit, lateral ukázky | bez labelů jako dataset; hesla k archivům | nepotvrzeno v této studii |
| LANL Unified Host and Network | 90 dní NetFlow v9 + host události, anonymizováno | FP baseline, identita host↔tok | bez označeného útoku | arXiv 1708.07518, 2017 [zdroj] |
| LANL Comprehensive Multi-Source (2015) | auth + toky + red-team | pivot podle auth | bez payloadu | csr.lanl.gov/data; zmínka v LANL stránce |
| DARPA OpTC | 1000 hostů, baseline + red team | pivot, C2 s hostem | slabá dokumentace | 2019-2020 [zdroj z vyhledávání] |
| Security-Datasets (Mordor) | JSON logy Windows z emulace APT | lateral, credential | hlavně host logy, málo pcap | 2019 [přehledová tabulka] |
| CICIDS2017 / CSE-CIC-IDS2018 / UNSW-NB15 | labelované flows | rychlé srovnání | umělé prostředí, známé problémy labelů | nepotvrzeno v této studii |
| Atomic Red Team + vlastní lab | testy mapované na ATT&CK | jediná cesta ke shellu/tunelu/pivotu s vlastním pcap | nutný izolovaný lab | nepotvrzeno v této studii |

Postup: (1) FP baseline na LANL a vlastních datech, (2) recall C2 na CTU-13 a MTA pcap přes Zeek→Skákavka, (3) pivot/lateral na OpTC a LANL 2015 po převodu na hrany, (4) vlastní lab pro reverse shell, tunely a pivot hloubky 2-5 s ručním ground truth. Výsledky reportovat odděleně od simulace; velký rozdíl proti simulaci znamená úpravu generátoru.

---

## 7. Etické a bezpečnostní meze

1. Simulace běží jen v paměti soak harnessu jako syntetické záznamy toků; nic se neposílá do sítě.
2. Lab: izolovaná virtuální síť bez připojení k produkci a internetu, vlastní zařízení, snapshot a zničení po testu.
3. Studie ani kód nesmí obsahovat funkční implantáty, exploity ani přesné postupy nasazení nástrojů; popisují se jen pozorovatelné vlastnosti.
4. Veřejné pcap/logy používat podle licence; cizí data bez záznamu v SOURCES.md nepatří do repozitáře.
5. Žádné osobní údaje ani tokeny v ukázkových datech; IP z dokumentačních rozsahů (RFC 5737) nebo soukromých.
6. Atomic Red Team jen na vlastních systémech.

---

## 8. Priorita (top 10)

| # | Krok | Odůvodnění | Přínos [odhad] | Náročnost [odhad] |
|---|---|---|---|---|
| 1 | Opravit scope filtr (zachovat externí cíle) | bez něj je slepá exfiltrace, C2, reverse shell i tunel; potvrzený produkční nález | předpoklad pro vše ostatní | nízká |
| 2 | Beaconing odolný vůči jitteru (MAD+šikmost+FFT) a N19-N21 | `c2_beacon` je nejslabší rodina (12,8 %, latence 360 min) | +20-40 pp | střední |
| 3 | Detektor interaktivní relace ven (N01, N02, N04) | chybí celá třída; D3-RTSD dává jasný signál | nová rodina, v simulaci vysoké, v reálu nižší | střední |
| 4 | Graf nových hran a řetězení (N10-N14) + `chain` v ground truth | pivot je klíč k přiřazení incidentu; lateral typ 12,5-64,8 % | +20-30 pp typ lateral | střední-vysoká |
| 5 | Oprava typování (`exploit_attempt` 0 %, `lateral`) a mapování Suricata sid → typ | rychlá výhra, IDS už vidí | +50 pp typ exploit | nízká |
| 6 | Lookalike sada (SSH admin, VPN, remote support, bastion, CI/CD, třívrstvá aplikace) | bez ní recall jen ukazuje slepou citlivost; FP 210,7 / síť-den | měření FP | střední |
| 7 | Zeek ssl+JA4 a dns | největší zisk u tunelů, DoH, C2, supply chain | +10-20 pp | střední |
| 8 | DHCP/ARP identita | rogue ~0 %; 8,7 % falešného rozdělení rozbíjí řetězy | rogue +50 pp | střední |
| 9 | Zeek smb/dce_rpc/ntlm/kerberos | PtH, Kerberoasting, spraying, enumerace SMB | +15-30 pp | vysoká |
| 10 | Kombinace a šum K1-K5 | měří přesnost přiřazení, ne jen izolovanou detekci | metodické | střední |

---

## 9. Co zůstává nejisté

1. Reálné vzory paketů chisel, ligolo-ng, Sliver, Meterpreter jsem v ověřitelném zdroji nenašel; čísla ve scénářích jsou návrhy.
2. Odhady v pp a počty FP / síť-den jsou odhady, ne měření.
3. Ověřil jsem texty T1572 a T1095 a existenci T1090.003; ostatní ID z obecné znalosti.
4. Chování zápisu `conn.log` u dlouhých spojení (ACM): ověřit v dokumentaci Zeek verze, kterou Skákavka používá.
5. arXiv 2609.19091 (2026, o RITA a lognormálních mezičasech) jsem viděl jen ve výsledcích vyhledávání, nečteno; tvrzení o N20 stavět až po přečtení.
6. Licence JA4+: JA4 TLS je BSD-3, zbytek FoxIO License 1.1 [zdroj FoxIO]; právní stanovisko nemám.
7. URL a licence CTU, MTA, CICIDS, Atomic Red Team nepotvrzeny; ověřit před použitím.
8. Zda D5 odliší útočný řetěz od legitimního třívrstvého (N14) jen z toků, je otevřené; může být nutná role/identita.
9. Run-v2-72h běží (v době čtení 3,25 h); čísla ze `status.md` jsou průběžná.
10. Čísla "v1" jsou z `soak-findings.md` (3 h, seed 20260131), "v2" z průběžného `status.md` (seed 20261031); nejsou přímo srovnatelná.

---

## 10. Zdroje (URL, rok, stav)

| Téma | URL | Rok | Stav |
|---|---|---|---|
| ATT&CK T1572 Protocol Tunneling | https://attack.mitre.org/techniques/T1572/ | 2024-2025 | potvrzeno vyhledáváním |
| ATT&CK T1095 Non-Application Layer Protocol | https://attack.mitre.org/techniques/T1095 | 2024-2025 | potvrzeno |
| ATT&CK T1090 Proxy (.003 multi-hop) | https://attack.mitre.org/techniques/T1090/ | 2024-2025 | z vedlejšího zdroje |
| ATT&CK TA0008 Lateral Movement | https://attack.mitre.org/tactics/TA0008 | 2024-2025 | odkaz z vyhledávání |
| CTID mapování TA0011 (ATT&CK 16.1) | https://center-for-threat-informed-defense.github.io/mappings-explorer/attack/attack-16.1/domain-enterprise/tactics/TA0011 | 2024 | odkaz z vyhledávání |
| D3FEND Remote Terminal Session Detection | https://d3fend.mitre.org/technique/d3f:RemoteTerminalSessionDetection | 2023-2025 | potvrzeno |
| D3FEND Per Host Download-Upload Ratio Analysis | https://d3fend.mitre.org/technique/d3f:PerHostDownload-UploadRatioAnalysis | 2023-2025 | potvrzeno |
| Zeek conn.log | https://docs.zeek.org/en/lts/logs/conn.html | aktuální | potvrzeno (conn_state, history) |
| Zeek SSH | https://docs.zeek.org/en/lts/scripts/base/protocols/ssh/index.html | aktuální | potvrzeno |
| Corelight SSH/RDP Inferences | https://corelight.com/blog/how-zeek-can-provide-insights-despite-encrypted-communications | 2023-2024 | vyhledávání |
| FoxIO JA4+ | https://github.com/FoxIO-LLC/ja4 | 2023-2025 | potvrzeno včetně licencí a JA4SSH příkladu |
| Zeek balíček JA4+ | https://packages.bro.org/packages/view/65d88958-d5f0-11ee-8674-0a598146b5c6 | 2024 | odkaz z vyhledávání |
| ACM Long Connection Detection | https://www.activecountermeasures.com/threat-hunting-long-connection-detection-video-blog/ | cca 2020-2023 | vyhledávání |
| ACM Understanding C2 Beacons | https://www.activecountermeasures.com/malware-of-the-day-understanding-c2-beacons-part-1-of-2/ | cca 2020 | vyhledávání |
| ACM Saefko (jitter 33 %) | https://www.activecountermeasures.com/malware-of-the-day-saefko/ | cca 2020 | vyhledávání |
| Hunting C2 beaconing (FFT) | https://dev.to/cgivre/hunting-for-c2-beaconing-with-python-4mpg | cca 2021 | vedlejší zdroj |
| Outflank DoH C2 | https://www.outflank.nl/blog/2018/10/25/building-resilient-c2-infrastructues-using-dns-over-https/ | 2018 | potvrzeno |
| Black Hills DoH pro Cobalt Strike | https://blackhillsinfosec.com/?p=20262 | cca 2020 | vyhledávání |
| LANL Unified Host and Network Data Set | https://arxiv.org/pdf/1708.07518 | 2017 | potvrzeno |
| LANL data | https://csr.lanl.gov/data/2017/ | 2017 | potvrzeno |
| CISA Volt Typhoon, LOTL | https://cisa.gov/news-events/alerts/2024/02/07/cisa-and-partners-release-advisory-prc-sponsored-volt-typhoon-activity-and-supplemental-living-land | 2024 | z vyhledávání, ověřit přímo |
| Přehled datasetů | https://github.com/shramos/Awesome-Cybersecurity-Datasets | různé | rozcestník |
| arXiv 2609.19091 (RITA vs. LN mezičasy) | https://arxiv.org/pdf/2609.19091 | 2026 | jen ve výsledcích, nečteno |
| Interní měření | docs/diplomka/eval/soak-findings.md; F:\Projekty\bakula-soak\run-v2-72h\status.md | 2026 | přečteno (status průběžný) |
