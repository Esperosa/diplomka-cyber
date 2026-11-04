# Plán vlastní laboratoře, pasivního sběru a dotaz pro UHK (krok 5, návrh, zatím nenasazeno)

Datum 2026-11-04. Je to plán, nic z něj zatím neběží. Proč je potřeba: simulace (soak) a veřejné datasety ověřují engine jen nepřímo. CTU-13 a IoT-23 pokrývají asi 4 z 19 rodin a CIC-IDS2017 a UNSW-NB15 jsou staré záznamy z testbedu (`audit-pokryti.md`, bod 7 a 8). Chybí dvě věci:

1. útoky provedené skutečnými nástroji proti skutečným systémům, se známou pozemní pravdou;
2. dlouhý skutečný neškodný provoz s provozními poruchami, které opravdu nastanou.

Uživatel nemá firmu ani známého s pilotní sítí. Zdroje jsou proto vlastní laboratoř, vlastní domácí síť (jen pasivně) a případně polygon UHK.

## A) Vlastní izolovaná laboratoř

**Hardware.** Samostatný stroj, ne pracovní PC uživatele, který je vytížený: mini-PC nebo starší PC s 32 GB RAM a Proxmoxem. Dále jeden spravovaný switch se zrcadlením portu (SPAN), nebo jen virtuální bridge v Proxmoxu. Odhad ceny je 0 Kč (repasovaný stroj, který už je k dispozici) až 6 000 Kč.

**Síť.** Izolovaná VLAN nebo virtuální bridge bez cesty do domácí sítě a do internetu. Stahování aktualizací se dělá jen přes dočasný řízený NAT, mimo okna měření. Senzor je VM se Zeekem a Suricatou na zrcadleném portu. Výstupem jsou stejné formáty jako v produkci (Zeek `conn.log`, Suricata `eve.json`), takže engine je čte beze změny.

**Cíle.** Veřejně dostupné záměrně zranitelné obrazy (Metasploitable 2/3, DVWA, OWASP Juice Shop), Windows Server ve zkušební verzi se sdílením SMB, linuxový souborový a webový server, DNS a DHCP server (dnsmasq), VPN server (WireGuard nebo OpenVPN) a dvě až tři klientské VM s generátorem běžné práce.

**Útočné nástroje.** Jen standardní veřejné nástroje používané při penetračních testech a při výuce (nmap, hydra, sqlmap, Metasploit Framework, a pro řetězení podle ATT&CK MITRE Caldera nebo Atomic Red Team). Nové techniky se nevymýšlejí. Každý scénář odpovídá existující rodině soaku. Mapování a parametry tempa (časovací volby skeneru, počet paralelních pokusů, prodlevy) se zapíšou do runbooku. Tytéž osy jako v A2 předregistrace kroku 5 tak půjdou porovnat se simulací.

**Pozemní pravda.** Každé spuštění zapíše řádek do `runs.jsonl`: čas začátku a konce, nástroj, parametry, zdrojová a cílová IP a rodina. Štítkovač pak označí toky v okně a mezi těmito adresami. Neoznačené toky ze stejného okna jsou „neznámé“, ne neškodné, stejně jako u CTU-13.

**Provozní poruchy naostro.** Krok 5 poruchy jen simuluje. Tady se provedou skutečně a s časem v runbooku:

- vypnutí DNS serveru;
- obnova DHCP s novým rozsahem;
- prošlý certifikát na webovém serveru;
- opakované odpojení linky;
- chybná maska na klientovi;
- selhaná záloha (plný disk cíle);
- vypnutí virtuálního segmentu;
- restart VPN serveru se znovupřipojením klientů;
- přesun služby na nové adresy.

**Měření.** Stejné metriky jako soak: zobrazené položky a FP na síť-den, detekce po rodinách, zavřeno omylem. Navíc srovnání se simulací: liší-li se detekce rodiny v laboratoři a v soaku o víc než 20 p. b., jde o kandidáta na chybu generátoru (riziko cirkularity, M50). Lab se ladí jen na první polovině běhů, druhá je držená.

**Bezpečnost a právo.** Útočí se jen na vlastní stroje v izolované síti. Žádný provoz laboratoře nesmí odejít ven: kontroluje se to pravidlem na hraničním routeru a měřením na senzoru. Obrazy se zranitelnostmi nikdy nedostanou síťové rozhraní do domácí sítě. Data laboratoře neobsahují osobní údaje.

**Pořadí.** (1) Senzor a dva cíle, skeny a hádání hesel, 1 týden. (2) Web a SMB, pohyb v síti a exfiltrace přes vlastní server, 1 týden. (3) Poruchy naostro, 1 týden. (4) Kampaně přes Calderu, 1 až 2 týdny.

## B) Pasivní sběr z domácí sítě uživatele

**Účel.** Jen neškodný provoz: FP na skutečném dlouhém provozu (týdny), drift, skutečné poruchy (výpadky ISP, aktualizace, nová zařízení). V domácí síti se neútočí.

**Sběr.** Zeek na zrcadleném portu switche za routerem, nebo na samostatném malém stroji (například Raspberry Pi 5) jako bridge. Ukládá se jen `conn.log` (metadata toků) a volitelně `dns.log` bez odpovědí. Žádný obsah, žádné pcap.

**Ochrana údajů.** Domácí provoz jsou osobní údaje členů domácnosti, proto:

- všichni dospělí v domácnosti předem souhlasí a vědí, co se sbírá;
- IP a MAC adresy se při sběru pseudonymizují klíčovaným hashem s tajnou solí uloženou mimo data;
- doménová jména se ukládají jen jako hash nebo vůbec;
- data leží mimo repo, šifrovaně, a po 90 dnech se mažou;
- ven z domácnosti jdou jen agregované metriky (FP na den, typy nálezů), nikdy záznamy.

**Měření.** Engine `v3` pasivně, bez zásahů (bez blokování). Výstup: zobrazené položky na den a na 100 zařízení (provozní cíl ≤ 10, `00-zaver` otázka U1), FP podle typu a rozpad podle poruch zapsaných ručně do deníku (výpadek, nové zařízení, aktualizace).

**Délka.** Nejméně 4 týdny, první 2 týdny ladicí, další 2 týdny držené.

## C) Polygon UHK

Pokud vedoucí práce a správci kybernetických laboratoří FIM (J5/J7) povolí přístup, dají se scénáře z části A pustit ve větší síti s realističtějším provozem. Rozhodnutí je na UHK. Dotaz je níže.

## Dotaz pro UHK (návrh, neodesláno)

> Dobrý den,
>
> píšu diplomovou práci o automatickém ověřování podezření v síťovém provozu (navazuje na bakalářskou práci Bakula). Rád bych ověřil detekci na skutečném provozu se známou pozemní pravdou, nejen v simulaci a na veřejných datasetech.
>
> Bylo by možné použít kybernetickou laboratoř FIM (J5/J7, cyber range) pro tato pasivní měření?
>
> 1. Přehrát několik známých scénářů (skenování, hádání hesel, pohyb v síti) standardními nástroji proti strojům polygonu.
> 2. Z výstupů Zeeku a Suricaty měřit, co nástroj pozná.
>
> Všechno jen uvnitř izolovaného prostředí a podle pravidel laboratoře, bez zásahů do jiných sítí. Data bez osobních údajů zůstanou u mě a do práce půjdou jen agregované výsledky.
>
> Pokud to jde, s kým to mám domluvit a jaké jsou podmínky (termíny, dohled, schválení vedoucím)?
>
> Děkuji, [jméno], [studijní program]
