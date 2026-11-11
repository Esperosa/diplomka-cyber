# Studie 08: koncová telemetrie jako nezávislý druh důkazu

Stav: krok 8, 2026-11-11. Rešerše z veřejných stránek (ověřeno 2026-11-11, nic se neodesílalo). Jistota u každého tvrzení: V = vysoká (oficiální dokumentace nebo stránka datasetu), S = střední (vlastní syntéza z více zdrojů), N = nízká (úsudek autora, neověřeno měřením).

## 1. Schémata zdrojů

| zdroj | co nese | co nenese | jistota |
|---|---|---|---|
| Sysmon, ID 1 (vznik procesu) | `Image`, `ParentImage`, `CommandLine`, `User`, `Hashes`, `Company`, `Product` | podpis procesu (pole `Signed` je až u ID 7, načtení obrazu) | V |
| Sysmon, ID 3 (spojení) | `Image`, `Protocol`, `Initiated`, zdrojová a cílová adresa a port | objem dat | V |
| Sysmon, ID 7, 10, 11, 13, 22 | načtení obrazu (`Signed`, `Signature`), přístup k procesu (`TargetImage`, `GrantedAccess`), vznik souboru, registr, DNS dotaz s `Image` | – | V |
| Windows Security 4624/4625, System 7045 | typ přihlášení, uživatel, zdrojová adresa; instalace služby | – | V |
| Wazuh alerts JSON | `rule.{id,level,groups}`, `agent.{id,name,ip}`, `data.*`, `syscheck.*`; Windows události vnořené v `data.win.{system,eventdata}` | surová událost, pokud ji pravidlo nezachytí | S |
| osquery results (log) | `name`, `hostIdentifier`, `unixTime`, `action`, `columns`; obsah dává dotaz (pack) | cokoliv, na co nikdo nenapsal dotaz | V |
| auditd, Velociraptor | syscall a artefakty; v tomto kroku neimplementováno (jen návrh adaptéru) | – | S |

Důsledek pro návrh: „známý podepsaný proces“ nejde u Sysmon ID 1 odvodit z podpisu. Používá se dvojice (cesta obrazu pod systémovou nebo programovou složkou, výrobce `Company`) a seznam schválených správcem. Podpis z ID 7 se připojí, jen když je k dispozici (S).

## 2. Veřejné datasety a licence

Licence se ověřily na stránkách datasetů 2026-11-11. Do repozitáře se nic nestahuje ani nekopíruje.

| dataset | obsah | licence podle stránky | poznámka |
|---|---|---|---|
| OTRF Security-Datasets | Sysmon a Windows události v JSON (simulace technik ATT&CK) | stránka repozitáře uvádí GPL-3.0 i MIT zároveň; text LICENSE se nepodařilo potvrdit | před použitím ověřit soubor LICENSE; do té doby jen odkaz |
| EVTX-ATTACK-SAMPLES | 200 EVTX souborů (Sysmon, Security) | GPL-3.0 (`LICENSE.GPL`) | pro test parseru stačí vlastní syntetické vzorky, kopírování vzorků do repa se nedělá |
| DARPA OpTC | eCAR JSON, hostitelské události 17 dní | „public domain“, Distribution A, bez záruk (README) | velký (stovky GB), jiný formát než Sysmon |
| LANL Unified Host and Network | auth, proc, dns, flows, redteam, 58 dní, deidentifikováno | CC0 1.0, žádá citaci (DOI 10.17021/1179829); stažení po zadání e-mailu a účelu | bez cest k obrazům a příkazových řádek, použitelný jen pro korelaci přihlášení a toků |

Žádný z nich nemá sítové toky a hostitelské události ze stejného prostředí v podobě, kterou jádro čte hned (LANL ano, ale bez obsahu procesů). Reálný test korelace host + síť tedy zůstává otevřený (laboratoř UHK). Jistota: S.

## 3. Korelace host + síť: osvědčené postupy

1. **Identita zařízení.** Hostname, IP a MAC jsou slabé a měnitelné (DHCP, NAT, klonované obrazy). Událost se přiřadí hostu, jen když jednoznačně sedí aspoň jeden identifikátor a žádný jiný neukazuje na jiný host. Spor je `Ambiguous`, nikdy se nesloučí. Jistota V (obecná praxe, shoduje se s `IdentityMatch`).
2. **Čas.** Hodiny agentů se rozcházejí (sekundy až minuty). Spojení události s tokem má toleranci (výchozí 120 s) a posun agenta se odhaduje z jednoznačných dvojic (medián, aspoň 5 dvojic, ořez ±10 min). Jistota S.
3. **Spojení s tokem.** Pětice (protokol, zdroj, port, cíl, port) nebo Community ID v1 (v repu hotové) plus čas. Jistota V.
4. **Duplicity a pořadí.** Agent po výpadku posílá znovu (at-least-once), takže událost má otisk obsahu, duplicitní se zahazují. Pořadí se řadí podle času události, ne příjmu. Jistota V.
5. **Otrava a falšování.** Kompromitovaný agent může mlčet, nebo hlásit „vše v pořádku“, nebo se vydávat za jiný host. Důsledky: prázdná telemetrie není důkaz neškodnosti, neškodný koncový signál sám nezavírá nic, chráněný nález nezavírá nikdy, tvrzení „neškodný“ vyžaduje vzor starší než nález. Jistota N (návrh, měří se simulací, ne reálným útočníkem).
6. **Pokrytí.** Podíl hostů s živým agentem se zobrazuje; host bez agenta není neškodný. Jistota V.

## 4. Co z toho nevíme

Skutečnou míru falešných poplachů pravidel nad koncovými událostmi v cílovém prostředí. Simulace v kroku 8 je psaná autorem a měří jen to, zda zapojení do jádra funguje a nepoškozuje invarianty, ne skutečný zisk na reálném provozu.
