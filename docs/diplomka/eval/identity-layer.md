# Identity vrstva (Deliverable 2) — multi-signálová identita přes běhy

**Status: implementováno a testováno (29. 10. 2026).** Nová vrstva `src/identity.rs`, NAD `report.rs::normalize_inventory()` — `host_key`/`host_id` se nemění, přidává se doplňkový `asset_id` jako cross-run identifikátor.

## Problém

`normalize_inventory()` dává hostu identitu podle `host.ip` — stabilní jen uvnitř jednoho běhu. Ověřeno v kódu: žádná funkce v `correlation.rs`/`findings.rs`/`decision.rs` nezávisí na tom, že `host_key` je konkrétně IP, jen na tom, že je to stabilní klíč v rámci běhu — proto šlo identitu řešit jako samostatnou vrstvu beze zásahu do produkční logiky (stejný princip jako Deliverable 1).

## Řešení

`IdentityResolver` (stavový, pamatuje si MAC↔IP mapování mezi voláními — `storage.rs` dnes běhy ukládá jednotlivě bez cross-run registru, tohle je první místo s touto kontinuitou):

- **MAC jako primární klíč** (nemění se při DHCP renew) → DHCP renewal (stejná MAC, nová IP) rozpozná jako **stejný asset**.
- **IP, která dřív patřila jiné MAC, se objeví s novou MAC** → `Ambiguous` (NAT/výměna HW) — **ne tiché sloučení**. Vědomé rozhodnutí: tichá chyba (spojení dvou různých zařízení) je nebezpečnější než viditelně nerozhodnutý případ.
- **Host bez MAC** (firewall/router mimo ARP dosah — reálný případ, ne hypotetický, viz `nmap.rs:315-322`) → fallback na IP, se zdokumentovaným omezením.

## Proč žádný network-capture dataset (na rozdíl od Deliverable 1)

Identity-churn ground truth ("tohle fyzické zařízení si zachovává identitu přes změnu IP") je inherentně informace, kterou žádný reálný capture nelabeluje bez vlastní kontroly nad topologií. Testováno proti autorsky vytvořeným sekvencím `HostReport` (4 testy: DHCP renewal, NAT/swap, no-MAC fallback, smíšená flotila zařízení). Toto **není** stejná kategorie problému jako label-leakage z Deliverable 1 (tam šlo o skrytí ground truth od detekčního algoritmu v ablaci; tady o funkční korektnost deterministické resolving logiky — jednotkový test, ne statistická ablace).

## Naměřeno (deterministická korektnost, ne statistická přesnost)

| Scénář | Stará logika (`host_key=ip`) | Nová logika (`IdentityResolver`) |
|---|---|---|
| 1 zařízení, 3× DHCP renew | 3 "různé" hosty (fragmentace) | 1 asset |
| 2 zařízení, každé 2× DHCP renew | 4 "různí" hosté | 2 assets |
| NAT/výměna HW (stejná IP, jiná MAC) | tiše sloučeno do 1 hosta | `Ambiguous`, obě strany viditelné |
| Host bez MAC, stejná IP 2× | 1 host (shodou okolností správně) | 1 asset (fallback, zdokumentované omezení) |

## Omezení (explicitně, ne zamlčeno)

Žádná validace na reálných vícedenních síťových datech s potvrzenou fyzickou identitou zařízení (longitudinal capture) neexistuje — to je budoucí práce (vlna 3, Mininet/Containerlab simulace DHCP/NAT churn), ne tvrzení o současné vyřešenosti. `diff.rs::build_diff()` dnes srovnává běhy přes `host_key` (=IP) — napojení `asset_id` na `diff.rs` je navazující, samostatný krok (ne součást tohoto), aby zůstalo samostatně recenzovatelné.
