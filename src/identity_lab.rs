//! Deliverable 22: Identity vrstva (`src/identity.rs`) testovaná na REALNÝCH síťových
//! datech, ne jen na autorsky vytvořených syntetických `HostReport` sekvencích - viz
//! `docs/diplomka/eval/identity-layer.md`, limitace "chybí reálná vícedenní data".
//!
//! Docker custom bridge network dává kontejnerům skutečné virtuální MAC adresy a
//! podporuje explicitní `--mac-address`/`--ip` - ověřeno ručně (`ping` + `ip neigh show`
//! ze sidecar kontejneru na stejné síti) PŘED zapsáním do kódu, stejná disciplína jako
//! prometheus nález v Deliverable 7. DHCP renewal (stejná MAC, nová IP) a NAT/výměna HW
//! (stejná IP, nová MAC) se simulují tak, že se kontejnery se zvolenými MAC/IP páry
//! vytvářejí a odstraňují v řízeném pořadí - síť samotná a ARP tabulka jsou reálné,
//! jen časování událostí je řízené testem (ne čekání na skutečnou vícedenní síť).

use std::process::Command;
use std::time::Duration;

use crate::error::{BakulaError, Result};
use crate::model::HostReport;

const SUBNET: &str = "172.31.9.0/24";

pub struct IdentityNetHandle {
    network_name: String,
    scanner_name: String,
}

impl Drop for IdentityNetHandle {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.scanner_name])
            .status();
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network_name])
            .status();
    }
}

pub fn start_identity_network() -> Result<IdentityNetHandle> {
    let network_name = format!("bakula-identity-net-{}", uuid::Uuid::new_v4());
    let status = Command::new("docker")
        .args(["network", "create", "--subnet", SUBNET, &network_name])
        .status()
        .map_err(|error| {
            BakulaError::Processing(format!("docker network create selhal: {error}"))
        })?;
    if !status.success() {
        return Err(BakulaError::Processing(
            "docker network create pro identity lab se nepodarilo.".to_string(),
        ));
    }

    // --cap-add NET_ADMIN: scanner musi umet `ip neigh flush` pred kazdym lookupem
    // (viz real_arp_lookup) - bez toho vraci `ip neigh show` stare, uz neplatne ARP
    // zaznamy z predchoziho kola misto cerstveho razeseni. Zmereno rucne pred
    // zapsanim do kodu: bez flush selhavalo kolo 3 (NAT/swap) se 100% packet loss,
    // protoze scanner se snazil poslat ping na uz neexistujici stary MAC z kola 1.
    let scanner_name = format!("bakula-identity-scanner-{}", uuid::Uuid::new_v4());
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &scanner_name,
            "--network",
            &network_name,
            "--cap-add",
            "NET_ADMIN",
            "nicolaka/netshoot",
            "sleep",
            "600",
        ])
        .status()
        .map_err(|error| {
            BakulaError::Processing(format!("docker run (scanner) selhal: {error}"))
        })?;
    if !status.success() {
        let _ = Command::new("docker")
            .args(["network", "rm", &network_name])
            .status();
        return Err(BakulaError::Processing(
            "docker run pro ARP scanner kontejner se nepodarilo spustit.".to_string(),
        ));
    }

    Ok(IdentityNetHandle {
        network_name,
        scanner_name,
    })
}

pub fn stop_identity_network(handle: IdentityNetHandle) {
    drop(handle);
}

/// Spustí jeden "host" s explicitní MAC a IP adresou na dané síti. Volající si container
/// name zapisuje sám (`docker_rm_host` na konci) - žádný implicitní registr, ať je
/// pořadí vytváření/odstraňování v testu explicitně vidět.
pub fn spawn_host_with_mac_ip(
    handle: &IdentityNetHandle,
    container_name: &str,
    mac: &str,
    ip: &str,
) -> Result<()> {
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            container_name,
            "--network",
            &handle.network_name,
            "--mac-address",
            mac,
            "--ip",
            ip,
            "nginx:alpine",
        ])
        .status()
        .map_err(|error| BakulaError::Processing(format!("docker run (host) selhal: {error}")))?;
    if !status.success() {
        return Err(BakulaError::Processing(format!(
            "docker run pro host {container_name} ({ip}, {mac}) se nepodarilo spustit."
        )));
    }
    std::thread::sleep(Duration::from_millis(1500));
    Ok(())
}

pub fn remove_host(container_name: &str) {
    let _ = Command::new("docker")
        .args(["rm", "-f", container_name])
        .status();
}

/// Realny ARP lookup: `ip neigh flush all` (vyzaduje NET_ADMIN, viz start_identity_network)
/// prosince zahodi stare zaznamy z predchozich kol PRED pingem - bez tohohle kroku
/// zustava v cache stara MAC adresa stale IP z predchoziho kontejneru, ktery uz
/// neexistuje, a ping na ni tise selhava (100% packet loss), zatimco `ip neigh show`
/// by vracel tu starou, uz neplatnou polozku - zmereno rucne pred zapsanim do kodu
/// (presne tenhle bug se objevil v prvni verzi tohoto testu bez flush). Ping se pak
/// opakuje az 5x jako dalsi, nezavisla ochrana proti pomalemu startu kontejneru.
pub fn real_arp_lookup(handle: &IdentityNetHandle, ip: &str) -> Result<Option<String>> {
    let _ = Command::new("docker")
        .args(["exec", &handle.scanner_name, "ip", "neigh", "flush", "all"])
        .status();

    let mut ping_ok = false;
    for _ in 0..5 {
        let status = Command::new("docker")
            .args([
                "exec",
                &handle.scanner_name,
                "ping",
                "-c",
                "1",
                "-W",
                "1",
                ip,
            ])
            .status()
            .map_err(|error| BakulaError::Processing(format!("ping selhal: {error}")))?;
        if status.success() {
            ping_ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !ping_ok {
        return Err(BakulaError::Processing(format!(
            "ping na {ip} ze scanneru neuspel po 5 pokusech - host neni dostupny"
        )));
    }

    let output = Command::new("docker")
        .args(["exec", &handle.scanner_name, "ip", "neigh", "show", ip])
        .output()
        .map_err(|error| BakulaError::Processing(format!("ip neigh show selhal: {error}")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: "172.31.9.10 dev eth0 lladdr 02:42:ac:11:00:a1 REACHABLE"
    let mac = stdout
        .split_whitespace()
        .skip_while(|token| *token != "lladdr")
        .nth(1)
        .map(ToString::to_string);
    Ok(mac)
}

pub fn host_report_from_arp(ip: &str, mac: Option<String>) -> HostReport {
    HostReport {
        host_id: format!("identity-lab:{ip}"),
        host_key: ip.to_string(),
        ip: ip.to_string(),
        hostname: None,
        mac,
        vendor: None,
        asset_id: None,
        identity_note: None,
        device_class: None,
        services: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::identity::{IdentityMatch, IdentityResolver};

    /// Stejny zamek jako `lab::tests::LAB_PORT_LOCK` - testy v tomhle modulu nesmi bezet
    /// paralelne s sebou (sdileji podsit/jmena kontejneru v ramci jednoho CI/lokalniho
    /// bezu by se nestrety, ale sekvencni bezeni je jednodussi na diagnostiku).
    static IDENTITY_NET_LOCK: Mutex<()> = Mutex::new(());

    /// Deliverable 22 - DHCP renewal (stejna MAC, nova IP) a NAT/vymena HW (stejna IP,
    /// nova MAC) na REALNE Docker siti s realnym ARP objevovanim, ne na syntetickych
    /// HostReport sekvencich. Overuje presne tu limitaci, kterou
    /// `docs/diplomka/eval/identity-layer.md` zapsal jako chybejici.
    #[test]
    fn identity_resolver_correctly_classifies_real_dhcp_renewal_and_nat_swap() {
        let _guard = IDENTITY_NET_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let net = start_identity_network().expect("start identity network");

        const MAC_A: &str = "02:42:ac:11:09:a1";
        const MAC_B: &str = "02:42:ac:11:09:b2";
        const IP_1: &str = "172.31.9.10";
        const IP_2: &str = "172.31.9.20";

        let host1 = "bakula-identity-host1";
        let result = spawn_host_with_mac_ip(&net, host1, MAC_A, IP_1);
        if let Err(error) = result {
            stop_identity_network(net);
            panic!("spawn host1: {error}");
        }

        let mac1 = real_arp_lookup(&net, IP_1);
        remove_host(host1);

        let host1_renewed = "bakula-identity-host1-renewed";
        let result = spawn_host_with_mac_ip(&net, host1_renewed, MAC_A, IP_2);
        if let Err(error) = result {
            remove_host(host1_renewed);
            stop_identity_network(net);
            panic!("spawn host1 renewed: {error}");
        }
        let mac2 = real_arp_lookup(&net, IP_2);
        remove_host(host1_renewed);

        let host_swap = "bakula-identity-host-swap";
        let result = spawn_host_with_mac_ip(&net, host_swap, MAC_B, IP_1);
        if let Err(error) = result {
            remove_host(host_swap);
            stop_identity_network(net);
            panic!("spawn host swap: {error}");
        }
        let mac3 = real_arp_lookup(&net, IP_1);
        remove_host(host_swap);
        stop_identity_network(net);

        let mac1 = mac1
            .expect("arp lookup round 1")
            .expect("round 1 musi najit realnou MAC");
        let mac2 = mac2
            .expect("arp lookup round 2")
            .expect("round 2 musi najit realnou MAC");
        let mac3 = mac3
            .expect("arp lookup round 3")
            .expect("round 3 musi najit realnou MAC");

        println!(
            "Deliverable 22: round1 ip={IP_1} mac={mac1} | round2 (DHCP renewal) ip={IP_2} mac={mac2} | round3 (NAT/swap) ip={IP_1} mac={mac3}"
        );

        assert_eq!(
            mac1, MAC_A,
            "round 1 musi zmerit realnou MAC, kterou jsme explicitne nastavili"
        );
        assert_eq!(
            mac2, MAC_A,
            "round 2 (DHCP renewal) musi zmerit STEJNOU MAC na NOVE IP"
        );
        assert_eq!(
            mac3, MAC_B,
            "round 3 (NAT/swap) musi zmerit NOVOU MAC na PUVODNI IP"
        );

        let mut resolver = IdentityResolver::new();

        let round1 = resolver.resolve(&host_report_from_arp(IP_1, Some(mac1)));
        assert!(
            matches!(round1, IdentityMatch::New(_)),
            "prvni pozorovani musi byt New, dostal jsem {round1:?}"
        );
        let asset1 = round1.asset_id().to_string();

        let round2 = resolver.resolve(&host_report_from_arp(IP_2, Some(mac2)));
        assert!(
            matches!(round2, IdentityMatch::Same(ref id) if *id == asset1),
            "DHCP renewal (stejna MAC, nova IP) musi resolver rozpoznat jako STEJNY asset, dostal jsem {round2:?}"
        );

        let round3 = resolver.resolve(&host_report_from_arp(IP_1, Some(mac3)));
        assert!(
            matches!(round3, IdentityMatch::Ambiguous { .. }),
            "NAT/vymena HW (stejna IP, nova MAC) musi resolver oznacit jako Ambiguous, ne tise slit, dostal jsem {round3:?}"
        );
    }
}
