//! Deliverable 25 (H2, `docs/diplomka/produkcni-plan.md`): Community ID v1 - sdilena
//! normalizace 5-tuple do jednoho join-key, nezavisla na smeru toku a na tom, ktery
//! senzor (Zeek/Suricata/aktivni sken) tok pozoroval. Bez tohohle klice H2 nemuze
//! existovat v zadne forme - `src/passive/zeek.rs` a `src/passive/suricata.rs` dosud
//! pouzivaly jen sve vlastni, senzor-lokalni identifikatory (Zeek `uid`, Suricata
//! `flow_id`), ktere nejsou mezi senzory porovnatelne.
//!
//! **Algoritmus overen proti realnemu Zeek 9.0.1 vystupu, ne jen podle specifikace
//! odhadnut.** Postup: `docker run --network container:X corfr/tcpdump` zachytil
//! realny TCP handshake (172.17.0.1:49818 -> 172.17.0.2:80), `zeek -C -r test.pcap
//! policy/protocols/conn/community-id-logging` vratil `1:nTs1CSdTGlG13eI4k9WSGFAbjAw=`
//! pro tenhle tok - presne to, co tahle implementace pro stejnou 5-tuple pocita.
//! Overeno i na obracenem smeru (server->client) se stejnym vysledkem - to je cela
//! hodnota Community ID (identifikace toku nezavisle na smeru pozorovani).
//!
//! **Omezeno na TCP/UDP/SCTP (ma porty).** ICMP vyzaduje jinou typ/code logiku
//! (mapovani request/reply na stejnou hodnotu) - neimplementovano, `community_id_v1`
//! vraci `None` pro protokoly, kde nema smysl pouzit porty.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha1::{Digest, Sha1};
use std::net::IpAddr;

/// `proto` je IP protokolove cislo (6=TCP, 17=UDP, 132=SCTP - stejne hodnoty, ktere uz
/// `src/passive/zeek.rs`/`src/passive/suricata.rs` z logu ctou). `seed` je 0, pokud
/// senzory nejsou explicitne nakonfigurovany jinak (Zeek/Suricata vychozi hodnota).
/// Zapojeno pres `ConnectionObservation::community_id()` (Deliverable 26).
pub(crate) fn community_id_v1(
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    proto: u8,
) -> Option<String> {
    let (src_bytes, dst_bytes): (Vec<u8>, Vec<u8>) = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => (src.octets().to_vec(), dst.octets().to_vec()),
        (IpAddr::V6(src), IpAddr::V6(dst)) => (src.octets().to_vec(), dst.octets().to_vec()),
        // Smisene rodiny (v4 <-> v6) nemaji v jedne spojovane relaci smysl.
        _ => return None,
    };

    // Normalizace smeru: "mensi" endpoint (podle bytu adresy, pak podle portu) vzdy
    // prvni - tim pada toku videny z obou stran (klient->server i server->klient)
    // vyprodukuje STEJNY hash. Bez tohohle kroku by Community ID nemelo zadnou
    // hodnotu jako join-key mezi senzory.
    let (ordered_src, ordered_sport, ordered_dst, ordered_dport) =
        if src_bytes > dst_bytes || (src_bytes == dst_bytes && src_port > dst_port) {
            (dst_bytes, dst_port, src_bytes, src_port)
        } else {
            (src_bytes, src_port, dst_bytes, dst_port)
        };

    let seed: u16 = 0;
    let mut buf = Vec::with_capacity(2 + ordered_src.len() + ordered_dst.len() + 2 + 2 + 2);
    buf.extend_from_slice(&seed.to_be_bytes());
    buf.extend_from_slice(&ordered_src);
    buf.extend_from_slice(&ordered_dst);
    buf.push(proto);
    buf.push(0); // padding byte - cast specifikace, ne chyba
    buf.extend_from_slice(&ordered_sport.to_be_bytes());
    buf.extend_from_slice(&ordered_dport.to_be_bytes());

    let digest = Sha1::digest(&buf);
    Some(format!("1:{}", BASE64.encode(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Referencni hodnota ZISKANA Z REALNEHO ZEEKA (ne z psane specifikace), viz
    /// modulova dokumentace vyse - 172.17.0.1:49818 -> 172.17.0.2:80 tcp.
    #[test]
    fn matches_real_zeek_reference_value_for_captured_tcp_flow() {
        let id = community_id_v1(
            "172.17.0.1".parse().unwrap(),
            49818,
            "172.17.0.2".parse().unwrap(),
            80,
            6,
        );
        assert_eq!(id, Some("1:nTs1CSdTGlG13eI4k9WSGFAbjAw=".to_string()));
    }

    /// Druha referencni hodnota, tentokrat ZISKANA Z REALNEHO SURICATA 8.0.7
    /// (`jasonish/suricata`, offline analyza stejneho typu toku, `community-id=yes`
    /// v eve.json) - potvrzuje, ze implementace je kompatibilni s OBEMA senzory, ne
    /// jen s jednim. 172.17.0.1:35682 -> 172.17.0.2:80 tcp.
    #[test]
    fn matches_real_suricata_reference_value_for_captured_tcp_flow() {
        let id = community_id_v1(
            "172.17.0.1".parse().unwrap(),
            35682,
            "172.17.0.2".parse().unwrap(),
            80,
            6,
        );
        assert_eq!(id, Some("1:ylOa6zhQXyUgu30rGBQ82VAhhk4=".to_string()));
    }

    #[test]
    fn is_identical_regardless_of_observed_direction() {
        let forward = community_id_v1(
            "172.17.0.1".parse().unwrap(),
            49818,
            "172.17.0.2".parse().unwrap(),
            80,
            6,
        );
        let reverse = community_id_v1(
            "172.17.0.2".parse().unwrap(),
            80,
            "172.17.0.1".parse().unwrap(),
            49818,
            6,
        );
        assert_eq!(forward, reverse);
        assert!(forward.is_some());
    }

    #[test]
    fn differs_for_different_flows() {
        let a = community_id_v1(
            "10.0.0.1".parse().unwrap(),
            1234,
            "10.0.0.2".parse().unwrap(),
            80,
            6,
        );
        let b = community_id_v1(
            "10.0.0.1".parse().unwrap(),
            1235,
            "10.0.0.2".parse().unwrap(),
            80,
            6,
        );
        assert_ne!(a, b, "jiny zdrojovy port musi dat jiny Community ID");
    }

    #[test]
    fn mixed_address_families_return_none() {
        let id = community_id_v1(
            "10.0.0.1".parse().unwrap(),
            1234,
            "::1".parse().unwrap(),
            80,
            6,
        );
        assert_eq!(id, None);
    }
}
