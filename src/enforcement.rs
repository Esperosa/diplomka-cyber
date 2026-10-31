//! `enforce.block_ip` (`docs/diplomka/produkcni-plan.md`, Faze C) - orchestrace
//! EXISTUJICIHO `nftables`, ne vlastni packet-path engine. Shoda vsech 3 agentu
//! (Opus comprehensive, pragmatik, skeptik) po 2-kolove debate 31.10.2026: vlastni
//! firewall/IPS engine je nebezpecny pro solo vyvojare bez zadneho ostreho
//! nasazeni (blast radius: uzamceni operatora z vlastni site, vypadek DNS,
//! falesny block na kriticke infrastrukture).
//!
//! **Rozsah tohoto kroku: jen ROZHODOVACI LOGIKA a GENEROVANI `nft` prikazu, ZADNA
//! EXEKUCE.** `Command::new("nft")` se tady nikde nevola - to je navazujici,
//! samostaty krok (vyzaduje: audit log, nezavisly periodicky sweep overujici
//! zivy `nft` stav proti auditu - ne jen jeden naplanovany unblock job - a
//! zapojeni do `platform.rs`'s job systemu, ktery je dnes natvrdo svazany s
//! `PipelineJobSpec`, ne obecny job-kind dispatch). Tohle je presne ten typ
//! "postav cisty/testovatelny jadro prvni, zapoj pozdeji" postupu, co uz
//! zabral u `hypothesis.rs`/`verification_planner.rs`.
//!
//! Mantinely z kola 2 debaty (skeptik), vsechny vynucene TADY, v rozhodovaci
//! logice, ne jen jako doporuceni volajicimu:
//! 1. **Chraneny rozsah je vynucen i proti explicitnimu pozadavku** - caller
//!    nemuze blokovat gateway/management/loopback/multicast tim, ze o to
//!    vyslovne pozada.
//! 2. **TTL ma povinny strop** - "navzdy" blok neexistuje, i kdyby ho volajici
//!    chtel.
//! 3. **Dry-run je strukturalni vychozi stav** - `plan_block` vraci jen PLAN
//!    (`nft` prikaz jako text), nikdy ho nevykona. Prvni skutecne vykonani (az
//!    bude existence exekucni vrstvy) vyzaduje samostatny, explicitni krok -
//!    stejny "shadow/propose" vzor jako `verification_planner::requires_approval`.

use std::net::IpAddr;

use ipnet::IpNet;

/// Maximalni TTL bloku - 24 hodin. Zadny blok neni "navzdy"; delsi potreba
/// vyzaduje opakovane prodlouzeni (budouci krok), ne jednorazovy vysoky strop.
pub const MAX_BLOCK_TTL_SECONDS: u64 = 24 * 60 * 60;

/// Rozsahy, ktere se NESMI zablokovat, i kdyz o to volajici vyslovne pozada -
/// loopback, link-local, multicast. Konkretni gateway/DNS/management IP
/// konfiguruje operator pri nasazeni (`ProtectedRanges::with_additional`), tyto
/// 3 jsou univerzalni a nejde je vypnout.
fn universal_protected_ranges() -> Vec<IpNet> {
    vec![
        "127.0.0.0/8".parse().expect("valid cidr"),
        "169.254.0.0/16".parse().expect("valid cidr"),
        "224.0.0.0/4".parse().expect("valid cidr"),
    ]
}

#[derive(Debug, Clone)]
pub struct ProtectedRanges {
    ranges: Vec<IpNet>,
}

impl ProtectedRanges {
    /// `additional` jsou operatorem nakonfigurovane rozsahy (gateway, DNS
    /// resolver, management rozhrani) - NAD ramec univerzalnich (loopback/
    /// link-local/multicast), ktere jsou vzdy pritomne a nejde je vynechat.
    pub fn with_additional(additional: Vec<IpNet>) -> Self {
        let mut ranges = universal_protected_ranges();
        ranges.extend(additional);
        Self { ranges }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ranges.iter().any(|net| net.contains(ip))
    }
}

#[derive(Debug, Clone)]
pub struct BlockIpRequest {
    pub ip: String,
    pub ttl_seconds: u64,
    pub reason: String,
    pub finding_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementRejection {
    UnparseableIp,
    ProtectedRange,
    TtlExceedsMaximum,
}

/// Plan jedne akce - jeste NEVYKONANO. `nft_command` je presny prikaz, ktery by
/// se zavolal, az bude existovat exekucni vrstva - textova reprezentace je
/// vedomy navrh (snadno auditovatelne/logovatelne/testovatelne bez zavislosti
/// na skutecnem `nft` binary).
#[derive(Debug, Clone)]
pub struct BlockIpPlan {
    pub ip: String,
    pub ttl_seconds: u64,
    pub reason: String,
    pub finding_id: Option<String>,
    pub nft_command: Vec<String>,
}

/// Cista rozhodovaci funkce - fail-closed na vsech 3 mantinelech. Vraci plan
/// (text prikazu), NIKDY ho nevykona.
pub fn plan_block(
    request: &BlockIpRequest,
    protected: &ProtectedRanges,
) -> Result<BlockIpPlan, EnforcementRejection> {
    let addr = request
        .ip
        .parse::<IpAddr>()
        .map_err(|_| EnforcementRejection::UnparseableIp)?;

    if protected.contains(&addr) {
        return Err(EnforcementRejection::ProtectedRange);
    }
    if request.ttl_seconds == 0 || request.ttl_seconds > MAX_BLOCK_TTL_SECONDS {
        return Err(EnforcementRejection::TtlExceedsMaximum);
    }

    Ok(BlockIpPlan {
        ip: request.ip.clone(),
        ttl_seconds: request.ttl_seconds,
        reason: request.reason.clone(),
        finding_id: request.finding_id.clone(),
        nft_command: render_nft_add_element(&request.ip, request.ttl_seconds),
    })
}

/// `bakula` vlastni jen svoji `table inet bakula`/`set blocked_ips` - nikdy se
/// nedotyka operatorovych existujicich pravidel/tabulek/NAT. `flags timeout`
/// znamena, ze kernel sam odstrani prvek po vyprseni TTL i kdyby `bakula`
/// spadnul - self-healing bez zavislosti na tom, ze nejaky "unblock" job
/// skutecne dobehne (presne ten typ rizika, ktery uz jednou zpusobil
/// lease-renewal bug v `platform.rs`).
fn render_nft_add_element(ip: &str, ttl_seconds: u64) -> Vec<String> {
    vec![
        "add".to_string(),
        "element".to_string(),
        "inet".to_string(),
        "bakula".to_string(),
        "blocked_ips".to_string(),
        format!("{{ {ip} timeout {ttl_seconds}s }}"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protected() -> ProtectedRanges {
        ProtectedRanges::with_additional(vec!["192.168.1.1/32".parse().expect("valid cidr")])
    }

    fn request(ip: &str, ttl_seconds: u64) -> BlockIpRequest {
        BlockIpRequest {
            ip: ip.to_string(),
            ttl_seconds,
            reason: "test".to_string(),
            finding_id: Some("finding:1".to_string()),
        }
    }

    #[test]
    fn plan_block_accepts_ordinary_ip_within_ttl_cap() {
        let plan = plan_block(&request("203.0.113.50", 3600), &protected())
            .expect("obycejna IP s platnym TTL se musi naplanovat");
        assert_eq!(plan.ip, "203.0.113.50");
        assert_eq!(plan.ttl_seconds, 3600);
        assert!(plan.nft_command.contains(&"bakula".to_string()));
    }

    #[test]
    fn plan_block_rejects_operator_configured_protected_ip_even_if_explicitly_requested() {
        let result = plan_block(&request("192.168.1.1", 60), &protected());
        assert_eq!(result.unwrap_err(), EnforcementRejection::ProtectedRange);
    }

    #[test]
    fn plan_block_rejects_universal_loopback_even_without_operator_configuration() {
        let empty_additional = ProtectedRanges::with_additional(Vec::new());
        let result = plan_block(&request("127.0.0.1", 60), &empty_additional);
        assert_eq!(result.unwrap_err(), EnforcementRejection::ProtectedRange);
    }

    #[test]
    fn plan_block_rejects_ttl_above_maximum() {
        let result = plan_block(
            &request("203.0.113.50", MAX_BLOCK_TTL_SECONDS + 1),
            &protected(),
        );
        assert_eq!(result.unwrap_err(), EnforcementRejection::TtlExceedsMaximum);
    }

    #[test]
    fn plan_block_rejects_zero_ttl() {
        let result = plan_block(&request("203.0.113.50", 0), &protected());
        assert_eq!(result.unwrap_err(), EnforcementRejection::TtlExceedsMaximum);
    }

    #[test]
    fn plan_block_rejects_unparseable_ip_fail_closed() {
        let result = plan_block(&request("not-an-ip", 60), &protected());
        assert_eq!(result.unwrap_err(), EnforcementRejection::UnparseableIp);
    }

    #[test]
    fn plan_block_never_touches_a_pre_existing_table_or_ruleset() {
        // Regresni pojistka proti budoucimu rozsireni, ktere by omylem zacalo
        // generovat `flush`/`delete table`/jiny prikaz mimo vlastni "bakula" set.
        let plan = plan_block(&request("203.0.113.50", 60), &protected()).unwrap();
        assert_eq!(plan.nft_command[0], "add");
        assert!(!plan.nft_command.contains(&"flush".to_string()));
        assert!(!plan.nft_command.contains(&"delete".to_string()));
    }
}
