//! Strukturovane logovani (`tracing`). Do ted jen `println!/eprintln!` - nelze
//! filtrovat podle urovne, nelze strojove zpracovat a dlouho bezici
//! `monitor --continuous` / server se nedal ladit.
//!
//! - `SALTICUS_LOG_FORMAT=json` -> JSON radky na stderr (pro agregatory), jinak
//!   citelny text.
//! - Uroven pres `SALTICUS_LOG` (nebo `RUST_LOG`), vychozi `info`.
//! - CLI vystup pro cloveka (JSON reporty, tabulky) zustava na stdout; logy jdou
//!   VZDY na stderr, aby je nesmichaly s daty.
//! - Do logu se nikdy nepisou tokeny ani hodnoty hlavicek `Authorization` /
//!   `x-api-key`; audit zaznamy jdou pod cilem `salticus::audit`.

use tracing_subscriber::{EnvFilter, fmt};

pub fn init() {
    let filter = std::env::var("SALTICUS_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .ok()
        .and_then(|value| EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| EnvFilter::new("info"));
    let json = std::env::var("SALTICUS_LOG_FORMAT")
        .map(|value| value.eq_ignore_ascii_case("json"))
        .unwrap_or(false);
    let builder = fmt().with_env_filter(filter).with_writer(std::io::stderr);
    // `try_init`: opakovane volani (testy) nesmi panikovat.
    let _ = if json {
        builder.json().try_init()
    } else {
        builder.try_init()
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_is_idempotent() {
        super::init();
        super::init();
    }
}
