//! Měření výstupu enginu v soaku (krok 1A, oprava měření z auditu 01, bod #1):
//!
//! - `StateTracker`: odlišné stavy nálezů (stejné `finding_id`, mezera bez výskytu
//!   nejvýš `GAP_CYCLES`), aby se měřily odlišné problémy, ne nálezy × cykly (A14, A31).
//!   Stejný sledovač běží v obou ramenech A/B, takže je srovnatelný.
//! - tři skupiny výstupu (Dodatek A.1): zachyceno / automaticky vyřešeno / čeká na člověka.
//! - `unexpected_cause`: rozpad FP `unexpected_traffic`/`unmapped` podle příčiny (R13 E0).
//! - placebo okna (RQ5 S5, G0-plné): stejné klíčové IP v posunutém čase bez útoku dávají
//!   míru „detekce“ náhodnou shodou s pozadím; párový rozdíl skutečné a placebo detekce
//!   je poctivější než samotné „detekováno“.

use std::collections::{HashMap, HashSet};

use crate::soak::{netmodel::NetworkModel, stats::OutputStats};

/// Mezera (cykly), po které se opakovaný nález počítá jako nový stav (6 h).
pub const GAP_CYCLES: u32 = 12;

#[derive(Debug, Clone, Default)]
struct Tracked {
    last_cycle: u32,
    behavioral: bool,
    attributed: bool,
    displayed: bool,
    displayed_unattributed: bool,
    auto_resolved: bool,
}

/// Výstup pozorování jednoho nálezu v cyklu z pohledu sledovače.
#[derive(Debug, Clone, Copy, Default)]
pub struct Seen {
    pub behavioral: bool,
    pub attributed: bool,
    pub displayed: bool,
    pub auto_resolved: bool,
}

#[derive(Debug, Default)]
pub struct StateTracker {
    states: HashMap<String, Tracked>,
}

impl StateTracker {
    pub fn observe(&mut self, id: &str, cycle: u32, seen: Seen, out: &mut OutputStats) {
        if let Some(state) = self.states.get_mut(id) {
            if cycle.saturating_sub(state.last_cycle) <= GAP_CYCLES {
                state.last_cycle = cycle;
                state.attributed |= seen.attributed;
                state.displayed |= seen.displayed;
                state.displayed_unattributed |= seen.displayed && !seen.attributed;
                state.auto_resolved |= seen.auto_resolved;
                return;
            }
            let old = self.states.remove(id).expect("existuje");
            Self::finalize(&old, out);
        }
        self.states.insert(
            id.to_string(),
            Tracked {
                last_cycle: cycle,
                behavioral: seen.behavioral,
                attributed: seen.attributed,
                displayed: seen.displayed,
                displayed_unattributed: seen.displayed && !seen.attributed,
                auto_resolved: seen.auto_resolved,
            },
        );
    }

    /// Uzavře stavy bez výskytu déle než `GAP_CYCLES` (drží paměť sledovače omezenou).
    pub fn sweep(&mut self, cycle: u32, out: &mut OutputStats) {
        let stale: Vec<String> = self
            .states
            .iter()
            .filter(|(_, s)| cycle.saturating_sub(s.last_cycle) > GAP_CYCLES)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(state) = self.states.remove(&id) {
                Self::finalize(&state, out);
            }
        }
    }

    pub fn finish(&mut self, out: &mut OutputStats) {
        for (_, state) in self.states.drain() {
            Self::finalize(&state, out);
        }
    }

    fn finalize(state: &Tracked, out: &mut OutputStats) {
        out.states_captured += 1;
        if state.behavioral {
            out.states_behavioral += 1;
            if !state.attributed {
                out.states_fp += 1;
            }
        }
        if state.displayed {
            out.states_awaiting_human += 1;
            if state.behavioral && state.displayed_unattributed && !state.attributed {
                out.states_awaiting_human_fp += 1;
            }
        } else if state.auto_resolved {
            out.states_auto_resolved += 1;
        } else {
            out.states_collected_only += 1;
        }
    }
}

/// Inventář, který měl engine v daném cyklu k dispozici (pro diagnostiku příčin).
pub struct InventoryView<'a> {
    pub ips: &'a HashSet<&'a str>,
    pub services: &'a HashSet<(String, String, u16)>,
    /// zařízení přítomná v posledním skenu (id).
    pub devices: &'a HashSet<u32>,
}

/// Příčina FP `unexpected_traffic`/`unmapped_passive_event` na cíli `ip/proto/port`.
/// Používá pravdu modelu jen k diagnostice (do enginu nejde).
pub fn unexpected_cause(
    model: &NetworkModel,
    inventory: &InventoryView<'_>,
    service_key: &str,
    restart_cold: bool,
) -> &'static str {
    let mut parts = service_key.split('/');
    let (Some(ip), proto, port) = (
        parts.next(),
        parts.next().unwrap_or(""),
        parts.next().and_then(|p| p.parse::<u16>().ok()),
    ) else {
        return "neurceno";
    };
    if inventory.ips.is_empty() {
        return if restart_cold {
            "inventar_prazdny_po_restartu"
        } else {
            "inventar_prazdny"
        };
    }
    let Some(device) = model.device_by_ip(ip) else {
        return "ip_bez_zarizeni";
    };
    if !inventory.ips.contains(ip) {
        return if inventory.devices.contains(&device) {
            "ip_zmenena_od_skenu"
        } else {
            "zarizeni_mimo_provoz_pri_skenu"
        };
    }
    let Some(port) = port else {
        return "host_bez_sluzby";
    };
    let real = model.devices[device as usize]
        .services
        .iter()
        .any(|s| s.port == port && s.proto == proto);
    if real {
        if inventory
            .services
            .contains(&(ip.to_string(), proto.to_string(), port))
        {
            "sluzba_v_inventari"
        } else {
            "sluzba_chybi_v_inventari"
        }
    } else {
        "port_zarizeni_neposloucha"
    }
}

/// Placebo okno útoku: stejná délka, posunuté o délku + 24 cyklů (12 h) za konec,
/// nebo stejně před začátek; `None`, pokud se do epizody nevejde.
pub fn placebo_window(start: u32, end: u32, cycles: u32) -> Option<(u32, u32)> {
    let len = end.saturating_sub(start) + 1;
    let shift = len + 24;
    if end + shift < cycles {
        Some((start + shift, end + shift))
    } else if start >= shift {
        Some((start - shift, end - shift))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen(attributed: bool, displayed: bool) -> Seen {
        Seen {
            behavioral: true,
            attributed,
            displayed,
            auto_resolved: false,
        }
    }

    #[test]
    fn repeated_finding_within_gap_is_one_state_and_after_gap_a_new_one() {
        let mut tracker = StateTracker::default();
        let mut out = OutputStats::default();
        for cycle in 0..40 {
            tracker.observe("f1", cycle, seen(false, cycle == 0), &mut out);
        }
        tracker.observe("f1", 40 + GAP_CYCLES + 1, seen(false, true), &mut out);
        tracker.finish(&mut out);
        assert_eq!(out.states_captured, 2);
        assert_eq!(out.states_fp, 2);
        assert_eq!(out.states_awaiting_human, 2);
    }

    #[test]
    fn three_output_groups_partition_states() {
        let mut tracker = StateTracker::default();
        let mut out = OutputStats::default();
        tracker.observe("shown", 0, seen(true, true), &mut out);
        tracker.observe(
            "auto",
            0,
            Seen {
                auto_resolved: true,
                ..seen(false, false)
            },
            &mut out,
        );
        tracker.observe("collected", 0, seen(false, false), &mut out);
        tracker.sweep(100, &mut out);
        assert_eq!(out.states_captured, 3);
        assert_eq!(out.states_awaiting_human, 1);
        assert_eq!(out.states_auto_resolved, 1);
        assert_eq!(out.states_collected_only, 1);
        assert_eq!(out.states_fp, 2);
        assert_eq!(out.states_awaiting_human_fp, 0);
    }

    #[test]
    fn placebo_window_shifts_after_or_before_and_respects_bounds() {
        assert_eq!(placebo_window(10, 13, 200), Some((38, 41)));
        assert_eq!(placebo_window(150, 153, 160), Some((122, 125)));
        assert_eq!(placebo_window(5, 40, 60), None);
    }

    #[test]
    fn cause_classification_uses_inventory_state() {
        let model = NetworkModel::generate(20261102, 3);
        let ip0 = model.ip_of(0);
        let ips_full: HashSet<&str> = [ip0.as_str()].into_iter().collect();
        let services: HashSet<(String, String, u16)> = HashSet::new();
        let devices: HashSet<u32> = [0].into_iter().collect();
        let view = InventoryView {
            ips: &ips_full,
            services: &services,
            devices: &devices,
        };
        assert_eq!(
            unexpected_cause(&model, &view, &format!("{ip0}/tcp/65001"), false),
            "port_zarizeni_neposloucha"
        );
        assert_eq!(
            unexpected_cause(&model, &view, "203.0.113.1/tcp/80", false),
            "ip_bez_zarizeni"
        );
        let empty: HashSet<&str> = HashSet::new();
        let cold = InventoryView {
            ips: &empty,
            services: &services,
            devices: &devices,
        };
        assert_eq!(
            unexpected_cause(&model, &cold, &format!("{ip0}/tcp/22"), true),
            "inventar_prazdny_po_restartu"
        );
    }
}
