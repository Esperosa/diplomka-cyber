//! Kalibrační vrstva pravděpodobností (krok 2C; 00-zaver R12a, RQ2 Z7, Z11).
//!
//! Izotonická regrese (PAVA) nad váženými body (skóre, výsledek), produkční verze
//! `eval::calibration` (tam pro CTU-13): vazby skóre se nejdřív sloučí, takže výsledek
//! nezávisí na pořadí vstupu, mapování je neklesající schodová funkce (hodnota bloku od
//! jeho nejnižšího skóre) a je serializovatelné (fit offline, použití v jádru).
//!
//! Výhrady (RQ2): přínos izotonické kalibrace pro Brier je doložen velmi slabě (Z11),
//! při posunu distribuce kalibrace degraduje a potřebuje nové štítky (Z7, nízká
//! jistota), malá kalibrační množina dává nespolehlivé mapování (Z6b). Proto:
//! minimum vzorků, jinak se kalibrace nepoužije, a fit křížovou validací napříč sítěmi
//! (`tools/soak_calib.py`), nikdy na týchž sítích, na kterých se měří.

use serde::{Deserialize, Serialize};

use crate::error::{BakulaError, Result};

/// Minimální počet (vážených) vzorků pro použitelnou kalibraci.
pub const MIN_SAMPLES: f64 = 200.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IsotonicCalibrator {
    /// Nejnižší skóre bloku (vzestupně) a kalibrovaná pravděpodobnost bloku.
    pub knots: Vec<(f64, f64)>,
    pub samples: f64,
    /// Odkud kalibrace pochází (seedy/sítě), pro audit.
    #[serde(default)]
    pub source: String,
}

impl IsotonicCalibrator {
    /// Fit z vážených bodů (skóre, podíl pozitivních v bodě, váha). Body se stejným
    /// skóre se nejdřív sloučí (nezávislost na pořadí).
    pub fn fit(points: &[(f64, f64, f64)], source: &str) -> Option<Self> {
        let mut sorted: Vec<(f64, f64, f64)> = points
            .iter()
            .copied()
            .filter(|(s, y, w)| s.is_finite() && y.is_finite() && *w > 0.0)
            .collect();
        sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
        // (nejnizsi skore bloku, soucet y*w, soucet w)
        let mut blocks: Vec<(f64, f64, f64)> = Vec::new();
        for (score, y, w) in sorted {
            match blocks.last_mut() {
                Some(last) if (last.0 - score).abs() < 1e-12 => {
                    last.1 += y * w;
                    last.2 += w;
                }
                _ => blocks.push((score, y * w, w)),
            }
        }
        let samples: f64 = blocks.iter().map(|b| b.2).sum();
        if samples < MIN_SAMPLES {
            return None;
        }
        // PAVA nad bloky
        let mut stack: Vec<(f64, f64, f64)> = Vec::with_capacity(blocks.len());
        for block in blocks {
            stack.push(block);
            while stack.len() >= 2 {
                let n = stack.len();
                let (a, b) = (stack[n - 2], stack[n - 1]);
                if a.1 / a.2 > b.1 / b.2 {
                    stack.pop();
                    stack.pop();
                    stack.push((a.0, a.1 + b.1, a.2 + b.2));
                } else {
                    break;
                }
            }
        }
        Some(Self {
            knots: stack.iter().map(|b| (b.0, b.1 / b.2)).collect(),
            samples,
            source: source.to_string(),
        })
    }

    /// Kalibrovaná pravděpodobnost: hodnota posledního bloku s nejnižším skóre ≤ `score`
    /// (pod rozsahem první blok).
    pub fn predict(&self, score: f64) -> f64 {
        let Some(first) = self.knots.first() else {
            return score;
        };
        let at = self.knots.partition_point(|(min, _)| *min <= score);
        if at == 0 {
            first.1
        } else {
            self.knots[at - 1].1
        }
    }

    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let calibrator: Self = serde_json::from_str(&text).map_err(BakulaError::Json)?;
        if calibrator.knots.is_empty()
            || calibrator
                .knots
                .iter()
                .any(|(s, p)| !s.is_finite() || !(0.0..=1.0).contains(p))
        {
            return Err(BakulaError::Config(format!(
                "neplatna kalibrace {}",
                path.display()
            )));
        }
        Ok(calibrator)
    }
}

/// Brier skóre a ECE (10 košů, váženo počtem) pro (p, výsledek).
pub fn brier_and_ece(predictions: &[(f64, bool)]) -> (f64, f64) {
    if predictions.is_empty() {
        return (0.0, 0.0);
    }
    let n = predictions.len() as f64;
    let brier = predictions
        .iter()
        .map(|(p, y)| (p - if *y { 1.0 } else { 0.0 }).powi(2))
        .sum::<f64>()
        / n;
    let mut bins = [(0.0f64, 0.0f64, 0.0f64); 10];
    for (p, y) in predictions {
        let bin = ((p * 10.0) as usize).min(9);
        bins[bin].0 += 1.0;
        bins[bin].1 += *p;
        bins[bin].2 += *y as u8 as f64;
    }
    let ece = bins
        .iter()
        .filter(|b| b.0 > 0.0)
        .map(|b| b.0 / n * (b.1 / b.0 - b.2 / b.0).abs())
        .sum();
    (brier, ece)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_is_monotone_order_independent_and_needs_samples() {
        let mut points: Vec<(f64, f64, f64)> = Vec::new();
        for i in 0..300 {
            let s = (i % 10) as f64 / 10.0;
            // skutecna pravdepodobnost = s^2 (prekonfidentni surove skore)
            let y = ((i * 7919) % 100) as f64 / 100.0 < s * s;
            points.push((s, y as u8 as f64, 1.0));
        }
        let fitted = IsotonicCalibrator::fit(&points, "test").unwrap();
        let mut reversed = points.clone();
        reversed.reverse();
        assert_eq!(fitted, IsotonicCalibrator::fit(&reversed, "test").unwrap());
        let mut last = -1.0;
        for i in 0..=20 {
            let p = fitted.predict(i as f64 / 20.0);
            assert!(p >= last - 1e-12 && (0.0..=1.0).contains(&p));
            last = p;
        }
        assert!(fitted.predict(0.5) < 0.5, "prekonfidence se srovna dolu");
        assert!(IsotonicCalibrator::fit(&points[..50], "malo").is_none());
    }

    #[test]
    fn calibration_lowers_brier_on_overconfident_scores() {
        let points: Vec<(f64, bool)> = (0..2000)
            .map(|i| {
                let s = (i % 20) as f64 / 20.0;
                (s, ((i * 104_729) % 1000) as f64 / 1000.0 < s * 0.5)
            })
            .collect();
        let fitted = IsotonicCalibrator::fit(
            &points
                .iter()
                .map(|(s, y)| (*s, *y as u8 as f64, 1.0))
                .collect::<Vec<_>>(),
            "test",
        )
        .unwrap();
        let (b0, e0) = brier_and_ece(&points);
        let calibrated: Vec<(f64, bool)> = points
            .iter()
            .map(|(s, y)| (fitted.predict(*s), *y))
            .collect();
        let (b1, e1) = brier_and_ece(&calibrated);
        assert!(b1 < b0 && e1 < e0, "{b0} {e0} -> {b1} {e1}");
        let json = serde_json::to_string(&fitted).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cal.json");
        std::fs::write(&path, json).unwrap();
        assert_eq!(IsotonicCalibrator::load(&path).unwrap(), fitted);
        std::fs::write(&path, r#"{"knots":[[0.5,1.5]],"samples":1}"#).unwrap();
        assert!(IsotonicCalibrator::load(&path).is_err());
    }
}
