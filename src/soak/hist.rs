//! Mala logaritmicka histogramova struktura (HdrHistogram-lite) pro latence a
//! casy detekce: pevna pamet, slucitelna mezi vlakny, serializovatelna do
//! checkpointu. Relativni chyba percentilu ~5 % (faktor bucketu 1,05).

use serde::{Deserialize, Serialize};

const BUCKETS: usize = 520;
const LOWEST: f64 = 1e-7;
const FACTOR: f64 = 1.05;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogHistogram {
    counts: Vec<u64>,
    pub total: u64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
}

impl Default for LogHistogram {
    fn default() -> Self {
        Self {
            counts: vec![0; BUCKETS],
            total: 0,
            sum: 0.0,
            min: f64::INFINITY,
            max: 0.0,
        }
    }
}

impl LogHistogram {
    pub fn record(&mut self, value: f64) {
        if !value.is_finite() || value < 0.0 {
            return;
        }
        let index = if value <= LOWEST {
            0
        } else {
            (((value / LOWEST).ln() / FACTOR.ln()) as usize).min(BUCKETS - 1)
        };
        self.counts[index] += 1;
        self.total += 1;
        self.sum += value;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    pub fn mean(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.sum / self.total as f64
        }
    }

    /// Horni mez bucketu, ve kterem lezi percentil `p` (0..=1); presne `max` pro p=1.
    pub fn percentile(&self, p: f64) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        if p >= 1.0 {
            return self.max;
        }
        let target = (p.clamp(0.0, 1.0) * self.total as f64).ceil().max(1.0) as u64;
        let mut seen = 0u64;
        for (index, count) in self.counts.iter().enumerate() {
            seen += count;
            if seen >= target {
                return (LOWEST * FACTOR.powi(index as i32 + 1)).min(self.max);
            }
        }
        self.max
    }

    pub fn merge(&mut self, other: &LogHistogram) {
        for (mine, theirs) in self.counts.iter_mut().zip(other.counts.iter()) {
            *mine += theirs;
        }
        self.total += other.total;
        self.sum += other.sum;
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_are_within_bucket_error_of_exact_values() {
        let mut hist = LogHistogram::default();
        for i in 1..=10_000 {
            hist.record(i as f64 * 1e-3);
        }
        for (p, exact) in [(0.5, 5.0), (0.9, 9.0), (0.99, 9.9)] {
            let got = hist.percentile(p);
            assert!((got - exact).abs() / exact < 0.07, "p{p}: {got} vs {exact}");
        }
        assert!((hist.percentile(1.0) - 10.0).abs() < 1e-9);
        assert_eq!(hist.total, 10_000);
    }

    #[test]
    fn merge_equals_recording_everything_in_one_histogram() {
        let mut a = LogHistogram::default();
        let mut b = LogHistogram::default();
        let mut all = LogHistogram::default();
        for i in 0..5000 {
            let v = (i as f64 + 1.0) * 1e-4;
            if i % 2 == 0 {
                a.record(v)
            } else {
                b.record(v)
            }
            all.record(v);
        }
        a.merge(&b);
        assert_eq!(a.total, all.total);
        assert_eq!(a.percentile(0.95), all.percentile(0.95));
    }

    #[test]
    fn ignores_non_finite_and_negative_values() {
        let mut hist = LogHistogram::default();
        hist.record(f64::NAN);
        hist.record(-1.0);
        hist.record(f64::INFINITY);
        assert_eq!(hist.total, 0);
        assert_eq!(hist.percentile(0.5), 0.0);
    }
}
