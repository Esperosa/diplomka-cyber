//! Deterministicky generator nahodnych cisel pro soak simulaci. Kazdy (beh, sit,
//! cyklus) dostane vlastni odvozeny seed (`derive`), takze jakakoli sit/blok jde
//! znovu prehrat bit po bitu (`soak verify`) nezavisle na poradi/vlaknech.

use rand::{Rng as _, SeedableRng, rngs::StdRng};

/// SplitMix64 finalizer - rychle, dobre rozptyluje i po sobe jdouci vstupy.
pub fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

pub fn derive(a: u64, b: u64) -> u64 {
    mix(a ^ mix(b))
}

pub struct Rng {
    inner: StdRng,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self {
            inner: StdRng::seed_from_u64(mix(seed)),
        }
    }

    pub fn f64(&mut self) -> f64 {
        self.inner.random::<f64>()
    }

    pub fn u64(&mut self) -> u64 {
        self.inner.random::<u64>()
    }

    pub fn chance(&mut self, probability: f64) -> bool {
        self.f64() < probability
    }

    /// Cele cislo v intervalu lo..=hi (vcetne obou mezi).
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            self.inner.random_range(lo..=hi)
        }
    }

    pub fn range_f(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.f64()
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.inner.random_range(0..items.len())]
    }

    /// Vazeny vyber indexu (`weights` nemusi byt normalizovane).
    pub fn weighted(&mut self, weights: &[f64]) -> usize {
        let total: f64 = weights.iter().sum();
        let mut target = self.f64() * total;
        for (index, weight) in weights.iter().enumerate() {
            if target < *weight {
                return index;
            }
            target -= weight;
        }
        weights.len() - 1
    }

    pub fn normal(&mut self) -> f64 {
        let u1 = self.f64().max(1e-12);
        let u2 = self.f64();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    /// Log-normalni s danym medianem a sigma (heavy tail jako realne velikosti toku).
    pub fn lognormal(&mut self, median: f64, sigma: f64) -> f64 {
        median * (sigma * self.normal()).exp()
    }

    pub fn exp(&mut self, mean: f64) -> f64 {
        -mean * self.f64().max(1e-12).ln()
    }

    pub fn poisson(&mut self, lambda: f64) -> u64 {
        if lambda <= 0.0 {
            return 0;
        }
        if lambda < 30.0 {
            let limit = (-lambda).exp();
            let mut product = 1.0;
            let mut count = 0u64;
            loop {
                product *= self.f64();
                if product <= limit {
                    return count;
                }
                count += 1;
            }
        }
        (lambda + lambda.sqrt() * self.normal()).round().max(0.0) as u64
    }

    /// `k` ruznych hodnot z rozsahu 0..n (k se orizne na n).
    pub fn sample_distinct(&mut self, n: usize, k: usize) -> Vec<usize> {
        let k = k.min(n);
        if k * 3 >= n {
            let mut all: Vec<usize> = (0..n).collect();
            for i in 0..k {
                let j = self.inner.random_range(i..n);
                all.swap(i, j);
            }
            all.truncate(k);
            return all;
        }
        let mut seen = std::collections::HashSet::with_capacity(k * 2);
        let mut out = Vec::with_capacity(k);
        while out.len() < k {
            let value = self.inner.random_range(0..n);
            if seen.insert(value) {
                out.push(value);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_gives_identical_stream_and_derive_separates_streams() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.range(0, 1_000_000), b.range(0, 1_000_000));
        }
        assert_ne!(derive(1, 2), derive(1, 3));
        assert_ne!(derive(1, 2), derive(2, 1));
    }

    #[test]
    fn poisson_mean_is_close_to_lambda_for_small_and_large() {
        let mut rng = Rng::new(7);
        for lambda in [0.5, 4.0, 80.0] {
            let n = 20_000;
            let mean = (0..n).map(|_| rng.poisson(lambda) as f64).sum::<f64>() / n as f64;
            assert!(
                (mean - lambda).abs() < lambda * 0.05 + 0.05,
                "{lambda}: {mean}"
            );
        }
    }

    #[test]
    fn sample_distinct_returns_unique_values_in_range() {
        let mut rng = Rng::new(3);
        for (n, k) in [(10, 10), (100, 5), (50, 40), (5, 9)] {
            let sample = rng.sample_distinct(n, k);
            let mut sorted = sample.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), sample.len());
            assert!(sample.iter().all(|v| *v < n));
            assert_eq!(sample.len(), k.min(n));
        }
    }

    #[test]
    fn weighted_pick_respects_zero_weights() {
        let mut rng = Rng::new(9);
        for _ in 0..1000 {
            assert_ne!(rng.weighted(&[1.0, 0.0, 1.0]), 1);
        }
    }
}
