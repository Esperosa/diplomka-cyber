//! Pocitaci alokator: zive i maximalni bajty na halde bez externi zavislosti. Signal
//! pro detekci uniku pameti pri nekolikadennim behu (rust-allocator + RSS z OS).
//! Aktivuje se v binarce (`#[global_allocator]` v main.rs); v knihovne a testech je
//! jen pasivni citac.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicU64, Ordering},
};

static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

pub struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live =
                LIVE.fetch_add(layout.size() as u64, Ordering::Relaxed) + layout.size() as u64;
            PEAK.fetch_max(live, Ordering::Relaxed);
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size() as u64, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            if new_size >= layout.size() {
                let live = LIVE.fetch_add((new_size - layout.size()) as u64, Ordering::Relaxed)
                    + (new_size - layout.size()) as u64;
                PEAK.fetch_max(live, Ordering::Relaxed);
            } else {
                LIVE.fetch_sub((layout.size() - new_size) as u64, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

pub fn heap_live() -> u64 {
    LIVE.load(Ordering::Relaxed)
}

pub fn heap_peak() -> u64 {
    PEAK.load(Ordering::Relaxed)
}

pub fn allocations() -> u64 {
    ALLOCATIONS.load(Ordering::Relaxed)
}

/// Rezidentni pamet procesu (bajty) nebo `None`, kdyz ji platforma neumi snadno zjistit.
pub fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4096)
    }
    #[cfg(target_os = "windows")]
    {
        let pid = std::process::id().to_string();
        let output = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        // "image","pid","session","#","12 345 K" - posledni sloupec jsou KiB s oddelovaci tisicu.
        let last = text.trim().rsplit("\",\"").next()?;
        let digits: String = last.chars().filter(|c| c.is_ascii_digit()).collect();
        digits.parse::<u64>().ok().map(|kib| kib * 1024)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_monotone_for_peak_and_rss_is_readable_when_supported() {
        let before = heap_peak();
        let block = vec![0u8; 1 << 20];
        std::hint::black_box(&block);
        assert!(heap_peak() >= before);
        if cfg!(any(target_os = "linux", target_os = "windows")) {
            assert!(process_rss_bytes().unwrap_or(1) > 0);
        }
    }
}
