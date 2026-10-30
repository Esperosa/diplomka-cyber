use std::{
    env,
    path::{Path, PathBuf},
};

pub fn project_path(parts: &[&str]) -> PathBuf {
    let relative = parts.iter().collect::<PathBuf>();
    for base in runtime_bases() {
        let candidate = base.join(&relative);
        if candidate.exists() {
            return candidate;
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Audit nalez (30.10.2026, produkcni gap analyza): `webscan.rs`/`pipeline/mod.rs`
/// mely natvrdo "httpx.exe"/"nuclei.exe" jako jmeno souboru pro vyhledavani
/// (vlastni, ne `Command::new`'s OS-nativni PATH resoluce) - na Linuxu (realisticke
/// nasazeni vedle Zeeku/Suricaty) by tyhle nastroje nikdy nenaslo, i kdyby byly
/// spravne nainstalovane na PATH pod svym skutecnym jmenem bez pripony.
pub fn exe_name(base: &str) -> String {
    format!("{base}{}", std::env::consts::EXE_SUFFIX)
}

fn runtime_bases() -> Vec<PathBuf> {
    let mut bases = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            push_unique(&mut bases, parent.to_path_buf());
        }
    }
    if let Ok(current_dir) = env::current_dir() {
        push_unique(&mut bases, current_dir);
    }
    push_unique(&mut bases, PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    bases
}

fn push_unique(items: &mut Vec<PathBuf>, value: PathBuf) {
    if !items.iter().any(|item| item == &value) {
        items.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit nalez (30.10.2026, produkcni gap analyza): `webscan.rs`/`pipeline/mod.rs`
    /// mely natvrdo "httpx.exe"/"nuclei.exe" - na Linuxu (realisticke nasazeni)
    /// by se tyhle nastroje nikdy nenasly, i kdyby byly na PATH pod spravnym
    /// jmenem bez pripony. `#[cfg]` zajisti, ze se overuje spravna hodnota na
    /// kazde platforme, kde se testy skutecne spousti (Windows lokalne, Linux v CI).
    #[cfg(windows)]
    #[test]
    fn exe_name_appends_exe_suffix_on_windows() {
        assert_eq!(exe_name("httpx"), "httpx.exe");
    }

    #[cfg(unix)]
    #[test]
    fn exe_name_has_no_suffix_on_unix() {
        assert_eq!(exe_name("httpx"), "httpx");
    }
}
