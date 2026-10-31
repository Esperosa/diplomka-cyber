//! Inkrementalni ingest pasivnich logu (`monitor --continuous`). Navrh (sekce 3.1)
//! pozaduje offsety/checkpointy a semantiku "at-least-once"; dosud kazdy cyklus
//! cetl celou Suricata/Zeek historii znovu (kazda udalost se opakovala v dalsich
//! reportech a naklady rostly s velikosti logu).
//!
//! Princip: pro kazdy zdrojovy soubor se uklada kurzor (offset za poslednim
//! UPLNYM radkem + otisk prvnich bajtu). Cyklus dostane jen nove uplne radky
//! zapsane do "delta" souboru. **Kurzor se posune az `commit()` po uspesnem
//! behu** - spadne-li pipeline, dalsi cyklus precte stejna data znovu
//! (at-least-once, nikdy tiche ztraceni udalosti).
//!
//! Rotace/zkraceni: soubor mensi nez ulozeny offset, nebo jina "prvni bajty" =
//! novy soubor, cte se od zacatku a pocita se do `rotations` (viditelne, ne tise).
//! Neuplny posledni radek (zapis prave probiha) se nikdy nezpracuje napul.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{error::Result, storage::write_atomic};

const FINGERPRINT_BYTES: usize = 256;
const CURSOR_FILE: &str = "ingest-cursors.json";
const ZEEK_LOGS: &[&str] = &["conn.log", "notice.log", "http.log"];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct FileCursor {
    offset: u64,
    /// Kolik uvodnich bajtu otisk pokryva (min(256, offset)) - hashuje se jen
    /// to, co uz bylo zpracovano, protoze pripisovane radky otisk nemeni.
    fp_len: usize,
    fingerprint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CursorStore {
    files: BTreeMap<String, FileCursor>,
}

/// Navrzene posuny kurzoru - aplikuji se az v `commit()`.
#[derive(Debug, Default)]
pub struct PendingIngest {
    updates: BTreeMap<String, FileCursor>,
    pub new_bytes: u64,
    pub rotations: usize,
    scratch: Vec<PathBuf>,
}

fn fingerprint(path: &Path, len: usize) -> Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0u8; len];
    let read = file.read(&mut buffer)?;
    let mut hasher = Sha256::new();
    hasher.update(&buffer[..read]);
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn load_store(workspace: &Path) -> CursorStore {
    fs::read_to_string(workspace.join(CURSOR_FILE))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

fn leading_comment_header(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path)?;
    let mut header = String::new();
    for line in text.lines() {
        if line.starts_with('#') {
            header.push_str(line);
            header.push('\n');
        } else {
            break;
        }
    }
    Ok(header)
}

/// Vraci nove UPLNE radky od ulozeneho offsetu + navrzeny novy kurzor.
fn read_new_lines(
    store: &CursorStore,
    source: &Path,
    pending: &mut PendingIngest,
) -> Result<(String, bool)> {
    let key = source.to_string_lossy().to_string();
    let length = fs::metadata(source)?.len();

    let previous = store.files.get(&key);
    let (start, rotated) = match previous {
        Some(cursor)
            if length >= cursor.offset
                && cursor.fingerprint == fingerprint(source, cursor.fp_len)? =>
        {
            (cursor.offset, false)
        }
        Some(_) => (0, true),
        None => (0, false),
    };
    if rotated {
        pending.rotations += 1;
    }

    let mut file = File::open(source)?;
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(length.saturating_sub(start))
        .read_to_end(&mut bytes)?;

    let complete_len = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|index| index + 1)
        .unwrap_or(0);
    let text = String::from_utf8_lossy(&bytes[..complete_len]).to_string();

    pending.new_bytes += complete_len as u64;
    let new_offset = start + complete_len as u64;
    let fp_len = (new_offset as usize).min(FINGERPRINT_BYTES);
    pending.updates.insert(
        key,
        FileCursor {
            offset: new_offset,
            fp_len,
            fingerprint: fingerprint(source, fp_len)?,
        },
    );
    Ok((text, start == 0))
}

fn delta_dir(workspace: &Path) -> Result<PathBuf> {
    let dir = workspace
        .join("tmp")
        .join("ingest")
        .join(uuid::Uuid::new_v4().simple().to_string());
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Suricata `eve.json` (JSONL) -> delta soubor s novymi radky.
pub fn delta_eve(workspace: &Path, source: &Path, pending: &mut PendingIngest) -> Result<PathBuf> {
    let store = load_store(workspace);
    let (text, _) = read_new_lines(&store, source, pending)?;
    let dir = delta_dir(workspace)?;
    pending.scratch.push(dir.clone());
    let target = dir.join("eve.json");
    fs::write(&target, text)?;
    Ok(target)
}

/// Zeek adresar -> delta adresar; kazdy log dostane puvodni `#`-hlavicku
/// (parser bez `#fields` odmita soubor) + jen nove radky. Prazdny delta log
/// (jen hlavicka) je platny a znamena "nic noveho".
pub fn delta_zeek_dir(
    workspace: &Path,
    source_dir: &Path,
    pending: &mut PendingIngest,
) -> Result<PathBuf> {
    let store = load_store(workspace);
    let target_dir = delta_dir(workspace)?;
    pending.scratch.push(target_dir.clone());
    for name in ZEEK_LOGS {
        let source = source_dir.join(name);
        if !source.exists() {
            continue;
        }
        let header = leading_comment_header(&source)?;
        let (text, from_start) = read_new_lines(&store, &source, pending)?;
        let body = if from_start {
            // Od zacatku souboru uz text hlavicku obsahuje.
            text
        } else {
            format!("{header}{text}")
        };
        fs::write(target_dir.join(name), body)?;
    }
    Ok(target_dir)
}

impl PendingIngest {
    /// Posune kurzory. Volat az po uspesnem dokonceni behu.
    pub fn commit(self, workspace: &Path) -> Result<()> {
        for dir in &self.scratch {
            let _ = fs::remove_dir_all(dir);
        }
        if self.updates.is_empty() {
            return Ok(());
        }
        let mut store = load_store(workspace);
        store.files.extend(self.updates);
        write_atomic(
            &workspace.join(CURSOR_FILE),
            serde_json::to_string_pretty(&store)?.as_bytes(),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn append(path: &Path, text: &str) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    fn eve_lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(ToString::to_string)
            .collect()
    }

    #[test]
    fn second_cycle_sees_only_newly_appended_lines() {
        let dir = tempfile::tempdir().unwrap();
        let eve = dir.path().join("eve.json");
        append(&eve, "{\"a\":1}\n{\"a\":2}\n");

        let mut first = PendingIngest::default();
        let delta1 = delta_eve(dir.path(), &eve, &mut first).unwrap();
        assert_eq!(eve_lines(&delta1).len(), 2);
        first.commit(dir.path()).unwrap();

        append(&eve, "{\"a\":3}\n");
        let mut second = PendingIngest::default();
        let delta2 = delta_eve(dir.path(), &eve, &mut second).unwrap();
        assert_eq!(eve_lines(&delta2), vec!["{\"a\":3}".to_string()]);
    }

    #[test]
    fn uncommitted_cycle_is_read_again_at_least_once() {
        let dir = tempfile::tempdir().unwrap();
        let eve = dir.path().join("eve.json");
        append(&eve, "{\"a\":1}\n");

        let mut crashed = PendingIngest::default();
        delta_eve(dir.path(), &eve, &mut crashed).unwrap();
        drop(crashed); // beh spadl, commit nikdy nenastal

        let mut retry = PendingIngest::default();
        let delta = delta_eve(dir.path(), &eve, &mut retry).unwrap();
        assert_eq!(eve_lines(&delta).len(), 1, "data nesmi byt ztracena");
    }

    #[test]
    fn partial_last_line_is_not_consumed_half_written() {
        let dir = tempfile::tempdir().unwrap();
        let eve = dir.path().join("eve.json");
        append(&eve, "{\"a\":1}\n{\"a\":");

        let mut first = PendingIngest::default();
        let delta = delta_eve(dir.path(), &eve, &mut first).unwrap();
        assert_eq!(eve_lines(&delta), vec!["{\"a\":1}".to_string()]);
        first.commit(dir.path()).unwrap();

        append(&eve, "2}\n");
        let mut second = PendingIngest::default();
        let delta = delta_eve(dir.path(), &eve, &mut second).unwrap();
        assert_eq!(eve_lines(&delta), vec!["{\"a\":2}".to_string()]);
    }

    #[test]
    fn truncated_or_replaced_file_is_read_from_start_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let eve = dir.path().join("eve.json");
        append(&eve, "{\"old\":1}\n{\"old\":2}\n{\"old\":3}\n");
        let mut first = PendingIngest::default();
        delta_eve(dir.path(), &eve, &mut first).unwrap();
        first.commit(dir.path()).unwrap();

        // Rotace: novy, mensi soubor s jinym obsahem.
        fs::write(&eve, "{\"new\":1}\n").unwrap();
        let mut second = PendingIngest::default();
        let delta = delta_eve(dir.path(), &eve, &mut second).unwrap();
        assert_eq!(eve_lines(&delta), vec!["{\"new\":1}".to_string()]);
        assert_eq!(second.rotations, 1);
    }

    #[test]
    fn replaced_file_of_same_or_larger_size_is_still_detected_by_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let eve = dir.path().join("eve.json");
        fs::write(&eve, "{\"old\":1}\n").unwrap();
        let mut first = PendingIngest::default();
        delta_eve(dir.path(), &eve, &mut first).unwrap();
        first.commit(dir.path()).unwrap();

        fs::write(&eve, "{\"new\":1}\n{\"new\":2}\n{\"new\":3}\n").unwrap();
        let mut second = PendingIngest::default();
        let delta = delta_eve(dir.path(), &eve, &mut second).unwrap();
        assert_eq!(eve_lines(&delta).len(), 3);
        assert_eq!(second.rotations, 1);
    }

    #[test]
    fn zeek_delta_keeps_header_so_parser_still_accepts_it() {
        let dir = tempfile::tempdir().unwrap();
        let zeek = dir.path().join("zeek");
        fs::create_dir_all(&zeek).unwrap();
        let conn = zeek.join("conn.log");
        append(
            &conn,
            "#separator \\x09\n#fields\tts\tid.resp_h\n#types\ttime\taddr\n1.0\t10.0.0.1\n",
        );

        let mut first = PendingIngest::default();
        let delta1 = delta_zeek_dir(dir.path(), &zeek, &mut first).unwrap();
        let text1 = fs::read_to_string(delta1.join("conn.log")).unwrap();
        assert!(text1.contains("#fields") && text1.contains("1.0\t10.0.0.1"));
        first.commit(dir.path()).unwrap();

        append(&conn, "2.0\t10.0.0.2\n");
        let mut second = PendingIngest::default();
        let delta2 = delta_zeek_dir(dir.path(), &zeek, &mut second).unwrap();
        let text2 = fs::read_to_string(delta2.join("conn.log")).unwrap();
        assert!(text2.starts_with("#separator"));
        assert!(text2.contains("#fields"));
        assert!(text2.contains("2.0\t10.0.0.2"));
        assert!(
            !text2.contains("1.0\t10.0.0.1"),
            "stary radek se nesmi opakovat"
        );
    }

    #[test]
    fn nothing_new_yields_valid_empty_delta() {
        let dir = tempfile::tempdir().unwrap();
        let eve = dir.path().join("eve.json");
        append(&eve, "{\"a\":1}\n");
        let mut first = PendingIngest::default();
        delta_eve(dir.path(), &eve, &mut first).unwrap();
        first.commit(dir.path()).unwrap();

        let mut second = PendingIngest::default();
        let delta = delta_eve(dir.path(), &eve, &mut second).unwrap();
        assert!(eve_lines(&delta).is_empty());
        assert_eq!(second.new_bytes, 0);
    }
}
