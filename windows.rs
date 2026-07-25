//! Windows autorun enumeration: the registry `Run`/`RunOnce` keys and the
//! per-user / all-users **Startup** folders — the classic user-mode autostart
//! locations.
//!
//! Registry values under `Run`/`RunOnce` (HKLM + HKCU, incl. the 32-bit
//! `WOW6432Node` view) each name a command that runs at logon. The Startup
//! folders hold shortcuts/programs launched at logon for the user (`%APPDATA%`)
//! or for everyone (`%ProgramData%`).

use limen_sdk_rust::{json, Value};
use std::path::Path;

use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::types::FromRegValue;
use winreg::{RegKey, HKEY};

use crate::entry;

pub fn list_autoruns() -> Value {
    let mut entries: Vec<Value> = Vec::new();
    collect_registry(&mut entries);
    collect_startup_folders(&mut entries);

    // Every location here is an active autorun (no "disabled" state to read).
    let enabled = entries.len();
    json!({
        "os": "windows",
        "note": "Programs that auto-start at logon: the registry Run/RunOnce keys \
                 (HKLM + HKCU, incl. WOW6432Node) and the per-user / all-users \
                 Startup folders.",
        "total": entries.len(),
        "enabled": enabled,
        "disabled": 0,
        "entries": entries,
    })
}

/// The Run/RunOnce subkeys to read under each hive.
const RUN_KEYS: &[(&str, &str)] = &[
    ("Run", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("RunOnce", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (
        "Run",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "RunOnce",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
];

fn collect_registry(out: &mut Vec<Value>) {
    for (hive, scope) in [
        (HKEY_LOCAL_MACHINE, "system"),
        (HKEY_CURRENT_USER, "user"),
    ] {
        let root = RegKey::predef(hive);
        for (which, path) in RUN_KEYS {
            let Ok(key) = root.open_subkey(path) else {
                continue;
            };
            for item in key.enum_values() {
                let Ok((name, value)) = item else {
                    continue;
                };
                let command = String::from_reg_value(&value).unwrap_or_default();
                out.push(entry(
                    &format!("registry:{which}"),
                    name,
                    command,
                    format!("{}\\{}", hive_name(hive), path),
                    scope,
                    true,
                ));
            }
        }
    }
}

fn hive_name(hive: HKEY) -> &'static str {
    if hive == HKEY_LOCAL_MACHINE {
        "HKLM"
    } else {
        "HKCU"
    }
}

fn collect_startup_folders(out: &mut Vec<Value>) {
    let startup = r"Microsoft\Windows\Start Menu\Programs\Startup";
    let dirs: Vec<(String, &str)> = [
        (std::env::var("APPDATA").ok(), "user"),
        (std::env::var("ProgramData").ok(), "system"),
    ]
    .into_iter()
    .filter_map(|(base, scope)| base.map(|b| (format!("{b}\\{startup}"), scope)))
    .collect();

    for (dir, scope) in dirs {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for f in rd.flatten() {
            let path = f.path();
            if path.is_dir() {
                continue;
            }
            let fname = f.file_name().to_string_lossy().to_string();
            // Folder bookkeeping, not an autorun.
            if fname.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            out.push(entry(
                "startup-folder",
                Path::new(&fname)
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or(fname),
                path.to_string_lossy().to_string(),
                dir.clone(),
                scope,
                true,
            ));
        }
    }
}
