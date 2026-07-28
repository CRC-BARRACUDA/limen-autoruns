//! Windows autorun enumeration — the major Auto-Start Extensibility Points
//! (ASEP) that Sysinternals Autoruns checks, focused on the ones that name a
//! *program* to run:
//!
//! - **Logon** — the `Run` / `RunOnce` family (HKLM + HKCU, incl. `WOW6432Node`),
//!   `Winlogon` (`Userinit`/`Shell`/`Taskman`/`AppSetup`), `Windows\Load` &
//!   `\Run`, the `Command Processor` `AutoRun`, and `Active Setup` `StubPath`.
//! - **Startup folders** — per-user (`%APPDATA%`) and all-users (`%ProgramData%`).
//! - **Image hijacks** — Image File Execution Options `Debugger`.
//! - **Services / drivers** — `…\Services\*` with `Start = 2` (automatic).
//! - **Scheduled tasks** — the task XML under `%SystemRoot%\System32\Tasks`.
//!
//! Each `location` is the registry key or file the entry lives in, so the UI's
//! "Open in Registry" / "Open location" actions can navigate straight to it.
//! Some system-wide keys need elevation; inaccessible ones are simply skipped.

use std::path::{Path, PathBuf};

use limen_sdk_rust::{json, Value};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::types::FromRegValue;
use winreg::{RegKey, HKEY};

use crate::entry;

pub fn list_autoruns() -> Value {
    let mut entries: Vec<Value> = Vec::new();
    collect_run_keys(&mut entries);
    collect_winlogon(&mut entries);
    collect_windows_load_run(&mut entries);
    collect_command_processor(&mut entries);
    collect_active_setup(&mut entries);
    collect_image_hijacks(&mut entries);
    collect_services(&mut entries);
    collect_scheduled_tasks(&mut entries);
    collect_startup_folders(&mut entries);

    // These are all active autostart points (the enabled/disabled state stored
    // in StartupApproved isn't read here), so `enabled` == the total.
    let total = entries.len();
    json!({
        "os": "windows",
        "note": "Windows auto-start extensibility points (ASEP) that name a program: \
                 Run/RunOnce family, Winlogon, Windows Load/Run, Command Processor, \
                 Active Setup, Image File Execution Options debuggers, auto-start \
                 services/drivers, scheduled tasks, and the Startup folders.",
        "total": total,
        "enabled": total,
        "disabled": 0,
        "entries": entries,
    })
}

// --------------------------------------------------------------------------- //
// Registry helpers
// --------------------------------------------------------------------------- //

fn hive_name(hive: HKEY) -> &'static str {
    if hive == HKEY_LOCAL_MACHINE {
        "HKLM"
    } else {
        "HKCU"
    }
}

/// Read a single named string value under `subkey`; push an entry if it's set
/// and non-empty. The `location` is the key (so the UI can open it in regedit).
fn value_entry(
    out: &mut Vec<Value>,
    hive: HKEY,
    subkey: &str,
    value: &str,
    source: &str,
    scope: &str,
) {
    let root = RegKey::predef(hive);
    let Ok(key) = root.open_subkey(subkey) else {
        return;
    };
    let Ok(command) = key.get_value::<String, _>(value) else {
        return;
    };
    if command.trim().is_empty() {
        return;
    }
    out.push(entry(
        source,
        value.to_string(),
        command,
        format!("{}\\{}", hive_name(hive), subkey),
        scope,
        true,
    ));
}

// --------------------------------------------------------------------------- //
// Logon — the Run/RunOnce family (each value is a command)
// --------------------------------------------------------------------------- //

/// Multi-value keys where every value names a command that runs at logon.
const RUN_KEYS: &[(&str, &str)] = &[
    ("Run", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("RunOnce", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("RunOnceEx", r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx"),
    ("Run", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("RunOnce", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("Policies\\Run", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    // Legacy (9x/NT) — usually absent, harmless if so.
    ("RunServices", r"Software\Microsoft\Windows\CurrentVersion\RunServices"),
    ("RunServicesOnce", r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
];

fn collect_run_keys(out: &mut Vec<Value>) {
    for (hive, scope) in [(HKEY_LOCAL_MACHINE, "system"), (HKEY_CURRENT_USER, "user")] {
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

// --------------------------------------------------------------------------- //
// Logon — single-value keys
// --------------------------------------------------------------------------- //

fn collect_winlogon(out: &mut Vec<Value>) {
    let key = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon";
    for v in ["Userinit", "Shell", "Taskman", "AppSetup"] {
        value_entry(out, HKEY_LOCAL_MACHINE, key, v, "winlogon", "system");
    }
}

fn collect_windows_load_run(out: &mut Vec<Value>) {
    let key = r"Software\Microsoft\Windows NT\CurrentVersion\Windows";
    for (hive, scope) in [(HKEY_LOCAL_MACHINE, "system"), (HKEY_CURRENT_USER, "user")] {
        for v in ["Load", "Run"] {
            value_entry(out, hive, key, v, "windows-load", scope);
        }
    }
}

fn collect_command_processor(out: &mut Vec<Value>) {
    let key = r"Software\Microsoft\Command Processor";
    for (hive, scope) in [(HKEY_LOCAL_MACHINE, "system"), (HKEY_CURRENT_USER, "user")] {
        value_entry(out, hive, key, "AutoRun", "cmd-autorun", scope);
    }
}

/// Active Setup: each Installed Component may carry a `StubPath` that runs once
/// per user at first logon.
fn collect_active_setup(out: &mut Vec<Value>) {
    let base = r"Software\Microsoft\Active Setup\Installed Components";
    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = root.open_subkey(base) else {
        return;
    };
    for comp in key.enum_keys().flatten() {
        let Ok(sub) = key.open_subkey(&comp) else {
            continue;
        };
        let Ok(stub) = sub.get_value::<String, _>("StubPath") else {
            continue;
        };
        if stub.trim().is_empty() {
            continue;
        }
        // The default value is the component's display name, if present.
        let name = sub
            .get_value::<String, _>("")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| comp.clone());
        out.push(entry(
            "active-setup",
            name,
            stub,
            format!(r"HKLM\{base}\{comp}"),
            "system",
            true,
        ));
    }
}

// --------------------------------------------------------------------------- //
// Image hijacks — IFEO Debugger
// --------------------------------------------------------------------------- //

fn collect_image_hijacks(out: &mut Vec<Value>) {
    let base = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = root.open_subkey(base) else {
        return;
    };
    for exe in key.enum_keys().flatten() {
        let Ok(sub) = key.open_subkey(&exe) else {
            continue;
        };
        let Ok(dbg) = sub.get_value::<String, _>("Debugger") else {
            continue;
        };
        if dbg.trim().is_empty() {
            continue;
        }
        out.push(entry(
            "image-hijack",
            exe.clone(),
            dbg,
            format!(r"HKLM\{base}\{exe}"),
            "system",
            true,
        ));
    }
}

// --------------------------------------------------------------------------- //
// Services / drivers — auto-start (Start = 2)
// --------------------------------------------------------------------------- //

fn collect_services(out: &mut Vec<Value>) {
    let base = r"System\CurrentControlSet\Services";
    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    let Ok(key) = root.open_subkey(base) else {
        return;
    };
    for svc in key.enum_keys().flatten() {
        let Ok(sub) = key.open_subkey(&svc) else {
            continue;
        };
        // Only automatic-start (Start == 2) entries.
        if sub.get_value::<u32, _>("Start").unwrap_or(u32::MAX) != 2 {
            continue;
        }
        let command = sub.get_value::<String, _>("ImagePath").unwrap_or_default();
        // Type 1/2 are kernel/file-system drivers; the rest are services.
        let ty = sub.get_value::<u32, _>("Type").unwrap_or(0);
        let source = if ty == 1 || ty == 2 { "driver" } else { "service" };
        let name = sub
            .get_value::<String, _>("DisplayName")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| svc.clone());
        out.push(entry(
            source,
            name,
            command,
            format!(r"HKLM\{base}\{svc}"),
            "system",
            true,
        ));
    }
}

// --------------------------------------------------------------------------- //
// Scheduled tasks — the XML under %SystemRoot%\System32\Tasks
// --------------------------------------------------------------------------- //

fn collect_scheduled_tasks(out: &mut Vec<Value>) {
    let Some(root) = std::env::var("SystemRoot").ok() else {
        return;
    };
    let base = PathBuf::from(&root).join(r"System32\Tasks");
    walk_tasks(&base, &base, out);
}

/// Recursively list task definition files, using the path under `Tasks\` as the
/// (folder-qualified) task name, and pulling the first `<Command>` for context.
fn walk_tasks(base: &Path, dir: &Path, out: &mut Vec<Value>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for f in rd.flatten() {
        let path = f.path();
        if path.is_dir() {
            walk_tasks(base, &path, out);
            continue;
        }
        let name = path
            .strip_prefix(base)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let command = std::fs::read_to_string(&path)
            .ok()
            .and_then(|xml| between(&xml, "<Command>", "</Command>"))
            .unwrap_or_default();
        out.push(entry(
            "scheduled-task",
            name,
            command,
            path.to_string_lossy().to_string(),
            "system",
            true,
        ));
    }
}

/// The text between the first `open` and the following `close` marker, trimmed.
fn between(s: &str, open: &str, close: &str) -> Option<String> {
    let start = s.find(open)? + open.len();
    let end = s[start..].find(close)? + start;
    let text = s[start..end].trim();
    (!text.is_empty()).then(|| text.to_string())
}

// --------------------------------------------------------------------------- //
// Startup folders
// --------------------------------------------------------------------------- //

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
