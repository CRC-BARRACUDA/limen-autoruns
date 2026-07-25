//! XDG desktop autostart — `.desktop` files that the desktop environment runs at
//! login, from `/etc/xdg/autostart` (system) and `~/.config/autostart` (user).
//!
//! A user file shadows a system file of the same name, so we key by filename and
//! let the user entry win. `Hidden=true` (or `X-GNOME-Autostart-enabled=false`)
//! marks an autostart the user has turned off — reported with `enabled = false`.

use limen_sdk_rust::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::entry;

pub(super) fn collect(out: &mut Vec<Value>) {
    // Keyed by .desktop filename; system first, user overrides.
    let mut by_name: BTreeMap<String, Value> = BTreeMap::new();

    for (dir, scope) in dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }
            let fname = ent.file_name().to_string_lossy().to_string();
            if let Some(v) = parse_desktop(&path, scope) {
                by_name.insert(fname, v);
            }
        }
    }

    out.extend(by_name.into_values());
}

/// The autostart dirs to scan, in precedence order (system first, user last).
fn dirs() -> Vec<(PathBuf, &'static str)> {
    let mut v = vec![(PathBuf::from("/etc/xdg/autostart"), "system")];
    let user = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    if let Some(cfg) = user {
        v.push((cfg.join("autostart"), "user"));
    }
    v
}

fn parse_desktop(path: &Path, scope: &str) -> Option<Value> {
    let text = std::fs::read_to_string(path).ok()?;

    let mut name: Option<String> = None;
    let mut exec: Option<String> = None;
    let mut hidden = false;
    let mut gnome_disabled = false;
    let mut in_entry = false;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            // Prefer the unlocalized `Name`; ignore `Name[xx]` variants.
            "Name" if name.is_none() => name = Some(val.trim().to_string()),
            "Exec" => exec = Some(val.trim().to_string()),
            "Hidden" => hidden = val.trim().eq_ignore_ascii_case("true"),
            "X-GNOME-Autostart-enabled" => {
                gnome_disabled = val.trim().eq_ignore_ascii_case("false")
            }
            _ => {}
        }
    }

    let display = name.unwrap_or_else(|| {
        path.file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    });
    let command = exec.unwrap_or_default();

    Some(entry(
        "xdg-autostart",
        display,
        command,
        path.to_string_lossy().to_string(),
        scope,
        !(hidden || gnome_disabled),
    ))
}
