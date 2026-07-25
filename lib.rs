//! `autoruns` — a native Limen module that lists programs configured to start
//! automatically on **this** machine.
//!
//! Provides `autoruns.local`. Methods: `list` (raw data, for other modules),
//! plus `ui`/`scan` for the built-in view — the UI does **not** scan on open;
//! it enumerates only when the user presses **Scan**. Sources are per-OS:
//! - **Linux** — enabled `systemd` units (system + user), `cron` (`/etc/crontab`,
//!   `/etc/cron.d`, the periodic dirs, and the user crontab), and **XDG**
//!   desktop autostart entries.
//! - **Windows** — the registry `Run`/`RunOnce` keys (HKLM + HKCU, incl.
//!   `WOW6432Node`) and the per-user / all-users **Startup** folders.
//!
//! Every entry is emitted in one shared schema (see [`entry`]):
//!
//! `source`, `name`, `command`, `location`, `scope`, `enabled`.
//!
//! Built as a native (`cdylib`) module using `limen-sdk-rust`.

use limen_sdk_rust::ui::{button, label, separator, table, text, window};
use limen_sdk_rust::{export_module, json, rpc, Handler, Host, RpcError, Value};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::list_autoruns;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::list_autoruns;

/// Fallback for platforms without a collector.
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn list_autoruns() -> Value {
    json!({
        "os": std::env::consts::OS,
        "note": "autorun listing is only implemented for Windows and Linux",
        "total": 0,
        "enabled": 0,
        "disabled": 0,
        "entries": [],
    })
}

#[derive(Default)]
struct Autoruns;

impl Handler for Autoruns {
    fn capabilities(&self) -> Vec<String> {
        vec!["autoruns.local".into()]
    }

    fn invoke(
        &mut self,
        _capability: &str,
        method: &str,
        params: Value,
        _host: &Host,
    ) -> Result<Value, RpcError> {
        match method {
            // Initial view: a Scan button only — enumeration runs on demand.
            "ui" => Ok(idle_view()),
            // Scan now and render the results (also what Refresh calls).
            "scan" => Ok(scan_view(&params)),
            "list" => Ok(list_autoruns()),
            other => Err(RpcError::new(
                rpc::METHOD_NOT_FOUND,
                format!("autoruns has no method {other}"),
            )),
        }
    }
}

/// Build one autorun record in the shared schema. Used by every platform collector.
///
/// - `source` — where it is defined (`systemd`, `cron`, `xdg-autostart`,
///   `registry:Run`, `startup-folder`, …).
/// - `command` — the program/command that runs.
/// - `location` — the file or registry key that declares it.
/// - `scope` — `system` (all users / machine) or `user`.
/// - `enabled` — whether it is active (a hidden/disabled autostart is `false`).
pub(crate) fn entry(
    source: &str,
    name: String,
    command: String,
    location: String,
    scope: &str,
    enabled: bool,
) -> Value {
    json!({
        "source": source,
        "name": name,
        "command": command,
        "location": location,
        "scope": scope,
        "enabled": enabled,
    })
}

/// The landing view: nothing is scanned until the user asks. Just a hint and a
/// Scan button that invokes `scan`.
fn idle_view() -> Value {
    window(
        "Autoruns",
        vec![
            label("Scan this machine for programs configured to start automatically.").weak(),
            button("Scan", "autoruns.local", "scan").primary(),
        ],
    )
}

/// The results view: a search box + Refresh, then one table of every autostart
/// entry. Runs the scan. `params.query` filters; Refresh re-scans.
fn scan_view(params: &Value) -> Value {
    let query = params
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();

    let data = list_autoruns();
    let empty = Vec::new();
    let entries = data.get("entries").and_then(Value::as_array).unwrap_or(&empty);

    let cell = |d: &Value, key: &str| -> String {
        d.get(key).and_then(Value::as_str).unwrap_or("").to_string()
    };
    // Case-insensitive substring match across the text fields.
    let matches = |d: &Value| -> bool {
        if query.is_empty() {
            return true;
        }
        let hay = format!(
            "{} {} {} {} {}",
            cell(d, "source"),
            cell(d, "name"),
            cell(d, "command"),
            cell(d, "location"),
            cell(d, "scope"),
        )
        .to_lowercase();
        hay.contains(&query)
    };
    let enabled_str = |d: &Value| -> String {
        if d.get("enabled").and_then(Value::as_bool).unwrap_or(true) {
            "yes".to_string()
        } else {
            "no".to_string()
        }
    };
    let row = |d: &Value| -> Vec<String> {
        vec![
            cell(d, "source"),
            cell(d, "name"),
            cell(d, "command"),
            cell(d, "scope"),
            enabled_str(d),
            cell(d, "location"),
        ]
    };
    let rows: Vec<Vec<String>> = entries.iter().filter(|d| matches(d)).map(row).collect();

    let cols: Vec<String> = ["Source", "Name", "Command", "Scope", "Enabled", "Location"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    window(
        "Autoruns",
        vec![
            text("query")
                .label("Search")
                .placeholder("source, name, command, location…")
                .default(query.clone()),
            button("Refresh", "autoruns.local", "scan").primary(),
            separator(),
            label(format!("Autostart entries ({})", rows.len())).strong(),
            table(cols, rows),
        ],
    )
}

export_module!(Autoruns);
