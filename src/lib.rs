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
//! The results table is interactive: right-click a row for **About** / **Open
//! location**, or double-click for its details. When a report provider is
//! loaded, a **Make Report** action is offered.
//!
//! Every entry is emitted in one shared schema (see [`entry`]):
//!
//! `source`, `name`, `command`, `location`, `scope`, `enabled`.
//!
//! Built as a native (`cdylib`) module using `limen-sdk-rust`.

pub(crate) use std::collections::HashMap;

pub(crate) use limen_sdk_rust::ui::{
    button, label, menu_item, row, select, separator, table, text, window, MenuItem,
};
pub(crate) use limen_sdk_rust::{export_module, json, rpc, Catalog, Handler, Host, RpcError, Value};

/// Every word this module shows, in each language it has.
///
/// English lives in a file beside the Ukrainian rather than in the code: two
/// catalogues that can be read side by side are two catalogues somebody can
/// check, and a string left behind in the source is a string nobody translates.
fn catalog() -> &'static Catalog {
    static C: std::sync::OnceLock<Catalog> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        Catalog::new(&[
            ("en", include_str!("../locales/en.toml")),
            ("uk", include_str!("../locales/uk.toml")),
        ])
    })
}

/// Whether a dropdown's answer is this choice, in whichever language it was
/// shown in.
///
/// An option is its own value — a person reading Ukrainian sends Ukrainian
/// back — so the answer is compared against every language rather than against
/// the English it used to be.
fn chose(answer: &str, key: &str) -> bool {
    ["en", "uk"].iter().any(|lang| catalog().tr(lang, key) == answer)
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::list_autoruns;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::list_autoruns;

mod entry;
mod handler;
mod report;
mod view;

#[cfg(test)]
mod tests;

// This reads best as one namespace: each part takes `use crate::*` and finds
// everything, rather than every file carrying a list of its neighbours that
// has to be maintained by hand.
pub(crate) use entry::*;
pub(crate) use handler::*;
pub(crate) use report::*;
pub(crate) use view::*;

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

export_module!(Autoruns);
