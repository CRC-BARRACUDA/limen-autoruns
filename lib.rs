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

use std::collections::HashMap;

use limen_sdk_rust::ui::{
    button, label, menu_item, row, select, separator, table, text, window, MenuItem,
};
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
struct Autoruns {
    /// Whether the user has scanned this session. Once true, reopening the tab
    /// shows the saved results instead of the landing Scan button.
    scanned: bool,
    /// The raw search text from the last scan (restored into the search box).
    last_query: String,
    /// The full entry list from the last scan, so the view can be re-rendered on
    /// reopen without re-enumerating the machine.
    last_entries: Vec<Value>,
    /// The last scan, keyed by the row id sent back on a row action, so `about`
    /// / `open_location` can resolve which entry the user acted on.
    last: HashMap<String, Value>,
}

impl Handler for Autoruns {
    fn capabilities(&self) -> Vec<String> {
        vec!["autoruns.local".into()]
    }

    fn invoke(
        &mut self,
        _capability: &str,
        method: &str,
        params: Value,
        host: &Host,
    ) -> Result<Value, RpcError> {
        // Optional integration: only offer "Make Report" when a report provider
        // is actually loaded (discovered at call time, never a hard dependency).
        let report = host.has_capability("report.build");
        match method {
            // Landing view: the saved results if the user has scanned this
            // session, otherwise just a Scan button (no enumeration on open).
            "ui" => Ok(if self.scanned {
                let entries = self.last_entries.clone();
                let query = self.last_query.clone();
                self.render(&entries, &query, report)
            } else {
                idle_view()
            }),
            // Scan now (enumerate), save the state, and render (also Refresh).
            "scan" => Ok(self.scan(&params, report)),
            "list" => Ok(list_autoruns()),
            // Row actions: open an entry's details, or open where it's defined.
            "about" => Ok(self.about(&params)),
            "open_location" => Ok(self.open_location(&params, host)),
            // Report integration (present only while a report provider is loaded).
            "report_config" => Ok(report_config()),
            "make_report" => Ok(self.make_report(&params, host)),
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

/// A cell value (empty string if the field is missing).
fn cell(d: &Value, key: &str) -> String {
    d.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Whether an entry is enabled (default `true` if unset).
fn is_enabled(d: &Value) -> bool {
    d.get("enabled").and_then(Value::as_bool).unwrap_or(true)
}

/// The six visible columns for an entry row.
fn row_cells(d: &Value) -> Vec<String> {
    vec![
        cell(d, "source"),
        cell(d, "name"),
        cell(d, "command"),
        cell(d, "scope"),
        if is_enabled(d) { "yes".into() } else { "no".into() },
        cell(d, "location"),
    ]
}

/// How to open an entry, decided from its actual `location`:
/// `(menu/button label, host.open target, value)`. `None` when there's nothing
/// to open — a systemd unit is *named*, not a path, and some locations are
/// labels or missing files, so those rows simply get no open action.
fn open_kind(d: &Value) -> Option<(&'static str, &'static str, String)> {
    let source = cell(d, "source");
    let location = cell(d, "location");
    if source.starts_with("registry") {
        return Some(("Open in Registry", "registry", to_regedit(&location)));
    }
    let p = std::path::Path::new(&location);
    if p.is_dir() {
        Some(("Open path", "path", location)) // a folder → file manager
    } else if p.is_file() {
        Some(("Open script", "path", location)) // a script / .desktop / crontab file
    } else {
        None // systemd unit, or a path that doesn't exist
    }
}

/// The right-click menu for one entry: About, plus an open action only when the
/// location is actually openable (labelled for a script / folder / registry).
fn row_menu_for(d: &Value) -> Vec<MenuItem> {
    let mut items = vec![menu_item("About", "autoruns.local", "about").open_in_tab()];
    if let Some((label, _, _)) = open_kind(d) {
        items.push(menu_item(label, "autoruns.local", "open_location"));
    }
    items
}

/// Convert an `HKLM\…` / `HKCU\…` key into the form regedit navigates to.
fn to_regedit(loc: &str) -> String {
    if let Some(rest) = loc.strip_prefix(r"HKLM\") {
        format!(r"Computer\HKEY_LOCAL_MACHINE\{rest}")
    } else if let Some(rest) = loc.strip_prefix(r"HKCU\") {
        format!(r"Computer\HKEY_CURRENT_USER\{rest}")
    } else {
        loc.to_string()
    }
}

/// The "Make Report" configuration view (opened in a tab).
fn report_config() -> Value {
    let opts = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    window(
        "Make Report",
        vec![
            label("Report options").strong(),
            select("format", opts(&["In-app view", "Markdown", "HTML", "CSV"])).label("Output"),
            select("content", opts(&["Tables and charts", "Tables only", "Charts only"]))
                .label("Include"),
            select("scope", opts(&["All entries", "Enabled only", "Disabled only"])).label("Show"),
            button("Generate", "autoruns.local", "make_report").primary().open_in_tab(),
        ],
    )
}

impl Autoruns {
    /// Enumerate the machine, save the scan state (so reopening the tab restores
    /// it), and render. `params.query` filters; Refresh calls this again.
    fn scan(&mut self, params: &Value, report: bool) -> Value {
        let query = params.get("query").and_then(Value::as_str).unwrap_or("").to_string();
        let data = list_autoruns();
        let entries: Vec<Value> = data
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        self.scanned = true;
        self.last_entries = entries.clone();
        self.last_query = query.clone();
        self.render(&entries, &query, report)
    }

    /// The results view: a search box + Refresh (+ Make Report when a report
    /// provider is loaded), then one interactive table of every autostart entry.
    /// Filters `entries` by `query_raw` and caches each shown entry by its row id
    /// so row actions (`about` / `open_location`) resolve it.
    fn render(&mut self, entries: &[Value], query_raw: &str, report: bool) -> Value {
        let query = query_raw.to_lowercase();
        let matches = |d: &Value| -> bool {
            if query.is_empty() {
                return true;
            }
            row_cells(d).join(" ").to_lowercase().contains(&query)
        };

        self.last.clear();
        let (mut rows, mut ids, mut menus) = (Vec::new(), Vec::new(), Vec::new());
        for (i, d) in entries.iter().enumerate() {
            if !matches(d) {
                continue;
            }
            let rid = i.to_string();
            self.last.insert(rid.clone(), d.clone());
            ids.push(rid);
            rows.push(row_cells(d));
            menus.push(row_menu_for(d)); // per-row: open action only when openable
        }

        let cols: Vec<String> = ["Source", "Name", "Command", "Scope", "Enabled", "Location"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut actions = vec![button("Refresh", "autoruns.local", "scan").primary()];
        if report {
            actions.push(button("Make Report", "autoruns.local", "report_config").open_in_tab());
        }

        window(
            "Autoruns",
            vec![
                text("query")
                    .label("Search")
                    .placeholder("source, name, command, location…")
                    .default(query_raw.to_string()),
                row(actions),
                label("Right-click a row for actions; double-click to open its details.").weak(),
                separator(),
                label(format!("Autostart entries ({})", rows.len())).strong(),
                table(cols, rows)
                    .row_ids(ids)
                    .row_menus(menus)
                    .on_activate("autoruns.local", "about"),
            ],
        )
    }

    /// A detail view for one entry (opened in a new tab from a row action).
    fn about(&self, params: &Value) -> Value {
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        let Some(d) = self.last.get(id) else {
            return window(
                "Autorun",
                vec![label("This entry isn't in the latest scan — re-scan and try again.").weak()],
            );
        };
        let shown = |v: String| if v.is_empty() { "—".to_string() } else { v };
        let field = |name: &str, val: String| {
            row(vec![label(name.to_string()).strong(), label(shown(val))])
        };
        let title = {
            let n = cell(d, "name");
            if n.is_empty() { cell(d, "command") } else { n }
        };

        let mut widgets = vec![
            label(title.clone()).strong(),
            separator(),
            field("Source", cell(d, "source")),
            field("Name", cell(d, "name")),
            field("Command", cell(d, "command")),
            field("Scope", cell(d, "scope")),
            field("Enabled", if is_enabled(d) { "yes".into() } else { "no".into() }),
            field("Location", cell(d, "location")),
        ];
        // Offer the open action only where the location is actually openable,
        // labelled for what it is (script / folder / registry).
        if let Some((label, _, _)) = open_kind(d) {
            widgets.push(separator());
            widgets.push(
                button(label, "autoruns.local", "open_location")
                    .args(json!({ "id": id }))
                    .primary(),
            );
        }
        window(title, widgets)
    }

    /// Open where an entry is defined: the registry key (Windows Run/RunOnce),
    /// or the file / folder in the file manager. `params`: `{ id }`.
    fn open_location(&self, params: &Value, host: &Host) -> Value {
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        if let Some(d) = self.last.get(id) {
            if let Some((_, target, value)) = open_kind(d) {
                host.open(target, &value);
            }
        }
        Value::Null
    }

    /// Build a report spec from the last scan and hand it to a report provider.
    fn make_report(&self, params: &Value, host: &Host) -> Value {
        let fmt = match params.get("format").and_then(Value::as_str).unwrap_or("") {
            "Markdown" => "markdown",
            "HTML" => "html",
            "CSV" => "csv",
            _ => "view",
        };
        let content = params.get("content").and_then(Value::as_str).unwrap_or("");
        let scope = params.get("scope").and_then(Value::as_str).unwrap_or("");
        let spec = self.report_spec(fmt, content, scope);
        match host.call("report.build", "build", spec) {
            Ok(v) if v.get("widgets").is_some() => v,
            Ok(_) => window(
                "Report",
                vec![
                    label("Report exported").strong(),
                    label("The document was generated and opened in your default app.").weak(),
                ],
            ),
            Err(e) => window(
                "Report",
                vec![
                    label("Couldn't build the report").strong(),
                    label(format!("{e}")).weak(),
                ],
            ),
        }
    }

    /// Assemble the report spec (a by-source chart + an entries table) from the
    /// last scan, honoring the config choices.
    fn report_spec(&self, fmt: &str, content: &str, scope: &str) -> Value {
        let entries = &self.last_entries;
        let in_scope = |d: &Value| match scope {
            "Enabled only" => is_enabled(d),
            "Disabled only" => !is_enabled(d),
            _ => true,
        };
        let total = entries.len();
        let enabled = entries.iter().filter(|d| is_enabled(d)).count();

        let mut counts: HashMap<String, i64> = HashMap::new();
        for d in entries.iter().filter(|d| in_scope(d)) {
            *counts.entry(cell(d, "source")).or_default() += 1;
        }
        let mut pairs: Vec<(String, i64)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let chart_data: Vec<Value> = pairs
            .iter()
            .map(|(k, v)| json!({ "label": k, "value": v }))
            .collect();

        let cols = ["Source", "Name", "Command", "Scope", "Enabled", "Location"];
        let rows: Vec<Vec<String>> =
            entries.iter().filter(|d| in_scope(d)).map(row_cells).collect();

        let mut charts = Vec::new();
        if content != "Tables only" && !chart_data.is_empty() {
            charts.push(json!({ "title": "Entries by source", "data": chart_data }));
        }
        let mut sections = Vec::new();
        if content != "Charts only" {
            sections.push(json!({ "heading": "Autostart entries", "columns": cols, "rows": rows }));
        }

        json!({
            "title": "Autoruns Report",
            "subtitle": format!("{total} entries · {enabled} enabled"),
            "format": fmt,
            "summary": [
                format!("Total entries: {total}"),
                format!("Enabled: {enabled}"),
            ],
            "charts": charts,
            "sections": sections,
        })
    }
}

export_module!(Autoruns);
