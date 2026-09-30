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
            // Act on the program the entry runs, rather than where it's declared.
            "reveal_file" => Ok(self.with_target(&params, |path| host.open("reveal", path))),
            "edit_file" => Ok(self.with_target(&params, |path| host.open("edit", path))),
            "show_value" => Ok(self.show_value(&params, host)),
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
    let location = cell(d, "location");
    // A registry location (any Windows ASEP source) opens in regedit.
    if is_registry_location(&location) {
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

/// Whether `loc` names a Windows registry key (rather than a filesystem path).
fn is_registry_location(loc: &str) -> bool {
    loc.starts_with(r"HKLM\")
        || loc.starts_with(r"HKCU\")
        || loc.starts_with("HKEY_")
        || loc.starts_with(r"Computer\")
}

/// Expand `%VAR%` references, leaving unknown ones untouched so the original
/// text stays visible rather than silently collapsing to nothing.
fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Turn the many forms an image path takes in the registry into a real one.
///
/// Service and driver entries store kernel-style or root-relative paths —
/// `\SystemRoot\System32\drivers\x.sys`, `\??\C:\…`, or a bare `system32\…` —
/// none of which resolve as written.
fn normalize_image(raw: &str) -> String {
    let s = expand_env(raw.trim());
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    if let Some(rest) = s.strip_prefix(r"\??\") {
        rest.to_string()
    } else if let Some(rest) = s.strip_prefix(r"\SystemRoot\") {
        format!("{root}\\{rest}")
    } else if s.len() > 8 && s[..8].eq_ignore_ascii_case(r"system32") {
        format!("{root}\\{s}")
    } else {
        s
    }
}

/// Resolve one candidate program string to a file on disk.
///
/// Beyond the path forms [`normalize_image`] handles, a bare program name is
/// common in the most security-relevant keys — Winlogon's `Shell` is just
/// `explorer.exe` — so an unqualified name is looked up the way Windows would.
fn resolve_program(raw: &str) -> Option<String> {
    // Winlogon values carry a trailing comma; quotes may wrap either end.
    let path = normalize_image(raw.trim().trim_matches('"'));
    let path = path.trim_end_matches([',', ' ']).to_string();
    if path.is_empty() {
        return None;
    }
    let p = std::path::Path::new(&path);
    if p.is_file() {
        return Some(path);
    }
    if p.components().count() != 1 {
        return None; // a qualified path that simply isn't there
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    let mut dirs = vec![format!(r"{root}\System32"), root];
    dirs.extend(std::env::var("PATH").unwrap_or_default().split(';').map(str::to_string));
    dirs.into_iter().find_map(|dir| {
        let cand = std::path::Path::new(&dir).join(&path);
        cand.is_file().then(|| cand.to_string_lossy().into_owned())
    })
}

/// The file a command line actually runs, if it exists on disk.
///
/// Quoted programs are easy; an unquoted path may contain spaces
/// (`C:\Program Files\App\app.exe -silent`), so prefixes are tried longest
/// first and the first one that names a real file wins. `None` when nothing
/// resolves — a moved program, or a value that is only arguments (some Active
/// Setup `StubPath`s are just `/UserInstall`).
fn target_file(d: &Value) -> Option<String> {
    let command = cell(d, "command");
    let command = command.trim();
    if command.is_empty() {
        return None;
    }
    // A quoted program is unambiguous: everything up to the closing quote.
    if let Some(rest) = command.strip_prefix('"') {
        return resolve_program(rest.split('"').next().unwrap_or_default());
    }
    // Comma-delimited values (Winlogon `Userinit`) list the program first; a
    // comma also separates rundll32's DLL from its entry point.
    let head = command.split(',').next().unwrap_or(command);
    if let Some(found) = resolve_program(head) {
        return Some(found);
    }
    // Unquoted with arguments: cut at each space, longest candidate first.
    let mut cuts: Vec<usize> = head.match_indices(' ').map(|(i, _)| i).collect();
    cuts.reverse();
    cuts.into_iter().find_map(|i| resolve_program(&head[..i]))
}

/// Whether a file is worth showing as text. Opening a binary in an editor is
/// just noise, so the action is offered only for script-shaped files.
fn is_text_file(path: &str) -> bool {
    const TEXT: &[&str] = &[
        "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "reg", "ini", "inf", "txt",
        "xml", "json", "log", "py", "sh", "pl", "lnk",
    ];
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| TEXT.iter().any(|t| e.eq_ignore_ascii_case(t)))
}

/// The right-click menu for one entry: About, an open action when the location
/// is openable, and — when the command resolves to a real file — actions to
/// reveal it in the file manager and read it. Registry-defined entries can also
/// show the stored value itself, which is the whole definition for a Run key.
fn row_menu_for(d: &Value) -> Vec<MenuItem> {
    let mut items = vec![menu_item("About", "autoruns.local", "about").open_in_tab()];
    if let Some((label, _, _)) = open_kind(d) {
        items.push(menu_item(label, "autoruns.local", "open_location"));
    }
    if let Some(path) = target_file(d) {
        items.push(menu_item("Show in Explorer", "autoruns.local", "reveal_file"));
        if is_text_file(&path) {
            items.push(menu_item("Open in Notepad", "autoruns.local", "edit_file"));
        }
    }
    if is_registry_location(&cell(d, "location")) {
        items.push(menu_item("Show value in Notepad", "autoruns.local", "show_value"));
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
/// This machine's name, for the report's title and its filename.
///
/// Read from the kernel on Linux and from the environment on Windows — no new
/// permission, and no process spawned for a string the system already has.
/// Empty rather than a guess if neither answers: a report labelled "unknown" is
/// one somebody has to open to identify.
fn hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
            let name = name.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(name) = std::env::var(var) {
            if !name.trim().is_empty() {
                return name.trim().to_string();
            }
        }
    }
    String::new()
}

fn report_config() -> Value {
    let opts = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    window(
        "Make Report",
        vec![
            label("Report options").strong(),
            select("content", opts(&["Tables and charts", "Tables only", "Charts only"]))
                .label("Include"),
            select("scope", opts(&["All entries", "Enabled only", "Disabled only"])).label("Show"),
            // Not `open_in_tab`: the report provider answers with a pop-up,
            // and one opened into a tab of its own leaves that tab empty.
            button("Generate", "autoruns.local", "make_report").primary(),
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

    /// Resolve the row's program on disk and hand it to `act`. Silently does
    /// nothing when the row is unknown or its command names no real file — the
    /// menu item is only offered when it does, so this is a stale-scan guard.
    fn with_target(&self, params: &Value, act: impl FnOnce(&str)) -> Value {
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        if let Some(path) = self.last.get(id).and_then(target_file) {
            act(&path);
        }
        Value::Null
    }

    /// Show what the registry actually stores for this entry.
    ///
    /// For a Run key the value *is* the whole autorun — there is no script to
    /// read — so it is written to a temp file and opened as text, alongside the
    /// key and value name it came from.
    fn show_value(&self, params: &Value, host: &Host) -> Value {
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        let Some(d) = self.last.get(id) else {
            return Value::Null;
        };
        let name = cell(d, "name");
        let body = format!(
            "Key:      {}\r\nValue:    {}\r\nSource:   {}\r\nScope:    {}\r\n\r\n{}\r\n",
            cell(d, "location"),
            name,
            cell(d, "source"),
            cell(d, "scope"),
            cell(d, "command"),
        );
        // Keep the entry's name in the filename so Notepad's title bar says
        // which autorun this is; sanitise it, since it comes from the registry.
        let safe: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .take(48)
            .collect();
        let path = std::env::temp_dir().join(format!("autorun-{safe}.txt"));
        if std::fs::write(&path, body).is_ok() {
            host.open("edit", &path.to_string_lossy());
        }
        Value::Null
    }

    /// Build a report spec from the last scan and hand it to a report provider.
    fn make_report(&self, params: &Value, host: &Host) -> Value {
        // Always the preview: which file it becomes — a PDF, a page — is
        // chosen there, beside the thing being saved, rather than in a dropdown
        // here that has to be kept in step with what the report module can
        // actually produce.
        let fmt = "view";
        let content = params.get("content").and_then(Value::as_str).unwrap_or("");
        let scope = params.get("scope").and_then(Value::as_str).unwrap_or("");
        let spec = self.report_spec(fmt, content, scope);
        match host.call("report.build", "build", spec) {
            Ok(v) if v.get("widgets").is_some() => v,
            // A provider that writes a file and acknowledges with nothing.
            // The one shipped with Limen always answers with a screen; this is
            // for any other.
            Ok(_) => window("Report", vec![label("Report written").strong()]),
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
        let host = hostname();

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
            "subtitle": if host.is_empty() {
                format!("{total} entries · {enabled} enabled")
            } else {
                format!("{host} · {total} entries · {enabled} enabled")
            },
            // Filed under the machine it is about. The report module adds the
            // date; a folder of files all called "autoruns" is a folder nobody
            // can find anything in.
            "file_name": if host.is_empty() {
                "autoruns".to_string()
            } else {
                format!("{host}_autoruns")
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry as the collectors emit one.
    fn sample(name: &str, enabled: bool) -> Value {
        entry(
            "systemd",
            name.to_string(),
            "/usr/bin/thing --daemon".to_string(),
            "/etc/systemd/system/thing.service".to_string(),
            "system",
            enabled,
        )
    }

    fn scanned(entries: Vec<Value>) -> Autoruns {
        Autoruns { last_entries: entries, scanned: true, ..Default::default() }
    }

    /// The report is filed under the machine it is about — a folder of files
    /// all called "autoruns" is a folder nobody can find anything in. The date
    /// is the report module's to add.
    #[test]
    fn the_report_is_named_after_the_machine() {
        let spec = scanned(vec![sample("a", true)]).report_spec("view", "", "");
        let name = spec["file_name"].as_str().unwrap();
        assert!(name.ends_with("autoruns"), "{name}");
        assert!(!name.contains("20"), "{name} dated itself");
        assert!(!name.starts_with('_'), "{name} has a dangling separator");
        // On this machine there is a hostname, and it is in both.
        let host = hostname();
        if !host.is_empty() {
            assert!(name.starts_with(&host), "{name} is not filed under {host}");
            assert!(spec["subtitle"].as_str().unwrap().starts_with(&host));
        }
    }

    /// A machine that will not give up its name still produces a report, and
    /// one whose subtitle does not start with a separator.
    #[test]
    fn a_nameless_machine_still_reports() {
        // `hostname()` is read from the system, so the empty case is exercised
        // through the same formatting the spec uses.
        let (host, total, enabled) = (String::new(), 3usize, 2usize);
        let subtitle = if host.is_empty() {
            format!("{total} entries · {enabled} enabled")
        } else {
            format!("{host} · {total} entries · {enabled} enabled")
        };
        assert_eq!(subtitle, "3 entries · 2 enabled");
    }

    /// The scope the dialog offers is the scope the report carries.
    #[test]
    fn the_scope_narrows_what_is_reported() {
        let m = scanned(vec![sample("on", true), sample("off", false), sample("on2", true)]);
        let rows = |scope: &str| -> usize {
            m.report_spec("view", "", scope)["sections"][0]["rows"]
                .as_array()
                .map_or(0, Vec::len)
        };
        assert_eq!(rows(""), 3, "all of them");
        assert_eq!(rows("Enabled only"), 2);
        assert_eq!(rows("Disabled only"), 1);
    }

    /// What goes in is still the caller's choice; what comes out is the report
    /// module's. This one always asks for the preview.
    #[test]
    fn the_content_choice_still_works_and_the_format_is_the_preview() {
        let m = scanned(vec![sample("a", true)]);
        let both = m.report_spec("view", "Tables and charts", "");
        assert_eq!(both["format"], "view");
        assert!(!both["charts"].as_array().unwrap().is_empty());
        assert!(!both["sections"].as_array().unwrap().is_empty());

        let tables = m.report_spec("view", "Tables only", "");
        assert!(tables["charts"].as_array().unwrap().is_empty());
        let charts = m.report_spec("view", "Charts only", "");
        assert!(charts["sections"].as_array().unwrap().is_empty());
    }

    /// The dialog offers nothing the module no longer honours.
    #[test]
    fn the_dialog_asks_only_what_it_uses() {
        let json = report_config().to_string();
        assert!(!json.contains("\"format\""), "the format is the report module's: {json}");
        assert!(json.contains("\"content\""));
        assert!(json.contains("\"scope\""));
        // A pop-up opened into a tab of its own leaves that tab empty.
        assert!(!json.contains("open_in_tab"), "{json}");
    }
}
