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
use limen_sdk_rust::{export_module, json, rpc, Catalog, Handler, Host, RpcError, Value};

/// Every word this module shows, in each language it has.
///
/// English lives in a file beside the Ukrainian rather than in the code: two
/// catalogues that can be read side by side are two catalogues somebody can
/// check, and a string left behind in the source is a string nobody translates.
fn catalog() -> &'static Catalog {
    static C: std::sync::OnceLock<Catalog> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        Catalog::new(&[
            ("en", include_str!("locales/en.toml")),
            ("uk", include_str!("locales/uk.toml")),
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
        let lang = host.locale();
        let lang = lang.as_str();
        match method {
            // Landing view: the saved results if the user has scanned this
            // session, otherwise just a Scan button (no enumeration on open).
            "ui" => Ok(if self.scanned {
                let entries = self.last_entries.clone();
                let query = self.last_query.clone();
                self.render(&entries, &query, report, lang)
            } else {
                idle_view(lang)
            }),
            // Scan now (enumerate), save the state, and render (also Refresh).
            "scan" => Ok(self.scan(&params, report, lang)),
            "list" => Ok(list_autoruns()),
            // Row actions: open an entry's details, or open where it's defined.
            "about" => Ok(self.about(&params, lang)),
            "open_location" => Ok(self.open_location(&params, host)),
            // Act on the program the entry runs, rather than where it's declared.
            "reveal_file" => Ok(self.with_target(&params, |path| host.open("reveal", path))),
            "edit_file" => Ok(self.with_target(&params, |path| host.open("edit", path))),
            "show_value" => Ok(self.show_value(&params, host, lang)),
            // Report integration (present only while a report provider is loaded).
            "report_config" => Ok(report_config(lang)),
            "make_report" => Ok(self.make_report(&params, host, lang)),
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
fn idle_view(lang: &str) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    window(
        t("ui.title"),
        vec![
            label(t("ui.idle_hint")).weak(),
            button(t("ui.scan"), "autoruns.local", "scan").primary(),
        ],
    )
}

/// The six visible columns, as catalogue keys — named once, so the table and
/// the report cannot drift apart.
const COLUMNS: [&str; 6] = [
    "col.source",
    "col.name",
    "col.command",
    "col.scope",
    "col.enabled",
    "col.location",
];

/// A cell value (empty string if the field is missing).
fn cell(d: &Value, key: &str) -> String {
    d.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Whether an entry is enabled (default `true` if unset).
fn is_enabled(d: &Value) -> bool {
    d.get("enabled").and_then(Value::as_bool).unwrap_or(true)
}

/// The six visible columns for an entry row.
fn row_cells(d: &Value, lang: &str) -> Vec<String> {
    vec![
        cell(d, "source"),
        cell(d, "name"),
        cell(d, "command"),
        cell(d, "scope"),
        catalog().tr(lang, if is_enabled(d) { "val.yes" } else { "val.no" }),
        cell(d, "location"),
    ]
}

/// How to open an entry, decided from its actual `location`:
/// `(the catalogue key its label comes from, host.open target, value)`. `None` when there's nothing
/// to open — a systemd unit is *named*, not a path, and some locations are
/// labels or missing files, so those rows simply get no open action.
fn open_kind(d: &Value) -> Option<(&'static str, &'static str, String)> {
    let location = cell(d, "location");
    // A registry location (any Windows ASEP source) opens in regedit.
    if is_registry_location(&location) {
        return Some(("menu.open_registry", "registry", to_regedit(&location)));
    }
    let p = std::path::Path::new(&location);
    if p.is_dir() {
        Some(("menu.open_path", "path", location)) // a folder → file manager
    } else if p.is_file() {
        Some(("menu.open_script", "path", location)) // a script / .desktop / crontab file
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
fn row_menu_for(d: &Value, lang: &str) -> Vec<MenuItem> {
    let t = |k: &str| catalog().tr(lang, k);
    let mut items = vec![menu_item(t("menu.about"), "autoruns.local", "about").open_in_tab()];
    if let Some((key, _, _)) = open_kind(d) {
        items.push(menu_item(t(key), "autoruns.local", "open_location"));
    }
    if let Some(path) = target_file(d) {
        items.push(menu_item(t("menu.reveal"), "autoruns.local", "reveal_file"));
        if is_text_file(&path) {
            items.push(menu_item(t("menu.edit"), "autoruns.local", "edit_file"));
        }
    }
    if is_registry_location(&cell(d, "location")) {
        items.push(menu_item(t("menu.show_value"), "autoruns.local", "show_value"));
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

fn report_config(lang: &str) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let opts = |keys: &[&str]| keys.iter().map(|k| t(k)).collect::<Vec<_>>();
    window(
        t("report.config_title"),
        vec![
            label(t("report.options")).strong(),
            select(
                "content",
                opts(&[
                    "report.content_both",
                    "report.content_tables",
                    "report.content_charts",
                ]),
            )
            .label(t("report.include")),
            select(
                "scope",
                opts(&[
                    "report.scope_all",
                    "report.scope_enabled",
                    "report.scope_disabled",
                ]),
            )
            .label(t("report.show")),
            // Not `open_in_tab`: the report provider answers with a pop-up,
            // and one opened into a tab of its own leaves that tab empty.
            button(t("report.generate"), "autoruns.local", "make_report").primary(),
        ],
    )
}

impl Autoruns {
    /// Enumerate the machine, save the scan state (so reopening the tab restores
    /// it), and render. `params.query` filters; Refresh calls this again.
    fn scan(&mut self, params: &Value, report: bool, lang: &str) -> Value {
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
        self.render(&entries, &query, report, lang)
    }

    /// The results view: a search box + Refresh (+ Make Report when a report
    /// provider is loaded), then one interactive table of every autostart entry.
    /// Filters `entries` by `query_raw` and caches each shown entry by its row id
    /// so row actions (`about` / `open_location`) resolve it.
    fn render(
        &mut self,
        entries: &[Value],
        query_raw: &str,
        report: bool,
        lang: &str,
    ) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let query = query_raw.to_lowercase();
        let matches = |d: &Value| -> bool {
            if query.is_empty() {
                return true;
            }
            row_cells(d, lang).join(" ").to_lowercase().contains(&query)
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
            rows.push(row_cells(d, lang));
            menus.push(row_menu_for(d, lang)); // per-row: open only when openable
        }

        let cols: Vec<String> = COLUMNS.iter().map(|k| t(k)).collect();

        let mut actions = vec![button(t("ui.refresh"), "autoruns.local", "scan").primary()];
        if report {
            actions.push(
                button(t("ui.report"), "autoruns.local", "report_config").open_in_tab(),
            );
        }

        window(
            t("ui.title"),
            vec![
                text("query")
                    .label(t("ui.search"))
                    .placeholder(t("ui.search_ph"))
                    .default(query_raw.to_string()),
                row(actions),
                label(t("ui.rows_hint")).weak(),
                separator(),
                label(t("ui.count").replace("{n}", &rows.len().to_string())).strong(),
                table(cols, rows)
                    .row_ids(ids)
                    .row_menus(menus)
                    .on_activate("autoruns.local", "about"),
            ],
        )
    }

    /// A detail view for one entry (opened in a new tab from a row action).
    fn about(&self, params: &Value, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        let Some(d) = self.last.get(id) else {
            return window(t("detail.title"), vec![label(t("detail.missing")).weak()]);
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
            field(&t("col.source"), cell(d, "source")),
            field(&t("col.name"), cell(d, "name")),
            field(&t("col.command"), cell(d, "command")),
            field(&t("col.scope"), cell(d, "scope")),
            field(
                &t("col.enabled"),
                t(if is_enabled(d) { "val.yes" } else { "val.no" }),
            ),
            field(&t("col.location"), cell(d, "location")),
        ];
        // Offer the open action only where the location is actually openable,
        // labelled for what it is (script / folder / registry).
        if let Some((key, _, _)) = open_kind(d) {
            widgets.push(separator());
            widgets.push(
                button(t(key), "autoruns.local", "open_location")
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
    fn show_value(&self, params: &Value, host: &Host, lang: &str) -> Value {
        let id = params.get("id").and_then(Value::as_str).unwrap_or("");
        let Some(d) = self.last.get(id) else {
            return Value::Null;
        };
        let name = cell(d, "name");
        // Each label padded to the same width so the four values line up in a
        // plain text editor, whatever language names them.
        let t = |k: &str| catalog().tr(lang, k);
        let fields = [
            (t("value.key"), cell(d, "location")),
            (t("value.name"), name.clone()),
            (t("value.source"), cell(d, "source")),
            (t("value.scope"), cell(d, "scope")),
        ];
        let width = fields.iter().map(|(k, _)| k.chars().count()).max().unwrap_or(0);
        let mut body = String::new();
        for (key, value) in &fields {
            let pad = " ".repeat(width - key.chars().count());
            body.push_str(&format!("{key}:{pad}   {value}\r\n"));
        }
        body.push_str(&format!("\r\n{}\r\n", cell(d, "command")));
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
    fn make_report(&self, params: &Value, host: &Host, lang: &str) -> Value {
        // Always the preview: which file it becomes — a PDF, a page — is
        // chosen there, beside the thing being saved, rather than in a dropdown
        // here that has to be kept in step with what the report module can
        // actually produce.
        let fmt = "view";
        let content = params.get("content").and_then(Value::as_str).unwrap_or("");
        let scope = params.get("scope").and_then(Value::as_str).unwrap_or("");
        let spec = self.report_spec(fmt, content, scope, lang);
        match host.call("report.build", "build", spec) {
            Ok(v) if v.get("widgets").is_some() => v,
            // A provider that writes a file and acknowledges with nothing.
            // The one shipped with Limen always answers with a screen; this is
            // for any other.
            Ok(_) => window(
                catalog().tr(lang, "report.config_title"),
                vec![label(catalog().tr(lang, "report.written")).strong()],
            ),
            Err(e) => window(
                catalog().tr(lang, "report.config_title"),
                vec![
                    label(catalog().tr(lang, "report.failed")).strong(),
                    label(format!("{e}")).weak(),
                ],
            ),
        }
    }

    /// Assemble the report spec (a by-source chart + an entries table) from the
    /// last scan, honoring the config choices.
    fn report_spec(&self, fmt: &str, content: &str, scope: &str, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        let entries = &self.last_entries;
        let in_scope = |d: &Value| {
            if chose(scope, "report.scope_enabled") {
                is_enabled(d)
            } else if chose(scope, "report.scope_disabled") {
                !is_enabled(d)
            } else {
                true
            }
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

        let cols: Vec<String> = COLUMNS.iter().map(|k| t(k)).collect();
        let rows: Vec<Vec<String>> =
            entries.iter().filter(|d| in_scope(d)).map(|d| row_cells(d, lang)).collect();

        let mut charts = Vec::new();
        if !chose(content, "report.content_tables") && !chart_data.is_empty() {
            charts.push(json!({ "title": t("report.chart"), "data": chart_data }));
        }
        let mut sections = Vec::new();
        if !chose(content, "report.content_charts") {
            sections.push(json!({ "heading": t("report.section"), "columns": cols, "rows": rows }));
        }

        json!({
            "title": t("report.title"),
            "subtitle": if host.is_empty() {
                t("report.subtitle")
                    .replace("{total}", &total.to_string())
                    .replace("{enabled}", &enabled.to_string())
            } else {
                t("report.subtitle_host")
                    .replace("{host}", &host)
                    .replace("{total}", &total.to_string())
                    .replace("{enabled}", &enabled.to_string())
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
                t("report.total").replace("{n}", &total.to_string()),
                t("report.enabled").replace("{n}", &enabled.to_string()),
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
    pub(super) fn sample(name: &str, enabled: bool) -> Value {
        entry(
            "systemd",
            name.to_string(),
            "/usr/bin/thing --daemon".to_string(),
            "/etc/systemd/system/thing.service".to_string(),
            "system",
            enabled,
        )
    }

    pub(super) fn scanned(entries: Vec<Value>) -> Autoruns {
        Autoruns { last_entries: entries, scanned: true, ..Default::default() }
    }

    /// The report is filed under the machine it is about — a folder of files
    /// all called "autoruns" is a folder nobody can find anything in. The date
    /// is the report module's to add.
    #[test]
    fn the_report_is_named_after_the_machine() {
        let spec = scanned(vec![sample("a", true)]).report_spec("view", "", "", "en");
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
            m.report_spec("view", "", scope, "en")["sections"][0]["rows"]
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
        let both = m.report_spec("view", "Tables and charts", "", "en");
        assert_eq!(both["format"], "view");
        assert!(!both["charts"].as_array().unwrap().is_empty());
        assert!(!both["sections"].as_array().unwrap().is_empty());

        let tables = m.report_spec("view", "Tables only", "", "en");
        assert!(tables["charts"].as_array().unwrap().is_empty());
        let charts = m.report_spec("view", "Charts only", "", "en");
        assert!(charts["sections"].as_array().unwrap().is_empty());
    }

    /// The dialog offers nothing the module no longer honours.
    #[test]
    fn the_dialog_asks_only_what_it_uses() {
        let json = report_config("en").to_string();
        assert!(!json.contains("\"format\""), "the format is the report module's: {json}");
        assert!(json.contains("\"content\""));
        assert!(json.contains("\"scope\""));
        // A pop-up opened into a tab of its own leaves that tab empty.
        assert!(!json.contains("open_in_tab"), "{json}");
    }
}

/// The catalogue, and that both languages actually say everything.
#[cfg(test)]
mod i18n_tests {
    use super::tests::{sample, scanned};
    use super::*;

    /// Every `a.b` key a locale file defines, read from the file rather than
    /// through the catalogue: `tr` falls back to English for a key Ukrainian is
    /// missing, so asking it would hide exactly what this is looking for.
    fn keys(src: &str) -> Vec<String> {
        let mut table = String::new();
        let mut out = Vec::new();
        for line in src.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                table = name.to_string();
            } else if let Some((key, _)) = line.split_once(" = ") {
                out.push(format!("{table}.{key}"));
            }
        }
        out
    }

    /// Ukrainian says everything English says. A key only one of them has is a
    /// screen that falls back to English mid-sentence.
    #[test]
    fn both_languages_say_the_same_things() {
        let en = keys(include_str!("locales/en.toml"));
        let uk = keys(include_str!("locales/uk.toml"));
        assert!(!en.is_empty() && en.len() > 40, "the catalogue is suspiciously small");
        for key in &en {
            assert!(uk.contains(key), "uk.toml is missing {key}");
        }
        for key in &uk {
            // `[module]` is the card the host draws, and English comes from
            // limen.toml — so it is the one table Ukrainian has alone.
            if !key.starts_with("module.") {
                assert!(en.contains(key), "en.toml is missing {key}");
            }
        }
    }

    /// A screen asked for in Ukrainian comes back in Ukrainian — not a mix, and
    /// not English with a translated title.
    #[test]
    fn the_screens_are_translated_not_merely_titled() {
        let uk = idle_view("uk").to_string();
        assert!(uk.contains("Автозапуски"), "{uk}");
        assert!(uk.contains("Сканувати"), "{uk}");
        assert!(!uk.contains("Scan this machine"), "English survived: {uk}");

        let cfg = report_config("uk").to_string();
        for word in ["Параметри звіту", "Лише таблиці", "Лише увімкнені", "Створити"] {
            assert!(cfg.contains(word), "{word} is missing from {cfg}");
        }
        assert!(!cfg.contains("Tables only"), "English survived: {cfg}");

        let entry = json!({ "source": "cron", "name": "n", "command": "c",
                            "location": "/etc/crontab", "scope": "user", "enabled": true });
        let mut m = Autoruns::default();
        m.last.insert("0".into(), entry.clone());
        let about = m.about(&json!({ "id": "0" }), "uk").to_string();
        assert!(about.contains("Джерело") && about.contains("Розташування"), "{about}");
    }

    /// A dropdown's answer comes back in the language it was shown in, so the
    /// module has to recognise its own words — in either language, because a
    /// spec built elsewhere may still say "Enabled only".
    #[test]
    fn a_choice_is_understood_in_the_language_it_was_made_in() {
        assert!(chose("Лише увімкнені", "report.scope_enabled"));
        assert!(chose("Enabled only", "report.scope_enabled"));
        assert!(!chose("Лише вимкнені", "report.scope_enabled"));

        let m = scanned(vec![sample("on", true), sample("off", false)]);
        for answer in ["Лише увімкнені", "Enabled only"] {
            let rows = m.report_spec("view", "", answer, "uk")["sections"][0]["rows"]
                .as_array()
                .unwrap()
                .len();
            assert_eq!(rows, 1, "{answer} did not narrow the report");
        }
    }

    /// The report a Ukrainian screen asks for is a Ukrainian report: its title,
    /// its headings and its columns, not only the rows it carries.
    #[test]
    fn the_report_speaks_the_language_it_was_asked_in() {
        let spec = scanned(vec![sample("a", true)]).report_spec("view", "", "", "uk");
        assert_eq!(spec["title"], "Звіт про автозапуски");
        assert_eq!(spec["sections"][0]["heading"], "Записи автозапуску");
        assert_eq!(spec["sections"][0]["columns"][0], "Джерело");
        assert!(spec["summary"][0].as_str().unwrap().starts_with("Усього записів"));
    }
}
