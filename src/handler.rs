//! The module itself — what it holds between calls, and what each call does.

use crate::*;

#[derive(Default)]
pub(crate) struct Autoruns {
    /// Whether the user has scanned this session. Once true, reopening the tab
    /// shows the saved results instead of the landing Scan button.
    pub(crate) scanned: bool,
    /// The raw search text from the last scan (restored into the search box).
    pub(crate) last_query: String,
    /// The full entry list from the last scan, so the view can be re-rendered on
    /// reopen without re-enumerating the machine.
    pub(crate) last_entries: Vec<Value>,
    /// The last scan, keyed by the row id sent back on a row action, so `about`
    /// / `open_location` can resolve which entry the user acted on.
    pub(crate) last: HashMap<String, Value>,
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

impl Autoruns {
    /// Enumerate the machine, save the scan state (so reopening the tab restores
    /// it), and render. `params.query` filters; Refresh calls this again.
    pub(crate) fn scan(&mut self, params: &Value, report: bool, lang: &str) -> Value {
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

    /// Open where an entry is defined: the registry key (Windows Run/RunOnce),
    /// or the file / folder in the file manager. `params`: `{ id }`.
    pub(crate) fn open_location(&self, params: &Value, host: &Host) -> Value {
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
    pub(crate) fn with_target(&self, params: &Value, act: impl FnOnce(&str)) -> Value {
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
    pub(crate) fn show_value(&self, params: &Value, host: &Host, lang: &str) -> Value {
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
}
