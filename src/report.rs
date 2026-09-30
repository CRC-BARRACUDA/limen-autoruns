//! Handing the last scan to a report provider.
//!
//! `report.build` is optional: the action appears only while a provider is
//! loaded, so nothing here is reached by somebody with no way to read the
//! result.

use crate::*;

/// The "Make Report" configuration view (opened in a tab).
/// This machine's name, for the report's title and its filename.
///
/// Read from the kernel on Linux and from the environment on Windows — no new
/// permission, and no process spawned for a string the system already has.
/// Empty rather than a guess if neither answers: a report labelled "unknown" is
/// one somebody has to open to identify.
pub(crate) fn hostname() -> String {
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

pub(crate) fn report_config(lang: &str) -> Value {
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
    /// Build a report spec from the last scan and hand it to a report provider.
    pub(crate) fn make_report(&self, params: &Value, host: &Host, lang: &str) -> Value {
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
    pub(crate) fn report_spec(&self, fmt: &str, content: &str, scope: &str, lang: &str) -> Value {
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
