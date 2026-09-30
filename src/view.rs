//! Everything the module draws.
//!
//! Each screen takes `lang` and resolves its words through the catalog, so
//! the same call renders in whatever language the host is set to.

use crate::*;

/// The landing view: nothing is scanned until the user asks. Just a hint and a
/// Scan button that invokes `scan`.
pub(crate) fn idle_view(lang: &str) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    window(
        t("ui.title"),
        vec![
            label(t("ui.idle_hint")).weak(),
            button(t("ui.scan"), "autoruns.local", "scan").primary(),
        ],
    )
}

impl Autoruns {
    /// The results view: a search box + Refresh (+ Make Report when a report
    /// provider is loaded), then one interactive table of every autostart entry.
    /// Filters `entries` by `query_raw` and caches each shown entry by its row id
    /// so row actions (`about` / `open_location`) resolve it.
    pub(crate) fn render(
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
    pub(crate) fn about(&self, params: &Value, lang: &str) -> Value {
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
}
