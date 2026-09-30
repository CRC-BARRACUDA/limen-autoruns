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
            button(t("ui.scan"), CAP, "scan").primary(),
        ],
    )
}

impl Autoruns {
    /// The results view: the filter and Refresh (+ Make Report when a report
    /// provider is loaded), then one interactive table of the open category.
    /// Narrows `entries` by the filter in force and caches each shown entry by
    /// its row id so row actions (`about` / `open_location`) resolve it.
    pub(crate) fn render(&mut self, entries: &[Value], report: bool, lang: &str) -> Value {
        let t = |k: &str| catalog().tr(lang, k);
        // Matched against the row as the table shows it, so what is on screen
        // in the user's own language is what a term can name.
        let matches = |d: &Value| -> bool { self.filter.matches(d, &row_cells(d, lang)) };

        self.last.clear();
        // Kept by family, in the order the families are declared, with whatever
        // no family claims last under its own heading.
        let mut shown: Vec<(&'static str, Vec<usize>)> =
            FAMILIES.iter().map(|(k, _)| (*k, Vec::new())).collect();
        shown.push(("family.other", Vec::new()));
        // How many each category holds, whichever one is open.
        let mut counts: Vec<(&'static str, usize)> =
            shown.iter().map(|(k, _)| (*k, 0usize)).collect();
        // Counted first, and over everything: the tab strip says how many each
        // category holds, not how many are in front of you.
        for d in entries.iter().filter(|d| matches(d)) {
            let key = family_of(d).unwrap_or("family.other");
            if let Some((_, n)) = counts.iter_mut().find(|(k, _)| *k == key) {
                *n += 1;
            }
        }
        // Which category is open. One always is: the chosen one while it still
        // has anything in it — a search can empty it — and otherwise the first
        // that does.
        let open = counts
            .iter()
            .find(|(k, n)| *n > 0 && *k == self.family)
            .or_else(|| counts.iter().find(|(_, n)| *n > 0))
            .map(|(k, _)| *k)
            .unwrap_or_default();
        for (i, d) in entries.iter().enumerate() {
            if !matches(d) || family_of(d).unwrap_or("family.other") != open {
                continue;
            }
            if let Some((_, idxs)) = shown.iter_mut().find(|(k, _)| *k == open) {
                idxs.push(i);
            }
        }

        // The page is cut across the category on screen, not within each table:
        // a page that held four hundred of every family would be ten times the
        // size it says it is.
        let in_view: usize = shown.iter().map(|(_, i)| i.len()).sum();
        let page_count = in_view.div_ceil(PAGE_SIZE).max(1);
        let page = self.page.min(page_count - 1);
        let (from, to) = (page * PAGE_SIZE, ((page + 1) * PAGE_SIZE).min(in_view));
        let mut seen = 0usize;
        for (_, idxs) in shown.iter_mut() {
            let start = seen;
            seen += idxs.len();
            // Keep only this family's share of the window [from, to).
            let lo = from.saturating_sub(start).min(idxs.len());
            let hi = to.saturating_sub(start).min(idxs.len());
            *idxs = idxs[lo..hi].to_vec();
        }

        let cols: Vec<String> = COLUMNS.iter().map(|k| t(k)).collect();

        let mut actions = vec![button(t("ui.refresh"), CAP, "scan").primary()];
        // The filter says on its face whether anything is in force, so a
        // narrowed list is never mistaken for a short one.
        let n = self.filter.count();
        let filter_label = if self.filter.is_empty() {
            t("filter.open")
        } else {
            t("filter.open_n").replace("{n}", &n.to_string())
        };
        let filter_btn = button(filter_label, CAP, "filter");
        actions.push(if self.filter.is_empty() { filter_btn } else { filter_btn.primary() });
        if !self.filter.is_empty() {
            actions.push(button(t("filter.clear"), CAP, "filter_clear"));
        }
        if report {
            actions.push(
                button(t("ui.report"), CAP, "report_config").open_in_tab(),
            );
        }

        // One button per category that has anything in it. A category this
        // machine has none of gets no button: a tab that opens on an empty
        // table is a tab that wasted the click.
        //
        // There is no "everything" tab. All of them at once is ten tables and
        // four hundred rows — the view every layout problem came out of, and
        // not one anybody read: the categories are the reason this is grouped
        // at all, and the total is on the line above.
        let mut tabs = Vec::new();
        for (key, n) in &counts {
            if *n == 0 {
                continue;
            }
            let b = button(format!("{} ({n})", t(key)), CAP, "family")
                .args(json!({ "key": key }));
            tabs.push(if *key == open { b.primary() } else { b });
        }

        let mut widgets = vec![
            row(actions),
            label(t("ui.rows_hint")).weak(),
            separator(),
            row(tabs),
        ];

        // How many rows are marked, said once at the top. A count of things
        // worth looking at is the reason to scroll; finding them by eye is not.
        let flagged = entries
            .iter()
            .filter(|d| matches(d) && !row_level(&cell(d, "signature")).is_empty())
            .count();
        if flagged > 0 {
            widgets.push(
                label(t("ui.unsigned_count").replace("{n}", &flagged.to_string())).weak(),
            );
        }

        for (key, idxs) in &shown {
            if idxs.is_empty() {
                // A family this machine has none of gets no heading. An empty
                // "Scheduled tasks" table reads as a failed collector.
                continue;
            }
            // One category at a time; see `open` above.
            if *key != open {
                continue;
            }
            let (mut rows, mut ids, mut menus, mut levels) =
                (Vec::new(), Vec::new(), Vec::new(), Vec::new());
            for &i in idxs {
                let d = &entries[i];
                let rid = i.to_string();
                self.last.insert(rid.clone(), d.clone());
                ids.push(rid);
                rows.push(row_cells(d, lang));
                menus.push(row_menu_for(d, lang)); // per-row: open only when openable
                levels.push(row_level(&cell(d, "signature")).to_string());
            }
            widgets.push(separator());
            widgets.push(
                label(format!("{} · {}", t(key), rows.len())).strong(),
            );
            widgets.push(
                table(cols.clone(), rows)
                    .row_ids(ids)
                    .row_menus(menus)
                    .row_levels(levels)
                    .on_activate(CAP, "about"),
            );
        }

        // A pager, only when there is more than one page — which on an
        // ordinary machine there is not.
        if page_count > 1 {
            widgets.push(separator());
            widgets.push(
                label(
                    t("ui.page")
                        .replace("{page}", &(page + 1).to_string())
                        .replace("{pages}", &page_count.to_string())
                        .replace("{from}", &(from + 1).to_string())
                        .replace("{to}", &to.to_string())
                        .replace("{total}", &in_view.to_string()),
                )
                .weak(),
            );
            let go = |p: usize, text: String, now: bool| {
                let b = button(text, CAP, "page")
                    .args(json!({ "page": p }));
                if now { b.primary() } else { b }
            };
            let mut pager = Vec::new();
            if page > 0 {
                pager.push(go(page - 1, t("ui.prev"), false));
            }
            for p in 0..page_count {
                pager.push(go(p, (p + 1).to_string(), p == page));
            }
            if page + 1 < page_count {
                pager.push(go(page + 1, t("ui.next"), false));
            }
            widgets.push(row(pager));
        }

        window(t("ui.title"), widgets)
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
            field(&t("col.publisher"), signature_label(d, lang)),
            // Where the signature lives, which the table has no room to say and
            // which explains a disagreement worth understanding: Sysinternals
            // Autoruns reports a catalog-signed file as "not verified", because
            // it looks only inside the file. Most of Windows is signed this way
            // — the signature is in a catalog the OS keeps, not in the binary —
            // and it is the catalog that Windows itself trusts the file by.
            field(&t("detail.sig_kind"), sig_kind_label(d, lang)),
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
                button(t(key), CAP, "open_location")
                    .args(json!({ "id": id }))
                    .primary(),
            );
        }
        window(title, widgets)
    }
}
