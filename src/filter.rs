//! What the user chose to look at, and whether an entry answers to it.
//!
//! A filter narrows what was already found. It never causes another scan: the
//! entries are in hand from the last one, and re-reading the machine to answer
//! "show me the unsigned ones" would be slow and would quietly change the
//! answer underneath the question.
//!
//! Two halves, and an entry has to satisfy both:
//!
//! - **states** — the signature verdicts to keep. Empty means every verdict.
//! - **terms** — words that must *all* appear somewhere in the row. Empty means
//!   no restriction. Each is matched against the whole row, so a term can name
//!   a source, a publisher, a path or a key without the user saying which.
//!
//! Signature verdicts are a Windows idea. On Linux there is no Authenticode and
//! every entry's state is empty, so a filter that named states would match
//! nothing at all — the caller offers them only when the scan actually produced
//! some (see [`Filter::states_offered`]).

use crate::*;

/// What the user is looking for.
#[derive(Default, Clone, Debug, PartialEq)]
pub(crate) struct Filter {
    /// Signature verdicts to keep — `valid`, `unsigned`, `invalid`, `unknown`,
    /// `missing`, and [`NO_STATE`] for entries with nothing to verify.
    pub states: Vec<String>,
    /// The words, exactly as the window's fields hold them — a blank one is a
    /// field waiting to be typed into, kept so the window can draw it again.
    /// [`Filter::matches`] ignores blanks; [`Filter::count`] does not count
    /// them.
    pub terms: Vec<String>,
}

/// The state of an entry that named no file to check — a systemd unit, an LSA
/// package, a command that is not a path. Its own choice in the filter, because
/// "nothing to verify" is a real group and a large one, and leaving it out of
/// the list would make it unselectable.
pub(crate) const NO_STATE: &str = "none";

/// The verdicts a filter can name, in the order they are offered.
pub(crate) const STATES: [&str; 6] = [
    signature::VALID,
    signature::UNSIGNED,
    signature::INVALID,
    signature::UNKNOWN,
    signature::MISSING,
    NO_STATE,
];

impl Filter {
    /// Whether this filter lets everything through. A field nobody typed into
    /// narrows nothing, so it does not count as a filter.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty() && self.words().next().is_none()
    }

    /// How many choices are in force, for saying so on the button.
    pub fn count(&self) -> usize {
        self.states.len() + self.words().count()
    }

    /// The terms that actually say something.
    fn words(&self) -> impl Iterator<Item = &String> {
        self.terms.iter().filter(|t| !t.trim().is_empty())
    }

    /// Whether `entry` answers to this filter.
    ///
    /// `row` is the entry as the table shows it — every cell, already in the
    /// user's language — so a term matches what is on screen rather than the
    /// raw field underneath it. Somebody who reads "Не перевірено" in a column
    /// and types it should find that row.
    pub fn matches(&self, entry: &Value, row: &[String]) -> bool {
        if !self.states.is_empty() {
            let state = match cell(entry, "signature") {
                s if s.is_empty() => NO_STATE.to_string(),
                s => s,
            };
            if !self.states.contains(&state) {
                return false;
            }
        }
        let haystack = row.join(" ").to_lowercase();
        // Every term, not any: each field the user adds narrows what is left,
        // which is what a filter of several parts is for. One that widened
        // would need only one field and a space.
        self.words()
            .all(|t| haystack.contains(&t.trim().to_lowercase()))
    }

    /// Which verdicts are worth offering, given what the scan actually found.
    ///
    /// Only those present. On Linux that is none of them — there is no
    /// Authenticode, so every entry's state is empty — and a list of choices
    /// that match nothing is worse than no list: it invites a filter that hides
    /// everything and gives no clue why.
    pub fn states_offered(entries: &[Value]) -> Vec<&'static str> {
        STATES
            .iter()
            .copied()
            .filter(|s| {
                entries.iter().any(|d| {
                    let have = cell(d, "signature");
                    if *s == NO_STATE { have.is_empty() } else { have == *s }
                })
            })
            .collect()
    }
}


/// The filter window: which verdicts to keep, and the words to look for.
///
/// A pop-up rather than a row of controls on the tab. There are as many text
/// fields as the user has asked for, and the ones they have not filled in yet
/// still have to be somewhere.
pub(crate) fn filter_modal(lang: &str, f: &Filter, offered: &[&'static str]) -> Value {
    let t = |k: &str| catalog().tr(lang, k);
    let mut w: Vec<limen_sdk_rust::ui::Widget> = Vec::new();

    // Verdicts, when the scan produced any. On Linux it produces none — there
    // is no Authenticode — and a list of choices matching nothing is worse than
    // no list at all.
    if !offered.is_empty() {
        w.push(label(t("filter.states")).strong());
        w.push(label(t("filter.states_hint")).weak());
        for s in offered {
            let c = checkbox(format!("state_{s}"), t(&format!("filter.state.{s}")));
            w.push(if f.states.iter().any(|x| x == s) { c.checked() } else { c });
        }
        w.push(separator());
    }

    // The words. One field per term the window holds, and never fewer than
    // one — a filter with nowhere to type is a filter that cannot be started.
    w.push(label(t("filter.terms")).strong());
    w.push(label(t("filter.terms_hint")).weak());
    let mut terms: Vec<String> = f.terms.clone();
    if terms.is_empty() {
        terms.push(String::new());
    }
    let lone = terms.len() == 1;
    for (i, term) in terms.iter().enumerate() {
        w.push(row(vec![
            // Tells the module as it is typed, so the Add button below can
            // know whether this field has anything in it yet.
            text(format!("term_{i}"))
                .placeholder(t("filter.term_ph"))
                .default(term.clone())
                .on_change(CAP, "filter_touch"),
            // Nothing to remove when there is one field: taking it away would
            // leave the window with nowhere to type.
            button(t("filter.remove"), CAP, "filter_remove")
                .args(json!({ "i": i }))
                .enabled(!lone),
        ]));
    }
    // Nothing to add while the last field is blank: that field *is* the next
    // word. The fields report what is typed into them, so this switches itself
    // back on as soon as one has something in it.
    let blank = terms.last().map(|x| x.trim().is_empty()).unwrap_or(true);
    w.push(
        button(t("filter.add"), CAP, "filter_add")
            .enabled(!blank && terms.len() < MAX_TERMS),
    );
    w.push(separator());
    w.push(row(vec![
        button(t("filter.apply"), CAP, "filter_apply").primary(),
        button(t("filter.clear"), CAP, "filter_clear"),
        button(t("filter.close"), CAP, "filter").dismiss(),
    ]));

    window_modal_sized(t("filter.title"), "autoruns.filter", 560.0, w)
}

/// Read a filter back off the window's inputs.
///
/// The checkbox ids carry the verdict, and the text ids their position, so what
/// comes back is whatever the user last had on screen — including a field they
/// typed into but never pressed Add on, which would otherwise be silently
/// thrown away.
pub(crate) fn from_inputs(params: &Value, offered: &[&'static str]) -> Filter {
    let on = |id: &str| {
        params
            .get(id)
            .map(|v| v.as_bool().unwrap_or_else(|| v.as_str() == Some("true")))
            .unwrap_or(false)
    };
    let states = offered
        .iter()
        .filter(|s| on(&format!("state_{s}")))
        .map(|s| s.to_string())
        .collect();
    let mut terms = Vec::new();
    for i in 0..MAX_TERMS {
        let Some(v) = params.get(format!("term_{i}")).and_then(Value::as_str) else {
            continue;
        };
        // Blanks are kept: a field the user has not typed into yet is still a
        // field, and dropping it here would make it vanish from the window the
        // moment anything else was pressed.
        terms.push(v.trim().to_string());
    }
    Filter { states, terms }
}

/// How many text fields the window will ever show.
///
/// A bound rather than a feature: the ids are read back by position, so
/// something has to say where to stop. Nobody filters on twenty words, and if
/// they did, one more would not be what was missing.
pub(crate) const MAX_TERMS: usize = 20;

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_with(state: &str) -> Value {
        let mut d = entry(
            "registry:run",
            "Thing".into(),
            r"C:\Windows\thing.exe".into(),
            r"HKLM\Run".into(),
            "system",
            true,
        );
        if !state.is_empty() {
            d.as_object_mut()
                .unwrap()
                .insert("signature".into(), Value::String(state.into()));
        }
        d
    }

    /// Nothing chosen lets everything through, which is what an unopened
    /// filter must do.
    #[test]
    fn an_empty_filter_keeps_everything() {
        let f = Filter::default();
        assert!(f.is_empty());
        for state in ["", signature::VALID, signature::UNSIGNED] {
            let d = entry_with(state);
            assert!(f.matches(&d, &["anything".into()]));
        }
    }

    /// A chosen verdict keeps that verdict and no other.
    #[test]
    fn a_chosen_state_keeps_only_that_state() {
        let f = Filter {
            states: vec![signature::UNSIGNED.into()],
            terms: vec![],
        };
        assert!(f.matches(&entry_with(signature::UNSIGNED), &[]));
        assert!(!f.matches(&entry_with(signature::VALID), &[]));
        assert!(!f.matches(&entry_with(""), &[]));
    }

    /// An entry with nothing to verify is its own group, and selectable.
    ///
    /// It is also the *only* group on Linux, where there is no Authenticode —
    /// so if it were not offered, no state filter there could match anything.
    #[test]
    fn having_nothing_to_verify_is_a_state_of_its_own() {
        let f = Filter {
            states: vec![NO_STATE.into()],
            terms: vec![],
        };
        assert!(f.matches(&entry_with(""), &[]));
        assert!(!f.matches(&entry_with(signature::VALID), &[]));
    }

    /// Several verdicts at once: any of the chosen ones.
    #[test]
    fn several_states_are_any_of_them() {
        let f = Filter {
            states: vec![signature::UNSIGNED.into(), signature::MISSING.into()],
            terms: vec![],
        };
        assert!(f.matches(&entry_with(signature::UNSIGNED), &[]));
        assert!(f.matches(&entry_with(signature::MISSING), &[]));
        assert!(!f.matches(&entry_with(signature::VALID), &[]));
    }

    /// Every term must appear: each field the user adds narrows what is left.
    #[test]
    fn every_term_has_to_appear() {
        let row = vec![
            "registry:run".to_string(),
            "Thing".to_string(),
            r"C:\Windows\thing.exe".to_string(),
        ];
        let f = |terms: &[&str]| Filter {
            states: vec![],
            terms: terms.iter().map(|s| s.to_string()).collect(),
        };
        let d = entry_with("");
        assert!(f(&["thing"]).matches(&d, &row));
        assert!(f(&["thing", "registry"]).matches(&d, &row));
        // One that is not there fails the whole filter.
        assert!(!f(&["thing", "chrome"]).matches(&d, &row));
    }

    /// Terms are matched without regard to case, and a stray space is not a
    /// term nobody can satisfy.
    #[test]
    fn a_term_is_matched_loosely_enough_to_be_usable() {
        let row = vec!["Microsoft Windows".to_string()];
        let d = entry_with("");
        for term in ["microsoft", "MICROSOFT", "  Microsoft  "] {
            let f = Filter {
                states: vec![],
                terms: vec![term.into()],
            };
            assert!(f.matches(&d, &row), "{term:?}");
        }
    }

    /// A term is matched against the row as shown, so what is on screen in the
    /// user's own language is what they can type.
    #[test]
    fn a_term_matches_what_the_table_shows() {
        let d = entry_with(signature::UNSIGNED);
        let shown = vec!["(Не перевірено)".to_string()];
        let f = Filter {
            states: vec![],
            terms: vec!["перевірено".into()],
        };
        assert!(f.matches(&d, &shown));
    }

    /// Only verdicts the scan produced are offered.
    ///
    /// On Linux that is none: there is no Authenticode, every state is empty,
    /// and a list of choices matching nothing invites a filter that hides
    /// everything for no visible reason.
    #[test]
    fn only_the_verdicts_that_exist_are_offered() {
        let windows = [
            entry_with(signature::VALID),
            entry_with(signature::UNSIGNED),
            entry_with(""),
        ];
        let offered = Filter::states_offered(&windows);
        assert!(offered.contains(&signature::VALID));
        assert!(offered.contains(&signature::UNSIGNED));
        assert!(offered.contains(&NO_STATE));
        assert!(!offered.contains(&signature::MISSING), "{offered:?}");

        // A Linux scan: nothing is verified, so only "nothing to verify" is
        // offered — and never a verdict that could not occur there.
        let linux = [entry_with(""), entry_with("")];
        assert_eq!(Filter::states_offered(&linux), vec![NO_STATE]);
    }

    /// The count is what the button says, so it has to mean something.
    #[test]
    fn the_count_is_what_is_in_force() {
        assert_eq!(Filter::default().count(), 0);
        let f = Filter {
            states: vec![signature::UNSIGNED.into()],
            terms: vec!["chrome".into(), "update".into()],
        };
        assert_eq!(f.count(), 3);
        assert!(!f.is_empty());
    }
}
