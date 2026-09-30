//! One table per kind of autostart, and the mark that says a program is not
//! signed.

use super::*;

/// Every string a person actually reads on a view: labels, button text,
/// headings, column names and cells — not ids, action names or arguments.
fn shown_text(v: &Value) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(o) => {
                for (k, val) in o {
                    match k.as_str() {
                        "text" | "label" | "title" | "placeholder" => {
                            if let Some(s) = val.as_str() {
                                out.push(s.to_string());
                            }
                        }
                        // What a click sends back, not what it says.
                        "args" | "action" | "id" => {}
                        _ => walk(val, out),
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            Value::String(s) => out.push(s.clone()),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

/// An entry of a given source, optionally carrying a signature verdict.
fn of(source: &str, name: &str, signature: &str) -> Value {
    let mut d = entry(
        source,
        name.to_string(),
        r"C:\Windows\System32\thing.exe".to_string(),
        format!(r"HKLM\{name}"),
        "system",
        true,
    );
    if !signature.is_empty() {
        d.as_object_mut()
            .unwrap()
            .insert("signature".into(), Value::String(signature.into()));
    }
    d
}

/// Every source a collector emits lands in a family. A source nobody claimed
/// would still be shown, but a collector this module ships should not have to
/// rely on that safety net.
#[test]
fn every_source_the_collectors_emit_has_a_family() {
    let sources = [
        "registry:run",
        "registry:runonce",
        "winlogon",
        "windows-load",
        "cmd-autorun",
        "active-setup",
        "image-hijack",
        "service",
        "driver",
        "scheduled-task",
        "startup-folder",
        "systemd",
        "cron",
        "xdg-autostart",
    ];
    for s in sources {
        assert!(
            family_of(&of(s, "x", "")).is_some(),
            "{s} belongs to no table"
        );
    }
}

/// A source no family claims is still shown. A new collector whose source was
/// never added to `FAMILIES` would otherwise enumerate perfectly and display
/// nothing, which looks like a broken collector rather than a missing line
/// here.
#[test]
fn an_unclaimed_source_is_not_dropped() {
    assert_eq!(family_of(&of("something-new", "x", "")), None);
    let entries = vec![of("something-new", "newthing", "")];
    let v = scanned(entries.clone())
        .render(&entries, false, "en")
        .to_string();
    assert!(v.contains("newthing"), "{v}");
    assert!(v.contains("Other"), "it needs a heading of its own: {v}");
}

/// Red for what is not signed, or signed and failing; yellow for a check that
/// did not answer. The distinction is the point: not knowing is not evidence,
/// and a row coloured as unsigned on the strength of a failed check is an
/// accusation made out of ignorance.
#[test]
fn a_row_is_marked_by_what_its_signature_said() {
    assert_eq!(row_level(signature::UNSIGNED), "error");
    assert_eq!(row_level(signature::INVALID), "error");
    assert_eq!(row_level(signature::UNKNOWN), "warning");
    assert_eq!(row_level(signature::VALID), "");
    // Nothing to check is not a finding.
    assert_eq!(row_level(""), "");
}

/// The marks reach the table, in step with the rows they mark.
#[test]
fn the_marks_travel_with_their_rows() {
    let entries = vec![
        of("registry:run", "signed-one", signature::VALID),
        of("registry:run", "unsigned-one", signature::UNSIGNED),
        of("registry:run", "unchecked-one", signature::UNKNOWN),
    ];
    let v = scanned(entries.clone()).render(&entries, false, "en");
    let t = v["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["kind"] == "table")
        .expect("a table");
    let levels: Vec<&str> = t["row_levels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    assert_eq!(levels, ["", "error", "warning"]);
    assert_eq!(
        t["rows"].as_array().unwrap().len(),
        levels.len(),
        "a mark per row"
    );
}

/// Colour is how the eye finds the row; the Publisher column is the finding. A
/// reader in greyscale, or one who does not tell red from grey, must lose
/// nothing.
#[test]
fn the_publisher_says_who_signed_it_and_whether_that_holds() {
    for (word, expected) in [
        (signature::VALID, "(Verified)"),
        (signature::UNSIGNED, "(Not verified)"),
        (signature::INVALID, "(Not verified)"),
        // Its own words, not the red row's: a check that never answered is not
        // a signature that failed, and a yellow row reading "(Not verified)"
        // cannot be told from a red one.
        (signature::UNKNOWN, "(Not checked)"),
    ] {
        let cells = row_cells(&of("registry:run", "x", word), "en");
        assert_eq!(cells[3], expected, "{word}");
    }
    // Nothing checked, nothing claimed: an empty cell, not a dash that implies
    // a check happened and had nothing to say.
    assert_eq!(row_cells(&of("registry:run", "x", ""), "en")[3], "");
}

/// Who signed it goes beside whether it holds. Either half alone misleads: a
/// name on its own reads as an assurance, and plenty of malware is signed —
/// sometimes with a certificate that no longer verifies.
#[test]
fn a_signed_program_names_its_publisher() {
    let mut d = of("registry:run", "x", signature::VALID);
    d.as_object_mut()
        .unwrap()
        .insert("signer".into(), Value::String("Microsoft Corporation".into()));
    assert_eq!(row_cells(&d, "en")[3], "(Verified) Microsoft Corporation");

    // Signed by somebody, and the signature does not hold: both facts, since
    // the name is the clue and the mark is the warning.
    let mut bad = of("registry:run", "x", signature::INVALID);
    bad.as_object_mut()
        .unwrap()
        .insert("signer".into(), Value::String("Igor Pavlov".into()));
    assert_eq!(row_cells(&bad, "en")[3], "(Not verified) Igor Pavlov");

    // Nothing signed it, so there is no name to give — just the mark.
    assert_eq!(
        row_cells(&of("registry:run", "x", signature::UNSIGNED), "en")[3],
        "(Not verified)"
    );
}

/// Both languages, for everything this added. A screen half in English is worse
/// than one not translated at all, because nobody notices.
#[test]
fn the_new_words_are_in_both_languages() {
    let entries = vec![of("registry:run", "x", signature::UNSIGNED)];
    for lang in ["en", "uk"] {
        let v = scanned(entries.clone()).render(&entries, false, lang);
        // Only what is *shown*. A catalogue key legitimately appears in a
        // button's `args` — that is the identifier the click sends back, not
        // text anybody reads — so checking the whole document would fail on
        // correct code.
        for text in shown_text(&v) {
            for key in [
                "family.logon",
                "sig.not_verified",
                "col.publisher",
                "ui.unsigned_count",
            ] {
                assert!(!text.contains(key), "{lang}: bare key {key} on screen");
            }
        }
    }
    for key in [
        "family.logon",
        "family.startup",
        "sig.not_verified",
        "col.publisher",
    ] {
        assert_ne!(
            catalog().tr("en", key),
            catalog().tr("uk", key),
            "{key} is the same in both languages"
        );
    }
}

/// One category on screen at a time, with a button for each that has anything
/// in it. Four hundred rows in ten tables is a page to scroll through, not one
/// to read — which is why Autoruns gives each category a tab.
#[test]
fn only_the_chosen_category_is_on_screen() {
    let entries = vec![
        of("registry:run", "reg-one", ""),
        of("service", "svc-one", ""),
        of("scheduled-task", "task-one", ""),
    ];
    let mut a = scanned(entries.clone());
    a.family = "family.services".into();
    let v = a.render(&entries, false, "en");
    let s = v.to_string();

    // One table, and it is the one asked for.
    let tables = v["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["kind"] == "table")
        .count();
    assert_eq!(tables, 1, "{s}");
    assert!(s.contains("svc-one"), "{s}");
    assert!(!s.contains("reg-one"), "{s}");
    assert!(!s.contains("task-one"), "{s}");

    // Every category still has a button, counted, whichever one is open.
    assert!(s.contains("Logon (1)"), "{s}");
    assert!(s.contains("Services and drivers (1)"), "{s}");
    assert!(s.contains("Scheduled (1)"), "{s}");
    // No "everything" button: the categories are the whole of the strip.
    assert!(!s.contains("Everything"), "{s}");
}

/// A category this machine has none of gets no button: a tab that opens on an
/// empty table is a tab that wasted the click.
#[test]
fn a_category_with_nothing_in_it_gets_no_button() {
    let entries = vec![of("registry:run", "only-one", "")];
    let s = scanned(entries.clone())
        .render(&entries, false, "en")
        .to_string();
    assert!(s.contains("Logon (1)"), "{s}");
    for absent in ["Explorer (", "Scheduled (", "Services and drivers ("] {
        assert!(!s.contains(absent), "{absent} should not be offered: {s}");
    }
}

/// Many entries are split into pages, and only one page is drawn.
#[test]
fn a_long_list_is_cut_into_pages() {
    let entries: Vec<Value> = (0..PAGE_SIZE + 25)
        .map(|i| of("registry:run", &format!("entry-{i}"), ""))
        .collect();
    let mut a = scanned(entries.clone());
    a.family = "family.logon".into();
    let v = a.render(&entries, false, "en");
    let rows: usize = v["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["kind"] == "table")
        .map(|w| w["rows"].as_array().unwrap().len())
        .sum();
    assert_eq!(rows, PAGE_SIZE, "a page is {PAGE_SIZE} entries");

    let s = v.to_string();
    assert!(s.contains("Page 1 of 2"), "{s}");
    assert!(s.contains("entry-0"), "the first page starts at the start");
    assert!(!s.contains("entry-400"), "and stops at the page's end");
}

/// The second page holds the remainder, and starts where the first left off.
#[test]
fn the_last_page_holds_what_is_left() {
    let entries: Vec<Value> = (0..PAGE_SIZE + 25)
        .map(|i| of("registry:run", &format!("entry-{i}"), ""))
        .collect();
    let mut a = scanned(entries.clone());
    a.family = "family.logon".into();
    a.page = 1;
    let v = a.render(&entries, false, "en");
    let rows: usize = v["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["kind"] == "table")
        .map(|w| w["rows"].as_array().unwrap().len())
        .sum();
    assert_eq!(rows, 25);
    let s = v.to_string();
    assert!(s.contains("entry-400"), "{s}");
    assert!(!s.contains("\"entry-0\""), "the first page is not repeated");
}

/// A machine with an ordinary number of autoruns sees no pager at all.
#[test]
fn one_page_of_entries_shows_no_pager() {
    let entries: Vec<Value> = (0..40)
        .map(|i| of("registry:run", &format!("entry-{i}"), ""))
        .collect();
    let s = scanned(entries.clone())
        .render(&entries, false, "en")
        .to_string();
    assert!(!s.contains("Page 1 of"), "{s}");
}

/// A page past the end is not a blank screen: it settles on the last one.
#[test]
fn a_page_past_the_end_shows_the_last_one() {
    let entries: Vec<Value> = (0..PAGE_SIZE + 10)
        .map(|i| of("registry:run", &format!("entry-{i}"), ""))
        .collect();
    let mut a = scanned(entries.clone());
    a.family = "family.logon".into();
    a.page = 99;
    let v = a.render(&entries, false, "en");
    let rows: usize = v["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["kind"] == "table")
        .map(|w| w["rows"].as_array().unwrap().len())
        .sum();
    assert_eq!(rows, 10, "the last page, not an empty one");
    assert!(v.to_string().contains("Page 2 of 2"));
}

/// The tab strip counts what each category holds, not what is on this page.
#[test]
fn the_tabs_count_the_whole_category_not_the_page() {
    let entries: Vec<Value> = (0..PAGE_SIZE + 25)
        .map(|i| of("registry:run", &format!("entry-{i}"), ""))
        .collect();
    let mut a = scanned(entries.clone());
    a.family = "family.logon".into();
    let s = a.render(&entries, false, "en").to_string();
    assert!(s.contains(&format!("Logon ({})", PAGE_SIZE + 25)), "{s}");
}

/// A command that names no file on disk is called out as missing, and marked
/// yellow — the way Sysinternals Autoruns marks the same thing.
///
/// Usually leftovers. Worth seeing anyway: an autostart pointing at a path that
/// does not exist *yet* is somewhere an attacker can put a file of their own
/// and have it loaded on every boot.
#[test]
fn an_entry_naming_a_file_that_is_not_there_says_so() {
    assert_eq!(row_level(signature::MISSING), "warning");
    let mut d = of("registry:run", "gone", "");
    d.as_object_mut()
        .unwrap()
        .insert("signature".into(), Value::String(signature::MISSING.into()));
    assert_eq!(row_cells(&d, "en")[3], "File not found");
    // Not phrased as a signature result: there is no file to have verified.
    assert!(!row_cells(&d, "en")[3].contains("verified"));
}

/// Only a command that actually names a file is judged on whether it exists.
///
/// An autorun's command is often not a path at all: `BootExecute` holds
/// `autocheck autochk *`, a systemd unit is a unit name, an LSA package is a
/// bare module the loader resolves its own way. Calling those "file not found"
/// would be a confident false alarm on entries working exactly as intended.
#[test]
fn only_something_that_looks_like_a_file_is_judged_on_existing() {
    for names in [
        r"C:\Windows\System32\thing.exe",
        r"C:\Program Files\App\app.exe --silent",
        "thing.dll",
        "/usr/bin/thing",
        r#""C:\Program Files\A B\x.exe" -q"#,
    ] {
        assert!(names_a_file(names), "{names:?} names a file");
    }
    for does_not in [
        "autocheck autochk *",
        "msv1_0",
        "scecli",
        "thing.service",
        // An Active Setup StubPath that is only a switch: a forward slash
        // starts an argument on Windows, it does not open a path.
        "/UserInstall",
        "/q",
        "U",
        "",
        "   ",
    ] {
        assert!(!does_not.is_empty() || !names_a_file(does_not));
        assert!(!names_a_file(does_not), "{does_not:?} does not name a file");
    }
}

/// The three states are told apart, and only two of them are a warning.
#[test]
fn the_states_a_row_can_be_in_are_distinct() {
    let states = [
        (signature::VALID, ""),
        (signature::UNSIGNED, "error"),
        (signature::INVALID, "error"),
        (signature::UNKNOWN, "warning"),
        (signature::MISSING, "warning"),
        ("", ""),
    ];
    for (state, level) in states {
        assert_eq!(row_level(state), level, "{state}");
    }
    // And each says something different in the column.
    let label = |s: &str| {
        let mut d = of("registry:run", "x", "");
        if !s.is_empty() {
            d.as_object_mut()
                .unwrap()
                .insert("signature".into(), Value::String(s.into()));
        }
        row_cells(&d, "en")[3].clone()
    };
    assert_ne!(label(signature::MISSING), label(signature::UNSIGNED));
    assert_ne!(label(signature::MISSING), label(signature::VALID));
    assert_ne!(label(signature::MISSING), label(""));
}

/// Where a signature lives is recorded, because it explains a disagreement.
///
/// Sysinternals Autoruns reports Defender's `shellext.dll` as "(Not Verified)
/// Microsoft Corporation"; Windows reports it `Valid`, signed by "Microsoft
/// Windows", with the signature in a **catalog** rather than in the file.
/// Autoruns looks only inside the file. Most of Windows is catalog-signed, and
/// the catalog is what the OS trusts those files by — so calling them
/// unverified would cry wolf on the whole operating system.
#[test]
fn a_catalog_signature_is_still_a_signature_and_says_where_it_lives() {
    let mut d = of("explorer", "EPP", signature::VALID);
    {
        let o = d.as_object_mut().unwrap();
        o.insert("signer".into(), Value::String("Microsoft Windows".into()));
        o.insert("sig_kind".into(), Value::String("catalog".into()));
    }
    // Verified, not "not verified" — the table agrees with Windows.
    assert_eq!(row_cells(&d, "en")[3], "(Verified) Microsoft Windows");
    // And the details say where the signature actually is.
    assert_eq!(sig_kind_label(&d, "en"), "In a Windows catalogue, not in the file");

    let mut embedded = of("explorer", "Other", signature::VALID);
    embedded
        .as_object_mut()
        .unwrap()
        .insert("sig_kind".into(), Value::String("embedded".into()));
    assert_eq!(sig_kind_label(&embedded, "en"), "In the file itself");

    // Nothing verified, nothing to locate.
    assert_eq!(sig_kind_label(&of("explorer", "x", ""), "en"), "");
}

/// One category on screen, with a counted button for each that has anything.
///
/// There is no "everything" tab: all of them at once is ten tables and four
/// hundred rows, which is the view every layout problem came out of and not one
/// anybody read.
#[test]
fn one_category_is_shown_and_every_category_has_a_button() {
    let entries = vec![
        of("registry:run", "reg-one", ""),
        of("registry:runonce", "reg-two", ""),
        of("startup-folder", "folder-one", ""),
        of("scheduled-task", "task-one", ""),
    ];
    let v = scanned(entries.clone()).render(&entries, false, "en");
    let s = v.to_string();

    let tables = v["widgets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["kind"] == "table")
        .count();
    assert_eq!(tables, 1, "{s}");
    assert!(s.contains("Logon"), "{s}");
    assert!(s.contains("reg-one") && s.contains("reg-two"), "{s}");
    assert!(!s.contains("folder-one"), "another category leaked in: {s}");

    for (label, n) in [("Logon", 2), ("Startup folders", 1), ("Scheduled", 1)] {
        assert!(s.contains(&format!("{label} ({n})")), "{label}: {s}");
    }
    let at = |needle: &str| s.find(needle).unwrap_or_else(|| panic!("{needle} missing"));
    assert!(at("Logon (2)") < at("Startup folders (1)"));
    assert!(at("Startup folders (1)") < at("Scheduled (1)"));
    assert!(!s.contains("Services and drivers ("), "{s}");
}

/// How many rows are worth looking at, said once at the top of the category.
#[test]
fn the_count_of_what_is_worth_looking_at_is_said_once() {
    let entries = vec![
        of("registry:run", "a", signature::VALID),
        of("registry:run", "b", signature::UNSIGNED),
    ];
    let s = scanned(entries.clone())
        .render(&entries, false, "en")
        .to_string();
    assert!(s.contains("1 of them run a program"), "{s}");

    let clean = vec![of("registry:run", "a", signature::VALID)];
    let s = scanned(clean.clone())
        .render(&clean, false, "en")
        .to_string();
    assert!(!s.contains("of them run a program"), "{s}");
}

/// A filter that empties the open category opens one that still has something,
/// rather than showing an empty table under a heading.
#[test]
fn a_filter_that_empties_a_category_opens_one_that_is_not_empty() {
    let entries = vec![
        of("registry:run", "dropme", ""),
        of("startup-folder", "keepme", ""),
    ];
    let mut a = scanned(entries.clone());
    a.family = "family.logon".into();
    a.filter = filter::Filter {
        states: vec![],
        terms: vec!["keepme".into()],
    };
    let s = a.render(&entries, false, "en").to_string();
    assert!(s.contains("keepme"), "{s}");
    assert!(!s.contains("dropme"), "{s}");
    assert!(s.contains("Startup folders"), "{s}");
    assert!(!s.contains("Logon ("), "an emptied category keeps no button: {s}");
}

/// The filter is the module's own state, so changing category keeps it —
/// the old search box had to be carried along by hand, and silently widened
/// the list back out when it was not.
#[test]
fn the_filter_survives_a_change_of_category() {
    let entries = vec![
        of("registry:run", "keepme-reg", ""),
        of("registry:run", "other-reg", ""),
        of("service", "keepme-svc", ""),
        of("service", "other-svc", ""),
    ];
    let mut a = scanned(entries.clone());
    a.filter = filter::Filter {
        states: vec![],
        terms: vec!["keepme".into()],
    };
    a.family = "family.logon".into();
    let s = a.render(&entries, false, "en").to_string();
    assert!(s.contains("keepme-reg") && !s.contains("other-reg"), "{s}");

    a.family = "family.services".into();
    let s = a.render(&entries, false, "en").to_string();
    assert!(s.contains("keepme-svc"), "{s}");
    assert!(!s.contains("other-svc"), "the filter was dropped: {s}");
    // And the counts follow the filter, not the whole scan.
    assert!(s.contains("Services and drivers (1)"), "{s}");
}

/// The button says whether anything is in force, so a narrowed list is never
/// mistaken for a short one.
#[test]
fn the_filter_button_says_when_it_is_doing_something() {
    let entries = vec![of("registry:run", "a", "")];
    let plain = scanned(entries.clone()).render(&entries, false, "en").to_string();
    assert!(plain.contains(r#""text":"Filter""#), "{plain}");
    assert!(!plain.contains("Clear filter"), "nothing to clear: {plain}");

    let mut a = scanned(entries.clone());
    a.filter = filter::Filter {
        states: vec![signature::UNSIGNED.into()],
        terms: vec!["x".into()],
    };
    let on = a.render(&entries, false, "en").to_string();
    assert!(on.contains("Filter (2)"), "{on}");
    assert!(on.contains("Clear filter"), "{on}");
}

/// The report is of what the user is looking at: everything with no filter,
/// and what the filter left with one.
#[test]
fn the_report_covers_exactly_what_the_filter_left() {
    let entries = vec![
        of("registry:run", "keepme", ""),
        of("registry:run", "dropme", ""),
        of("service", "also-dropped", ""),
    ];
    let all = scanned(entries.clone()).report_spec("view", "", "", "en");
    let s = all.to_string();
    assert!(s.contains("keepme") && s.contains("dropme"), "{s}");

    let mut a = scanned(entries.clone());
    a.filter = filter::Filter {
        states: vec![],
        terms: vec!["keepme".into()],
    };
    let one = a.report_spec("view", "", "", "en");
    let s = one.to_string();
    assert!(s.contains("keepme"), "{s}");
    assert!(!s.contains("dropme"), "the report widened back out: {s}");
    assert!(!s.contains("also-dropped"), "{s}");
}

/// On Linux the filter still works, and offers nothing it cannot honour.
///
/// There is no Authenticode there, so every entry's verdict is empty. A window
/// offering "Not signed" on a Linux scan invites a filter that hides everything
/// and gives no clue why — so the verdicts are offered only when the scan
/// produced some, and the words always are.
#[test]
fn on_a_machine_without_signatures_the_filter_is_words_only() {
    let entries = vec![
        of("systemd", "thing.service", ""),
        of("cron", "backup", ""),
        of("xdg-autostart", "panel", ""),
    ];
    let offered = filter::Filter::states_offered(&entries);
    assert_eq!(offered, vec![filter::NO_STATE], "{offered:?}");

    let v = filter::filter_modal("en", &filter::Filter::default(), &offered);
    let s = v.to_string();
    // No verdict a Linux scan can never produce.
    for absent in ["Not signed", "Signature does not hold", "File not found"] {
        assert!(!s.contains(absent), "{absent} offered on Linux: {s}");
    }
    // The words are always there, and so is somewhere to type one.
    assert!(s.contains("Words"), "{s}");
    assert!(s.contains(r#""id":"term_0""#), "{s}");

    // And filtering by a word works on entries with no verdict at all.
    let mut a = scanned(entries.clone());
    a.filter = filter::Filter {
        states: vec![],
        terms: vec!["backup".into()],
    };
    let s = a.render(&entries, false, "en").to_string();
    assert!(s.contains("backup"), "{s}");
    assert!(!s.contains("thing.service"), "{s}");
}

/// What the window puts on screen comes back off it.
#[test]
fn the_window_reads_back_what_it_wrote() {
    let entries = vec![of("registry:run", "a", signature::UNSIGNED)];
    let offered = filter::Filter::states_offered(&entries);

    // A verdict ticked and two words typed.
    let params = json!({
        "state_unsigned": true,
        "term_0": "chrome",
        "term_1": "  update  ",
        "term_2": "",
    });
    let f = filter::from_inputs(&params, &offered);
    assert_eq!(f.states, vec![signature::UNSIGNED]);
    // Trimmed, and the blank field is kept: it is a field the user has not
    // typed into yet, and dropping it here would make it vanish from the
    // window the moment anything else was pressed. It is not *counted*, and it
    // narrows nothing.
    assert_eq!(f.terms, vec!["chrome", "update", ""]);
    assert_eq!(f.count(), 3, "one verdict and two words");

    // Nothing ticked and nothing typed is no filter.
    assert!(filter::from_inputs(&json!({}), &offered).is_empty());
}

/// The window shows the filter that is in force, so opening it does not lose
/// what was already chosen.
#[test]
fn the_window_opens_on_what_is_already_chosen() {
    let entries = vec![of("registry:run", "a", signature::UNSIGNED)];
    let offered = filter::Filter::states_offered(&entries);
    let f = filter::Filter {
        states: vec![signature::UNSIGNED.into()],
        terms: vec!["chrome".into()],
    };
    let v = filter::filter_modal("en", &f, &offered);
    let s = v.to_string();
    assert_eq!(v["modal"], json!("autoruns.filter"));
    assert!(s.contains(r#""default":true"#), "the verdict is ticked: {s}");
    assert!(s.contains("chrome"), "the word is in its field: {s}");
    // One word, one field: the window draws what it holds and no more.
    assert!(!s.contains(r#""id":"term_1""#), "{s}");
}
/// Which buttons a filter window offers, by label, with whether each is on.
fn buttons(v: &Value) -> Vec<(String, bool)> {
    fn walk(v: &Value, out: &mut Vec<(String, bool)>) {
        match v {
            Value::Object(o) => {
                if o.get("kind").and_then(Value::as_str) == Some("button") {
                    out.push((
                        o["text"].as_str().unwrap_or_default().to_string(),
                        o.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                    ));
                }
                for (_, x) in o {
                    walk(x, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut out);
    out
}

/// A lone field cannot be removed: taking it away would leave the window with
/// nowhere to type.
#[test]
fn the_only_field_keeps_its_remove_button_switched_off() {
    let offered: Vec<&'static str> = vec![];

    // Nothing typed yet: one field, and its Remove is off.
    let v = filter::filter_modal("en", &filter::Filter::default(), &offered);
    assert_eq!(v.to_string().matches(r#""kind":"text""#).count(), 1);
    let removes: Vec<bool> = buttons(&v)
        .into_iter()
        .filter(|(l, _)| l == "Remove")
        .map(|(_, on)| on)
        .collect();
    assert_eq!(removes, vec![false], "the lone field could be removed");

    // Two fields: both can go.
    let two = filter::Filter {
        states: vec![],
        terms: vec!["chrome".into(), String::new()],
    };
    let v = filter::filter_modal("en", &two, &offered);
    let removes: Vec<bool> = buttons(&v)
        .into_iter()
        .filter(|(l, _)| l == "Remove")
        .map(|(_, on)| on)
        .collect();
    assert_eq!(removes, vec![true, true]);
}

/// Add is off while the last field is blank, and on once it says something.
///
/// The fields report what is typed into them, so the button switches itself
/// back on without anything else being pressed — which is what makes disabling
/// it usable rather than a trap.
#[test]
fn add_is_off_until_the_last_field_says_something() {
    let offered: Vec<&'static str> = vec![];
    let add_on = |f: &filter::Filter| {
        buttons(&filter::filter_modal("en", f, &offered))
            .into_iter()
            .find(|(l, _)| l == "Add another word")
            .expect("an Add button")
            .1
    };

    // A fresh window: nothing typed, nothing to add.
    assert!(!add_on(&filter::Filter::default()));

    // A word in the only field: Add comes on.
    assert!(add_on(&filter::Filter {
        states: vec![],
        terms: vec!["chrome".into()],
    }));

    // A blank field waiting at the end: off again.
    assert!(!add_on(&filter::Filter {
        states: vec![],
        terms: vec!["chrome".into(), String::new()],
    }));

    // And it never offers more fields than the window will read back.
    let full = filter::Filter {
        states: vec![],
        terms: (0..filter::MAX_TERMS).map(|i| format!("w{i}")).collect(),
    };
    assert!(!add_on(&full), "it offered a field past the last one read");
}

/// The fields tell the module as they are typed — without that the Add button
/// could not know whether the last one is empty, and disabling it would be a
/// trap with no way out.
#[test]
fn the_fields_report_what_is_typed_into_them() {
    let v = filter::filter_modal("en", &filter::Filter::default(), &[]);
    let s = v.to_string();
    assert!(s.contains(r#""method":"filter_touch""#), "{s}");
}

/// Add does nothing while the last field is blank — that field *is* the next
/// word, and another beside it would only be a second empty box.
///
/// It stays pressable rather than being greyed out. A text field has no
/// `on_change`, so the module does not learn what is in the box until a button
/// is pressed: an Add disabled because the box was empty when the window was
/// drawn could never be pressed to un-disable itself.
#[test]
fn add_does_nothing_until_the_last_field_says_something() {
    let entries = vec![of("registry:run", "a", "")];
    let mut a = scanned(entries.clone());

    // Pressed with an empty box: still one field.
    a.add_term(&json!({ "term_0": "" }));
    assert_eq!(a.filter.terms, vec![""], "an empty box added another");

    // Pressed with a word in it: a new blank field follows.
    a.add_term(&json!({ "term_0": "chrome" }));
    assert_eq!(a.filter.terms, vec!["chrome", ""]);

    // And again with the new one still blank: nothing more.
    a.add_term(&json!({ "term_0": "chrome", "term_1": "" }));
    assert_eq!(a.filter.terms, vec!["chrome", ""]);
}

/// A blank field narrows nothing, so it is not a filter.
#[test]
fn a_blank_field_is_not_a_filter() {
    let f = filter::Filter {
        states: vec![],
        terms: vec![String::new(), "   ".into()],
    };
    assert!(f.is_empty(), "blank fields counted as a filter");
    assert_eq!(f.count(), 0);
    let d = of("registry:run", "anything", "");
    assert!(f.matches(&d, &row_cells(&d, "en")), "blanks matched nothing");
}
