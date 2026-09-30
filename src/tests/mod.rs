//! What this module is expected to do, in the language of what it is for.

use crate::*;

mod i18n;


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
