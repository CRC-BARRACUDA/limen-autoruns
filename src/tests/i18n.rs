//! That every string the code asks for exists, in both languages.

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
    let en = keys(include_str!("../../locales/en.toml"));
    let uk = keys(include_str!("../../locales/uk.toml"));
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
