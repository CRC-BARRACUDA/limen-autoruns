//! The kinds of autostart, and how a row is marked.
//!
//! One long table of everything answers "what starts on this machine" and
//! nothing else; the questions people bring to an autorun list are narrower,
//! so each kind gets a table of its own.

use crate::*;

/// The six visible columns, as catalogue keys — named once, so the table and
/// the report cannot drift apart.
pub(crate) const COLUMNS: [&str; 7] = [
    "col.source",
    "col.name",
    "col.command",
    "col.publisher",
    "col.scope",
    "col.enabled",
    "col.location",
];

/// The kinds of autostart, and which `source` values belong to each.
///
/// One long table of everything answers "what starts on this machine" and
/// nothing else. The questions people actually bring to an autorun list are
/// narrower — *what did somebody put in the registry*, *what is in the Startup
/// folder*, *what is scheduled* — and those are different mechanisms, checked
/// in different places, with different things worth being suspicious about. A
/// table each puts the comparison where it belongs: among its own kind.
///
/// Matched by prefix, because the registry sources carry which key they came
/// from (`registry:run`, `registry:runonce`). Order is the order they are
/// shown: registry first, being both the largest and the most often abused.
pub(crate) const FAMILIES: [(&str, &[&str]); 12] = [
    (
        "family.logon",
        &[
            "registry:",
            "winlogon",
            "windows-load",
            "cmd-autorun",
            "active-setup",
        ],
    ),
    ("family.explorer", &["explorer"]),
    ("family.browser", &["internet-explorer"]),
    ("family.startup", &["startup-folder", "xdg-autostart"]),
    ("family.scheduled", &["scheduled-task", "cron"]),
    ("family.services", &["service", "driver", "systemd"]),
    ("family.boot", &["boot-execute", "known-dll"]),
    ("family.hijack", &["image-hijack", "appinit"]),
    ("family.lsa", &["lsa"]),
    ("family.network", &["winsock", "network-provider"]),
    ("family.print", &["print-monitor", "print-provider"]),
    ("family.office", &["office", "codec"]),
];

/// How many entries go on one page.
///
/// A machine has a few hundred autostart points and can have a few thousand:
/// every one of them on a single page is a page that takes a moment to lay out
/// and a long time to read. Four hundred is enough that an ordinary machine is
/// one page and the pager never appears, and small enough that an unusual one
/// stays quick.
pub(crate) const PAGE_SIZE: usize = 400;

/// Which table an entry belongs in. `None` for a source no family claims —
/// those go last, under their own heading, rather than being dropped: a new
/// collector whose source was never added here would otherwise enumerate
/// perfectly and show nothing.
pub(crate) fn family_of(d: &Value) -> Option<&'static str> {
    let source = cell(d, "source");
    FAMILIES
        .iter()
        .find(|(_, sources)| sources.iter().any(|s| source.starts_with(s)))
        .map(|(key, _)| *key)
}

/// How a row is marked, from what the signature said.
///
/// Red for a program that nothing signed, or whose signature does not hold —
/// the two findings worth looking at. Yellow when the check itself did not
/// answer, which is a different thing: not knowing is not evidence, and
/// colouring it red would be an accusation made out of ignorance.
///
/// Nothing is marked where there is nothing to check — no resolvable file, or a
/// platform without Authenticode — because an unmarked row means "ordinary"
/// and an uncheckable one is not a finding.
pub(crate) fn row_level(signature: &str) -> &'static str {
    match signature {
        signature::UNSIGNED | signature::INVALID => "error",
        // Yellow, the way Sysinternals Autoruns marks the same thing: a file
        // that is not there is not an accusation, it is something to look at.
        signature::UNKNOWN | signature::MISSING => "warning",
        _ => "",
    }
}
