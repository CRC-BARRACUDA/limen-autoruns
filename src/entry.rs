//! One entry: the shared record, and what can be done with one.
//!
//! Every collector emits the same shape — `source`, `name`, `command`,
//! `location`, `scope`, `enabled` — so everything above here works the same
//! way whether the entry came from a registry key, a systemd unit or a
//! scheduled task.

use crate::*;

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

/// A cell value (empty string if the field is missing).
pub(crate) fn cell(d: &Value, key: &str) -> String {
    d.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Whether an entry is enabled (default `true` if unset).
pub(crate) fn is_enabled(d: &Value) -> bool {
    d.get("enabled").and_then(Value::as_bool).unwrap_or(true)
}

/// The six visible columns for an entry row.
pub(crate) fn row_cells(d: &Value, lang: &str) -> Vec<String> {
    vec![
        cell(d, "source"),
        cell(d, "name"),
        cell(d, "command"),
        // In words as well as in colour. Somebody reading in greyscale, or not
        // telling red from grey, gets the whole finding from the column; the
        // colour is only how the eye finds the row in three hundred.
        signature_label(d, lang),
        cell(d, "scope"),
        catalog().tr(lang, if is_enabled(d) { "val.yes" } else { "val.no" }),
        cell(d, "location"),
    ]
}

/// What the publisher column says: who signed the program, and whether that
/// signature holds — `(Verified) Microsoft Corporation`.
///
/// Empty when there was nothing to check: an entry naming no file that
/// resolves, or a platform with no Authenticode. A dash would claim a check
/// happened and found nothing to say.
pub(crate) fn signature_label(d: &Value, lang: &str) -> String {
    let t = |k: &str| catalog().tr(lang, k);
    let status = cell(d, "signature");
    // Nothing was signed because nothing is there: say that instead, since it
    // is the more useful fact and "not verified" would imply a file to verify.
    if status == signature::MISSING {
        return t("sig.missing");
    }
    signature::Signed {
        status,
        signer: cell(d, "signer"),
        kind: cell(d, "sig_kind"),
    }
    .publisher(&t("sig.verified"), &t("sig.not_verified"), &t("sig.not_checked"))
}

/// How to open an entry, decided from its actual `location`:
/// `(the catalogue key its label comes from, host.open target, value)`. `None` when there's nothing
/// to open — a systemd unit is *named*, not a path, and some locations are
/// labels or missing files, so those rows simply get no open action.
pub(crate) fn open_kind(d: &Value) -> Option<(&'static str, &'static str, String)> {
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
pub(crate) fn is_registry_location(loc: &str) -> bool {
    loc.starts_with(r"HKLM\")
        || loc.starts_with(r"HKCU\")
        || loc.starts_with("HKEY_")
        || loc.starts_with(r"Computer\")
}

/// Expand `%VAR%` references, leaving unknown ones untouched so the original
/// text stays visible rather than silently collapsing to nothing.
pub(crate) fn expand_env(s: &str) -> String {
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
pub(crate) fn normalize_image(raw: &str) -> String {
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
pub(crate) fn resolve_program(raw: &str) -> Option<String> {
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
pub(crate) fn target_file(d: &Value) -> Option<String> {
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
pub(crate) fn is_text_file(path: &str) -> bool {
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
pub(crate) fn row_menu_for(d: &Value, lang: &str) -> Vec<MenuItem> {
    let t = |k: &str| catalog().tr(lang, k);
    let mut items = vec![menu_item(t("menu.about"), CAP, "about").open_in_tab()];
    if let Some((key, _, _)) = open_kind(d) {
        items.push(menu_item(t(key), CAP, "open_location"));
    }
    if let Some(path) = target_file(d) {
        items.push(menu_item(t("menu.reveal"), CAP, "reveal_file"));
        if is_text_file(&path) {
            items.push(menu_item(t("menu.edit"), CAP, "edit_file"));
        }
    }
    if is_registry_location(&cell(d, "location")) {
        items.push(menu_item(t("menu.show_value"), CAP, "show_value"));
    }
    items
}

/// Convert an `HKLM\…` / `HKCU\…` key into the form regedit navigates to.
pub(crate) fn to_regedit(loc: &str) -> String {
    if let Some(rest) = loc.strip_prefix(r"HKLM\") {
        format!(r"Computer\HKEY_LOCAL_MACHINE\{rest}")
    } else if let Some(rest) = loc.strip_prefix(r"HKCU\") {
        format!(r"Computer\HKEY_CURRENT_USER\{rest}")
    } else {
        loc.to_string()
    }
}
