//! Turning a raw enumeration into entries worth showing.
//!
//! The collectors say what is registered; this says what each entry's
//! program turned out to be — who signed it, or that it is not there.

use crate::*;

/// Add what signed each entry's program, in one pass over the whole scan.
///
/// Done here rather than in the collectors: they enumerate different mechanisms
/// and would each end up asking the same question, and the point of one pass is
/// that the same executable — named by a dozen services — is checked once.
///
/// An entry whose command resolves to no file on disk gets no `signature` at
/// all, which the view leaves unmarked. That is not an oversight: a scheduled
/// task naming a program that has been uninstalled has nothing to verify, and
/// saying "unsigned" about a file that is not there would be wrong.
pub(crate) fn add_signatures(entries: &mut [Value]) {
    let paths: Vec<String> = entries.iter().filter_map(target_file).collect();
    if paths.is_empty() {
        return;
    }
    let verdicts = signature::verify(&paths);
    for d in entries.iter_mut() {
        let Some(path) = target_file(d) else {
            // Nothing on disk answers to this. Reported only when the command
            // actually names a file — see [`names_a_file`] — because plenty of
            // entries name something else entirely and "file not found" would
            // be a lie about every one of them.
            if names_a_file(&cell(d, "command")) {
                if let Some(o) = d.as_object_mut() {
                    o.insert("signature".into(), Value::String(signature::MISSING.into()));
                }
            }
            continue;
        };
        let Some(signed) = verdicts.get(&path) else {
            continue;
        };
        if let Some(o) = d.as_object_mut() {
            o.insert("signature".into(), Value::String(signed.status.clone()));
            o.insert("signer".into(), Value::String(signed.signer.clone()));
            o.insert("sig_kind".into(), Value::String(signed.kind.clone()));
        }
    }
}

/// Where a verified file's signature lives — inside it, or in a catalog.
///
/// Empty when nothing was verified, since there is then no signature to locate.
pub(crate) fn sig_kind_label(d: &Value, lang: &str) -> String {
    let t = |k: &str| catalog().tr(lang, k);
    match cell(d, "sig_kind").as_str() {
        "catalog" => t("detail.catalog"),
        "embedded" => t("detail.embedded"),
        _ => String::new(),
    }
}

/// Whether a command names a file at all, as opposed to something else.
///
/// An autorun's command is not always a path. `BootExecute` holds
/// `autocheck autochk *`, a systemd unit is a unit name, an LSA package is a
/// bare module name the loader resolves its own way, and an Active Setup
/// `StubPath` is sometimes only arguments. Calling any of those "file not
/// found" would be a confident false alarm on entries that are working exactly
/// as intended — so only something with a path separator or an executable
/// extension is judged on whether it exists.
pub(crate) fn names_a_file(command: &str) -> bool {
    let c = command.trim().trim_matches('"').to_ascii_lowercase();
    if c.is_empty() {
        return false;
    }
    const EXT: [&str; 8] = [".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".bat", ".cmd"];
    let head = c.split_whitespace().next().unwrap_or_default();
    // A backslash is a path on Windows. A forward slash is not: it starts an
    // argument — an Active Setup `StubPath` of `/UserInstall` is a switch and
    // nothing else, and reading it as a path reported a missing file for an
    // entry that names none. A Unix path is recognised by having more than one
    // separator, which `/UserInstall` does not.
    head.contains('\\')
        || (head.starts_with('/') && head.matches('/').count() > 1)
        || EXT.iter().any(|e| head.ends_with(e))
}
