//! The rest of the Auto-Start Extensibility Points, the ones Sysinternals
//! Autoruns gives a tab each.
//!
//! [`crate::windows`] covers the places a program is named outright — a `Run`
//! key, a service, a scheduled task. These are the places a **library** is
//! named, and they are where persistence actually hides: a shell extension
//! loads into Explorer on every logon and never appears in a list of programs,
//! an LSA package loads into the process that checks passwords, and a codec
//! loads into anything that plays media.
//!
//! Almost all of them are one of four shapes, so they are written as tables
//! rather than as twenty near-identical functions:
//!
//! | shape | what is under the key | example |
//! |---|---|---|
//! | [`Shape::NamedClsid`]  | subkeys whose default value is a CLSID | context-menu handlers |
//! | [`Shape::KeyIsClsid`]  | subkeys *named* by a CLSID              | browser helper objects |
//! | [`Shape::ValueList`]   | one value listing DLLs or commands      | `AppInit_DLLs`, `BootExecute` |
//! | [`Shape::SubkeyValue`] | subkeys each naming their own library   | print monitors |
//!
//! A CLSID is resolved to the file it loads and the name its author gave it, so
//! a row says `7-Zip Shell Extension … 7-zip.dll` rather than a bare
//! `{23170F69-40C1-278A-1000-000100020000}`.

use limen_sdk_rust::Value;
use winreg::enums::{HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use winreg::types::FromRegValue;
use winreg::{RegKey, HKEY};

use crate::entry;

/// How the entries under one key are laid out.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Shape {
    /// Subkeys named for the handler, each whose default value is a CLSID.
    NamedClsid,
    /// Subkeys whose *name* is the CLSID.
    KeyIsClsid,
    /// A single named value listing one or more libraries or commands.
    ValueList(&'static str),
    /// Every value in the key is an entry of its own — `KnownDLLs` has a value
    /// per library and `Drivers32` a value per codec, with no list anywhere.
    AllValues,
    /// Subkeys that each carry a named value pointing at their library.
    SubkeyValue(&'static str),
}

/// One place worth looking, and what is in it.
pub(crate) struct Asep {
    /// The `source` every entry from here carries — also what decides which
    /// table it appears under (see `FAMILIES` in `lib.rs`).
    pub source: &'static str,
    pub shape: Shape,
    /// Where it lives. `None` for a hive means look in both HKLM and HKCU.
    pub hive: Option<HKEY>,
    pub path: &'static str,
}

/// Everything checked beyond the program-naming points in [`crate::windows`].
///
/// The 32-bit views (`WOW6432Node`) are listed separately rather than derived:
/// a handler registered only there is a real finding, and deriving the path
/// would silently skip the ones whose 64-bit twin does not exist.
pub(crate) const ASEPS: &[Asep] = &[
    // ---- Explorer: the shell loads these into itself on every logon -------- //
    named("explorer", r"Software\Classes\*\ShellEx\ContextMenuHandlers"),
    named("explorer", r"Software\Classes\*\ShellEx\PropertySheetHandlers"),
    named("explorer", r"Software\Classes\AllFilesystemObjects\ShellEx\ContextMenuHandlers"),
    named("explorer", r"Software\Classes\Directory\ShellEx\ContextMenuHandlers"),
    named("explorer", r"Software\Classes\Directory\ShellEx\DragDropHandlers"),
    named("explorer", r"Software\Classes\Directory\Background\ShellEx\ContextMenuHandlers"),
    named("explorer", r"Software\Classes\Folder\ShellEx\ContextMenuHandlers"),
    named("explorer", r"Software\Classes\Folder\ShellEx\DragDropHandlers"),
    named("explorer", r"Software\Classes\Drive\ShellEx\ContextMenuHandlers"),
    named("explorer", r"Software\Classes\Drive\ShellEx\DragDropHandlers"),
    named(
        "explorer",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers",
    ),
    clsid_keys(
        "explorer",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects",
    ),
    clsid_keys(
        "explorer",
        r"Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
    ),
    clsid_keys(
        "explorer",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
    ),
    // ---- Internet Explorer ------------------------------------------------ //
    clsid_keys(
        "internet-explorer",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    ),
    clsid_keys(
        "internet-explorer",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
    ),
    clsid_keys("internet-explorer", r"Software\Microsoft\Internet Explorer\Toolbar"),
    clsid_keys("internet-explorer", r"Software\Microsoft\Internet Explorer\Explorer Bars"),
    // ---- Codecs: loaded by anything that plays media ---------------------- //
    clsid_keys(
        "codec",
        r"Software\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance",
    ),
    clsid_keys(
        "codec",
        r"Software\Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance",
    ),
    Asep {
        source: "codec",
        shape: Shape::AllValues,
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"Software\Microsoft\Windows NT\CurrentVersion\Drivers32",
    },
    // ---- Boot and session start ------------------------------------------- //
    boot("boot-execute", "BootExecute"),
    boot("boot-execute", "SetupExecute"),
    boot("boot-execute", "Execute"),
    boot("boot-execute", "S0InitialCommand"),
    Asep {
        source: "known-dll",
        shape: Shape::AllValues,
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"System\CurrentControlSet\Control\Session Manager\KnownDLLs",
    },
    // ---- Loaded into every GUI process ------------------------------------ //
    Asep {
        source: "appinit",
        shape: Shape::ValueList("AppInit_DLLs"),
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
    },
    Asep {
        source: "appinit",
        shape: Shape::ValueList("AppInit_DLLs"),
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    },
    // ---- LSA: loaded into the process that checks passwords ---------------- //
    lsa("Authentication Packages"),
    lsa("Notification Packages"),
    lsa("Security Packages"),
    Asep {
        source: "lsa",
        shape: Shape::ValueList("SecurityProviders"),
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"System\CurrentControlSet\Control\SecurityProviders",
    },
    // ---- Printing and networking ------------------------------------------ //
    Asep {
        source: "print-monitor",
        shape: Shape::SubkeyValue("Driver"),
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"System\CurrentControlSet\Control\Print\Monitors",
    },
    Asep {
        source: "print-provider",
        shape: Shape::SubkeyValue("Driver"),
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"System\CurrentControlSet\Control\Print\Providers",
    },
    Asep {
        source: "network-provider",
        shape: Shape::ValueList("ProviderOrder"),
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"System\CurrentControlSet\Control\NetworkProvider\Order",
    },
    Asep {
        source: "winsock",
        shape: Shape::SubkeyValue("LibraryPath"),
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries",
    },
    // ---- Office add-ins ---------------------------------------------------- //
    office(r"Software\Microsoft\Office\Excel\Addins"),
    office(r"Software\Microsoft\Office\Word\Addins"),
    office(r"Software\Microsoft\Office\Outlook\Addins"),
    office(r"Software\Microsoft\Office\PowerPoint\Addins"),
    office(r"Software\Microsoft\Office\Access\Addins"),
];

/// Subkeys named for the handler, each whose default value is a CLSID — both
/// hives, since a user can register one for themselves alone.
const fn named(source: &'static str, path: &'static str) -> Asep {
    Asep { source, shape: Shape::NamedClsid, hive: None, path }
}

/// Subkeys whose name is the CLSID.
const fn clsid_keys(source: &'static str, path: &'static str) -> Asep {
    Asep { source, shape: Shape::KeyIsClsid, hive: None, path }
}

/// One of Session Manager's command lists.
const fn boot(source: &'static str, value: &'static str) -> Asep {
    Asep {
        source,
        shape: Shape::ValueList(value),
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"System\CurrentControlSet\Control\Session Manager",
    }
}

/// One of the LSA package lists.
const fn lsa(value: &'static str) -> Asep {
    Asep {
        source: "lsa",
        shape: Shape::ValueList(value),
        hive: Some(HKEY_LOCAL_MACHINE),
        path: r"System\CurrentControlSet\Control\Lsa",
    }
}

/// One Office application's add-ins, by its key path. Registered per-user as
/// often as not, so both hives are looked at.
const fn office(path: &'static str) -> Asep {
    Asep { source: "office", shape: Shape::NamedClsid, hive: None, path }
}

/// Walk every place in [`ASEPS`] and add what is registered there.
pub(crate) fn collect(out: &mut Vec<Value>) {
    for a in ASEPS {
        let hives: &[(HKEY, &str)] = match a.hive {
            Some(h) if h == HKEY_LOCAL_MACHINE => &[(HKEY_LOCAL_MACHINE, "system")],
            Some(_) => &[(HKEY_CURRENT_USER, "user")],
            None => &[(HKEY_LOCAL_MACHINE, "system"), (HKEY_CURRENT_USER, "user")],
        };
        for (hive, scope) in hives {
            one(out, a, *hive, scope);
        }
    }
}

fn one(out: &mut Vec<Value>, a: &Asep, hive: HKEY, scope: &str) {
    let Ok(key) = RegKey::predef(hive).open_subkey(a.path) else {
        return;
    };
    let where_ = format!("{}\\{}", crate::windows::hive_name(hive), a.path);
    match a.shape {
        Shape::NamedClsid => {
            for name in key.enum_keys().flatten() {
                let Ok(sub) = key.open_subkey(&name) else {
                    continue;
                };
                // The default value: the CLSID this handler is.
                let clsid: String = sub.get_value("").unwrap_or_default();
                let (path, about) = clsid_target(&clsid);
                // An add-in names itself in `FriendlyName`; a shell handler
                // does not, and its key name is the best label there is.
                let friendly: String = sub.get_value("FriendlyName").unwrap_or_default();
                let label = first_nonempty(&[&friendly, &about, &name]);
                out.push(entry(
                    a.source,
                    label,
                    if path.is_empty() { clsid } else { path },
                    format!("{where_}\\{name}"),
                    scope,
                    true,
                ));
            }
        }
        Shape::KeyIsClsid => {
            for name in key.enum_keys().flatten() {
                let (path, about) = clsid_target(&name);
                // A subkey's own default value sometimes names it, which is
                // friendlier than the CLSID and than nothing.
                let own: String = key
                    .open_subkey(&name)
                    .ok()
                    .and_then(|s| s.get_value("").ok())
                    .unwrap_or_default();
                let label = first_nonempty(&[&own, &about, &name]);
                out.push(entry(
                    a.source,
                    label,
                    if path.is_empty() { name.clone() } else { path },
                    format!("{where_}\\{name}"),
                    scope,
                    true,
                ));
            }
        }
        Shape::ValueList(value) => {
            let Ok(raw) = key.get_raw_value(value) else {
                return;
            };
            for item in reg_strings(&raw) {
                out.push(entry(
                    a.source,
                    value.to_string(),
                    item,
                    where_.clone(),
                    scope,
                    true,
                ));
            }
        }
        Shape::AllValues => {
            for (name, raw) in key.enum_values().flatten() {
                // A value's *name* here is the thing being provided — the DLL
                // alias in `KnownDLLs`, the format in `Drivers32` — and its
                // data is the library that provides it.
                for item in reg_strings(&raw) {
                    out.push(entry(
                        a.source,
                        name.clone(),
                        item,
                        where_.clone(),
                        scope,
                        true,
                    ));
                }
            }
        }
        Shape::SubkeyValue(value) => {
            for name in key.enum_keys().flatten() {
                let Ok(sub) = key.open_subkey(&name) else {
                    continue;
                };
                let lib: String = sub.get_value(value).unwrap_or_default();
                if lib.trim().is_empty() {
                    continue;
                }
                out.push(entry(
                    a.source,
                    name.clone(),
                    lib,
                    format!("{where_}\\{name}"),
                    scope,
                    true,
                ));
            }
        }
    }
}

/// A `ValueList` value as the strings it holds.
///
/// `REG_MULTI_SZ` is a list already; `REG_SZ` and `REG_EXPAND_SZ` hold one
/// entry, except `AppInit_DLLs`, which is a single string of several paths
/// separated by spaces or commas — and is the one an attacker reaches for, so
/// it must not be read as a single nonexistent file.
fn reg_strings(raw: &winreg::RegValue) -> Vec<String> {
    use winreg::enums::RegType;
    let items: Vec<String> = match raw.vtype {
        RegType::REG_MULTI_SZ => Vec::<String>::from_reg_value(raw).unwrap_or_default(),
        _ => {
            let one = String::from_reg_value(raw).unwrap_or_default();
            one.split([',', ' ', ';']).map(str::to_string).collect()
        }
    };
    // Trimmed and emptied out in one place, for both shapes: a REG_MULTI_SZ is
    // terminated by an empty string, which would otherwise become a row naming
    // nothing.
    items
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// What a CLSID loads, and what its author called it: `(path, description)`.
///
/// Looked up in both registry views, because a 32-bit handler registered under
/// `WOW6432Node` is invisible from the 64-bit one — and a CLSID that resolves
/// nowhere is left to the caller to show as itself, which is the honest thing:
/// a registered handler whose library is gone is worth seeing.
fn clsid_target(clsid: &str) -> (String, String) {
    if !clsid.starts_with('{') {
        return (String::new(), String::new());
    }
    for base in ["CLSID", r"WOW6432Node\CLSID"] {
        let Ok(k) = RegKey::predef(HKEY_CLASSES_ROOT).open_subkey(format!("{base}\\{clsid}"))
        else {
            continue;
        };
        let about: String = k.get_value("").unwrap_or_default();
        // In-process first: a shell extension is a DLL. `LocalServer32` is the
        // out-of-process form, rarer but the same question.
        for server in ["InprocServer32", "LocalServer32"] {
            if let Ok(s) = k.open_subkey(server) {
                let path: String = s.get_value("").unwrap_or_default();
                if !path.trim().is_empty() {
                    return (path, about);
                }
            }
        }
        if !about.is_empty() {
            return (String::new(), about);
        }
    }
    (String::new(), String::new())
}

/// The first of these that has anything in it.
fn first_nonempty(options: &[&str]) -> String {
    options
        .iter()
        .map(|s| s.trim())
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every place listed is a real registry path, spelled the way the API
    /// takes it: no leading or trailing slash, and no hive prefix — the hive is
    /// a field of its own.
    #[test]
    fn every_place_is_spelled_as_a_subkey_path() {
        for a in ASEPS {
            assert!(!a.path.is_empty(), "{} has no path", a.source);
            assert!(!a.path.starts_with('\\'), "{}: {}", a.source, a.path);
            assert!(!a.path.ends_with('\\'), "{}: {}", a.source, a.path);
            for prefix in ["HKLM", "HKCU", "HKEY_"] {
                assert!(
                    !a.path.starts_with(prefix),
                    "{}: the hive is a field, not part of the path: {}",
                    a.source,
                    a.path
                );
            }
        }
    }

    /// The same thing must not be read twice: it would report every entry in it
    /// twice, and a duplicated row in a persistence list is a row somebody
    /// wastes time on.
    ///
    /// A *key* may well appear more than once — Session Manager holds four
    /// separate command lists and the LSA key three package lists — so what
    /// must be unique is the key together with the value being read from it.
    #[test]
    fn nothing_is_read_twice() {
        let what = |a: &Asep| match a.shape {
            Shape::ValueList(v) => format!("{}::{v}", a.path),
            Shape::SubkeyValue(v) => format!("{}::*::{v}", a.path),
            Shape::AllValues => format!("{}::*", a.path),
            Shape::NamedClsid | Shape::KeyIsClsid => a.path.to_string(),
        };
        let mut seen: Vec<String> = Vec::new();
        for a in ASEPS {
            let k = what(a);
            assert!(!seen.contains(&k), "{k} is read twice");
            seen.push(k);
        }
    }

    /// A list value is split into the things it names. `AppInit_DLLs` is one
    /// string of several paths, and reading it as a single file would miss the
    /// one an attacker added.
    #[test]
    fn a_list_value_is_read_as_a_list() {
        use winreg::enums::RegType;
        let raw = winreg::RegValue {
            vtype: RegType::REG_SZ,
            bytes: "a.dll, b.dll c.dll"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .chain([0, 0])
                .collect(),
        };
        assert_eq!(reg_strings(&raw), ["a.dll", "b.dll", "c.dll"]);
    }

    /// Anything that is not a CLSID resolves to nothing rather than being
    /// looked up as one.
    #[test]
    fn only_a_clsid_is_treated_as_one() {
        assert_eq!(clsid_target("not a clsid"), (String::new(), String::new()));
        assert_eq!(clsid_target(""), (String::new(), String::new()));
    }

    /// A row is labelled with the best name available, in that order.
    #[test]
    fn the_friendliest_available_name_is_used() {
        assert_eq!(first_nonempty(&["Friendly", "About", "{CLSID}"]), "Friendly");
        assert_eq!(first_nonempty(&["", "About", "{CLSID}"]), "About");
        assert_eq!(first_nonempty(&["", "  ", "{CLSID}"]), "{CLSID}");
        assert_eq!(first_nonempty(&["", ""]), "");
    }
}
