//! Linux autorun enumeration: `systemd` (enabled units), `cron`, and XDG
//! desktop autostart.
//!
//! Each source has its own submodule with a `collect(&mut Vec<Value>)` fn; this
//! module fans out to them and wraps the result in the summary envelope.

use limen_sdk_rust::{json, Value};

mod cron;
mod systemd;
mod xdg;

pub fn list_autoruns() -> Value {
    let mut entries: Vec<Value> = Vec::new();
    systemd::collect(&mut entries);
    xdg::collect(&mut entries);
    cron::collect(&mut entries);

    let enabled = entries
        .iter()
        .filter(|e| e.get("enabled").and_then(Value::as_bool).unwrap_or(true))
        .count();

    json!({
        "os": "linux",
        "note": "Programs that auto-start on this machine: enabled systemd units \
                 (system + user), cron jobs (/etc/crontab, /etc/cron.d, the periodic \
                 dirs, and the user crontab), and XDG desktop autostart entries.",
        "total": entries.len(),
        "enabled": enabled,
        "disabled": entries.len() - enabled,
        "entries": entries,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn envelope_shape_is_consistent() {
        let v = super::list_autoruns();
        assert_eq!(v.get("os").and_then(|o| o.as_str()), Some("linux"));
        let entries = v.get("entries").and_then(|e| e.as_array()).expect("entries[]");
        let total = v.get("total").and_then(|t| t.as_u64()).unwrap();
        assert_eq!(total, entries.len() as u64);

        // Every entry carries the full shared schema.
        for e in entries {
            for key in ["source", "name", "command", "location", "scope"] {
                assert!(e.get(key).and_then(|x| x.as_str()).is_some(), "missing {key}");
            }
            assert!(e.get("enabled").and_then(|x| x.as_bool()).is_some());
        }
    }
}
