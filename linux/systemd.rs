//! Enabled `systemd` units — the services/timers/sockets that start at boot (or
//! at user login for the `--user` manager).
//!
//! Reads `systemctl list-unit-files --state=enabled`, which is one cheap call per
//! manager (system + user). The unit id identifies the program; resolving each
//! unit's `ExecStart` would cost one call per unit, so we keep the unit name.

use limen_sdk_rust::Value;
use std::process::Command;

use crate::entry;

pub(super) fn collect(out: &mut Vec<Value>) {
    // System manager, then the calling user's manager.
    collect_manager(out, false, "system");
    collect_manager(out, true, "user");
}

fn collect_manager(out: &mut Vec<Value>, user: bool, scope: &str) {
    let mut cmd = Command::new("systemctl");
    if user {
        cmd.arg("--user");
    }
    cmd.args([
        "list-unit-files",
        "--state=enabled",
        "--no-legend",
        "--no-pager",
        "--type=service,timer,socket,path",
    ]);

    let Ok(out_bytes) = cmd.output() else {
        return;
    };
    if !out_bytes.status.success() {
        return;
    }
    let text = String::from_utf8_lossy(&out_bytes.stdout);
    let location = if user { "systemd (user)" } else { "systemd (system)" };

    for line in text.lines() {
        // "UNIT-FILE   STATE [PRESET]" — the unit is the first field.
        let Some(unit) = line.split_whitespace().next() else {
            continue;
        };
        if unit.is_empty() {
            continue;
        }
        out.push(entry(
            "systemd",
            unit.to_string(),
            unit.to_string(),
            location.to_string(),
            scope,
            true,
        ));
    }
}
