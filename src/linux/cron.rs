//! `cron` jobs — scheduled commands from the system crontabs, the drop-in dir,
//! the periodic script dirs, and the calling user's own crontab.
//!
//! - `/etc/crontab` and `/etc/cron.d/*` — system tables, which carry a **user**
//!   field between the schedule and the command.
//! - `/etc/cron.{hourly,daily,weekly,monthly}/*` — scripts run on that cadence.
//! - `crontab -l` — the invoking user's personal crontab (no user field).

use limen_sdk_rust::Value;
use std::path::Path;
use std::process::Command;

use crate::entry;

pub(super) fn collect(out: &mut Vec<Value>) {
    // System tables: schedule + USER + command.
    collect_table(out, Path::new("/etc/crontab"), true, "system");
    if let Ok(rd) = std::fs::read_dir("/etc/cron.d") {
        for f in rd.flatten() {
            let p = f.path();
            if p.is_file() {
                collect_table(out, &p, true, "system");
            }
        }
    }

    // Periodic script dirs — every executable script is an autorun.
    for dir in [
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ] {
        collect_periodic(out, Path::new(dir));
    }

    // The calling user's crontab: schedule + command (no user field).
    collect_user_crontab(out);
}

/// Parse a crontab file (system tables have a user field).
fn collect_table(out: &mut Vec<Value>, path: &Path, has_user: bool, scope: &str) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let location = path.to_string_lossy().to_string();
    for line in text.lines() {
        if let Some(command) = parse_cron_line(line, has_user) {
            out.push(entry(
                "cron",
                prog_name(&command),
                command,
                location.clone(),
                scope,
                true,
            ));
        }
    }
}

/// List the scripts in a periodic dir (`cron.daily`, …) as autorun entries.
fn collect_periodic(out: &mut Vec<Value>, dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let location = dir.to_string_lossy().to_string();
    for f in rd.flatten() {
        let path = f.path();
        if !path.is_file() {
            continue;
        }
        let fname = f.file_name().to_string_lossy().to_string();
        // Skip the run-parts bookkeeping files.
        if fname.starts_with('.') || fname == "README" || fname == ".placeholder" {
            continue;
        }
        out.push(entry(
            "cron",
            fname,
            path.to_string_lossy().to_string(),
            location.clone(),
            "system",
            true,
        ));
    }
}

fn collect_user_crontab(out: &mut Vec<Value>) {
    let Ok(res) = Command::new("crontab").arg("-l").output() else {
        return;
    };
    // No crontab for the user → non-zero exit; nothing to add.
    if !res.status.success() {
        return;
    }
    let text = String::from_utf8_lossy(&res.stdout);
    for line in text.lines() {
        if let Some(command) = parse_cron_line(line, false) {
            out.push(entry(
                "cron",
                prog_name(&command),
                command,
                "crontab (user)".to_string(),
                "user",
                true,
            ));
        }
    }
}

/// Extract the command from a crontab line, or `None` for comments, blanks, and
/// `NAME=value` environment assignments. `has_user` skips the user field that
/// system tables (`/etc/crontab`, `/etc/cron.d`) place before the command.
fn parse_cron_line(line: &str, has_user: bool) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || is_env_assignment(trimmed) {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let first = parts.clone().next()?;
    // `@reboot`/`@daily`/… is a single schedule token; otherwise 5 time fields.
    let skip = if first.starts_with('@') { 1 } else { 5 };
    for _ in 0..skip {
        parts.next()?;
    }
    if has_user {
        parts.next()?; // the user the job runs as
    }
    let command = parts.collect::<Vec<_>>().join(" ");
    if command.is_empty() {
        None
    } else {
        Some(command)
    }
}

/// A leading `NAME=value` (no spaces around `=`) is a crontab env assignment,
/// not a job — e.g. `SHELL=/bin/sh`, `MAILTO=root`, `PATH=/usr/bin`.
fn is_env_assignment(line: &str) -> bool {
    match line.find('=') {
        Some(eq) => {
            let name = &line[..eq];
            !name.is_empty()
                && !name.contains(char::is_whitespace)
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// A short display name: the basename of the command's first token.
fn prog_name(command: &str) -> String {
    let first = command.split_whitespace().next().unwrap_or(command);
    first.rsplit('/').next().unwrap_or(first).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_system_and_user_cron_lines() {
        // system table: schedule + user + command
        assert_eq!(
            parse_cron_line("17 *  * * *  root  cd / && run-parts /etc/cron.hourly", true),
            Some("cd / && run-parts /etc/cron.hourly".to_string())
        );
        // user crontab: schedule + command
        assert_eq!(
            parse_cron_line("*/5 * * * * /usr/bin/backup --now", false),
            Some("/usr/bin/backup --now".to_string())
        );
        // @-schedule
        assert_eq!(
            parse_cron_line("@reboot root /opt/app/start.sh", true),
            Some("/opt/app/start.sh".to_string())
        );
    }

    #[test]
    fn skips_comments_blanks_and_env() {
        assert_eq!(parse_cron_line("# a comment", false), None);
        assert_eq!(parse_cron_line("   ", false), None);
        assert_eq!(parse_cron_line("SHELL=/bin/sh", false), None);
        assert_eq!(parse_cron_line("PATH=/usr/bin:/bin", false), None);
        // a real job with an =flag is not mistaken for an assignment
        assert!(parse_cron_line("* * * * * app --opt=val", false).is_some());
    }

    #[test]
    fn prog_name_is_basename() {
        assert_eq!(prog_name("/usr/bin/backup --now"), "backup");
        assert_eq!(prog_name("run-parts /etc/cron.daily"), "run-parts");
    }
}
