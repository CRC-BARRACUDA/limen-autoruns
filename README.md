# autoruns

A native [Limen](https://github.com/CRC-BARRACUDA/Limen) module that lists the
programs configured to **start automatically** on this machine — the Sysinternals
*Autoruns* idea, cross-platform.

Provides the capability **`autoruns.local`**.

## What it does

Enumerates every autostart location the OS exposes and presents them in one
searchable, refreshable table. Each entry has a **source**, the **command** that
runs, **where** it's declared, its **scope** (system vs user), and whether it's
**enabled**.

### Sources

| OS | Source | What |
|---|---|---|
| **Linux** | `systemd` | Enabled unit files (system + `--user`): services, timers, sockets, paths |
| | `cron` | `/etc/crontab`, `/etc/cron.d/*`, the `cron.{hourly,daily,weekly,monthly}` scripts, and the user's `crontab -l` |
| | `xdg-autostart` | `.desktop` files in `/etc/xdg/autostart` and `~/.config/autostart` (login apps); `Hidden=true` → `enabled = false` |
| **Windows** | `registry:Run` / `registry:RunOnce` | HKLM + HKCU `…\CurrentVersion\Run`/`RunOnce`, including the 32-bit `WOW6432Node` view |
| | `startup-folder` | Per-user (`%APPDATA%`) and all-users (`%ProgramData%`) Start Menu → Startup |

## Methods

| Method | Returns |
|---|---|
| `list` | JSON: `{os, total, enabled, disabled, entries[]}` — each entry has `source`, `name`, `command`, `location`, `scope`, `enabled`. For other modules; always scans |
| `ui`   | The landing view — a **Scan** button. Nothing is enumerated until pressed |
| `scan` | Runs the scan and returns the results view (search + Refresh + table) |

## Permissions

```toml
[permissions]
subprocess = true          # Linux: spawns `systemctl` (enabled units) and `crontab -l`
may_require_admin = true   # some hosts need admin for complete enumeration (heads-up only)
```

Reading the Windows registry Run keys and the autostart/cron files is plain
filesystem access; only the Linux `systemctl`/`crontab` queries spawn a process.

## Install

```bash
limen-cli add CRC-BARRACUDA/limen-autoruns@0.1.0
```

Limen clones the source, reads `limen.toml`, sees `language = "native"`, and
downloads the prebuilt library for your platform from the release assets (saved
locally as `libautoruns.so`). No build step on install.

## Build from source

It's a `cdylib` built against `limen-sdk-rust`:

```bash
cargo build --release        # → target/release/libautoruns.so
```

## Releasing (for maintainers)

Limen's package manager picks the release asset whose name **ends with** the
platform extension (`.so` / `.dll` / `.dylib`) **and contains** the arch token
(`x86_64` / `aarch64`). Name assets accordingly:

| Platform | Asset name |
|---|---|
| Linux x64 | `autoruns-linux-x86_64.so` |
| Windows x64 | `autoruns-windows-x86_64.dll` |

Tag the release with the module version so `add …@<version>` resolves it:

```bash
cargo build --release
cp target/release/libautoruns.so autoruns-linux-x86_64.so
strip autoruns-linux-x86_64.so

gh release create 0.1.0 \
  --repo CRC-BARRACUDA/limen-autoruns \
  --title "autoruns 0.1.0" \
  autoruns-linux-x86_64.so
```

## Scope / non-goals

v0.1 covers the high-signal, user-facing autostart locations. Not (yet) included:
Windows scheduled tasks and services, Linux `rc.local`/`init.d`, and shell login
scripts (`~/.bashrc`, `/etc/profile`). These may be added as further sources.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
