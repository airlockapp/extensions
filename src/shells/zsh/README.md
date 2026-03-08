# Airlock Zsh plugin

Opt-in Zsh integration that intercepts **Enter** in an interactive session, calls `airlock-cli approve` with the current command, and only executes the command when the CLI exits with code `0` (approved).

## Requirements

- **Zsh** (interactive session)
- **airlock-cli** — built and on your `PATH`, or set `AIRLOCK_CLI` to its path
- Signed in and paired: run `airlock-cli sign-in` and `airlock-cli pair` before using the plugin

## Installation

### 1. Install airlock-cli

Build or download `airlock-cli` and place it in a directory on your `PATH`, or in `~/.airlock/bin/`:

```bash
mkdir -p ~/.airlock/bin
# Copy or link airlock-cli into ~/.airlock/bin
```

### 2. Install the plugin

Copy the plugin file into your shell config directory:

```bash
mkdir -p ~/.airlock/shell
cp /path/to/airlock/src/shells/zsh/airlock.plugin.zsh ~/.airlock/shell/
```

### 3. Load the plugin in `.zshrc`

Add the following to your `~/.zshrc`:

```bash
export AIRLOCK_CLI="${AIRLOCK_CLI:-$HOME/.airlock/bin/airlock-cli}"
export AIRLOCK_ENABLED=1
export AIRLOCK_FAIL_MODE=open
source "$HOME/.airlock/shell/airlock.plugin.zsh"
```

Then start a new Zsh session or run `source ~/.zshrc`.

## Environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `AIRLOCK_CLI` | `airlock-cli` | Path to the `airlock-cli` binary. |
| `AIRLOCK_ENABLED` | `1` | Set to `0` to disable interception (commands run without approval). |
| `AIRLOCK_FAIL_MODE` | `open` | When the CLI is unavailable or returns an error (e.g. timeout): `open` = allow command; `closed` = block command. |
| `AIRLOCK_SESSION_ID` | (auto) | Session identifier. Set only if you need a fixed value; otherwise generated once per shell. |

## Behavior

- **Enter** / **Ctrl+J** — Current line is sent to `airlock-cli approve` with:
  - `--shell zsh`
  - `--cwd "$PWD"`
  - `--command "$BUFFER"`
  - `--session-id` (stable per session)
  - `--shell-pid "$$"`
  - `--host` (from `$HOST` or `hostname` or `unknown-host`)

- **Exit 0** — Approved: command runs (no message).
- **Exit 1 or 2** — Denied or verification failed: command does **not** run; line is cleared; “[Airlock] Denied” shown.
- **Other exit** — Unavailable/error: if `AIRLOCK_FAIL_MODE=open`, command runs and “Unavailable, continuing” is shown; if `closed`, command is blocked.

Empty lines are not sent to the CLI; they just insert a newline.

## Testing with a fake CLI

Use the provided fake CLI to test the plugin without a real gateway:

```bash
# Approve all commands
export AIRLOCK_CLI="$(pwd)/fake-airlock-cli.zsh"
export FAKE_AIRLOCK_EXIT=0
source airlock.plugin.zsh
# Type a command and press Enter → it runs

# Deny all commands
export FAKE_AIRLOCK_EXIT=1
# Type a command and press Enter → it is blocked
```

Replace `$(pwd)` with the path to the `zsh` folder if needed.

## Limitations

- **Interactive only** — Non-interactive scripts are not intercepted.
- **No alias expansion** — The exact buffer is sent; aliases are not expanded before sending.
- **Multiline** — Multiline commands are sent as-is; behavior may be refined in future versions.
- **Opt-in** — This is a workflow aid, not a hardened security boundary; users can bypass by disabling the plugin or using another shell.

## File layout (recommended)

```text
~/.airlock/
  bin/
    airlock-cli
  shell/
    airlock.plugin.zsh
```

## See also

- [USER_GUIDE.md](USER_GUIDE.md) — Step-by-step user guide.
- [airlock-zsh-interceptor-implementation.md](airlock-zsh-interceptor-implementation.md) — Implementation plan and acceptance criteria.
- Main **airlock-cli** [README](../../airlock-cli/README.md) and [USER_GUIDE](../../airlock-cli/USER_GUIDE.md) for sign-in, pairing, and CLI usage.
