# Airlock Zsh plugin — User guide

This guide walks you through installing and using the Airlock Zsh plugin so that **every command you type** in Zsh can require approval on your phone before it runs.

---

## What this plugin does

When the plugin is enabled and you press **Enter** on a command:

1. The command is sent to **Airlock** (via `airlock-cli`).
2. A notification appears on your **Airlock mobile app**.
3. You tap **Approve** or **Reject**.
4. If you approve, the command runs in your terminal. If you reject (or don’t respond in time), it does not run.

So you get a second check before risky commands (e.g. `git push`, `rm -rf`, production deploys) actually execute.

---

## Before you start

You need:

1. **airlock-cli** — Installed and on your `PATH` (or you’ll set `AIRLOCK_CLI` to its path).
2. **Signed in** — Run `airlock-cli sign-in` once and complete the browser login.
3. **Paired** — Run `airlock-cli pair` once and enter the code in the Airlock mobile app.
4. **Zsh** — You’re using Zsh as your interactive shell (macOS default or Linux install).

---

## Step 1: Install airlock-cli

If you haven’t already:

- Download or build `airlock-cli` for your OS (see the main [airlock-cli README](../../airlock-cli/README.md)).
- Put it somewhere in your `PATH`, or in a folder you’ll reference below (e.g. `~/.airlock/bin/`).

Example (if you build from repo):

```bash
mkdir -p ~/.airlock/bin
cp /path/to/airlock-cli ~/.airlock/bin/
# Optional: add to PATH
export PATH="$HOME/.airlock/bin:$PATH"
```

---

## Step 2: Sign in and pair

In a terminal:

```bash
airlock-cli sign-in
# Complete login in the browser when it opens.

airlock-cli pair
# Enter the code shown in the Airlock mobile app.
```

When both succeed, `airlock-cli status` should show “Signed in: true” and “Paired: true”.

---

## Step 3: Install the Zsh plugin

1. Copy the plugin file into a stable location, for example:

   ```bash
   mkdir -p ~/.airlock/shell
   cp /path/to/airlock/src/shells/zsh/airlock.plugin.zsh ~/.airlock/shell/
   ```

   Replace `/path/to/airlock` with the path to your Airlock repo or install.

2. Open your Zsh config:

   ```bash
   nano ~/.zshrc
   # or use your preferred editor
   ```

3. Add these lines at the end (adjust paths if you put the CLI or plugin elsewhere):

   ```bash
   export AIRLOCK_CLI="$HOME/.airlock/bin/airlock-cli"
   export AIRLOCK_ENABLED=1
   export AIRLOCK_FAIL_MODE=open
   source "$HOME/.airlock/shell/airlock.plugin.zsh"
   ```

4. Reload your config:

   ```bash
   source ~/.zshrc
   ```

---

## Step 4: Try it

1. Open a **new** Zsh window or tab.
2. Type a command, for example: `echo hello`
3. Press **Enter**.

The command will run (no approval message). On your phone, you should see the approval request in the Airlock app.

- If you **reject** in the app, the command will not run and you’ll see “[Airlock] Denied” in the terminal.
- If you don’t approve in time (default timeout is a few minutes), the CLI returns a non‑zero exit; with default `AIRLOCK_FAIL_MODE=open` the command still runs and you’ll see “Unavailable, continuing”.

---

## Turning the plugin off temporarily

Set `AIRLOCK_ENABLED=0` and reload, or comment out the `source` line in `.zshrc`:

```bash
# export AIRLOCK_ENABLED=0
# source "$HOME/.airlock/shell/airlock.plugin.zsh"
```

Then `source ~/.zshrc`. Commands will run without going through Airlock until you re-enable it.

---

## If the CLI is unavailable (e.g. not signed in, network error)

The plugin respects **fail mode**:

- **`AIRLOCK_FAIL_MODE=open`** (default) — If the CLI fails or times out, the command **still runs** and you see “Airlock unavailable, continuing”. Use this so your shell stays usable when Airlock isn’t available.
- **`AIRLOCK_FAIL_MODE=closed`** — If the CLI fails or times out, the command **does not run** and you see “Unavailable, blocked”. Use this when you want to block execution unless approval clearly succeeded.

Set it before sourcing the plugin, for example in `.zshrc`:

```bash
export AIRLOCK_FAIL_MODE=closed
source "$HOME/.airlock/shell/airlock.plugin.zsh"
```

---

## Troubleshooting

- **“command not found: airlock-cli”**  
  Install the CLI and either add it to your `PATH` or set `AIRLOCK_CLI` to the full path of the binary before sourcing the plugin.

- **“Not signed in” / “Not paired”**  
  Run `airlock-cli sign-in` and `airlock-cli pair` in a terminal and complete the steps. Then try again.

- **Nothing happens when I press Enter**  
  Make sure you’re in an **interactive** Zsh session (not a script) and that you’ve run `source ~/.zshrc` (or opened a new shell) after adding the plugin.

- **Plugin breaks my prompt or key bindings**  
  The plugin binds **Enter** and **Ctrl+J**. If another plugin or config also binds these, load order can matter. Try sourcing the Airlock plugin last, or adjust the other binding.

---

## Quick reference

| What you want | What to do |
| -------------- | ---------- |
| Use Airlock on every command | Keep `AIRLOCK_ENABLED=1` and source the plugin in `.zshrc`. |
| Run without approval for a while | Set `AIRLOCK_ENABLED=0` and `source ~/.zshrc`. |
| Block commands when CLI fails | Set `AIRLOCK_FAIL_MODE=closed` before sourcing the plugin. |
| Point to a different CLI | Set `AIRLOCK_CLI=/path/to/airlock-cli` before sourcing the plugin. |

For more details (environment variables, behavior, testing with a fake CLI), see [README.md](README.md).
