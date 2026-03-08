# Airlock Bash plugin — User guide

This guide walks you through installing and using the Airlock Bash plugin so that **every command you type** in Bash can require approval on your phone before it runs.

---

## What this plugin does

When the plugin is enabled and you press **Enter** on a command:

1. The command is sent to **Airlock** (via `airlock-cli`).
2. A notification appears on your **Airlock mobile app**.
3. You tap **Approve** or **Deny**.
4. If you approve, the command runs in your terminal. If you deny (or don’t respond in time), it does not run.

So you get a second check before risky commands (e.g. `git push`, `rm -rf`, production deploys) actually execute.

---

## Before you start

You need:

1. **airlock-cli** — Installed and on your `PATH` (or you’ll set `AIRLOCK_CLI` to its path).
2. **Signed in** — Run `airlock-cli sign-in` once and complete the browser login.
3. **Paired** — Run `airlock-cli pair` once and enter the code in the Airlock mobile app.
4. **Bash** — You’re using Bash as your interactive shell.

---

## Step 1: Install airlock-cli

If you haven’t already:

- Download or build `airlock-cli` for your OS (see the main [airlock-cli README](../../airlock-cli/README.md)).
- Put it somewhere in your `PATH`, or in a folder you’ll reference below (e.g. `~/.airlock/bin/`).

Example (if you build from repo):

```bash
mkdir -p ~/.airlock/bin
cp /path/to/airlock-cli ~/.airlock/bin/
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

## Step 3: Install the Bash plugin

1. Copy the plugin file into a stable location, for example:

   ```bash
   mkdir -p ~/.airlock/shell
   cp /path/to/airlock/src/shells/bash/airlock.plugin.bash ~/.airlock/shell/
   ```

   Replace `/path/to/airlock` with the path to your Airlock repo or install.

2. Open your Bash config:

   ```bash
   nano ~/.bashrc
   ```

3. Add these lines at the end (adjust paths if you put the CLI or plugin elsewhere):

   ```bash
   export AIRLOCK_CLI="$HOME/.airlock/bin/airlock-cli"
   export AIRLOCK_ENABLED=1
   export AIRLOCK_FAIL_MODE=open
   source "$HOME/.airlock/shell/airlock.plugin.bash"
   ```

4. Reload your config:

   ```bash
   source ~/.bashrc
   ```

---

## Step 4: Try it

1. Open a **new** Bash window or tab.
2. Type a command, for example: `echo hello`
3. Press **Enter**.

The command will run (no approval message). On your phone, you should see the approval request in the Airlock app.

- If you **deny** in the app, the command will not run and you’ll see “[Airlock] Denied” in the terminal.
- If you don’t approve in time, with default `AIRLOCK_FAIL_MODE=open` the command still runs and you’ll see “Unavailable, continuing”.

---

## Turning the plugin off temporarily

Set `AIRLOCK_ENABLED=0` and reload, or comment out the `source` line in `.bashrc`:

```bash
# export AIRLOCK_ENABLED=0
# source "$HOME/.airlock/shell/airlock.plugin.bash"
```

Then `source ~/.bashrc`. Commands will run without going through Airlock until you re-enable it.

---

## If the CLI is unavailable

The plugin respects **fail mode**:

- **`AIRLOCK_FAIL_MODE=open`** (default) — If the CLI fails or times out, the command **still runs** and you see “Unavailable, continuing”.
- **`AIRLOCK_FAIL_MODE=closed`** — If the CLI fails or times out, the command **does not run** and you see “Unavailable, blocked”.

Set it before sourcing the plugin in `.bashrc`:

```bash
export AIRLOCK_FAIL_MODE=closed
source "$HOME/.airlock/shell/airlock.plugin.bash"
```

---

## Troubleshooting

- **“command not found: airlock-cli”**  
  Install the CLI and either add it to your `PATH` or set `AIRLOCK_CLI` to the full path of the binary before sourcing the plugin.

- **“Not signed in” / “Not paired”**  
  Run `airlock-cli sign-in` and `airlock-cli pair` in a terminal and complete the steps. Then try again.

- **Nothing happens when I press Enter**  
  Make sure you’re in an **interactive** Bash session (not a script) and that you’ve run `source ~/.bashrc` (or opened a new shell) after adding the plugin.

- **Strange behavior with multiline or history**  
  The plugin uses `bind -x` and `READLINE_LINE`; multiline and history expansion can behave differently than in Zsh. For complex use cases, consider using the Zsh plugin if available.

---

## Quick reference

| What you want | What to do |
| -------------- | ---------- |
| Use Airlock on every command | Keep `AIRLOCK_ENABLED=1` and source the plugin in `.bashrc`. |
| Run without approval for a while | Set `AIRLOCK_ENABLED=0` and `source ~/.bashrc`. |
| Block commands when CLI fails | Set `AIRLOCK_FAIL_MODE=closed` before sourcing the plugin. |
| Point to a different CLI | Set `AIRLOCK_CLI=/path/to/airlock-cli` before sourcing the plugin. |

For more details (environment variables, behavior, testing with a fake CLI), see [README.md](README.md).
