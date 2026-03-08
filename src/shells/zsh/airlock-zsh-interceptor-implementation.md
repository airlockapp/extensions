# Airlock Zsh Interceptor — AI-Friendly Implementation Plan

## Purpose

Implement an opt-in `zsh` interceptor that captures an interactive command before execution, calls `airlock-cli approve`, and only lets the command proceed when the CLI exits with code `0`.

Use this document as an implementation guide for an AI coding agent. The target is a practical, maintainable, user-installable shell integration for macOS and Linux.

## CLI Contract

The shell integration must call the CLI exactly in this shape:

```bash
airlock-cli approve \
  --shell zsh \
  --cwd "/work/project" \
  --command "git push origin main" \
  --session-id "..." \
  --shell-pid "12345" \
  --host "mbp-01"
```

Rules:

- exit code `0` => approved
- exit code `2` => denied
- any other exit code => unavailable/error
- shell plugin must not mutate the command before sending it
- `--command` must be the exact interactive command line currently in the buffer

## Scope

This implementation covers:

- interactive `zsh` sessions
- interception of Enter / command submission
- forwarding metadata to `airlock-cli`
- allowing or denying command execution based on exit code
- optional fail-open or fail-closed handling for CLI errors

This implementation does **not** cover:

- non-interactive shell scripts
- commands launched outside `zsh`
- hard security enforcement against local bypass
- terminal multiplexers or PTY-level capture

## Recommended Design

Use a `zsh` plugin script loaded from `.zshrc`.

Preferred interception point:

- bind Enter to a custom ZLE widget
- inspect `$BUFFER`
- call `airlock-cli`
- if approved, invoke normal accept-line
- if denied, keep the shell alive and clear or preserve the buffer depending on UX choice

Why this design:

- cleaner than relying only on `preexec`
- decision happens before actual execution
- better UX feedback
- easier to reason about for an AI coding agent

## Required Inputs

The plugin must derive and send these values:

- `--shell`: literal string `zsh`
- `--cwd`: current `$PWD`
- `--command`: exact current command from `$BUFFER`
- `--session-id`: stable shell session identifier
- `--shell-pid`: `$$`
- `--host`: machine hostname

## Session ID Requirements

Generate one session ID per shell session and reuse it for all commands in that session.

Recommended approach:

- on first load, if `AIRLOCK_SESSION_ID` is empty, generate one
- export it so subshells may inherit it if desired

Recommended format:

```text
<unix-seconds>-<pid>-<random>
```

Example:

```text
1741401000-8123-48291
```

## Host Resolution

Resolve host in this order:

1. `$HOST`
2. `hostname`
3. fallback string `unknown-host`

The plugin must avoid failing only because hostname discovery is unavailable.

## Decision Handling Policy

Implement configurable fail mode:

- `AIRLOCK_FAIL_MODE=open` => errors/unavailable allow command to proceed
- `AIRLOCK_FAIL_MODE=closed` => errors/unavailable block command

Recommended default for opt-in mode:

```bash
AIRLOCK_FAIL_MODE=open
```

## UX Requirements

The plugin should provide lightweight terminal feedback:

- Approved: no message (command just runs)
- `Airlock denied`
- `Airlock unavailable, continuing`
- `Airlock unavailable, blocked`

The UI must remain terminal-safe and not require GUI dependencies.

## Installation Model

Recommended file layout:

```text
~/.airlock/
  bin/
    airlock-cli
  shell/
    airlock.plugin.zsh
```

Recommended `.zshrc` snippet:

```bash
export AIRLOCK_CLI="$HOME/.airlock/bin/airlock-cli"
export AIRLOCK_ENABLED=1
export AIRLOCK_FAIL_MODE=open
source "$HOME/.airlock/shell/airlock.plugin.zsh"
```

## Implementation Steps

### Step 1 — Create the plugin file

Create `airlock.plugin.zsh`.

### Step 2 — Load ZLE support

Use:

```zsh
autoload -Uz add-zsh-hook
```

Even though the primary design uses a ZLE widget, autoloading standard helpers is acceptable.

### Step 3 — Define environment defaults

Support these env vars:

- `AIRLOCK_CLI`
- `AIRLOCK_ENABLED`
- `AIRLOCK_FAIL_MODE`

Optional future vars:

- `AIRLOCK_LOG_FILE`
- `AIRLOCK_VERBOSE`

### Step 4 — Initialize session ID

If `AIRLOCK_SESSION_ID` is missing, generate and export it.

### Step 5 — Create helper functions

Implement helpers:

- `_airlock_resolve_host`
- `_airlock_call_cli`
- `airlock_accept_line`

### Step 6 — Intercept Enter

Register a custom widget and bind both Enter variants:

```zsh
zle -N airlock_accept_line
bindkey '^M' airlock_accept_line
bindkey '^J' airlock_accept_line
```

### Step 7 — Execute decision flow

Pseudo-flow:

1. read current command from `$BUFFER`
2. if empty => allow normal accept-line
3. if disabled => allow normal accept-line
4. resolve `cwd`, `session-id`, `pid`, `host`
5. call `airlock-cli approve ...`
6. inspect `$?`
7. on `0` => execute normal accept-line
8. on `2` => deny, do not execute
9. on other exit code => apply fail mode

## Reference Implementation Skeleton

```zsh
# airlock.plugin.zsh

: ${AIRLOCK_CLI:=airlock-cli}
: ${AIRLOCK_ENABLED:=1}
: ${AIRLOCK_FAIL_MODE:=open}

if [[ -z "$AIRLOCK_SESSION_ID" ]]; then
  export AIRLOCK_SESSION_ID="$(date +%s)-$$-$RANDOM"
fi

_airlock_resolve_host() {
  if [[ -n "$HOST" ]]; then
    print -r -- "$HOST"
    return
  fi

  if command -v hostname >/dev/null 2>&1; then
    hostname 2>/dev/null && return
  fi

  print -r -- "unknown-host"
}

_airlock_call_cli() {
  local cmd="$1"
  local host="$(_airlock_resolve_host)"

  "$AIRLOCK_CLI" approve     --shell zsh     --cwd "$PWD"     --command "$cmd"     --session-id "$AIRLOCK_SESSION_ID"     --shell-pid "$$"     --host "$host"
}

airlock_accept_line() {
  local cmd="$BUFFER"

  if [[ -z "${cmd// }" ]]; then
    zle .accept-line
    return
  fi

  if [[ "$AIRLOCK_ENABLED" != "1" ]]; then
    zle .accept-line
    return
  fi

  _airlock_call_cli "$cmd"
  local rc=$?

  case $rc in
    0)
      zle .accept-line
      ;;
    2)
      zle -M "Airlock denied"
      print
      print -P "%F{red}[Airlock]%f Denied: $cmd"
      BUFFER=""
      CURSOR=0
      zle redisplay
      ;;
    *)
      if [[ "$AIRLOCK_FAIL_MODE" == "closed" ]]; then
        zle -M "Airlock unavailable, blocked"
        print
        print -P "%F{red}[Airlock]%f Unavailable, blocked: $cmd"
        BUFFER=""
        CURSOR=0
        zle redisplay
      else
        zle -M "Airlock unavailable, continuing"
        zle .accept-line
      fi
      ;;
  esac
}

zle -N airlock_accept_line
bindkey '^M' airlock_accept_line
bindkey '^J' airlock_accept_line
```

## Acceptance Criteria

The implementation is complete when all of the following are true:

1. entering `echo hello` in an interactive `zsh` session calls `airlock-cli`
2. when CLI returns `0`, the command executes normally
3. when CLI returns `2`, the command does not execute
4. `--command` matches the exact command typed
5. `--cwd` is the current working directory
6. `--session-id` stays stable across multiple commands in one shell session
7. `--shell-pid` equals the current shell PID
8. `--host` is non-empty
9. fail-open and fail-closed modes both work
10. loading the plugin from `.zshrc` does not break normal shell startup

## Test Plan

### Manual tests

Test 1:

- command: `echo hello`
- fake CLI returns `0`
- expected: command runs

Test 2:

- command: `git push origin main`
- fake CLI returns `2`
- expected: command does not run

Test 3:

- fake CLI returns `5`
- fail mode open
- expected: command runs

Test 4:

- fake CLI returns `5`
- fail mode closed
- expected: command does not run

Test 5:

- enter empty line
- expected: no CLI call, normal prompt behavior

### Metadata tests

Verify that CLI receives:

- `--shell zsh`
- actual `PWD`
- original command string
- stable session ID
- `$$`
- hostname

## Risks and Edge Cases

- multiline commands may need future refinement
- shell quoting must be preserved exactly in `$BUFFER`
- aliases are not expanded yet, and that is acceptable for v1
- commands executed by history expansion may need later validation
- this is opt-in workflow interception, not anti-bypass security

## Recommended V1 Boundaries

Do not add these in v1:

- cryptography in the plugin
- HTTP calls from the plugin
- command hashing in the plugin
- background daemons
- async approval logic
- prompt theming

Keep the plugin thin. All policy, transport, and crypto belong in `airlock-cli`.

## Deliverables

The coding agent should produce:

1. `airlock.plugin.zsh`
2. example `.zshrc` integration snippet
3. a tiny fake CLI test script
4. a short README section describing installation and behavior
