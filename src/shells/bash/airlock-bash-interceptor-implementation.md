# Airlock Bash Interceptor — AI-Friendly Implementation Plan

## Purpose

Implement an opt-in `bash` interceptor that captures an interactive command before execution, calls `airlock-cli approve`, and only lets the command execute when the CLI exits with code `0`.

This document is optimized for an AI coding agent. The solution should be practical and minimal, while acknowledging that Bash is less elegant than Zsh for interactive interception.

## CLI Contract

The shell integration must call the CLI in this shape:

```bash
airlock-cli approve \
  --shell bash \
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
- `--command` must be the exact current command line from the interactive buffer

## Scope

This implementation covers:

- interactive Bash sessions
- interception of Enter using `bind -x`
- forwarding metadata to `airlock-cli`
- allow/deny behavior based on exit code
- configurable fail-open / fail-closed behavior

This implementation does **not** cover:

- non-interactive shell scripts
- commands launched outside Bash
- full terminal security
- perfect parity with Zsh UX

## Recommended Design

Use a Bash plugin script loaded from `.bashrc`.

Preferred strategy:

- bind Enter using `bind -x`
- inspect `READLINE_LINE`
- call `airlock-cli`
- execute or block based on exit code

Reasoning:

- this is the most realistic opt-in interception technique available in interactive Bash
- it keeps the architecture aligned with the Zsh and PowerShell integrations
- it preserves a shared `airlock-cli` contract

## Required Inputs

The plugin must derive and send:

- `--shell`: literal string `bash`
- `--cwd`: current `$PWD`
- `--command`: exact current command from `READLINE_LINE`
- `--session-id`: stable session identifier for the shell session
- `--shell-pid`: `$$`
- `--host`: machine hostname

## Session ID Requirements

Generate once per shell session if `AIRLOCK_SESSION_ID` is not already set.

Recommended format:

```text
<unix-seconds>-<pid>-<random>
```

## Host Resolution

Resolve host in this order:

1. `$HOSTNAME`
2. `hostname`
3. `unknown-host`

## Decision Handling Policy

Support:

- `AIRLOCK_FAIL_MODE=open`
- `AIRLOCK_FAIL_MODE=closed`

Recommended default:

```bash
AIRLOCK_FAIL_MODE=open
```

## UX Requirements

Print simple terminal messages only:

- Approved: no message (command just runs)
- `[Airlock] Denied: ...`
- `[Airlock] Unavailable, continuing`
- `[Airlock] Unavailable, blocked: ...`

Do not introduce dependencies beyond standard Bash features.

## Installation Model

Recommended layout:

```text
~/.airlock/
  bin/
    airlock-cli
  shell/
    airlock.plugin.bash
```

Recommended `.bashrc` snippet:

```bash
export AIRLOCK_CLI="$HOME/.airlock/bin/airlock-cli"
export AIRLOCK_ENABLED=1
export AIRLOCK_FAIL_MODE=open
source "$HOME/.airlock/shell/airlock.plugin.bash"
```

## Implementation Steps

### Step 1 — Create plugin file

Create `airlock.plugin.bash`.

### Step 2 — Define environment defaults

Support:

- `AIRLOCK_CLI`
- `AIRLOCK_ENABLED`
- `AIRLOCK_FAIL_MODE`

### Step 3 — Initialize session ID

If not present, generate and export `AIRLOCK_SESSION_ID`.

### Step 4 — Implement helpers

Create:

- `_airlock_resolve_host`
- `_airlock_call_cli`
- `_airlock_execute_current_line`
- `_airlock_clear_current_line`
- `_airlock_bash_accept_line`

### Step 5 — Bind Enter

Use:

```bash
bind -x '"\C-m":_airlock_bash_accept_line'
bind -x '"\C-j":_airlock_bash_accept_line'
```

### Step 6 — Implement decision flow

Pseudo-flow:

1. read command from `READLINE_LINE`
2. if empty => execute normal behavior
3. if disabled => execute normal behavior
4. call `airlock-cli`
5. inspect exit code
6. on `0` => execute command
7. on `2` => deny and clear line
8. on other code => apply fail mode

## Reference Implementation Skeleton

```bash
# airlock.plugin.bash

AIRLOCK_CLI="${AIRLOCK_CLI:-airlock-cli}"
AIRLOCK_ENABLED="${AIRLOCK_ENABLED:-1}"
AIRLOCK_FAIL_MODE="${AIRLOCK_FAIL_MODE:-open}"

if [[ -z "$AIRLOCK_SESSION_ID" ]]; then
  export AIRLOCK_SESSION_ID="$(date +%s)-$$-$RANDOM"
fi

_airlock_resolve_host() {
  if [[ -n "$HOSTNAME" ]]; then
    printf '%s\n' "$HOSTNAME"
    return
  fi

  if command -v hostname >/dev/null 2>&1; then
    hostname 2>/dev/null && return
  fi

  printf '%s\n' "unknown-host"
}

_airlock_call_cli() {
  local cmd="$1"
  local host
  host="$(_airlock_resolve_host)"

  "$AIRLOCK_CLI" approve     --shell bash     --cwd "$PWD"     --command "$cmd"     --session-id "$AIRLOCK_SESSION_ID"     --shell-pid "$$"     --host "$host"
}

_airlock_execute_current_line() {
  local cmd="$READLINE_LINE"
  builtin history -s "$cmd"
  printf '\n'
  eval "$cmd"
  READLINE_LINE=""
  READLINE_POINT=0
}

_airlock_clear_current_line() {
  READLINE_LINE=""
  READLINE_POINT=0
}

_airlock_bash_accept_line() {
  local cmd="$READLINE_LINE"

  if [[ -z "${cmd// }" ]]; then
    _airlock_execute_current_line
    return
  fi

  if [[ "$AIRLOCK_ENABLED" != "1" ]]; then
    _airlock_execute_current_line
    return
  fi

  _airlock_call_cli "$cmd"
  local rc=$?

  case $rc in
    0)
      _airlock_execute_current_line
      ;;
    2)
      printf '\n[Airlock] Denied: %s\n' "$cmd"
      _airlock_clear_current_line
      ;;
    *)
      if [[ "$AIRLOCK_FAIL_MODE" == "closed" ]]; then
        printf '\n[Airlock] Unavailable, blocked: %s\n' "$cmd"
        _airlock_clear_current_line
      else
        printf '\n[Airlock] Unavailable, continuing\n'
        _airlock_execute_current_line
      fi
      ;;
  esac
}

bind -x '"\C-m":_airlock_bash_accept_line'
bind -x '"\C-j":_airlock_bash_accept_line'
```

## Acceptance Criteria

The implementation is complete when all of the following are true:

1. interactive Bash Enter submits through Airlock logic
2. CLI exit `0` executes the command
3. CLI exit `2` blocks the command
4. `--command` matches the exact text typed
5. `--cwd` is the current working directory
6. `--session-id` stays stable within the shell session
7. `--shell-pid` is the current Bash PID
8. `--host` is non-empty
9. fail-open and fail-closed both work
10. normal `.bashrc` startup remains stable

## Test Plan

### Manual tests

Test 1:

- fake CLI returns `0`
- command: `echo hello`
- expected: command executes

Test 2:

- fake CLI returns `2`
- command: `git push origin main`
- expected: command does not execute

Test 3:

- fake CLI returns `9`
- fail-open
- expected: command executes

Test 4:

- fake CLI returns `9`
- fail-closed
- expected: command blocked

Test 5:

- empty line
- expected: normal shell behavior

## Risks and Edge Cases

- `eval` in the wrapper means exact execution semantics should be reviewed carefully
- multiline and complex readline states may need later improvements
- history handling may need tuning
- Bash interception is inherently more awkward than Zsh
- this is an opt-in developer workflow, not a hardened security boundary

## Recommended V1 Boundaries

Do not add in v1:

- HTTP from Bash
- encryption in Bash
- DEBUG trap complexity
- alias expansion logic
- advanced prompt integration

Keep Bash thin and delegate all policy and transport to `airlock-cli`.

## Deliverables

The coding agent should produce:

1. `airlock.plugin.bash`
2. example `.bashrc` integration snippet
3. fake CLI test script
4. short README section describing limitations and setup
