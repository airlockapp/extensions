# Airlock Bash plugin — intercept Enter, call airlock-cli approve, allow/deny execution.
# Requires airlock-cli to be installed and signed in + paired.

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

  "$AIRLOCK_CLI" approve \
    --shell bash \
    --cwd "$PWD" \
    --command "$cmd" \
    --session-id "$AIRLOCK_SESSION_ID" \
    --shell-pid "$$" \
    --host "$host"
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
    1|2)
      # 1 = denied, 2 = verification failed; both block execution
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
