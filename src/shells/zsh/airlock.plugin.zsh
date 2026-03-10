# Airlock Zsh plugin — intercept Enter, call airlock-cli approve, allow/deny execution.
# Requires airlock-cli to be installed and signed in + paired.

: "${AIRLOCK_CLI:=airlock-cli}"
: "${AIRLOCK_ENABLED:=1}"
: "${AIRLOCK_FAIL_MODE:=open}"

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

  "$AIRLOCK_CLI" approve \
    --shell zsh \
    --cwd "$PWD" \
    --command "$cmd" \
    --session-id "$AIRLOCK_SESSION_ID" \
    --shell-pid "$$" \
    --host "$host"
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

  # Don't intercept airlock-cli's own commands (prevents recursive blocking)
  local cli_name="${AIRLOCK_CLI##*/}"  # basename of configured CLI
  if [[ "$cmd" == "$AIRLOCK_CLI "* || "$cmd" == "$AIRLOCK_CLI" || "$cmd" == "$cli_name "* || "$cmd" == "$cli_name" ]]; then
    zle .accept-line
    return
  fi

  _airlock_call_cli "$cmd"
  local rc=$?

  case $rc in
    0)
      zle .accept-line
      ;;
    1|2)
      # 1 = denied, 2 = verification failed; both block execution
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
