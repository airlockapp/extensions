#!/usr/bin/env zsh
# Fake airlock-cli for testing the Zsh plugin.
# Usage: AIRLOCK_CLI="path/to/fake-airlock-cli.zsh" (and optionally FAKE_AIRLOCK_EXIT=0|1|2|5)
# Example: FAKE_AIRLOCK_EXIT=2 source ~/.airlock/shell/airlock.plugin.zsh

exitcode="${FAKE_AIRLOCK_EXIT:-0}"
exit "$exitcode"
