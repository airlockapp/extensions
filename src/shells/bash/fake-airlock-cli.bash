#!/usr/bin/env bash
# Fake airlock-cli for testing the Bash plugin.
# Usage: export AIRLOCK_CLI="/path/to/fake-airlock-cli.bash"
#        export FAKE_AIRLOCK_EXIT=0   # or 1, 2, 5 etc.
# Then source airlock.plugin.bash and press Enter on a command.

exitcode="${FAKE_AIRLOCK_EXIT:-0}"
exit "$exitcode"
