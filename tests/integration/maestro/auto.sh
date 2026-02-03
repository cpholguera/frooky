#!/usr/bin/env bash
set -euo pipefail

FLOW="tests/integration/maestro/flow.yaml"

OUTPUT_JSON="output.json"
FROOKY_LOG="frooky.log"

APP_ID="org.owasp.mastestapp"
APP_NAME="MASTestApp"

adb wait-for-device
adb shell monkey -p "$APP_ID" -c android.intent.category.LAUNCHER 1
sleep 2

PS_OUT="$(frida-ps -Uai || true)"
printf '%s\n' "$PS_OUT"

PID="$(printf '%s\n' "$PS_OUT" | awk '$3=="org.owasp.mastestapp"{print $1; exit}')"
echo "Target pid: $PID"

if [ -z "${PID:-}" ]; then
  echo "Could not find pid for $APP_ID"
  exit 1
fi

# Run Maestro (https://docs.maestro.dev/getting-started/installing-maestro)
MAESTRO_CLI_NO_ANALYTICS=1 maestro test "$FLOW" 2>&1
MAESTRO_EXIT=$?


exit "$MAESTRO_EXIT"
