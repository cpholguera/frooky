#!/usr/bin/env bash
set -euo pipefail

FLOW="flow.yaml"

OUTPUT_JSON="output.json"
FROOKY_LOG="frooky.log"

APP_ID="org.owasp.mastestapp"
APP_NAME="MASTestApp"

adb wait-for-device
adb shell monkey -p "$APP_ID" -c android.intent.category.LAUNCHER 1
sleep 2

frida-ps -Uai | grep -i mas

PID="$(frida-ps -Uai | awk '$3=="org.owasp.mastestapp"{print $1; exit}')"
echo "Target pid, $PID"

# set +e
# timeout 5s frida -U -p "$PID" -l frida_sanity.js
# RC=$?
# set -e
# echo "frida exit code, $RC"


# Start frooky and redirect stdout and stderr to file
# timeout 5s frooky -U -f org.owasp.mastestapp --platform android hooks.json hooks2.json --keep-artifacts -o "$OUTPUT_JSON" >"$FROOKY_LOG" 2>&1 &

set +e
timeout 5s frooky -U -p "$PID" --platform android hooks.json hooks2.json --keep-artifacts -o "$OUTPUT_JSON" >"$FROOKY_LOG" 2>&1 &
RC=$?
set -e
echo "frooky exit code, $RC"

FROOKY_PID=$!

# Run Maestro (https://docs.maestro.dev/getting-started/installing-maestro)
maestro test "$FLOW" > auto.log 2>&1
MAESTRO_EXIT=$?

# Stop frooky when Maestro completes
kill -INT "$FROOKY_PID" 2>/dev/null || true
wait "$FROOKY_PID" 2>/dev/null || true
ls -laR .

exit "$MAESTRO_EXIT"
