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

PS_OUT="$(frida-ps -Uai || true)"
printf '%s\n' "$PS_OUT"

PID="$(printf '%s\n' "$PS_OUT" | awk '$3=="org.owasp.mastestapp"{print $1; exit}')"
echo "Target pid: $PID"

if [ -z "${PID:-}" ]; then
  echo "Could not find pid for $APP_ID"
  exit 1
fi

# set +e
# timeout 5s frida -U -p "$PID" -l frida_sanity.js
# RC=$?
# set -e
# echo "frida exit code, $RC"


# Start frooky and redirect stdout and stderr to file
# frooky -U -f org.owasp.mastestapp --platform android hooks.json hooks2.json -o "$OUTPUT_JSON" >"$FROOKY_LOG" 2>&1 &

# set +e
# timeout 5s frooky -U -p "$PID" --platform android hooks.json hooks2.json -o "$OUTPUT_JSON" >"$FROOKY_LOG" 2>&1
# RC=$?
# set -e
# echo "frooky exit code, $RC"


nohup frooky -U -p "$PID" --platform android hooks.json hooks2.json -o "$OUTPUT_JSON" >>"$FROOKY_LOG" 2>&1 </dev/null &
FROOKY_PID=$!

sleep 1
ps -p "$FROOKY_PID" >/dev/null 2>&1 || true
tail -n 20 "$FROOKY_LOG" || true

# Run Maestro (https://docs.maestro.dev/getting-started/installing-maestro)
MAESTRO_CLI_NO_ANALYTICS=1 maestro test "$FLOW" > auto.log 2>&1
MAESTRO_EXIT=$?

# Stop frooky when Maestro completes
kill -INT "$FROOKY_PID" 2>/dev/null || true

for _ in 1 2 3 4 5; do
  if ! kill -0 "$FROOKY_PID" 2>/dev/null; then
    break
  fi
  sleep 1
done

kill -KILL "$FROOKY_PID" 2>/dev/null || true
wait "$FROOKY_PID" 2>/dev/null || true

tail -n 200 "$FROOKY_LOG" || true

# ls -laR .

exit "$MAESTRO_EXIT"
