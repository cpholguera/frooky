#!/usr/bin/env bash
set -euo pipefail

FLOW="flow.yaml"

OUTPUT_JSON="output.json"
FROOKY_LOG="frooky.log"

APP_ID="org.owasp.mastestapp.MASTestApp-iOS"
APP_NAME="MASTestApp"

# Launch the app first
xcrun simctl launch booted "$APP_ID" || true
sleep 2

# List running processes (local device, not USB)
PS_OUT="$(frida-ps -ai 2>/dev/null || true)"
printf '%s\n' "$PS_OUT"

# PID="$(printf '%s\n' "$PS_OUT" | awk -F': *' -v id="$APP_ID" '$1==id {print $2; exit}')"
# echo "Target pid: $PID"

nohup frooky -n "$APP_NAME" --platform ios hooks.json -o "$OUTPUT_JSON" >>"$FROOKY_LOG" 2>&1 </dev/null &

# if [ -z "${PID:-}" ]; then
#   echo "Could not find pid for $APP_NAME, trying to attach by name"
#   # Start frooky attaching by name instead of PID
#   nohup frooky -n "$APP_NAME" --platform ios hooks.json -o "$OUTPUT_JSON" >>"$FROOKY_LOG" 2>&1 </dev/null &
# else
#   # Start frooky attaching by PID
#   nohup frooky -p "$PID" --platform ios hooks.json -o "$OUTPUT_JSON" >>"$FROOKY_LOG" 2>&1 </dev/null &
# fi

FROOKY_PID=$!

sleep 2
ps -p "$FROOKY_PID" >/dev/null 2>&1 || { echo "frooky exited early"; tail -n 50 "$FROOKY_LOG" || true; exit 1; }
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
