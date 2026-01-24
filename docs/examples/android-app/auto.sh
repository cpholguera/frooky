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

frida -U -n "$APP_NAME" -q <<'EOF'
Java.perform(function () {
  console.log("frida attached and Java is ready");
});
setTimeout(function () {
  console.log("detaching frida");
  Process.exit(0);
}, 1000);
EOF


# Start frooky and redirect stdout and stderr to file
# frooky -U -f org.owasp.mastestapp --platform android hooks.json hooks2.json --keep-artifacts -o "$OUTPUT_JSON" >"$FROOKY_LOG" 2>&1 &

# FROOKY_PID=$!

# Run Maestro (https://docs.maestro.dev/getting-started/installing-maestro)
maestro test "$FLOW" > auto.log 2>&1
MAESTRO_EXIT=$?

# Stop frooky when Maestro completes
# kill -INT "$FROOKY_PID" 2>/dev/null || true
# wait "$FROOKY_PID" 2>/dev/null || true
# ls -laR .

exit "$MAESTRO_EXIT"
