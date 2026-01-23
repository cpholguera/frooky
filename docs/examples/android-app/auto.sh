#!/usr/bin/env bash
set -euo pipefail

FLOW="flow.yaml"

DEVICE_ARGS=()
if [[ -n "${FROOKY_DEVICE_ID:-}" ]]; then
	DEVICE_ARGS=(-D "$FROOKY_DEVICE_ID")
elif [[ -n "${ANDROID_SERIAL:-}" ]]; then
	# On CI/emulators, Frida typically exposes the device using this ID (e.g. emulator-5554)
	DEVICE_ARGS=(-D "$ANDROID_SERIAL")
else
	DEVICE_ARGS=(-U)
fi

# Start Frida and redirect stdout and stderr to file
frooky "${DEVICE_ARGS[@]}" -f org.owasp.mastestapp --platform android hooks.json hooks2.json -o output.json > frooky.log 2>&1 &

FRIDA_PID=$!

# Give frooky a moment to connect/attach/spawn. If it dies early, surface the error.
sleep 5
if ! kill -0 "$FRIDA_PID" 2>/dev/null; then
	echo "frooky exited early; dumping frooky.log"
	tail -n 200 frooky.log || true
	exit 1
fi

# Run Maestro (https://docs.maestro.dev/getting-started/installing-maestro)
maestro test "$FLOW" > auto.log 2>&1
MAESTRO_EXIT=$?

# Stop Frida when Maestro completes
kill "$FRIDA_PID" 2>/dev/null || true

# Surface frooky log (useful in CI even on success)
tail -n 200 frooky.log || true

exit "$MAESTRO_EXIT"
