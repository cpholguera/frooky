#!/usr/bin/env bash
set -euo pipefail

FLOW="flow.yaml"

OUTPUT_JSON="output.json"
FROOKY_LOG="frooky.log"

DEVICE_ARGS=()
if [[ -n "${FROOKY_DEVICE_ID:-}" ]]; then
	DEVICE_ARGS=(-D "$FROOKY_DEVICE_ID")
elif [[ -n "${ANDROID_SERIAL:-}" ]]; then
	DEVICE_ARGS=(-D "$ANDROID_SERIAL")
else
	DEVICE_ARGS=(-U)
fi

# Start frooky and redirect stdout/stderr to file
frooky "${DEVICE_ARGS[@]}" -f org.owasp.mastestapp --platform android hooks.json hooks2.json --keep-artifacts -o "$OUTPUT_JSON" >"$FROOKY_LOG" 2>&1 &

FROOKY_PID=$!

# If frooky can't connect/attach/spawn, it tends to exit quickly.
# Make that a hard failure so we don't get a "successful" run with an empty output.json.
for _ in {1..15}; do
	if ! kill -0 "$FROOKY_PID" 2>/dev/null; then
		echo "frooky exited early; last logs:"
		tail -n 200 "$FROOKY_LOG" || true
		exit 1
	fi
	if [[ -s "$OUTPUT_JSON" ]]; then
		break
	fi
	sleep 1
done

if [[ ! -s "$OUTPUT_JSON" ]]; then
	echo "frooky produced no output after startup; last logs:"
	tail -n 200 "$FROOKY_LOG" || true
	exit 1
fi

# Run Maestro (https://docs.maestro.dev/getting-started/installing-maestro)
maestro test "$FLOW" > auto.log 2>&1
MAESTRO_EXIT=$?

# Stop frooky when Maestro completes
kill -INT "$FROOKY_PID" 2>/dev/null || true
wait "$FROOKY_PID" 2>/dev/null || true

tail -n 200 "$FROOKY_LOG" || true

exit "$MAESTRO_EXIT"
