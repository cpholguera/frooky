#!/bin/bash
set -eo pipefail

for app in target-apps-ios/*.app; do
  [ -d "$app" ] || { echo "No .app bundles found, skipping."; continue; }

  TARGET_APP=$(basename "$app" ".app")
  BUNDLE_ID="${TARGET_APP//-/_}.frooky.target.app"

  PID=$(xcrun simctl launch booted "$BUNDLE_ID" | awk '{print $2}')
  echo "Launched with PID $PID"

  for i in $(seq 1 10); do
    if kill -0 "$PID" 2>/dev/null; then
      echo "App $TARGET_APP is running (PID $PID)."
      break
    fi
    echo "Attempt $i: app not running yet, retrying in 2s..."
    sleep 2
    if [ "$i" -eq 10 ]; then
      echo "ERROR: App $TARGET_APP did not start within the timeout."
      exit 1
    fi
  done
done