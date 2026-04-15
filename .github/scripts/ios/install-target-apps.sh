#!/bin/bash
set -eo pipefail

for app in target-apps-ios/*.app; do
  [ -d "$app" ] || { echo "No .app bundles found, skipping."; continue; }

  TARGET_APP=$(basename "$app" ".app")

  echo "=== Installing $TARGET_APP ==="
  xcrun simctl install booted "$app"

done