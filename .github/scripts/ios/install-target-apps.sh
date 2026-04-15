#!/bin/bash
set -eo pipefail

for app in target-apps-ios/*.app; do
  [ -d "$app" ] || { echo "No .app bundles found, skipping."; continue; }

  TARGET_APP=$(basename "$app" ".app")
  BUNDLE_ID="${TARGET_APP//-/_}.frooky.target.app"

  echo "=== Installing $app (bundle ID: $BUNDLE_ID) ==="
  xcrun simctl install booted "$BUNDLE_ID"

done