#!/bin/bash
set -eo pipefail

for apk in target-apps-android/*.apk; do
  echo "=== Installing $apk ==="
  adb install -r "$apk"
done

