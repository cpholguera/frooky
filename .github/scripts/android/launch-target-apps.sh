#!/bin/bash
set -eo pipefail

for apk in target-apps-android/*.target-app.apk; do
  TARGET_APP=$(basename "$apk" .target-app.apk)
  APP_ID="${TARGET_APP//-/_}.mastestapp"
  echo "=== Launching $APP_ID ==="
  adb shell am start -n "$APP_ID/org.owasp.mastestapp.MainActivity"
done