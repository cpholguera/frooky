#!/bin/bash
set -eo pipefail

for apk in target-apps-android/*.apk; do
  TARGET_APP=$(basename "$apk" .apk)
  APP_ID="${TARGET_APP//-/_}.frooky.target.app"
  echo "=== Launching $APP_ID ==="
  adb shell am start -n "$APP_ID/org.owasp.mastestapp.MainActivity"
done