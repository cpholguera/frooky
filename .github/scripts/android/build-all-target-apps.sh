#!/usr/bin/env bash
for apk in target-apps-android/*.target-app.apk; do
    echo "=== Installing $apk ==="
    adb install -r "$apk"
done