#!/usr/bin/env bash
set -euo pipefail

if adb root >/dev/null 2>&1; then
  adb wait-for-device
  adb shell setenforce 0 >/dev/null 2>&1 || true
fi
