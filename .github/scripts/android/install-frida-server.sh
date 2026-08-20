#!/usr/bin/env bash
set -euo pipefail

# Download and setup frida-server
FRIDA_VERSION=$(frida --version) && echo "Frida version: $FRIDA_VERSION" && wget "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz" && unxz "frida-server-${FRIDA_VERSION}-android-x86_64.xz" && adb push "frida-server-${FRIDA_VERSION}-android-x86_64" /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"

# Start frida-server in background
adb shell "nohup /data/local/tmp/frida-server >/data/local/tmp/frida.log 2>&1 </dev/null &"

sleep 2
adb shell "ps | grep frida-server"
