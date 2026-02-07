#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$SCRIPT_DIR/frooky/agent"
npm ci

case "$1" in
    --prod)
        npm run prod-android
        npm run prod-ios
        ;;
    --dev)
        npm run dev-android
        npm run dev-ios
        ;;
    *)
        echo "Usage: $0 {--prod|--dev}"
        exit 1
        ;;
esac
