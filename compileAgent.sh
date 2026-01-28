#!/bin/bash

cd ./frooky/agent
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
        echo "Usage: $0 {--prod|--dev|--watch-android|--watch-ios}"
        exit 1
        ;;
esac
