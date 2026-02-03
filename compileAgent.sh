#!/bin/bash

cd ./frooky/agent
npm ci

case "$1" in
    --prod)
        npm run build:prod:android
        npm run build:prod:ios
        ;;
    --dev)
        npm run build:dev:android
        npm run build:dev:ios
        ;;
    *)
        echo "Usage: $0 {--prod|--dev}"
        exit 1
        ;;
esac
