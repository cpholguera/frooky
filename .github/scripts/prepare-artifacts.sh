#!/usr/bin/env bash
set -euo pipefail

# Usage: prepare-artifacts.sh <platform>
# Example: prepare-artifacts.sh android

PLATFORM="${1:-}"

if [ -z "$PLATFORM" ]; then
  echo "Error: Platform argument required (android or ios)"
  exit 1
fi

RESULTS_DIR="${PLATFORM}-test-results"
EXAMPLE_DIR="docs/examples/${PLATFORM}-app"

mkdir -p "$RESULTS_DIR"

# Copy files from example directory
cd "$EXAMPLE_DIR"
for file in auto.log frooky.log output.json before.png after.png; do
  cp "$file" "$GITHUB_WORKSPACE/$RESULTS_DIR/" 2>/dev/null || true
done
cp -r tmp "$GITHUB_WORKSPACE/$RESULTS_DIR/" 2>/dev/null || true
cd "$GITHUB_WORKSPACE"

# Copy maestro log from most recent test run
LATEST_TEST=$(find ~/.maestro/tests -type f -name "maestro.log" 2>/dev/null | head -1)
if [ -n "$LATEST_TEST" ]; then
  cp "$LATEST_TEST" "$RESULTS_DIR/maestro.log"
fi

echo "Artifacts prepared in $RESULTS_DIR/"
