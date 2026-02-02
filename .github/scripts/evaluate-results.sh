#!/usr/bin/env bash
set -euo pipefail

# Usage: evaluate-results.sh <platform>
# Example: evaluate-results.sh android

PLATFORM="${1:-}"

if [ -z "$PLATFORM" ]; then
  echo "Error: Platform argument required (android or ios)"
  exit 1
fi

EXAMPLE_DIR="docs/examples/${PLATFORM}-app"

cd "$EXAMPLE_DIR"
chmod +x ../evaluate.sh
../evaluate.sh | tee "$GITHUB_WORKSPACE/evaluation.txt"
EXIT_CODE=${PIPESTATUS[0]}
exit $EXIT_CODE
