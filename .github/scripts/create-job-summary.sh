#!/usr/bin/env bash
set -euo pipefail

# Usage: create-job-summary.sh <platform>
# Example: create-job-summary.sh android

PLATFORM="${1:-}"

if [ -z "$PLATFORM" ]; then
  echo "Error: Platform argument required (android or ios)"
  exit 1
fi

RESULTS_DIR="${PLATFORM}-test-results"
PLATFORM_TITLE="$(echo "$PLATFORM" | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')"

# Add evaluation results at the top
if [ -f evaluation.txt ]; then
  cat evaluation.txt
  echo ""
  echo "---"
  echo ""
fi

echo "# $PLATFORM_TITLE Test Results"
echo ""

echo "## frooky"
echo ""
echo '```sh'
cat "$RESULTS_DIR/frooky.log" 2>/dev/null || echo "No frooky.log found"
echo ""
echo '```'
echo ""

echo "## maestro"
echo ""
echo '```sh'
cat "$RESULTS_DIR/auto.log" 2>/dev/null || echo "No auto.log found"
echo '```'
echo ""
echo ""

echo "Job summary created for $PLATFORM_TITLE tests" >&2
