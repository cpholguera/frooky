#!/bin/bash

# Universal evaluation script for frooky test output.json
# Reads expectations from expectations.conf in the current directory or accepts them as arguments
# Usage: 
#   ./evaluate.sh (reads from expectations.conf in current dir)
#   ./evaluate.sh <expected_total_hooks> <expected_total_errors> <expected_hook_count> <hook_types>

if [ ! -f "output.json" ]; then
  echo "❌ FAIL: output.json not found"
  exit 1
fi

# Try to read from expectations.conf if no arguments provided
if [ $# -eq 0 ] && [ -f "expectations.conf" ]; then
  source expectations.conf
  EXPECTED_TOTAL_HOOKS=${EXPECTED_TOTAL_HOOKS}
  EXPECTED_TOTAL_ERRORS=${EXPECTED_TOTAL_ERRORS}
  EXPECTED_HOOK_COUNT=${EXPECTED_HOOK_COUNT}
  HOOK_TYPES=${HOOK_TYPES}
else
  # Parse arguments
  EXPECTED_TOTAL_HOOKS=${1}
  EXPECTED_TOTAL_ERRORS=${2}
  EXPECTED_HOOK_COUNT=${3}
  HOOK_TYPES=${4}
fi

# Validate that we have all required values
if [ -z "$EXPECTED_TOTAL_HOOKS" ] || [ -z "$EXPECTED_TOTAL_ERRORS" ] || [ -z "$EXPECTED_HOOK_COUNT" ] || [ -z "$HOOK_TYPES" ]; then
  echo "❌ ERROR: Missing expectations. Either provide:"
  echo "  1. expectations.conf file with EXPECTED_TOTAL_HOOKS, EXPECTED_TOTAL_ERRORS, EXPECTED_HOOK_COUNT, HOOK_TYPES"
  echo "  2. Command-line arguments: ./evaluate.sh <expected_total_hooks> <expected_total_errors> <expected_hook_count> <hook_types>"
  exit 1
fi

echo "# Evaluation Results"
echo ""

# Extract values from summary event (first line, NDJSON format)
TOTAL_HOOKS=$(jq -s '.[0] | .totalHooks' output.json)
TOTAL_ERRORS=$(jq -s '.[0] | .totalErrors' output.json)

# Build jq filter for hook types
IFS=',' read -ra TYPES <<< "$HOOK_TYPES"
JQ_FILTER=".type == \"${TYPES[0]}\""
for i in "${!TYPES[@]}"; do
  if [ $i -gt 0 ]; then
    JQ_FILTER="$JQ_FILTER or .type == \"${TYPES[$i]}\""
  fi
done

# Count hook entries using jq
HOOK_COUNT=$(jq -s "[.[] | select($JQ_FILTER)] | length" output.json)

PASS=true

if [ "$TOTAL_HOOKS" != "$EXPECTED_TOTAL_HOOKS" ]; then
  echo "❌ FAIL: Expected totalHooks=$EXPECTED_TOTAL_HOOKS, got $TOTAL_HOOKS"
  PASS=false
else
  echo "✅ PASS: totalHooks=$EXPECTED_TOTAL_HOOKS"
fi

if [ "$TOTAL_ERRORS" != "$EXPECTED_TOTAL_ERRORS" ]; then
  echo "❌ FAIL: Expected totalErrors=$EXPECTED_TOTAL_ERRORS, got $TOTAL_ERRORS"
  PASS=false
else
  echo "✅ PASS: totalErrors=$EXPECTED_TOTAL_ERRORS"
fi

if [ "$HOOK_COUNT" != "$EXPECTED_HOOK_COUNT" ]; then
  echo "❌ FAIL: Expected $EXPECTED_HOOK_COUNT type=hook entries, got $HOOK_COUNT"
  PASS=false
else
  echo "✅ PASS: $EXPECTED_HOOK_COUNT type=hook entries found"
fi

echo ""
if [ "$PASS" = true ]; then
  echo "✅ All validation checks passed!"
  exit 0
else
  echo "❌ Some validation checks failed!"
  exit 1
fi
