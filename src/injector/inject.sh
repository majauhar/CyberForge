#!/usr/bin/env bash
# Ensure opencode is on PATH, then run the Python injector.
# Usage: ./inject.sh /path/to/codebase [--cwe-group "..." ] [--model ...] [--verbose]
# Set LOG_FILE to save a copy of the run log (e.g. LOG_FILE=./inject.log ./inject.sh ...).

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Add common opencode install paths to PATH so "opencode" is found
for d in "$HOME/.opencode/bin" "$HOME/.local/bin"; do
  [ -d "$d" ] && export PATH="$d:$PATH"
done

run() { python3 "$SCRIPT_DIR/inject.py" "$@"; }
if [ -n "${LOG_FILE:-}" ]; then
  run "$@" 2>&1 | tee "$LOG_FILE"
else
  exec run "$@"
fi
