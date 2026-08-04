#!/usr/bin/env bash
# Batch-run the `setup` phase (pull/cache ready image) for every initialized
# project under vuljector-projects/. Idempotent: re-running re-validates and
# skips work whose ready image is already present.
#
# Usage: ./scripts/batch_setup.sh [JOBS]   (default JOBS=10)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECTS_DIR="$(cd "$REPO_ROOT/../vuljector-projects" && pwd)"
JOBS="${1:-10}"

LOG_DIR="$REPO_ROOT/runs/setup/_batch_$(date -u +%Y%m%dT%H%M%S)"
mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.log"

mapfile -t PROJECTS < <(cd "$PROJECTS_DIR" && for d in */; do [[ -f "$d/project.json" ]] && basename "$d"; done | sort)
TOTAL="${#PROJECTS[@]}"

{
    echo "Batch setup  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "Projects:    $TOTAL"
    echo "Jobs:        $JOBS"
    echo "Log dir:     $LOG_DIR"
    echo "──────────────────────────────────────────────────────"
} | tee "$SUMMARY"

export REPO_ROOT LOG_DIR SUMMARY

_worker() {
    local project="$1"
    local log_file="$LOG_DIR/${project}.log"
    local start dur
    start=$(date +%s)
    if (cd "$REPO_ROOT" && uv run vuljector setup "$project") >"$log_file" 2>&1; then
        dur=$(( $(date +%s) - start ))
        printf "PASS  %-28s %4ds\n" "$project" "$dur" | tee -a "$SUMMARY"
    else
        dur=$(( $(date +%s) - start ))
        printf "FAIL  %-28s %4ds  (see %s)\n" "$project" "$dur" "$log_file" | tee -a "$SUMMARY"
    fi
}
export -f _worker

printf '%s\n' "${PROJECTS[@]}" | xargs -P "$JOBS" -I{} bash -c '_worker "$@"' _ {}

PASS=$(grep -c "^PASS" "$SUMMARY" 2>/dev/null || echo 0)
FAIL=$(grep -c "^FAIL" "$SUMMARY" 2>/dev/null || echo 0)
{
    echo "──────────────────────────────────────────────────────"
    printf "Done  %s  |  pass=%d  fail=%d  total=%d\n" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PASS" "$FAIL" "$TOTAL"
} | tee -a "$SUMMARY"

if [[ "$FAIL" -gt 0 ]]; then
    echo "Failed projects:" | tee -a "$SUMMARY"
    grep "^FAIL" "$SUMMARY" | tee -a "$SUMMARY"
fi
