#!/usr/bin/env bash
# Batch-initialize projects from a selected_projects JSON file.
#
# Usage:
#   ./scripts/batch_init.sh [--json PATH] [--oss-fuzz PATH] [--model MODEL] [--jobs N]
#
# Defaults:
#   --json     scripts/selected_projects.json
#   --oss-fuzz /home/anl31/documents/code/vuljector/oss-fuzz
#   --model    azure/gpt-5.4-mini
#   --jobs     1   (sequential; set >1 for parallel — watch Docker memory)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────
JSON_FILE="$REPO_ROOT/scripts/selected_projects.json"
OSS_FUZZ_PATH="/home/anl31/documents/code/vuljector/oss-fuzz"
MODEL_ID="azure/gpt-5.4-mini"
JOBS=1

usage() {
    cat <<EOF
Usage: ./scripts/batch_init.sh [--json PATH] [--oss-fuzz PATH] [--model MODEL] [--jobs N]

Batch-initialize all projects listed in a selector JSON file.

Options:
  --json PATH      Selection JSON to read [scripts/selected_projects.json]
  --oss-fuzz PATH  Local oss-fuzz checkout
  --model MODEL    Model ID passed to 'vuljector init'
  --jobs N         Parallel workers [1]
  -h, --help       Show this help
EOF
}

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)   usage; exit 0 ;;
        --json)      JSON_FILE="$2";      shift 2 ;;
        --oss-fuzz)  OSS_FUZZ_PATH="$2";  shift 2 ;;
        --model)     MODEL_ID="$2";       shift 2 ;;
        --jobs)      JOBS="$2";           shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ ! -f "$JSON_FILE" ]]; then
    echo "Selection JSON not found: $JSON_FILE" >&2
    exit 1
fi

if [[ ! -d "$OSS_FUZZ_PATH" ]]; then
    echo "oss-fuzz checkout not found: $OSS_FUZZ_PATH" >&2
    exit 1
fi

if ! [[ "$JOBS" =~ ^[1-9][0-9]*$ ]]; then
    echo "--jobs must be a positive integer, got: $JOBS" >&2
    exit 1
fi

# ── Log setup ─────────────────────────────────────────────────────────────────
LOG_DIR="$REPO_ROOT/runs/init/_batch_$(date -u +%Y%m%dT%H%M%S)"
mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.log"

{
    echo "Batch init  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "JSON:       $JSON_FILE"
    echo "OSS-Fuzz:   $OSS_FUZZ_PATH"
    echo "Model:      $MODEL_ID"
    echo "Jobs:       $JOBS"
    echo ""
} | tee "$SUMMARY"

# ── Extract project names ─────────────────────────────────────────────────────
mapfile -t PROJECTS < <(python3 -c "
import json
with open('$JSON_FILE') as f:
    data = json.load(f)
for p in data['projects']:
    print(p['name'])
")

TOTAL="${#PROJECTS[@]}"
echo "Projects to init: $TOTAL" | tee -a "$SUMMARY"
echo "──────────────────────────────────────────────────────" | tee -a "$SUMMARY"

PASS=0
SKIP=0
FAIL=0

# ── Init one project; echoes STATUS line, returns 0=pass/skip, 1=fail ─────────
init_project() {
    local project="$1"
    local log_file="$LOG_DIR/${project}.log"

    # Skip if project.json already exists in vuljector-projects
    local proj_dir
    proj_dir="$(python3 -c "
import sys; sys.path.insert(0, '$REPO_ROOT/src')
from utils.paths import project_root
print(project_root('$project'))
" 2>/dev/null)"

    if [[ -n "$proj_dir" && -f "${proj_dir}/project.json" ]]; then
        echo "SKIP  $project  (already initialized)"
        return 2
    fi

    if (cd "$REPO_ROOT" && uv run vuljector init "$project" \
            --oss-fuzz-path "$OSS_FUZZ_PATH" \
            --model-id "$MODEL_ID" \
        ) >"$log_file" 2>&1; then
        echo "PASS  $project"
        return 0
    else
        echo "FAIL  $project  (see ${log_file})"
        return 1
    fi
}

# ── Sequential run ────────────────────────────────────────────────────────────
if [[ "$JOBS" -le 1 ]]; then
    IDX=0
    for project in "${PROJECTS[@]}"; do
        IDX=$((IDX + 1))
        printf "[%d/%d] " "$IDX" "$TOTAL"

        set +e
        output=$(init_project "$project")
        rc=$?
        set -e

        echo "$output" | tee -a "$SUMMARY"
        case $rc in
            0) PASS=$((PASS + 1)) ;;
            2) SKIP=$((SKIP + 1)) ;;
            *) FAIL=$((FAIL + 1)) ;;
        esac
    done

# ── Parallel run (xargs) ──────────────────────────────────────────────────────
else
    export REPO_ROOT LOG_DIR OSS_FUZZ_PATH MODEL_ID SUMMARY

    _worker() {
        local project="$1"
        local log_file="$LOG_DIR/${project}.log"
        local proj_dir
        proj_dir="$(python3 -c "
import sys; sys.path.insert(0, '$REPO_ROOT/src')
from utils.paths import project_root
print(project_root('$project'))
" 2>/dev/null)"

        if [[ -n "$proj_dir" && -f "${proj_dir}/project.json" ]]; then
            echo "SKIP  $project  (already initialized)" | tee -a "$SUMMARY"
            return 0
        fi

        if (cd "$REPO_ROOT" && uv run vuljector init "$project" \
                --oss-fuzz-path "$OSS_FUZZ_PATH" \
                --model-id "$MODEL_ID" \
            ) >"$log_file" 2>&1; then
            echo "PASS  $project" | tee -a "$SUMMARY"
        else
            echo "FAIL  $project  (see ${log_file})" | tee -a "$SUMMARY"
        fi
    }
    export -f _worker

    printf '%s\n' "${PROJECTS[@]}" | xargs -P "$JOBS" -I{} bash -c '_worker "$@"' _ {}

    PASS=$(grep -c "^PASS" "$SUMMARY" 2>/dev/null || echo 0)
    SKIP=$(grep -c "^SKIP" "$SUMMARY" 2>/dev/null || echo 0)
    FAIL=$(grep -c "^FAIL" "$SUMMARY" 2>/dev/null || echo 0)
fi

# ── Final summary ─────────────────────────────────────────────────────────────
{
    echo ""
    echo "══════════════════════════════════════════════════════"
    printf "Done  %s  |  pass=%d  skip=%d  fail=%d  total=%d\n" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PASS" "$SKIP" "$FAIL" "$TOTAL"
    echo "Log dir: $LOG_DIR"
} | tee -a "$SUMMARY"

if [[ "$FAIL" -gt 0 ]]; then
    echo "" | tee -a "$SUMMARY"
    echo "Failed projects:" | tee -a "$SUMMARY"
    grep "^FAIL" "$SUMMARY" | tee -a "$SUMMARY"
    exit 1
fi
