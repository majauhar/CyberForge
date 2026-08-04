#!/usr/bin/env bash
# Fuzz-guided selection + injection across ALL vuljector projects, with parallelism.
# Per project: mine OSS-Fuzz metadata -> fuzz_guided selection -> fuzzer_llm_inject injection.
# Resilient: any project lacking public OSS-Fuzz metadata, yielding no candidates, or
# erroring is logged and skipped; the batch keeps going.
#
# Waits for any in-progress cjson injection to finish first, then processes the rest
# with JOBS workers concurrently (default 3).
#
# A background janitor periodically reclaims docker disk WITHOUT touching images
# (stopped containers + unused build cache only) so a multi-day run can't fill the disk.
#
# Resume: set RESUME_DIR=<an existing _batch_* dir> to continue it; projects that already
# have a <P>.result there are skipped. Lets you relaunch (e.g. wider) without redoing work.
#
# Usage: ./scripts/fuzzing/run_all_fuzz_guided.sh
# Env overrides: JOBS, MODEL, MAX_CANDIDATES, NUM_VULN, STEP_LIMIT, RETRY_STOP, EXCLUDE,
#                CLEANUP_INTERVAL (s, 0=off), RESUME_DIR

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"
PROJECTS_DIR="$(cd "$REPO_ROOT/../vuljector-projects" && pwd)"

# ── Config ──────────────────────────────────────────────────────────────────
JOBS="${JOBS:-3}"
MODEL="${MODEL:-gemma-4-31b-it}"
MAX_CANDIDATES="${MAX_CANDIDATES:-50}"
NUM_VULN="${NUM_VULN:-50}"
EXCLUDE="${EXCLUDE:-cjson}"
CLEANUP_INTERVAL="${CLEANUP_INTERVAL:-1800}"   # docker prune cadence in seconds; 0 disables
RESUME_DIR="${RESUME_DIR:-}"
export VULJECTOR_INJECTION_STEP_LIMIT="${STEP_LIMIT:-100}"
export MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT="${RETRY_STOP:-20}"

set -a; . "$REPO_ROOT/src/.env" 2>/dev/null; set +a

# Reuse an existing batch dir when resuming, else make a fresh one.
if [[ -n "$RESUME_DIR" && -d "$RESUME_DIR" ]]; then
    LOG_DIR="$RESUME_DIR"
else
    LOG_DIR="$REPO_ROOT/runs/fuzz_guided_batch/_batch_$(date -u +%Y%m%dT%H%M%S)"
fi
mkdir -p "$LOG_DIR"
SUMMARY="$LOG_DIR/summary.log"
JANITOR_LOG="$LOG_DIR/janitor.log"
export REPO_ROOT LOG_DIR SUMMARY MODEL MAX_CANDIDATES NUM_VULN PROJECTS_DIR

slog() { ( flock 9; echo "$@" >>"$SUMMARY"; ) 9>>"$SUMMARY"; echo "$@"; }

# ── Docker janitor: reclaim disk safely (NEVER prunes images) ───────────────
docker_cleanup() {
    # stopped containers (active/running ones are untouched)
    docker container prune -f >/dev/null 2>&1
    # unused build cache (cache in use by an active build is protected)
    docker builder prune -f   >/dev/null 2>&1
}

janitor_loop() {
    while true; do
        sleep "$CLEANUP_INTERVAL"
        local before after
        before="$(docker system df --format '{{.Type}} {{.Reclaimable}}' 2>/dev/null | tr '\n' '|')"
        docker_cleanup
        after="$(docker system df --format '{{.Type}} {{.Reclaimable}}' 2>/dev/null | tr '\n' '|')"
        echo "[$(date -u +%FT%TZ)] cleanup done | reclaimable before: $before after: $after" >>"$JANITOR_LOG"
    done
}

JANITOR_PID=""
cleanup_on_exit() { [[ -n "$JANITOR_PID" ]] && kill "$JANITOR_PID" 2>/dev/null; }
trap cleanup_on_exit EXIT INT TERM

slog "Fuzz-guided batch  $(date -u +%Y-%m-%dT%H:%M:%SZ)${RESUME_DIR:+  [RESUME]}"
slog "jobs=$JOBS model=$MODEL max_candidates=$MAX_CANDIDATES num_vuln=$NUM_VULN step_limit=$VULJECTOR_INJECTION_STEP_LIMIT retry_stop=$MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT cleanup_interval=${CLEANUP_INTERVAL}s"
slog "log_dir=$LOG_DIR"
slog "──────────────────────────────────────────────────────"

# Initial reclaim + start periodic janitor (skip if disabled)
if [[ "$CLEANUP_INTERVAL" -gt 0 ]]; then
    slog "[janitor] initial docker cleanup (stopped containers + build cache; images untouched)"
    docker_cleanup
    janitor_loop &
    JANITOR_PID=$!
    slog "[janitor] periodic cleanup every ${CLEANUP_INTERVAL}s (pid $JANITOR_PID)"
fi

# ── Wait for any in-progress cjson injection to finish ──────────────────────
if pgrep -f "vuljector injection cjson" >/dev/null 2>&1; then
    slog "[wait] cjson injection in progress; waiting before starting batch..."
    while pgrep -f "vuljector injection cjson" >/dev/null 2>&1; do sleep 60; done
    slog "[wait] cjson injection finished; starting batch."
fi

# ── Project list (skip excluded + already-finished when resuming) ───────────
mapfile -t ALL < <(cd "$PROJECTS_DIR" && for d in */; do [[ -f "$d/project.json" ]] && basename "$d"; done | sort)
PROJECTS=(); RESUMED_SKIP=0
for p in "${ALL[@]}"; do
    skip=0; for e in $EXCLUDE; do [[ "$p" == "$e" ]] && skip=1; done
    [[ $skip -eq 1 ]] && continue
    if [[ -f "$LOG_DIR/${p}.result" ]]; then RESUMED_SKIP=$((RESUMED_SKIP+1)); continue; fi
    PROJECTS+=("$p")
done
TOTAL="${#PROJECTS[@]}"
slog "projects to process: $TOTAL  (jobs=$JOBS, excluded: $EXCLUDE, already-done skipped: $RESUMED_SKIP)"
slog "──────────────────────────────────────────────────────"

# ── Per-project worker ──────────────────────────────────────────────────────
worker() {
    local P="$1"
    local plog="$LOG_DIR/${P}.log"
    local start; start=$(date +%s)
    local rc res verified dur
    # NOTE: subshell ( ) not brace { } on purpose — an `exit N` on a SKIP/FAIL path
    # inside a brace group would terminate the whole `bash -c worker` process BEFORE
    # the ${P}.result write below, so skipped/failed projects were never recorded and
    # got re-processed on every resume. A subshell confines `exit` and preserves $?.
    (
        echo "### $P  $(date -u +%FT%TZ)"
        echo "-- mining metadata --"
        uv run python scripts/fuzzing/mine_public_oss_fuzz_metadata.py --project "$P" 2>&1 | tail -5
        if [[ ! -s "runs/ossfuzz_metadata/${P}.json" ]]; then echo "RESULT=SKIP reason=no_metadata"; exit 20; fi

        echo "-- fuzz_guided selection --"
        local sel_json="$LOG_DIR/${P}.selection.json"
        if ! uv run vuljector selection "$P" fuzz_guided "$MODEL" --max-candidates "$MAX_CANDIDATES" >"$sel_json" 2>>"$plog.selerr"; then
            echo "RESULT=SKIP reason=selection_failed"; exit 21
        fi
        local run_id cand ncand
        run_id="$(python3 -c "import json;print(json.load(open('$sel_json'))['run_id'])" 2>/dev/null)"
        cand="runs/selection/${P}/${run_id}/candidates.json"
        ncand="$(python3 -c "import json;print(len(json.load(open('$cand')).get('candidates',[])))" 2>/dev/null || echo 0)"
        echo "selection run_id=$run_id candidates=$ncand"
        if [[ "${ncand:-0}" -eq 0 ]]; then echo "RESULT=SKIP reason=no_candidates"; exit 22; fi

        echo "-- injection (num_vulnerabilities=$NUM_VULN) --"
        local inj_json="$LOG_DIR/${P}.injection.json"
        if ! uv run vuljector injection "$P" "$cand" "$MODEL" --num-vulnerabilities "$NUM_VULN" >"$inj_json" 2>>"$plog.injerr"; then
            echo "RESULT=FAIL reason=injection_error candidates=$ncand"; exit 1
        fi
        # True verified count from the persisted vulnerabilities dir (stdout JSON is log-polluted).
        verified="$(ls "$PROJECTS_DIR/$P/vulnerabilities/" 2>/dev/null | wc -l | tr -d ' ')"
        echo "RESULT=DONE candidates=$ncand verified=$verified"
    ) >"$plog" 2>&1
    rc=$?
    dur=$(( $(date +%s) - start ))
    res="$(grep -m1 '^RESULT=' "$plog" 2>/dev/null || echo 'RESULT=FAIL reason=unknown')"
    echo "$res" > "$LOG_DIR/${P}.result"
    local tag=DONE; case "$rc" in 20|21|22) tag=SKIP;; 0) tag=DONE;; *) tag=FAIL;; esac
    ( flock 9; printf '%-4s %-26s %5ds  %s\n' "$tag" "$P" "$dur" "$res" >>"$SUMMARY"; ) 9>>"$SUMMARY"
}
export -f worker

# ── Run with JOBS workers ───────────────────────────────────────────────────
printf '%s\n' "${PROJECTS[@]}" | xargs -P "$JOBS" -I{} bash -c 'worker "$@"' _ {}

# ── Final reclaim + tally ───────────────────────────────────────────────────
[[ "$CLEANUP_INTERVAL" -gt 0 ]] && docker_cleanup
DONE=$(grep -l 'RESULT=DONE' "$LOG_DIR"/*.result 2>/dev/null | wc -l)
SKIP=$(grep -l 'RESULT=SKIP' "$LOG_DIR"/*.result 2>/dev/null | wc -l)
FAIL=$(grep -l 'RESULT=FAIL' "$LOG_DIR"/*.result 2>/dev/null | wc -l)
TOTAL_VERIFIED=$(cat "$LOG_DIR"/*.result 2>/dev/null | sed -n 's/.*verified=\([0-9]*\).*/\1/p' | awk '{s+=$1} END{print s+0}')
slog "──────────────────────────────────────────────────────"
slog "Done  $(date -u +%FT%TZ)  |  done=$DONE skip=$SKIP fail=$FAIL  |  total_verified_vulns=${TOTAL_VERIFIED:-0}"
echo "BATCH_COMPLETE" >> "$SUMMARY"
