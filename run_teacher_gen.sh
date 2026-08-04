#!/usr/bin/env bash
# Run teacher-collection over a batch of projects in parallel to gather trajectories.
cd "$(cd "$(dirname "$0")" && pwd)" || exit 1
export PATH="$HOME/.local/bin:$PATH"
export VULJECTOR_TEMP=0.7
PROJECTS=$( { echo brotli; grep -oE "OK [a-z0-9-]+" setup_logs/batch.master.log | awk '{print $2}'; } | sort -u )
mkdir -p teacher_logs
collect() {
  uv run vuljector teacher-collect "$1" --model-id gemma-4-31b-base \
    --task-modes patch,poc-san --regimes faithful --limit 300 \
    > "teacher_logs/tc_$1.log" 2>&1 && echo "[$(date +%H:%M)] DONE $1" || echo "[$(date +%H:%M)] ERR $1"
}
export -f collect
echo "=== teacher-gen START $(date) projects=$(echo $PROJECTS | wc -w) parallel=3 temp=$VULJECTOR_TEMP ==="
printf "%s\n" $PROJECTS | xargs -P 3 -I {} bash -c 'collect "$@"' _ {}
echo "=== teacher-gen DONE $(date) ==="
