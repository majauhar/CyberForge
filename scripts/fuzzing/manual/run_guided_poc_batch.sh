#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "${REPO_ROOT}"

PROJECT="${PROJECT:?PROJECT required}"
SOURCE_RUN_DIR="${SOURCE_RUN_DIR:?SOURCE_RUN_DIR required}"
TAG="${TAG:-easywin_review}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-90}"
EXPLOIT_TIMEOUT="${EXPLOIT_TIMEOUT:-600}"
OUTPUT_ROOT="${OUTPUT_ROOT:-runs/manual_fuzz_validation}"
RUN_LABEL="${RUN_LABEL:-guided_poc_${PROJECT}}"

OUT_DIR="${OUTPUT_ROOT}/${RUN_LABEL}"
mkdir -p "${OUT_DIR}"

{
  echo "[start] $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "project=${PROJECT}"
  echo "source_run_dir=${SOURCE_RUN_DIR}"
  echo "tag=${TAG}"
  uv run vuljector fuzz-guided-poc batch \
    --source-run-dir "${SOURCE_RUN_DIR}" \
    --tag "${TAG}" \
    --max-total-time "${MAX_TOTAL_TIME}" \
    --exploit-timeout "${EXPLOIT_TIMEOUT}"
  echo "[done] $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee "${OUT_DIR}/session.log"
