#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "${REPO_ROOT}"

PROJECT="${PROJECT:?set PROJECT}"
MODEL="${MODEL:-azure/gpt-5-mini}"
MAX_CANDIDATES="${MAX_CANDIDATES:-5}"
NUM_VULNERABILITIES="${NUM_VULNERABILITIES:-5}"
OUTPUT_ROOT="${OUTPUT_ROOT:-runs/manual_fuzz_validation}"
RUN_LABEL="${RUN_LABEL:-sel_inj_${PROJECT}_${MAX_CANDIDATES}x${NUM_VULNERABILITIES}}"

export VULJECTOR_INJECTION_STEP_LIMIT="${VULJECTOR_INJECTION_STEP_LIMIT:-100}"

for key in AZURE_OPENAI_ENDPOINT AZURE_OPENAI_API_KEY AZURE_OPENAI_API_VERSION; do
  [[ -n "${!key:-}" ]] || { echo "missing required env: ${key}" >&2; exit 1; }
done

OUT_DIR="${OUTPUT_ROOT}/${RUN_LABEL}"
mkdir -p "${OUT_DIR}"
SELECTION_JSON="${OUT_DIR}/selection_stdout.json"
INJECTION_JSON="${OUT_DIR}/injection_stdout.json"
LOG_FILE="${OUT_DIR}/session.log"

{
  echo "[start] $(date -u +%FT%TZ)"
  echo "project=${PROJECT}"
  echo "model=${MODEL}"
  echo "max_candidates=${MAX_CANDIDATES}"
  echo "num_vulnerabilities=${NUM_VULNERABILITIES}"
  echo "step_limit=${VULJECTOR_INJECTION_STEP_LIMIT}"

  uv run python -m vuljector.cli selection \
    "${PROJECT}" \
    fuzz_guided \
    "${MODEL}" \
    --max-candidates "${MAX_CANDIDATES}" | tee "${SELECTION_JSON}"

  RUN_ID="$(
    python - <<'PY' "${SELECTION_JSON}"
import json
import sys
payload = json.load(open(sys.argv[1], encoding="utf-8"))
print(payload["run_id"])
PY
  )"
  CANDIDATES="runs/selection/${PROJECT}/${RUN_ID}/candidates.json"

  echo "selection_run_id=${RUN_ID}"
  echo "candidates=${CANDIDATES}"

  uv run python -m vuljector.cli injection \
    "${PROJECT}" \
    "${CANDIDATES}" \
    "${MODEL}" \
    --num-vulnerabilities "${NUM_VULNERABILITIES}" | tee "${INJECTION_JSON}"

  echo "[done] $(date -u +%FT%TZ)"
} 2>&1 | tee "${LOG_FILE}"
