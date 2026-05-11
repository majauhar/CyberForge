#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "${REPO_ROOT}"

PROJECT="${PROJECT:?set PROJECT}"
CANDIDATES="${CANDIDATES:?set CANDIDATES}"
MODEL="${MODEL:-azure/gpt-5-mini}"
NUM_VULNERABILITIES="${NUM_VULNERABILITIES:-5}"
OUTPUT_ROOT="${OUTPUT_ROOT:-runs/manual_fuzz_validation}"
RUN_LABEL="${RUN_LABEL:-inj_${PROJECT}_manual}"

export VULJECTOR_INJECTION_STEP_LIMIT="${VULJECTOR_INJECTION_STEP_LIMIT:-100}"

for key in AZURE_OPENAI_ENDPOINT AZURE_OPENAI_API_KEY AZURE_OPENAI_API_VERSION; do
  [[ -n "${!key:-}" ]] || { echo "missing required env: ${key}" >&2; exit 1; }
done

OUT_DIR="${OUTPUT_ROOT}/${RUN_LABEL}"
mkdir -p "${OUT_DIR}"

{
  echo "[start] $(date -u +%FT%TZ)"
  echo "project=${PROJECT}"
  echo "model=${MODEL}"
  echo "candidates=${CANDIDATES}"
  echo "num_vulnerabilities=${NUM_VULNERABILITIES}"
  echo "step_limit=${VULJECTOR_INJECTION_STEP_LIMIT}"
  uv run python -m vuljector.cli injection "${PROJECT}" "${CANDIDATES}" "${MODEL}" --num-vulnerabilities "${NUM_VULNERABILITIES}"
  echo "[done] $(date -u +%FT%TZ)"
} > "${OUT_DIR}/session.log" 2>&1
