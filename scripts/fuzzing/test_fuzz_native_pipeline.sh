#!/usr/bin/env bash
#
# End-to-end forward fuzz-native pipeline smoke script.
# Runs:
#   setup -> fuzz_guided selection -> injection -> fuzz-poc batch -> fuzz-poc batch-verify
#
# Usage:
#   bash scripts/fuzzing/test_fuzz_native_pipeline.sh
#   PROJECT=quickjs NUM_VULNS=2 MAX_CANDIDATES=25 bash scripts/fuzzing/test_fuzz_native_pipeline.sh
#   PROJECT=quickjs NUM_VULNS=30 MAX_CANDIDATES=0 bash scripts/fuzzing/test_fuzz_native_pipeline.sh
#

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════

PROJECT="${PROJECT:-quickjs}"
MODEL="${MODEL:-azure/gpt-5-mini}"
NUM_VULNS="${NUM_VULNS:-3}"
MAX_CANDIDATES="${MAX_CANDIDATES:-20}"
MAX_TOTAL_TIME="${MAX_TOTAL_TIME:-90}"
EXPLOIT_TIMEOUT="${EXPLOIT_TIMEOUT:-600}"
OUTPUT="${OUTPUT:-runs/fuzz_native_scratch/test_results_fuzz_native}"
INJECTION_MODE="${INJECTION_MODE:-full}"
INJECTION_STEP_LIMIT="${INJECTION_STEP_LIMIT:-30}"

export VULJECTOR_INJECTION_MODE="${VULJECTOR_INJECTION_MODE:-${INJECTION_MODE}}"
export VULJECTOR_INJECTION_STEP_LIMIT="${VULJECTOR_INJECTION_STEP_LIMIT:-${INJECTION_STEP_LIMIT}}"

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROJECT_ROOT="${REPO_ROOT}/../vuljector-projects/${PROJECT}"
PROJECT_JSON="${PROJECT_ROOT}/project.json"

header() { echo ""; echo "━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }
info()   { echo "  → $*"; }
ok()     { echo "  ✓ $*"; }
die()    { echo ""; echo "ERROR: $*" >&2; exit 1; }

mkdir -p "${OUTPUT}"
cd "${REPO_ROOT}"

for key in AZURE_OPENAI_ENDPOINT AZURE_OPENAI_API_KEY AZURE_OPENAI_API_VERSION; do
  [[ -n "${!key:-}" ]] || die "Missing required env: ${key}"
done

[[ -f "${PROJECT_JSON}" ]] || die "Missing ${PROJECT_JSON}. Use an initialized project under vuljector-projects/."

candidates_from() {
  local result_file="$1"
  python3 - "$result_file" <<'PYEOF'
import json, pathlib, sys
d = json.load(open(sys.argv[1]))
p = pathlib.Path("runs/selection") / d["project"] / d["run_id"] / "candidates.json"
print(p)
PYEOF
}

json_field() {
  local json_file="$1"
  local expr="$2"
  python3 - "$json_file" "$expr" <<'PYEOF'
import json, sys
path = sys.argv[1]
expr = sys.argv[2]
data = json.load(open(path))
value = data
for part in expr.split("."):
    if not part:
        continue
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
print("" if value is None else value)
PYEOF
}

capture_json() {
  local out_json="$1"
  local out_log="$2"
  shift 2
  "$@" >"${out_log}" 2>&1 || return $?
  python3 - "${out_log}" "${out_json}" <<'PYEOF'
import json, sys
from pathlib import Path
src = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
decoder = json.JSONDecoder()
best = None
best_score = -1
for idx, ch in enumerate(src):
    if ch != "{":
        continue
    try:
        obj, end = decoder.raw_decode(src[idx:])
    except Exception:
        continue
    score = 0
    if isinstance(obj, dict):
        keys = set(obj.keys())
        if {"project", "run_id"} & keys:
            score += 50
        if {"project", "run_id"} <= keys:
            score += 100
        if "status" in keys:
            score += 20
        if "selection_strategy_id" in keys:
            score += 80
        if "num_vulnerabilities_requested" in keys or "num_vulnerabilities_produced" in keys:
            score += 80
        if "candidates" in keys:
            score += 120
        if "attempts" in keys:
            score += 100
        if "generated_run_dir" in keys or "run_dir" in keys:
            score += 60
        score += len(keys)
    if score >= best_score:
        best = obj
        best_score = score
if best is None:
    raise SystemExit(f"Could not recover JSON from {sys.argv[1]}")
Path(sys.argv[2]).write_text(json.dumps(best, indent=2) + "\n", encoding="utf-8")
PYEOF
}

# ══════════════════════════════════════════════════════════════════════════════
# Step 1: Dependencies
# ══════════════════════════════════════════════════════════════════════════════
header "Step 1: Install dependencies"
if command -v uv &>/dev/null; then
  info "uv found — running: uv sync"
  uv sync 2>&1 | tail -5
  ok "Dependencies installed"
else
  die "'uv' not found. Install it first."
fi

# ══════════════════════════════════════════════════════════════════════════════
# Step 2: Setup
# ══════════════════════════════════════════════════════════════════════════════
header "Step 2: Setup"
SETUP_JSON="${OUTPUT}/setup_result.json"
if [[ -f "${SETUP_JSON}" ]]; then
  _setup_status="$(json_field "${SETUP_JSON}" "status" || true)"
else
  _setup_status=""
fi
if [[ "${_setup_status}" == "success" ]]; then
  ok "Setup already completed for this output directory — skipping"
else
  info "Running setup for ${PROJECT}"
  capture_json "${SETUP_JSON}" "${OUTPUT}/setup.log" uv run python -m vuljector.cli setup "${PROJECT}"
  _setup_status="$(json_field "${SETUP_JSON}" "status" || true)"
  [[ "${_setup_status}" == "success" ]] || die "Setup failed; see ${SETUP_JSON}"
  ok "Setup completed"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Step 3: fuzz_guided selection
# ══════════════════════════════════════════════════════════════════════════════
header "Step 3: Selection (fuzz_guided)"
SELECTION_JSON="${OUTPUT}/selection_fuzz_guided_result.json"
info "Running fuzz_guided selection with model ${MODEL}"
SELECTION_CMD=(uv run python -m vuljector.cli selection "${PROJECT}" fuzz_guided "${MODEL}")
if [[ -n "${MAX_CANDIDATES}" && "${MAX_CANDIDATES}" != "0" ]]; then
  SELECTION_CMD+=(--max-candidates "${MAX_CANDIDATES}")
else
  info "Running without a candidate cap"
fi
capture_json "${SELECTION_JSON}" "${OUTPUT}/selection_fuzz_guided.log" "${SELECTION_CMD[@]}"

SELECTION_RUN_ID="$(json_field "${SELECTION_JSON}" "run_id")"
SELECTION_CANDIDATE_COUNT="$(python3 - "${SELECTION_JSON}" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
print(len(d.get("candidates", [])))
PYEOF
)"
[[ "${SELECTION_CANDIDATE_COUNT}" != "0" ]] || die "fuzz_guided returned 0 candidates"
SELECTION_CANDIDATES="$(candidates_from "${SELECTION_JSON}")"
ok "Selection completed: ${SELECTION_CANDIDATE_COUNT} candidates"
info "Selection run: runs/selection/${PROJECT}/${SELECTION_RUN_ID}"
info "Candidates file: ${SELECTION_CANDIDATES}"

# ══════════════════════════════════════════════════════════════════════════════
# Step 4: injection
# ══════════════════════════════════════════════════════════════════════════════
header "Step 4: Injection (auto-routes to fuzzer_llm_inject)"
INJECTION_JSON="${OUTPUT}/injection_fuzz_guided_result.json"
info "Running injection for ${NUM_VULNS} vulnerability/vulnerabilities"
info "Injection mode: ${VULJECTOR_INJECTION_MODE} | step limit: ${VULJECTOR_INJECTION_STEP_LIMIT}"
capture_json "${INJECTION_JSON}" "${OUTPUT}/injection_fuzz_guided.log" \
  uv run python -m vuljector.cli injection \
  "${PROJECT}" "${SELECTION_CANDIDATES}" "${MODEL}" \
  --num-vulnerabilities "${NUM_VULNS}"

INJECTION_RUN_DIR="$(json_field "${INJECTION_JSON}" "run_dir")"
INJECTION_PRODUCED="$(json_field "${INJECTION_JSON}" "num_vulnerabilities_produced")"
ok "Injection completed: produced ${INJECTION_PRODUCED}/${NUM_VULNS}"
info "Injection run dir: ${INJECTION_RUN_DIR}"

[[ -n "${INJECTION_RUN_DIR}" && -d "${INJECTION_RUN_DIR}" ]] || die "Injection run directory not found"

if [[ "${VULJECTOR_INJECTION_MODE}" == "vuln_only" ]]; then
  header "Done"
  echo "Results in: ${OUTPUT}/"
  ls "${OUTPUT}/"
  echo ""
  python3 - "${SELECTION_JSON}" "${INJECTION_JSON}" <<'PYEOF'
import json, sys
selection = json.load(open(sys.argv[1]))
injection = json.load(open(sys.argv[2]))

print("Selection")
print(f"  strategy: {selection.get('selection_strategy_id')}")
print(f"  run_id: {selection.get('run_id')}")
print(f"  candidates: {len(selection.get('candidates', []))}")

print("Injection")
print(f"  mode: vuln_only")
print(f"  run_dir: {injection.get('run_dir')}")
print(f"  produced: {injection.get('num_vulnerabilities_produced')}/{injection.get('num_vulnerabilities_requested')}")
for attempt in injection.get("attempts", []):
    print(
        f"    attempt {attempt.get('attempt')}: "
        f"injection={attempt.get('injection_status')} "
        f"verification={attempt.get('verification_status')} "
        f"failure={attempt.get('failure_cause')}"
    )
PYEOF
  exit 0
fi

# ══════════════════════════════════════════════════════════════════════════════
# Step 5: fuzz-poc batch generate
# ══════════════════════════════════════════════════════════════════════════════
header "Step 5: Fuzz-PoC batch generate"
FUZZ_POC_GENERATE_JSON="${OUTPUT}/fuzz_poc_batch_generate.json"
info "Generating fuzz-backed PoCs from injection attempts"
capture_json "${FUZZ_POC_GENERATE_JSON}" "${OUTPUT}/fuzz_poc_batch_generate.log" \
  uv run python -m vuljector.cli fuzz-poc batch \
  --source-run-dir "${INJECTION_RUN_DIR}" \
  --tag "e2e_${PROJECT}" \
  --max-total-time "${MAX_TOTAL_TIME}"

FUZZ_POC_RUN_DIR="$(json_field "${FUZZ_POC_GENERATE_JSON}" "generated_run_dir")"
ok "Fuzz-PoC generation completed"
info "Fuzz-PoC run dir: ${FUZZ_POC_RUN_DIR}"

[[ -n "${FUZZ_POC_RUN_DIR}" && -d "${FUZZ_POC_RUN_DIR}" ]] || die "Fuzz-PoC run directory not found"

# ══════════════════════════════════════════════════════════════════════════════
# Step 6: fuzz-poc batch verify
# ══════════════════════════════════════════════════════════════════════════════
header "Step 6: Fuzz-PoC batch verify"
FUZZ_POC_VERIFY_JSON="${OUTPUT}/fuzz_poc_batch_verify.json"
info "Verifying generated fuzz-backed PoCs"
capture_json "${FUZZ_POC_VERIFY_JSON}" "${OUTPUT}/fuzz_poc_batch_verify.log" \
  uv run python -m vuljector.cli fuzz-poc batch-verify \
  --run-dir "${FUZZ_POC_RUN_DIR}" \
  --exploit-timeout "${EXPLOIT_TIMEOUT}"

ok "Fuzz-PoC verification completed"

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════
header "Done"
echo "Results in: ${OUTPUT}/"
ls "${OUTPUT}/"
echo ""

python3 - "${SELECTION_JSON}" "${INJECTION_JSON}" "${FUZZ_POC_GENERATE_JSON}" "${FUZZ_POC_VERIFY_JSON}" <<'PYEOF'
import json, sys
selection = json.load(open(sys.argv[1]))
injection = json.load(open(sys.argv[2]))
fuzz_gen = json.load(open(sys.argv[3]))
fuzz_verify = json.load(open(sys.argv[4]))

print("Selection")
print(f"  strategy: {selection.get('selection_strategy_id')}")
print(f"  run_id: {selection.get('run_id')}")
print(f"  candidates: {len(selection.get('candidates', []))}")

print("Injection")
print(f"  run_dir: {injection.get('run_dir')}")
print(f"  produced: {injection.get('num_vulnerabilities_produced')}/{injection.get('num_vulnerabilities_requested')}")
for attempt in injection.get("attempts", []):
    print(
        f"    attempt {attempt.get('attempt')}: "
        f"injection={attempt.get('injection_status')} "
        f"verification={attempt.get('verification_status')} "
        f"candidate={attempt.get('candidate_id')}"
    )

print("Fuzz-PoC Generate")
print(f"  run_dir: {fuzz_gen.get('generated_run_dir')}")
print(f"  attempts: {len(fuzz_gen.get('attempts', []))}")

print("Fuzz-PoC Verify")
print(f"  run_dir: {fuzz_verify.get('run_dir')}")
for item in fuzz_verify.get("attempts", []):
    result = item.get("verification_result") or {}
    print(
        f"    {item.get('attempt_dir')}: "
        f"status={result.get('status')} "
        f"failure_cause={result.get('failure_cause', '')}"
    )
PYEOF
