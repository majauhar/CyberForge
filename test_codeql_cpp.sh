#!/usr/bin/env bash
# test_codeql_cpp.sh — measure CodeQL taint-tracking yield on C/C++ OSS repos.
#
# For each project:
#   1. Clones the repo into the Vuljector workspace (idempotent)
#   2. Writes a minimal project.json + runtime.json
#   3. Runs: uv run vuljector selection <project> codeql <model>
#      CodeQL uses --build-mode=autobuild for C/C++ (intercepts the compiler).
#   4. Prints per-project yield, CWE breakdown, checkpoint × operation pairs
#
# Usage:
#   bash test_codeql_cpp.sh [model_id]
#
# IMPORTANT — C/C++ build requirements:
#   CodeQL extracts C/C++ by wrapping the compiler during a real build.
#   All repos below use CMake or Makefile and autobuild works on macOS/Linux.
#   Build dependencies (cmake, make, gcc/clang) must be installed:
#     macOS:  brew install cmake
#     Ubuntu: apt-get install -y cmake build-essential
#
#   DB creation times (first run):
#     Small  repos (< 50K LOC):    5-15 min
#     Medium repos (50K-200K LOC): 15-40 min
#   Subsequent runs reuse the cached DB (runs/codeql_dbs/<project>/cpp/).
#
# Notes:
#   - Requires CodeQL CLI on PATH or CODEQL_PATH env var.
#     Install: brew install codeql
#              OR: https://github.com/github/codeql-action/releases
#   - model_id is ignored by CodeQL analysis. Any string works.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODEL="${1:-claude-haiku-4-5-20251001}"

# ── Preflight checks ──────────────────────────────────────────────────────────
if ! command -v codeql &>/dev/null && [[ -z "${CODEQL_PATH:-}" ]]; then
  echo ""
  echo "ERROR: CodeQL CLI not found."
  echo ""
  echo "Install with one of:"
  echo "  brew install codeql                   # macOS"
  echo "  gh extension install github/gh-codeql # GitHub CLI"
  echo "  # Or download from: https://github.com/github/codeql-action/releases"
  echo "  # Then set: export CODEQL_PATH=/path/to/codeql/codeql"
  echo ""
  exit 1
fi

if ! command -v cmake &>/dev/null; then
  echo "WARNING: cmake not found. C/C++ builds may fail."
  echo "  macOS:  brew install cmake"
  echo "  Linux:  apt-get install -y cmake build-essential"
fi

CODEQL_BIN="${CODEQL_PATH:-$(command -v codeql)}"
echo "CodeQL CLI: $CODEQL_BIN  ($(${CODEQL_BIN} version --format=terse 2>/dev/null || echo 'unknown version'))"

# ── Install C/C++ QL pack dependencies once ──────────────────────────────────
QL_CPP_DIR="$SCRIPT_DIR/src/selector/codeql/ql/cpp"
LOCK_FILE="$QL_CPP_DIR/codeql-pack.lock.yml"
if [[ ! -f "$LOCK_FILE" ]]; then
  echo "Installing C/C++ QL pack dependencies (one-time, downloads to ~/.codeql/) ..."
  "${CODEQL_BIN}" pack install "$QL_CPP_DIR"
fi

# ── Project definitions ───────────────────────────────────────────────────────
# "project_name|github_url|target_dir|lang"
# Selected for:
#   - CMake or simple Makefile builds (autobuild-friendly)
#   - Moderate size (fast builds, good security surface)
#   - Rich use of memory operations, string handling, external input
PROJECTS=(
  # Only projects with proper vuljector-projects entries (dockerhub_image set)
  "brotli|https://github.com/google/brotli|brotli|c"
  "h3|https://github.com/uber/h3|h3|c"
  "openjpeg|https://github.com/uclouvain/openjpeg|openjpeg|c"
  "ninja|https://github.com/ninja-build/ninja|ninja|cpp"
)

# Paths
WORKSPACES_ROOT="$SCRIPT_DIR/runs/workspaces"
PROJECTS_ROOT="$(dirname "$SCRIPT_DIR")/vuljector-projects"
mkdir -p "$WORKSPACES_ROOT" "$PROJECTS_ROOT"

# ── Per-project loop ──────────────────────────────────────────────────────────
for entry in "${PROJECTS[@]}"; do
  IFS='|' read -r project url target_dir lang <<< "$entry"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $project  ($lang)  —  $url"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # 1. Clone (full clone — shallow clones break some C build systems)
  WORKSPACE_DIR="$WORKSPACES_ROOT/$project"
  CLONE_DEST="$WORKSPACE_DIR/$target_dir"
  mkdir -p "$WORKSPACE_DIR"
  if [[ ! -d "$CLONE_DEST/.git" ]]; then
    echo "→ Cloning (full clone for C/C++ build compatibility) ..."
    git clone "$url" "$CLONE_DEST"
  else
    echo "→ Already cloned"
  fi

  # 2. Verify project exists in vuljector-projects — never write project.json.
  PROJECT_DIR="$PROJECTS_ROOT/$project"
  if [[ ! -f "$PROJECT_DIR/project.json" ]]; then
    echo "  ✗ $project not found in vuljector-projects — skipping"
    continue
  fi
  DOCKER_IMAGE=$(python3 -c "import json; d=json.load(open('$PROJECT_DIR/project.json')); print(d.get('dockerhub_image',''))")
  echo "→ project.json found  (dockerhub_image=${DOCKER_IMAGE:-not set})"
  echo '{"setup_completed": true}' > "$WORKSPACE_DIR/runtime.json"

  # 3. DB cache check
  DB_PATH="$SCRIPT_DIR/runs/codeql_dbs/$project/cpp"
  if [[ -d "$DB_PATH" ]]; then
    echo "→ CodeQL DB cached at $DB_PATH (skipping build + extraction)"
  else
    echo "→ Building CodeQL DB (C/C++, autobuild mode — may take 5-30 min) ..."
    echo "  Tip: watch progress with: tail -f /tmp/codeql-build.log"
  fi

  # 4a. Run static_analysis (for comparison baseline)
  echo "→ uv run vuljector selection $project static_analysis $MODEL"
  if ! uv run vuljector selection "$project" static_analysis "$MODEL" > /dev/null 2>&1; then
    echo "  ⚠ static_analysis failed (continuing without baseline)"
  fi

  # 4b. Run CodeQL selection
  echo "→ uv run vuljector selection $project codeql $MODEL"
  START_TS=$SECONDS
  if ! uv run vuljector selection "$project" codeql "$MODEL" > /dev/null 2>&1; then
    echo "  ✗ CodeQL selection failed — full error:"
    uv run vuljector selection "$project" codeql "$MODEL" 2>&1 || true
    continue
  fi
  ELAPSED=$(( SECONDS - START_TS ))
  echo "→ Completed in ${ELAPSED}s"

  # 5a. Find most recent CodeQL candidates
  CANDIDATES_FILE=$(find "$SCRIPT_DIR/runs/selection/$project" -name "candidates.json" \
    2>/dev/null | sort | xargs -I{} sh -c \
    'python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1] if d.get(\"selection_strategy_id\")==\"codeql\" else \"\")" "$1" 2>/dev/null' \
    -- {} | grep -v '^$' | tail -1 || true)
  if [[ -z "$CANDIDATES_FILE" ]]; then
    CANDIDATES_FILE=$(find "$SCRIPT_DIR/runs/selection/$project" -name "candidates.json" \
      2>/dev/null | sort | tail -1)
  fi
  if [[ -z "$CANDIDATES_FILE" ]]; then
    echo "  ✗ candidates.json not found"
    continue
  fi

  # 5b. Find most recent static_analysis candidates (for comparison)
  SA_FILE=$(find "$SCRIPT_DIR/runs/selection/$project" -name "candidates.json" \
    2>/dev/null | sort | xargs -I{} sh -c \
    'python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1] if d.get(\"selection_strategy_id\")==\"static_analysis\" else \"\")" "$1" 2>/dev/null' \
    -- {} | grep -v '^$' | tail -1 || true)

  # 6. Print results
  uv run python - "$CANDIDATES_FILE" "${SA_FILE:-}" <<'PYEOF'
import sys, json, collections

import pathlib
codeql_file = sys.argv[1]
sa_file = sys.argv[2] if len(sys.argv) > 2 else ""

data = json.loads(open(codeql_file).read())
cands = data.get("candidates", [])
strats = collections.Counter(c.get("extra", {}).get("strategy", "?") for c in cands)
print(f"  CodeQL candidates : {len(cands)}")
for s, n in sorted(strats.items()):
    print(f"    {n:4d}  {s}")

if not cands:
    print("  (no candidates — CodeQL found no taint paths for this repo)")
    sys.exit(0)

# CWE breakdown
groups = collections.Counter(c.get("cwe_group", "Unknown") for c in cands)
print("  CWE groups:")
for g, n in groups.most_common():
    print(f"    {n:4d}  {g}")

# Path length distribution
lengths = [c.get("extra", {}).get("path_length", 0) for c in cands if c.get("extra", {}).get("path_length")]
if lengths:
    import statistics
    print(f"  Path length — min:{min(lengths)}  mean:{statistics.mean(lengths):.1f}  max:{max(lengths)}")

# Checkpoint presence
has_cp = sum(1 for c in cands if c.get("extra", {}).get("checkpoint", {}).get("text"))
print(f"  Guarded pairs   : {has_cp}/{len(cands)}")

# Checkpoint × operation type pairs (top 10)
pairs = collections.Counter(
    (
        c.get("extra", {}).get("checkpoint", {}).get("type", "(none)"),
        c.get("extra", {}).get("operation", {}).get("type", "?")
    )
    for c in cands
)
print("  Checkpoint × operation pairs:")
for (cp, op), n in pairs.most_common(10):
    print(f"    {n:4d}  {str(cp or "(none)"):<25s} × {str(op or "?")}")

# Top 5 by confidence
print("  Top 5 candidates:")
for c in sorted(cands, key=lambda x: x.get("confidence", 0), reverse=True)[:5]:
    cp = c.get("extra", {}).get("checkpoint", {})
    cp_label = cp.get("type", "none") if cp.get("type") else "no checkpoint"
    print(f"    [{c.get('rank',0):3d}] {str(c.get('symbol') or '?'):<35s}  {c.get('cwe_id','?')}  {cp_label}")

# Comparison vs static_analysis
if sa_file and pathlib.Path(sa_file).exists():
    sa_data = json.loads(open(sa_file).read())
    sa_cands = sa_data.get("candidates", [])
    cq_groups = collections.Counter(c.get("cwe_group", "?") for c in cands)
    sa_groups = collections.Counter(c.get("cwe_group", "?") for c in sa_cands)
    print(f"\n  vs static_analysis: CodeQL={len(cands)}  static_analysis={len(sa_cands)}")
    print("  CWE group (CodeQL / static_analysis):")
    for g in sorted(set(cq_groups) | set(sa_groups)):
        print(f"    {cq_groups.get(g,0):4d} / {sa_groups.get(g,0):<4d}  {g}")
PYEOF

done

# ── Aggregate summary ─────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  AGGREGATE (CodeQL — C/C++)"
echo "════════════════════════════════════════════════════════════════"
uv run python - "$SCRIPT_DIR/runs/selection" "${PROJECTS[@]}" <<'PYEOF'
import sys, json, collections, pathlib, statistics

sel_root = pathlib.Path(sys.argv[1])
projects = [e.split("|")[0] for e in sys.argv[2:]]

total = 0
groups:     collections.Counter = collections.Counter()
cwes:       collections.Counter = collections.Counter()
op_types:   collections.Counter = collections.Counter()
cp_types:   collections.Counter = collections.Counter()
pairs:      collections.Counter = collections.Counter()
per_project: dict = {}
path_lengths: list = []
guarded = 0
failed = []

for proj in projects:
    runs = sorted((sel_root / proj).glob("*/candidates.json")) if (sel_root / proj).exists() else []
    if not runs:
        failed.append(proj)
        continue
    cands = json.loads(runs[-1].read_text()).get("candidates", [])
    per_project[proj] = len(cands)
    total += len(cands)
    for c in cands:
        groups[c.get("cwe_group", "Unknown")] += 1
        cwes[c.get("cwe_id", "?")] += 1
        extra = c.get("extra", {})
        op_type = extra.get("operation", {}).get("type", "?")
        cp = extra.get("checkpoint", {})
        cp_type = cp.get("type", "(none)")
        op_types[op_type] += 1
        cp_types[cp_type] += 1
        pairs[(cp_type, op_type)] += 1
        if cp.get("text"):
            guarded += 1
        pl = extra.get("path_length", 0)
        if pl:
            path_lengths.append(pl)

print(f"\n  Total candidates : {total}")
if path_lengths:
    print(f"  Path length      : mean={statistics.mean(path_lengths):.1f}  max={max(path_lengths)}")
print(f"  Guarded pairs    : {guarded}/{total} ({100*guarded//total if total else 0}%)\n")

print("  Per-project yield:")
for p, n in sorted(per_project.items(), key=lambda x: -x[1]):
    bar = "█" * min(n // 3, 40)
    print(f"    {p:<22s}  {n:5d}  {bar}")
if failed:
    for p in failed:
        print(f"    {p:<22s}  FAILED (no candidates.json)")

print("\n  Top CWE groups:")
for g, n in groups.most_common(10):
    print(f"    {n:5d}  {g}")

print("\n  Top CWE IDs:")
for cwe, n in cwes.most_common(10):
    print(f"    {n:5d}  {cwe}")

print("\n  Checkpoint × operation pairs (top 12):")
for (cp, op), n in pairs.most_common(12):
    print(f"    {n:5d}  {str(cp or '(none)'):<25s} × {str(op or '?')}")
PYEOF
