# Vuljector

Automated vulnerability injection and agent task evaluation for synthetic security dataset
creation. Vuljector injects semantically plausible vulnerabilities into real OSS-Fuzz
projects, verifies them (exploit triggers are enforced; unit-test results are recorded),
can derive fuzz-backed follow-on PoCs from successful injections, and then runs
swe-agent-mini on synthetic tasks derived from those vulnerabilities to collect
trajectories for SFT.

## What It Does

Core five-phase pipeline:

```
Init             Build image, detect commit, discover test harness → portable project definition
Phase 1 — Setup      Build/cache ready container for local use
Phase 2 — Selection  Find where to inject: static analysis, CodeQL, fuzz-guided, LLM exploration, or CVE
Phase 3 — Injection  Inject vulnerability via LLM agent, verify exploit triggers, persist code-diff snapshot
Phase 4 — CVE Report  Generate a CVE JSON 5.0 record for an existing vulnerability (independent command)
Phase 5 — Agent Tasks Run swe-agent-mini on synthetic tasks, validate output, score trajectory
```

Each phase is independent and rerunnable. Phases communicate through JSON files under `runs/`.

Additional fuzz-native workflows build on successful injection runs:

```
Fuzz-Guided Selection  Rank injection sites by existing OSS-Fuzz harness reachability and hot-path quality
Fuzz PoC              Generate replayable fuzz-backed PoCs from successful injection attempts
Guided Fuzz PoC       Prefer selector metadata first when choosing harnesses and seed templates
Rex Triage            Package successful replay cases for downstream Rex crash analysis
```

## Quick Start

### Install

Requires Python ≥ 3.13 and Docker.

```bash
uv pip install -e .
```

### API Keys

Create `src/.env` (gitignored):

```env
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...            # for openai/ models
OPENAI_API_BASE=...              # custom OpenAI-compatible endpoint
RCHAT_OSS_API_BASE=...           # internal RCHAT proxy
RCHAT_OSS_API_KEY=...
GITHUB_TOKEN=ghp_...             # recommended for cve_select: raises GitHub API limit from 60 to 5 000 req/hr
```

Generate a token at <https://github.com/settings/tokens> (no scopes required for public repos).

### Prerequisites

Clone [oss-fuzz](https://github.com/google/oss-fuzz) alongside this repo:

```bash
git clone --depth=1 https://github.com/google/oss-fuzz ../oss-fuzz
```

The Docker image is built automatically by `setup` when needed — no manual build step required.

### Initialize a project

`init` builds the Docker image, detects the secure base commit, discovers the test harness, and writes everything to `vuljector-projects/`. The result is a self-contained, portable project definition that can be committed and shared. The processed Docker image can be pushed to Docker Hub.

```bash
uv run vuljector init flask --oss-fuzz-path /path/to/oss-fuzz
```

This creates `vuljector-projects/flask/` with `project.json` (including the secure base commit), `setup/`, and `unit_tests/`.
The directory name must exactly match the project name under `oss-fuzz/projects/`.

For native `C` / `C++` projects, you can opt into AFL++ at init or setup time:

```bash
uv run vuljector init jsoncpp --oss-fuzz-path /path/to/oss-fuzz --fuzzing-engine afl
uv run vuljector setup jsoncpp --fuzzing-engine afl
```

Engine-aware local image tags now include the engine name, for example
`vuljector/jsoncpp:<hash>-afl-ready`. Existing local libFuzzer images are
still adopted automatically and retagged to the new `-libfuzzer-ready` scheme.

To override the source subdirectory (if it differs from the project name):

```bash
uv run vuljector init myproject --oss-fuzz-path /path/to/oss-fuzz --target-dir myproject-src
```

The project name maps to:
- `oss-fuzz/projects/<project>/` — Dockerfile + build scripts
- `gcr.io/oss-fuzz/<project>` — Docker image tag (built locally via `helper.py`, not pulled)
- `/src/<target_dir>` — source location inside the container

For a selection JSON produced by `scripts/select_projects.py`, you can initialize many projects in one pass:

```bash
./scripts/batch_init.sh \
  --json scripts/selected_projects.json \
  --oss-fuzz /path/to/oss-fuzz \
  --jobs 4
```

This writes per-project logs plus a batch summary under `runs/init/_batch_<timestamp>/`.

### Run

```bash
# Initialize project (once, writes to vuljector-projects/):
uv run vuljector init flask --oss-fuzz-path /path/to/oss-fuzz --model-id claude-sonnet-4-6

# Phase by phase (setup builds/caches the ready container locally):
uv run vuljector setup flask
uv run vuljector selection flask static_analysis claude-sonnet-4-6
uv run vuljector selection flask codeql claude-sonnet-4-6
uv run vuljector selection flask fuzz_guided claude-sonnet-4-6
uv run vuljector selection flask llm_explore claude-sonnet-4-6 --max-candidates 10
uv run vuljector selection flask cve_select --max-candidates 5
uv run vuljector injection flask \
    runs/selection/flask/<run_id>/candidates.json claude-sonnet-4-6 --num-vulnerabilities 3
uv run vuljector injection flask \
    runs/selection/flask/<run_id>/candidates.json claude-sonnet-4-6 --num-vulnerabilities 3 --auto-fuzz-poc

# Filter candidates by CWE:
uv run vuljector selection flask static_analysis claude-sonnet-4-6 \
    --cwe-groups "Memory Safety,Injection" --cwe-ids "CWE-476,CWE-787"

# Or all phases at once (injection strategy auto-routes based on selection):
uv run vuljector run flask static_analysis claude-sonnet-4-6

# Post-injection fuzz-backed follow-ons:
uv run vuljector fuzz-poc batch --source-run-dir runs/injection/flask/<run_id>
uv run vuljector fuzz-guided-poc batch --source-run-dir runs/injection/flask/<run_id>
uv run vuljector rex-triage batch --source-run-dir runs/fuzz_poc/flask/<run_id>

# Native AFL++ smoke test:
uv run vuljector afl-smoke jsoncpp --seconds 15
```

## Selection Strategies

Four complementary strategies. Run one or all — they find different vulnerability classes.

### `fuzz_guided`

Harness-first selector for OSS-Fuzz targets. It loads local fuzz surface metadata,
clones the source checkout into `runs/workspaces/<project>/<target_dir>/` if needed,
and ranks candidate slices by how plausibly an existing harness can still reach them.

Each candidate carries a `fuzz_native` metadata block in `SelectionCandidate.extra`
with fields such as:

- `preferred_fuzzer` / `alternate_fuzzers`
- `reachability_kind`
- `existing_harness_viability`
- `hot_path_bucket`
- `helper_judgment`
- `bug_shape`, `format_family`, and input-model hints

This strategy defaults to "no cap" unless you pass `--max-candidates`, which is useful
for batch fuzz-native runs.

```bash
uv run vuljector selection flask fuzz_guided claude-sonnet-4-6
uv run vuljector selection flask fuzz_guided claude-sonnet-4-6 --max-candidates 15
```

### `static_analysis`

Runs a 7-stage AST pipeline on the repo (pure Python, runs on host, no container):

```
Stage 0  Classifier       Detect language, security models, FFI
Stage 1  API Extractor    Extract public API surface
Stage 2  Call Graph       AST parse → checkpoint/operation detection → BFS graph
Stage 3  Enumerator       Checkpoint × Operation cross-product (max 8 hops)
Stage 4  Scorer           Complexity score (6 weighted factors)
Stage 5  CWE Assigner     CWE candidates + injection hint per pair
Stage 6  Gap-fill         Crypto misuse, TOCTOU, missing-check detectors
```

### `codeql`

Runs CodeQL semantic analysis in three tiers. Requires `codeql` on PATH (`brew install codeql`).
C/C++ DB creation runs inside Docker (project image from `dockerhub_image`); Python and JS/TS run on the host.

```
Tier 1  Taint-tracked    Provable source → sink data flow paths  (confidence 0.95–0.60)
Tier 2  Sink-only        All dangerous sinks, no source needed    (confidence 0.70–0.75)
Tier 3  Combinatorial    All (sink × checkpoint) pairs in fn      (confidence 0.75)
```

Supported languages: **Python, JavaScript/TypeScript, C/C++**.

```bash
uv run vuljector selection flask codeql claude-sonnet-4-6
```

### `llm_explore`

Runs a mini-swe-agent inside the project container to autonomously explore the repo and
identify injection candidates. Writes `/tmp/candidates.json` in PipelineOutput format.
Works for any language.

### `cve_select`

Discovers and ranks CVEs for the project from [OSV.dev](https://osv.dev). Retrieves the fixing commit diff via the GitHub API and prepares candidates with CVE metadata (ID, description, CVSS, CWEs, fix diff). Orders CVEs by severity (CRITICAL → HIGH → MEDIUM → LOW) and publication date. Works for any language.

```bash
uv run vuljector selection flask cve_select --max-candidates 10
```

## Injection Strategies

### `llm_inject`

Runs a mini-swe-agent call against a fresh ephemeral container. Given a candidate location and
CWE hint (from any selection strategy), the agent injects a minimal vulnerability and writes a
PoC exploit in one shot. Language-aware prompts for Python, C/C++, and generic bash fallback.

Recent C/C++ flows now prefer a self-contained exploit directory rooted at
`/tmp/exploit/` with `/tmp/exploit/exploit.sh` as the entrypoint so verification,
fuzz follow-ons, and replay packaging all have one stable handoff format.

### `fuzzer_llm_inject`

Auto-selected for `fuzz_guided` candidates. This is a fuzz-native variant of
`llm_inject` that keeps the same basic injection loop but augments the prompt with:

- preferred harness and alternate harness metadata
- format-family and bug-shape hints
- exploit constraints derived from forward fuzzing context
- warnings about helper-vs-endpoint drift and blocker hotspots

Route selection is automatic:

```bash
uv run vuljector selection flask fuzz_guided claude-sonnet-4-6
uv run vuljector injection flask \
    runs/selection/flask/<run_id>/candidates.json claude-sonnet-4-6
```

### `cve_inject`

Reverses a real CVE. Takes the CVE metadata and fix diff (from `cve_select`) as context to re-introduce the vulnerability in the current codebase. The agent has full freedom — it may reverse the exact fix or locate an equivalent pattern elsewhere and inject a semantically equivalent vulnerability.

```bash
uv run vuljector selection flask cve_select --max-candidates 5
uv run vuljector injection flask \
    runs/selection/flask/<run_id>/candidates.json claude-sonnet-4-6 --num-vulnerabilities 2
```

### Shared verification

Regardless of strategy, the patch is applied in a fresh container and verified:

```
exploit on secure code          →  expects zero exit (not triggered)
apply vulnerable code + rebuild →  if the project needs it
unit tests                      →  expects baseline test count to pass
exploit on vulnerable code      →  expects non-zero exit (triggered)
```

Only entries that pass verification are persisted to the dataset.

### Optional post-hoc fuzz follow-up

`injection` can optionally trigger a fuzz-backed follow-on batch immediately after
the injection run completes:

```bash
uv run vuljector injection flask \
    runs/selection/flask/<run_id>/candidates.json claude-sonnet-4-6 \
    --num-vulnerabilities 3 \
    --auto-fuzz-poc
```

This records a `posthoc_fuzz_poc` block in the injection run summary and writes
generated attempts under `runs/fuzz_poc/<project>/...`.

## Fuzz-Backed PoCs

These workflows take a successful injection run and try to turn it into replayable,
fuzzer-oriented exploit artifacts in a dedicated runs namespace.

### `fuzz-poc`

Patch-inference-first flow. It maps a successful injection back onto likely harnesses,
builds minimal exploit inputs, and verifies them with the same secure-vs-vulnerable
replay contract used by the core injector.

```bash
# One successful injection attempt -> one or more fuzz-backed PoCs
uv run vuljector fuzz-poc generate \
  --source-attempt-dir runs/injection/flask/<run_id>/attempt_00

# Whole injection run -> batch generate and verify
uv run vuljector fuzz-poc batch \
  --source-run-dir runs/injection/flask/<run_id>

# Re-run verification only
uv run vuljector fuzz-poc batch-verify \
  --run-dir runs/fuzz_poc/flask/<fuzz_poc_run_id>
```

Artifacts are written under `runs/fuzz_poc/<project>/<run_id>/attempt_XX/` with
`source_injection_result.json`, generated inputs under `artifacts/exploit_files/`,
`fuzz_poc_manifest.json`, `fuzz_poc.py`, and `verification_result.json`.

### `fuzz-guided-poc`

Metadata-first variant of `fuzz-poc`. Instead of inferring everything from the patch,
it trusts the `fuzz_native` selector metadata first: preferred harness, likely format
family, bug shape, seed-template hints, and alternate fuzzer fallbacks.

```bash
uv run vuljector fuzz-guided-poc batch \
  --source-run-dir runs/injection/flask/<run_id>
```

Artifacts are written under `runs/fuzz_poc_guided/<project>/<run_id>/...`, with the
same attempt-oriented structure plus a run-level `verification_summary.json` when
inline verification is enabled.

### Fuzzing Utilities

Operational helpers for these flows live in `scripts/fuzzing/`, including:

- `test_fuzz_native_pipeline.sh` for an end-to-end smoke path
- `review_fuzz_guided_candidates.py` for compact selector review tables
- `triage_fuzz_hot_paths.py` for cheap hot-path bucketing on injection outputs
- metadata mining and harness-mapping helpers for offline analysis

## Rex Triage

`rex-triage` prepares successful replay-backed crash cases for downstream Rex work.
It scans a source run for attempts whose verification already succeeded, stages the
trigger input and vulnerable binary context, tries direct replay plus stdin-compatible
adapter routes, and records whether the case is suitable for Rex handoff.

```bash
uv run vuljector rex-triage batch \
  --source-run-dir runs/fuzz_poc/flask/<run_id>
```

Outputs live under `runs/rex_triage/<project>/<run_id>/attempt_XX/` and include:

- replay logs
- any generated stdin adapter binary
- Rex input/binary staging artifacts
- a run-level `run_summary.json` with prepared, skipped, and Rex-success counts

## CVE Report (Phase 4)

Generate a CVE JSON 5.0 record for any vulnerability in the dataset:

```bash
uv run vuljector cve-report flask vulnerability_8 claude-sonnet-4-6
```

Requires `patch.diff` and `exploit_files/` to be present in the vulnerability folder (produced by injection). Writes `cve_report.json` alongside them. The CWE is validated against the approved list (`src/utils/cwe/cwe_categories.csv`) and the CVSS 3.1 score is computed deterministically from the vector.

## Agent Tasks (Phase 5)

Once vulnerabilities are verified and stored in `vuljector-projects/<project>/vulnerabilities/`,
Phase 5 can run SEC-bench-style synthetic tasks against them. The current canonical task types are:

- `patch`
- `poc-repo`
- `poc-desc`
- `poc-san`

Legacy aliases are still accepted for compatibility:

- `secure_patch -> patch`
- `zero_day_poc -> poc-repo`
- `one_day_poc -> poc-desc`

### Task Types

| Task | What the agent knows | Agent must produce | Validation |
|---|---|---|---|
| `poc-repo` | Repo only | `/testcase/...` bundle | PoC triggers on vulnerable build |
| `poc-desc` | Repo + bug description | `/testcase/...` bundle | Same |
| `poc-san` | Repo + bug description + sanitizer report | `/testcase/...` bundle | SEC-bench-style `secb build` + `secb repro` |
| `patch` | Repo + bug description + sanitizer report | `/tmp/fix.patch` | Reference repro no longer triggers; unit tests pass |

For PoC tasks, the primary artifact is a testcase directory, saved from the agent container as
`artifacts/testcase/` and `artifacts/testcase.tar.gz`. The expected testcase filename is instance-specific
and comes from the local `secb` shim for that vulnerability.

### Run One Task

```bash
uv run vuljector agent-task <project> <vulnerability_id> <task_type> <model_id>

# Examples:
uv run vuljector agent-task libpng vulnerability_0 poc-san openai/gpt-5-mini-2025-08-07
uv run vuljector agent-task brotli vulnerability_18 patch openai/gpt-5-mini-2025-08-07
```

To include structured hints in the prompt:

```bash
uv run vuljector agent-task libpng vulnerability_0 poc-san openai/gpt-5-mini-2025-08-07 --include-hints
```

### Output

```
runs/agent_tasks/<project>/<task_type>/<run_id>/
  task_request.json
  task_spec.json
  task_prompt.txt
  task_system_prompt.txt
  trajectory.json
  validation_result.json
  task_result.json
  artifacts/
    testcase/           # PoC tasks
    testcase.tar.gz     # PoC tasks
    fix.patch           # patch tasks
```

### SEC-Bench-Style Collection

The intended flow for `poc-san` / `patch` data collection is:

1. Rank exported vulnerabilities for likely solvability.
2. Run assisted-first teacher collection with diverse assistance profiles.
3. Keep trajectories, prompts, artifacts, and validation for downstream SFT filtering.

#### 1. Rank Candidate Tasks

```bash
uv run vuljector task-scout <project> --task-modes poc-san,patch

# Example:
uv run vuljector task-scout brotli --task-modes poc-san,patch
```

Outputs land under:

```text
runs/task_scout/<project>/<run_id>/
  scout_summary.json
```

#### 2. Assisted-First Teacher Collection

```bash
uv run vuljector teacher-collect <project> \
  --model-id openai/gpt-5-mini-2025-08-07 \
  --scout-summary runs/task_scout/<project>/<run_id>/scout_summary.json \
  --task-modes poc-san \
  --limit 2 \
  --regimes assisted,oracle,faithful \
  --diversity standard
```

Notes:

- `--regimes assisted,oracle,faithful` runs assisted attempts first.
- `--diversity standard` enables multiple assistance profiles for `poc-san`, such as:
  - `corpus_first`
  - `slice_localized`
  - `hybrid`
- The collector records `teacher_regime`, optional `teacher_assistance`, and task-level results.

Outputs land under:

```text
runs/teacher_collection/<project>/<run_id>/
  collection_request.json
  candidates.json
  collection_summary.partial.json
  collection_summary.json
  attempts.jsonl
  errors.jsonl
  teacher_assistance/
```

Per-attempt task runs still land under:

```text
runs/agent_tasks/<project>/poc-san/<run_id>/
```

### Guided Export / Backfill

Successful guided fuzz PoC validations can be exported into `vuljector-projects` and then consumed by the
task pipeline. Historical successes can be backfilled with:

```bash
uv run vuljector fuzz-guided-poc backfill-exports <project>

# Example:
uv run vuljector fuzz-guided-poc backfill-exports assimp
```

### SFT Trajectory Tiers

`task_result.json` includes `quality_metrics.sft_tier` for downstream filtering.
The raw `trajectory.json` `messages` field contains the full agent conversation for SFT formatting.


## Metrics

Use the `report` subcommand to evaluate injection runs:

```bash
# Aggregate across all runs for a project/method (primary usage)
uv run vuljector report --run-dir runs/injection/flask

# Drill into a single run
uv run vuljector report --run-dir runs/injection/flask/<run_id>
```

Pointing at a project-level directory aggregates all injection runs inside it and prints a per-run summary table followed by rolled-up metrics. Pointing at a single run directory shows that run only.

The report covers:

| Section | Metrics |
|---|---|
| Per-run summary | Attempts, verified count, cost per run |
| Attack success | Patch rate, verification rate, LLM rejection rate, false-positive rate |
| Exploit checks | `exploit_on_vulnerable` / `exploit_on_secure` pass rates |
| Code breakage | Regression count, per-attempt unit test delta |
| Token & cost | Input/output tokens, steps, API calls — mean / median / mode + total cost |
| Format errors | Total format errors, avg per attempt, rate of all API calls |
| Failure causes | Breakdown with counts and bar chart |
| Per-attempt table | Run, candidate, CWE, injection/verification status, steps, API calls, format errors, cost, UT delta, failure cause |
