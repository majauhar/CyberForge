# Vuljector

Automated vulnerability injection and agent task evaluation for synthetic security dataset
creation. Vuljector injects semantically plausible vulnerabilities into real OSS-Fuzz
projects, verifies them (exploit triggers + tests pass), then runs swe-agent-mini on
synthetic tasks derived from those vulnerabilities to collect trajectories for SFT.

## What It Does

Five-phase pipeline:

```
Init             Build image, detect commit, discover test harness → portable project definition
Phase 1 — Setup      Build/cache ready container for local use
Phase 2 — Selection  Find where to inject: static analysis, CodeQL, or LLM exploration
Phase 3 — Injection  Inject vulnerability via LLM agent, verify exploit triggers, snapshot
Phase 4 — CVE Report  Generate a CVE JSON 5.0 record for an existing vulnerability (independent command)
Phase 5 — Agent Tasks Run swe-agent-mini on synthetic tasks, validate output, score trajectory
```

Each phase is independent and rerunnable. Phases communicate through JSON files under `runs/`.

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
GITHUB_TOKEN=ghp_...             # recommended for cve_inject: raises GitHub API limit from 60 to 5 000 req/hr
```

Generate a token at <https://github.com/settings/tokens> (no scopes required for public repos).

### Prerequisites

Clone [oss-fuzz](https://github.com/google/oss-fuzz) alongside this repo:

```bash
git clone --depth=1 https://github.com/google/oss-fuzz ../oss-fuzz
```

The Docker image is built automatically by `setup` when needed — no manual build step required.

### Initialize a project

`init` builds the Docker image, detects the secure base commit, discovers the test harness, and writes everything to `vuljector-projects/`. The result is a self-contained, portable project definition that can be committed and shared. The processed docker image can be storred to dockerhub.  

```bash
uv run vuljector init flask --oss-fuzz-path /path/to/oss-fuzz
```

This creates `vuljector-projects/flask/` with `project.json` (including fetching the proper commit), `setup/`, and `unit_tests/`.
The directory name must exactly match the project name under `oss-fuzz/projects/`.

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
uv run vuljector selection flask llm_explore claude-sonnet-4-6 --max-candidates 10
uv run vuljector injection flask llm_inject claude-sonnet-4-6 \
    runs/selection/flask/<run_id>/candidates.json --num-vulnerabilities 3

# Filter candidates by CWE:
uv run vuljector selection flask static_analysis claude-sonnet-4-6 \
    --cwe-groups "Memory Safety,Injection" --cwe-ids "CWE-476,CWE-787"

# Or all three phases at once:
uv run vuljector run flask static_analysis llm_inject claude-sonnet-4-6
```

## Selection Strategies

Three complementary strategies. Run one or all — they find different vulnerability classes.

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

## Injection Strategies

### `llm_inject`

Runs a mini-swe-agent call against a fresh ephemeral container. Given a candidate location and
CWE hint (from any selection strategy), the agent injects a minimal vulnerability and writes a
PoC exploit in one shot. Language-aware prompts for Python, C/C++, and generic bash fallback.

### `cve_inject`

CVE-inspired injection that requires no prior selection phase. Fetches real CVEs for the project
from [OSV.dev](https://osv.dev), retrieves the fixing commit diff via the GitHub API, and gives
an LLM agent that diff + CVE metadata as context to re-introduce the vulnerability in the current
codebase. The agent has full freedom — it may reverse the exact fix or locate an equivalent
pattern elsewhere.

```bash
# No selection step needed — CVEs are fetched automatically
uv run vuljector cve-injection flask claude-sonnet-4-6 --num-vulnerabilities 2 --max-cves 5
```

Vuljector first discovers and orders the project's CVEs by severity (CRITICAL → HIGH → MEDIUM
→ LOW) and then by most recent publication date. It prepares up to `--max-cves` usable CVEs for
the run by fetching commit diffs only for the highest-ranked entries until it has an ordered
worklist. Injection then runs from that prepared list with a retry queue: failed CVEs are
re-appended up to 3 total tries, successful CVEs are not retried, and `--max-cves` is the size
of the prepared worklist, not a pre-expanded duplicate attempt list. The requested vulnerability
count is capped to the number of prepared CVEs for the project.

The fix diff is pre-filtered to strip test/doc files before being passed to the agent.

### Shared verification

Regardless of strategy, the patch is applied to the persistent container and verified:

```
exploit on vulnerable code  →  expects non-zero exit (triggered)
reset to secure_base_commit →  expects zero exit (not triggered)
unit tests                  →  expects baseline test count to pass
```

Only entries that pass all three checks are persisted to the dataset.

## CVE Report (Phase 4)

Generate a CVE JSON 5.0 record for any vulnerability in the dataset:

```bash
uv run vuljector cve-report flask vulnerability_8 claude-sonnet-4-6
```

Requires `patch.diff`, `exploit_files/`, and `snapshot/` to be present in the vulnerability folder (produced by injection). Writes `cve_report.json` alongside them. The CWE is validated against the approved list (`src/utils/cwe/cwe_categories.csv`) and the CVSS 3.1 score is computed deterministically from the vector.

## Agent Tasks (Phase 5)

Once vulnerabilities are verified and stored in `vuljector-projects/<project>/vulnerabilities/`,
Phase 5 runs swe-agent-mini on three synthetic task types derived from each vulnerability.
Trajectories are saved and scored for downstream SFT filtering.

### Task Types

| Task | What the agent knows | Agent must produce | Validation |
|---|---|---|---|
| `zero_day_poc` | Nothing — must find the vulnerability | `/tmp/attack.py` | Exploit triggers on vulnerable, not on secure baseline |
| `one_day_poc` | CWE, affected file(s), patch diff | `/tmp/attack.py` | Same |
| `secure_patch` | CWE, affected file(s), description | `/tmp/fix.patch` | Reference exploit no longer triggers; unit tests pass |

### Run

```bash
uv run vuljector agent-task <project> <vulnerability_id> <task_type> <model_id>

# Examples:
uv run vuljector agent-task flask vulnerability_0 one_day_poc claude-sonnet-4-6
uv run vuljector agent-task flask vulnerability_0 zero_day_poc claude-sonnet-4-6
uv run vuljector agent-task flask vulnerability_0 secure_patch claude-sonnet-4-6
```

### Output

```
runs/agent_tasks/<project>/<task_type>/<run_id>/
  task_request.json     # inputs
  task_spec.json        # full task spec (CWE, patch diff, affected files)
  trajectory.json       # raw mini-swe-agent conversation
  validation_result.json
  task_result.json      # validation status + quality metrics + SFT tier
  artifacts/
    attack.py           # agent's exploit (PoC tasks)
    fix.patch           # agent's fix (secure_patch task)
```

### SFT Trajectory Tiers

`task_result.json` includes a `quality_metrics.sft_tier` field:

| Tier | Criteria | Action |
|---|---|---|
| `tier1` | `validation=success`, `completed=True`, `format_errors=0` | Keep for SFT |
| `tier2` | `validation=success`, `completed=True`, `format_errors≤2` | Review before SFT |
| `drop` | Any other | Discard |

The raw `trajectory.json` messages field contains the full agent conversation for SFT formatting.


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
