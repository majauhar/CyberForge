# Vuljector

Automated vulnerability injection for synthetic security dataset creation. Vuljector injects
semantically plausible vulnerabilities into real OSS-Fuzz projects and produces verified
(exploit triggers + tests pass) dataset entries.

## What It Does

Three-phase pipeline:

```
Init             Build image, detect commit, discover test harness → portable project definition
Phase 1 — Setup      Build/cache ready container for local use
Phase 2 — Selection  Find where to inject: static analysis or LLM repo exploration
Phase 3 — Injection  Inject vulnerability via LLM agent, verify exploit triggers, snapshot
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
```

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

### Run

```bash
# Initialize project (once, writes to vuljector-projects/):
uv run vuljector init flask --oss-fuzz-path /path/to/oss-fuzz --model-id claude-sonnet-4-6

# Phase by phase (setup builds/caches the ready container locally):
uv run vuljector setup flask
uv run vuljector selection flask static_analysis claude-sonnet-4-6
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

### `static_analysis`

Runs a 7-stage static analysis pipeline on the repo (pure Python, runs on host, no container):

```
Stage 0  Classifier       Detect language, security models, FFI
Stage 1  API Extractor    Extract public API surface
Stage 2  Call Graph       AST parse → checkpoint/operation detection → BFS graph
Stage 3  Enumerator       Checkpoint × Operation cross-product (max 8 hops)
Stage 4  Scorer           Complexity score (6 weighted factors)
Stage 5  CWE Assigner     CWE candidates + injection hint per pair
Stage 6  Gap-fill         Crypto misuse, TOCTOU, missing-check detectors
```

**Key design**: cross-products security checkpoints (null_check, bounds_check, auth_guard, etc.)
with security-critical operations (eval_exec, file_op, subprocess, sql_exec, etc.). No
pattern-library bias — uses code structure.

Produces up to 500 candidates per entry point, ranked by complexity score.

**Limitation**: Python only. C/Go/Java plugins not yet implemented.

### `llm_explore`

Runs a mini-swe-agent inside the project container to autonomously explore the repo and
identify injection candidates. Writes `/tmp/candidates.json` in PipelineOutput format.
Works for any language.

## Injection Strategy

### `llm_inject`

Runs two sequential mini-swe-agent calls against a fresh container (ephemeral, isolated from
the persistent phase container):

1. **Inject** — given candidate location + CWE, agent modifies source files to introduce the
   vulnerability and writes `/tmp/vuln.patch` (git diff format).
2. **Exploit** — agent writes a PoC at `/tmp/attack.py` (or `attack.sh` for C/bash targets),
   runs it inside the container, verifies it triggers.

Language-aware prompts for Python, C/C++, and generic bash fallback.

The patch is then applied to the persistent container and verified:

```
exploit on vulnerable code  →  expects non-zero exit (triggered)
reset to secure_base_commit →  expects zero exit (not triggered)
unit tests                  →  expects baseline test count to pass
```

Only entries that pass all three checks are persisted to the dataset.

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
