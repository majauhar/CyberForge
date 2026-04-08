# Vuljector Architecture

Vuljector generates a security dataset of executable environments with injected vulnerabilities from OSS-Fuzz projects.
It prioritizes:

- minimal code paths
- clear separation of phases
- explicit JSON contracts between phases
- reproducible container execution
- dataset artifacts saved as file snapshots

## Goals

- Keep the end-to-end flow lightweight and easy to reason about.
- Decouple vulnerability selection from vulnerability injection.
- Standardize all inter-step communication with explicit JSON files.
- Store vulnerabilities as snapshots of modified files with metadata links back to repository paths.
- Run agentic logic inside project containers using SWE-agent mini.

## High-Level Workflow

The workflow is split into three independent phases:

1. Setup phase
2. Vulnerability candidate selection phase
3. Vulnerability injection phase

Ordering constraint:

- `setup` must be run first
- `selection` requires completed setup
- `injection` requires completed setup and a previously generated `candidates.json`
- `cve-report` requires a completed injection (vulnerability folder with `patch.diff`, `exploit_files/`, `snapshot/`)

### Phase 1: Setup

- Build or reuse project container from `vuljector-projects/<project>/setup/`.
- Perform optional strategy-specific setup (dependencies, prompt assets, helper scripts).
- Validate that target repo path exists in container.

**Initial setup only** (git isolation):

- Move repo to `secure_base_commit` (via reset).
- Copy the `.git` directory out of the container and save it under `runs/workspaces/<project>/.git_backup/`.
- Remove `.git` from the container so the agent cannot access git history during selection or injection.
- Restore `.git` only when resetting the repo to `secure_base_commit`; delete it again immediately after the reset.

**Initial setup only** (unit tests baseline):

- If `vuljector-projects/<project>/unit_tests/test.sh` exists, run it in the container and count how many tests pass.
- Store `unit_tests.expected_passing_count` in `project.json`.
- During verification, the same number of tests must pass after injection (not that all pass).

### Phase 2: Candidate selection (category + location)

- Input: project + optional CWE filters + selection strategy id.
- Output: JSON file with ranked candidate locations and proposed CWE mappings.
- Artifact is stored in `runs/selection/` and can be reused for multiple injection runs.

### Phase 3: Injection

- Input: one candidate JSON file + desired vulnerability count + injection strategy id + optional debug flag.
- Reuse prepared container.
- Run strategy inside container.
- Save outputs and logs in `runs/`.
- Persist dataset artifact:
  - **Without debug**: only on success → `vuljector-projects/<project>/vulnerabilities/`.
  - **With debug**: always persist snapshots → `vuljector-projects/<project>/debug/success/` on success, `vuljector-projects/<project>/debug/failed/` on failure.

## Container Execution Model

### What is mounted

Vuljector source is not mounted into the project container.
Only a per-run output directory is mounted (created empty for that run):

- host `Vuljector/runs/(setup|selection|injection)/<project>/<run_id>/` -> container `/workspace/run/`

Optional mounts can be added per strategy, but the baseline flow keeps this minimal.

### SWE-agent mini integration

- SWE-agent mini runs directly inside the project container.
- A utility wrapper in `utils/swe_agent/` owns setup and invocation details.
- Strategies call the wrapper instead of building custom container command glue each time.

## Repository Layout

### Workspace layout

```text
Vuljector/
│
├── Vuljector/
│   └── src/
│       ├── vuljector/            # phase runners, CLI, shared plumbing
│       ├── injector/             # injection strategies + interface
│       ├── selector/             # candidate selection strategies + interface
│       ├── setup/                # container runtime + lifecycle helpers
│       ├── verifier/             # verification pipeline (tests, exploit, snapshot)
│       └── utils/
│           ├── swe_agent/        # SWE-agent setup and run helper
│
├── oss-fuzz/
└── vuljector-projects/
```

### `Vuljector/src` detailed blueprint

The tree above is the high-level view. This section defines the concrete scripts/modules and the
core classes (including abstract interfaces).

```text
Vuljector/src/
│
├── vuljector/
│   ├── cli.py                      # CLI entrypoint; subcommands: setup, selection, injection, cve-injection, run, cve-report
│   ├── core.py                     # shared plumbing for config, runtime, state checks, persistence
│   ├── run_setup.py                # run setup as a first-class independent phase
│   ├── run_selection.py            # require setup; run selector; persist candidates.json
│   ├── run_injection.py            # consume candidates + injector + verifier + dataset persist; --debug route
│   ├── run_cve_injection.py        # fetch CVEs from OSV.dev, synthesise candidates, delegate to run_injection
│   ├── cve_report.py               # generate CVE JSON 5.0 record after successful injection
│   └── io_contracts.py             # dataclasses for request/result payloads; to_dict/from_dict
│
├── selector/
│   ├── base.py                     # SelectionStrategy ABC; id, setup, run
│   ├── registry.py                 # maps strategy_id -> SelectionStrategy impl
│   └── <selector_id>/
│       └── run.py                  # concrete selection strategy
│
├── injector/
│   ├── base.py                     # InjectionStrategy ABC; id, setup, run
│   ├── registry.py                 # maps strategy_id -> InjectionStrategy impl
│   ├── llm_inject/
│   │   └── run.py                  # LLMInjectStrategy: agent injects at a given candidate location
│   └── cve_inject/
│       ├── cve_fetcher.py          # OSV.dev query, GitHub commit diff fetch, noise filtering → CVEData list
│       └── run.py                  # CVEInjectStrategy: agent re-introduces vulnerability guided by CVE fix diff
│
├── setup/
│   ├── container_runtime.py        # ContainerRuntime: build, start, exec, copy, .git backup/restore
│   ├── lifecycle.py                # phase setup helpers; base + optional strategy-specific
│   └── mounts.py                   # mount definitions; defaults to per-run /workspace/run mount
│
├── verifier/
│   ├── pipeline.py                 # run_verification; orchestrates all checks
│   ├── unit_tests.py               # runs unit_tests/test.sh; compares count to expected_passing_count
│   ├── exploit.py                  # runs exploit on vulnerable then secure baseline
│   └── snapshot.py                 # computes changed files; writes snapshot/files + manifest.json
│
└── utils/
    ├── json_io.py                   # load/save JSON with schema versioning
    ├── paths.py                     # path resolution for runs/, workspaces/, project roots
    ├── github_utils.py              # git commands; reset to secure_base_commit; .git backup/restore
    └── swe_agent/
        ├── setup.py                 # install/check SWE-agent mini in container
        ├── runner.py                # execute SWE-agent mini; capture logs to /workspace/run/logs/
        └── models.py                # dataclasses for swe-agent request/response
```

#### `vuljector/` (phase runners and shared plumbing)

- `cli.py`:
  - CLI entrypoint with subcommands:
    - `setup`
    - `selection`
    - `injection` (with `--debug` flag)
    - `cve-injection` (CVE-inspired injection; no prior selection phase required; calls `run_cve_injection.py`)
    - `run` (optional convenience wrapper: runs `setup` if needed, then `selection`, then `injection`)
    - `cve-report` (generate a CVE JSON 5.0 record for an existing vulnerability)
- `core.py`:
  - shared plumbing used by all phase runners:
    - load `project.json`
    - resolve paths
    - prepare/reuse runtime
    - check setup prerequisites
    - persist run metadata/results
- `run_setup.py`:
  - prepare container/runtime, perform initial setup, persist setup state.
- `run_selection.py`:
  - require setup state, run selector strategy, persist `candidates.json`.
- `run_injection.py`:
  - consume candidates + run injector strategy + verifier + dataset persist; honors `debug` flag for artifact location (`vulnerabilities/` vs `debug/success/` or `debug/failed/`).
- `run_cve_injection.py`:
  - fetches CVEs from OSV.dev for the project, resolves fixing commit diffs via GitHub API, synthesises `SelectionCandidate` objects (with CVE data in `extra`), and delegates to `run_injection()` with `strategy_id="cve_inject"`. Implements round-robin retry (up to 3× per CVE).
- `cve_report.py`:
  - after successful injection, runs a mini-agent task inside the project container to analyse the patch diff and exploit script.
  - the agent selects a CWE from the approved list (`utils/cwe/cwe_categories.csv`) and writes `/tmp/cve_analysis.json`.
  - CVSS 3.1 base score and severity are computed from the agent-provided vector using the standard formula (not LLM-generated).
  - the CWE group is inferred by looking up the selected CWE in `cwe_categories.csv`.
  - output is written to `vuljector-projects/<project>/vulnerabilities/vulnerability_N/cve_report.json`.
- `io_contracts.py`:
  - dataclasses / typed loaders for request/result payloads.

#### `selector/` (candidate location + CWE selection)

- `base.py` defines the abstract interface:
  - `class SelectionStrategy(ABC):`
    - `id: str`
    - `setup(runtime) -> None` (optional)
    - `run(runtime, request) -> SelectionResult`
- `registry.py`:
  - maps `selection_strategy_id -> SelectionStrategy` implementation.
- `selector/<selector_id>/run.py`:
  - concrete strategy module (e.g. agentic or heuristic).
  - outputs ranked candidates with rationale/confidence.

#### `injector/` (vulnerability injection)

- `base.py` defines the abstract interface:
  - `class InjectionStrategy(ABC):`
    - `id: str`
    - `setup(runtime) -> None` (optional)
    - `run(runtime, request, candidate) -> InjectionResult`
- `registry.py`:
  - maps `injection_strategy_id -> InjectionStrategy` implementation.
- `injector/<injector_id>/run.py`:
  - concrete injection strategy implementation.
  - typically invokes SWE-agent mini through `utils.swe_agent.runner`.

#### `setup/` (container lifecycle and reproducibility)

- `container_runtime.py`:
  - `ContainerRuntime` class:
    - build/reuse image
    - create/start container
    - run commands
    - copy files
    - reset repo to `secure_base_commit` (uses `utils.github_utils` for .git backup/restore)
- `lifecycle.py`:
  - helpers for phase-specific container lifecycle (start, stop, ensure repo exists).
- `mounts.py`:
  - canonical mount definitions.
  - default mounts only the per-run output directory at `/workspace/run`.

#### `verifier/` (post-injection checks)

- `pipeline.py`:
  - `run_verification(...)` orchestrates all checks and returns structured verdict.
- `unit_tests.py`:
  - runs optional `vuljector-projects/<project>/unit_tests/test.sh`.
  - passes if the number of passing tests matches `unit_tests.expected_passing_count`.
- `exploit.py`:
  - executes exploit on vulnerable code then on secure baseline.
- `snapshot.py`:
  - computes changed files and writes:
    - `snapshot/files/...`
    - `snapshot/manifest.json`

#### `utils/` (shared helpers)

- `github_utils.py`:
  - git operations: reset to `secure_base_commit`, `.git` backup/restore cycle.
- `json_io.py`: load/save JSON with consistent formatting.
- `paths.py`: resolve paths for `runs/`, `workspaces/`, project roots.

#### `utils/swe_agent/` (single integration surface for agent execution)

- `setup.py`:
  - installs/checks SWE-agent mini dependencies in the container.
- `runner.py`:
  - executes SWE-agent mini with normalized inputs/outputs.
  - captures stdout/stderr and writes logs to `/workspace/run/logs/`.
- `models.py`:
  - typed dataclasses for SWE-agent request/response normalization.

#### Core dataclasses (defined in `vuljector/io_contracts.py`)

- `ProjectConfig`
- `SelectionRequest`
- `SelectionCandidate`
- `SelectionResult`
- `InjectionRequest`
- `InjectionResult`
- `VerificationResult`
- `SnapshotFile`
- `SnapshotManifest`

Each dataclass supports `to_dict()` / `from_dict()` helpers for stable JSON I/O.

### `vuljector-projects` layout

```text
vuljector-projects/
│
└── <project>/
    ├── project.json
    ├── setup/
    │   ├── Dockerfile
    │   ├── project.yaml
    │   └── ...
    ├── unit_tests/                     # optional
    │   └── test.sh                     # optional standardized entrypoint
    ├── vulnerabilities/                # production dataset; only on success (no debug)
    │   └── vulnerability_N/
    │       ├── vulnerability_metadata.json
    │       ├── cve_report.json             # CVE JSON 5.0 record; generated after successful injection
    │       ├── exploit_files/
    │       │   └── exploit.sh
    │       └── snapshot/
    │           ├── files/
    │           │   └── ... modified files only ...
    │           └── manifest.json
    └── debug/                          # only when injection run has debug=true
        ├── success/                    # succeeded injection + verification
        │   └── vulnerability_N/
        └── failed/                     # failed injection or verification
            └── vulnerability_N/
```

## `runs/` Architecture

```text
Vuljector/runs/
│
├── setup/
│   └── <project>/
│       └── <setup_run_id>/
│           ├── setup_request.json      # input to setup phase
│           ├── setup_result.json       # output: setup status + baseline info
│           └── setup_log.txt           # optional; combined setup log
│
├── selection/
│   └── <project>/
│       └── <selection_run_id>/
│           ├── selection_request.json    # input to selection phase
│           ├── candidates.json          # output: ranked locations + CWE
│           └── selection_log.txt        # optional; combined log if needed
│
├── injection/
│   └── <project>/
│       └── <injection_run_id>/
│           ├── injection_request.json  # input: references candidates file
│           ├── injection_result.json   # output from injector strategy
│           ├── verification_result.json
│           ├── logs/                    # optional; one file can suffice
│           │   └── run.log
│           └── artifacts/
│               ├── exploit_files/
│               └── snapshot/           # staging before dataset persist
│
└── workspaces/
    └── <project>/
        ├── runtime.json                # container_id, setup_hash, setup_completed, strategy_setup_done
        └── .git_backup/               # .git dir saved during initial setup
```

**Workspaces** is the single location for persistent project-level runtime state:

- **Container metadata**: `runtime.json` holds `container_id`, `setup_hash`, `image_tag`.
- **Setup state**: `runtime.json` holds whether base setup has completed for this project. Selection and injection check this before running.
- **Strategy setup state**: `runtime.json` holds `strategy_setup_done` (map of `phase:strategy_id -> setup_hash`) so strategy-specific setup is not repeated unnecessarily.
- **Git backup**: `.git_backup/` stores the `.git` directory taken from the container during initial setup. It is restored only when resetting the repo to `secure_base_commit`, then removed again.

## Data Contracts (JSON)

All steps communicate through versioned JSON payloads.
Each JSON includes:

- `project`
- `run_id`
- `timestamp_utc`

### 1) `setup_request.json`

Path: `runs/setup/<project>/<setup_run_id>/setup_request.json`

```json
{
  "project": "flask",
  "run_id": "<setup_run_id>",
  "timestamp_utc": "2026-01-01T00:00:00Z"
}
```

### 2) `setup_result.json`

Path: `runs/setup/<project>/<setup_run_id>/setup_result.json`

```json
{
  "project": "flask",
  "run_id": "<setup_run_id>",
  "timestamp_utc": "2026-01-01T00:00:20Z",
  "status": "success",
  "container_id": "<container_id>",
  "secure_base_commit": "<sha>",
  "git_backup_dir": "runs/workspaces/flask/.git_backup",
  "unit_tests": {
    "enabled": true,
    "expected_passing_count": 142
  }
}
```

### 3) `project.json` (dataset project config)

Path: `vuljector-projects/<project>/project.json`

```json
{
  "project": "flask",
  "main_repo_url": "https://github.com/pallets/flask",
  "target_dir": "flask",
  "secure_base_commit": "<sha>",
  "unit_tests": {
    "enabled": true,
    "expected_passing_count": 142
  }
}
```

Notes:

- `main_repo_url` comes from OSS-Fuzz `project.yaml` (`main_repo`) at `init` time.
- `target_dir` is the source location relative to `/src` inside the built image (for example `flask` or `project-parent/tika`).
- `unit_tests` is optional. If present and `enabled=true`, verifier runs `unit_tests/test.sh`.
- `expected_passing_count` is written during setup when the test script is first run; verification passes if the same count passes after injection.

### 4) `selection_request.json`

Path: `runs/selection/<project>/<selection_run_id>/selection_request.json`

```json
{
  "project": "flask",
  "run_id": "<selection_run_id>",
  "timestamp_utc": "2026-01-01T00:00:00Z",
  "selection_strategy_id": "vanilla_agent_v1",
  "model_id": "provider/model",
  "filters": {
    "cwe_groups": ["Input Validation"],
    "cwe_ids": ["79", "89"]
  },
  "max_candidates": 30
}
```

### 5) `candidates.json`

Path: `runs/selection/<project>/<selection_run_id>/candidates.json`

```json
{
  "project": "flask",
  "run_id": "<selection_run_id>",
  "timestamp_utc": "2026-01-01T00:00:10Z",
  "selection_strategy_id": "vanilla_agent_v1",
  "candidates": [
    {
      "candidate_id": "cand_0001",
      "rank": 1,
      "cwe_group": "Input Validation",
      "cwe_id": "79",
      "repo_path": "src/flask/templating.py",
      "symbol": "render_template",
      "location_hint": "unsanitized template parameter propagation",
      "rationale": "short textual reason",
      "confidence": 0.82
    }
  ]
}
```

### 6) `injection_request.json`

Path: `runs/injection/<project>/<injection_run_id>/injection_request.json`

```json
{
  "project": "flask",
  "run_id": "<injection_run_id>",
  "timestamp_utc": "2026-01-01T00:05:00Z",
  "selection_run_id": "<selection_run_id>",
  "candidates_file": "runs/selection/<project>/<selection_run_id>/candidates.json",
  "injection_strategy_id": "vanilla_agent_v1",
  "model_id": "provider/model",
  "num_vulnerabilities": 1,
  "debug": false
}
```

Notes: `debug=true` causes all snapshots (success or failure) to be persisted under `vuljector-projects/<project>/debug/success/` or `debug/failed/`.

### 7) `injection_result.json`

Path: `runs/injection/<project>/<injection_run_id>/injection_result.json`

```json
{
  "project": "flask",
  "run_id": "<injection_run_id>",
  "timestamp_utc": "2026-01-01T00:06:00Z",
  "status": "success",
  "selected_candidate_id": "cand_0001",
  "cwe_group": "Input Validation",
  "cwe_id": "79",
  "strategy": {
    "id": "vanilla_agent_v1",
    "model_id": "provider/model",
    "retries": 2
  },
  "usage": {
    "token_usage": null,
    "cost": null,
    "models_used": ["provider/model"]
  },
  "paths": {
    "exploit_dir": "runs/injection/<project>/<run_id>/artifacts/exploit_files",
    "snapshot_manifest": "runs/injection/<project>/<run_id>/artifacts/snapshot/manifest.json"
  },
  "failure": null
}
```

### 8) `verification_result.json`

Path: `runs/injection/<project>/<injection_run_id>/verification_result.json`

```json
{
  "project": "flask",
  "run_id": "<injection_run_id>",
  "timestamp_utc": "2026-01-01T00:06:20Z",
  "status": "success",
  "checks": {
    "unit_tests": "passed",
    "exploit_on_vulnerable": "passed",
    "exploit_on_secure": "passed"
  },
  "failure_cause": null,
  "failure_message": ""
}
```

## Snapshot Artifact Format

Vulnerabilities are stored as snapshots of modified files.

### Structure

- Only modified/added files are saved under `snapshot/files/`.
- Repository-relative paths are preserved under `snapshot/files/`.
- `snapshot/manifest.json` maps each snapshot file back to its location in the repository tree.

`snapshot/manifest.json`:

```json
{
  "project": "flask",
  "vulnerability_id": "vulnerability_12",
  "files": [
    {
      "repo_path": "src/flask/templating.py",
      "snapshot_path": "snapshot/files/src/flask/templating.py",
      "change_type": "modified"
    }
  ]
}
```

### `vulnerability_metadata.json`

Path: `vuljector-projects/<project>/vulnerabilities/vulnerability_N/vulnerability_metadata.json`

```json
{
  "id": "vulnerability_12",
  "project": "flask",
  "cwe_group": "Input Validation",
  "cwe_id": "79",
  "selection_run_id": "<selection_run_id>",
  "injection_run_id": "<injection_run_id>",
  "snapshot_manifest": "snapshot/manifest.json",
  "snapshot_links": [
    {
      "repo_path": "src/flask/templating.py",
      "snapshot_path": "snapshot/files/src/flask/templating.py"
    }
  ],
  "exploit_dir": "exploit_files",
  "secure_base_commit": "<sha>",
  "complexity": null
}
```

`snapshot_links` explicitly maps each saved file to its location in the original repository tree.

### `cve_report.json`

Path: `vuljector-projects/<project>/vulnerabilities/vulnerability_N/cve_report.json`

Generated after successful injection by `vuljector/cve_report.py`. Follows the CVE JSON 5.0 schema.

```json
{
  "dataType": "CVE_RECORD",
  "dataVersion": "5.0.0",
  "cveMetadata": {
    "cveId": "CVE-VULJECTOR-flask-vulnerability_12",
    "state": "PUBLISHED",
    "datePublished": "2026-01-01T00:07:00Z"
  },
  "containers": {
    "cna": {
      "providerMetadata": { "shortName": "Vuljector" },
      "title": "<one-line title>",
      "descriptions": [{ "lang": "en", "value": "<description>" }],
      "affected": [{ "vendor": "open-source", "product": "flask", "versions": [...] }],
      "problemTypes": [{ "descriptions": [{ "cweId": "CWE-N", "type": "CWE", ... }] }],
      "metrics": [{
        "cvssV3_1": {
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "baseScore": 9.8,
          "baseSeverity": "CRITICAL"
        }
      }],
      "x_vuljector": {
        "vulnerability_id": "vulnerability_12",
        "intended_cwe_group": "<group from injection candidate>",
        "intended_cwe_id": "<CWE-N from injection candidate>",
        "cwe_group": "<group inferred from agent-selected CWE via cwe_categories.csv>",
        "affected_file": "<repo-relative path>",
        "affected_function": "<function name>",
        "impact": "...",
        "proof_of_concept": "...",
        "fix": "..."
      }
    }
  }
}
```

Notes:
- `baseScore` and `baseSeverity` are computed from `vectorString` using the CVSS 3.1 formula — not LLM-generated.
- `x_vuljector.cwe_group` is looked up from `utils/cwe/cwe_categories.csv` using the agent's selected `cweId`.
- `x_vuljector.intended_cwe_group` / `intended_cwe_id` preserve the original injection candidate's CWE for traceability.

## Strategy Interfaces

### Selector

- input: `SelectionRequest` (project, strategy, model, CWE filters)
- output: `SelectionResult` with a ranked list of `SelectionCandidate` objects

### Injector

- input: `InjectionRequest` (project, strategy, model, num vulnerabilities) + `SelectionCandidate`
- output: `InjectionResult` + artifact files written to `/workspace/run/`

Both selectors and injectors implement a consistent ABC:

- `id: str`
- `setup(runtime) -> None` (optional one-time setup, cached by setup hash)
- `run(runtime, request[, candidate]) -> Result`

## Persist Rules

- `runs/setup/`, `runs/selection/`, and `runs/injection/` are always written.
- **Dataset artifacts** (snapshots in `vuljector-projects/<project>/`):
  - **Without debug**: only when injection + verification succeed → `vulnerabilities/`.
  - **With debug**: always persist → `debug/success/` on success, `debug/failed/` on failure.
- Snapshot metadata is the source of truth for vulnerability state; no git commit SHA is required.
