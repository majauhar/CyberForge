# CyberForge

CyberForge builds a synthetic security dataset by injecting structural vulnerabilities into
real OSS-Fuzz projects. For each project it selects a plausible injection site, has an LLM agent
introduce a minimal vulnerability, and then verifies that the produced exploit actually triggers
on the vulnerable build but not on the secure one. Every verified case is persisted as a
self-contained instance with the diff, metadata, and exploit artifacts needed to reproduce it.

The installed CLI and Python package are named `vuljector`.

## Setup

Prerequisites:

- Python >= 3.13
- [`uv`](https://github.com/astral-sh/uv)
- Docker (project images are built and run locally)
- A local clone of [OSS-Fuzz](https://github.com/google/oss-fuzz) for image builds

Install (editable):

```bash
uv pip install -e .
# or: uv sync
```

Clone OSS-Fuzz somewhere you can reference by path:

```bash
git clone --depth=1 https://github.com/google/oss-fuzz
```

Create `src/.env` from the template and fill in your API keys:

```bash
cp src/.env.example src/.env
# then edit src/.env
```

## Running injection

The core pipeline is four phases. Each writes JSON under `runs/` and can be rerun independently.
`<model_id>` is any LiteLLM model id (e.g. `claude-sonnet-4-6`).

```bash
# 1. Initialize: build the image, detect the secure base commit, discover the test harness.
#    Writes a portable project definition under vuljector-projects/<project>/.
vuljector init <project> --oss-fuzz-path /path/to/oss-fuzz

# 2. Setup: build and cache the ready container for local use.
vuljector setup <project>

# 3. Selection: find where to inject. Writes candidates.json in the run directory.
vuljector selection <project> static_analysis <model_id>

# 4. Injection: inject and verify. Point it at the candidates.json from step 3.
vuljector injection <project> runs/selection/<project>/<run_id>/candidates.json <model_id> \
    --num-vulnerabilities 3
```

Selection strategies (step 3) are interchangeable: `static_analysis`, `codeql`, `llm_explore`,
and `fuzz_guided`. Injection auto-routes its strategy based on the candidates.

The convenience wrapper runs selection + injection in one call:

```bash
vuljector run <project> static_analysis <model_id> --num-vulnerabilities 3
```

Fuzz-guided PoC path — a first-class flow that turns verified injections into replayable,
fuzzer-backed PoCs:

```bash
vuljector selection <project> fuzz_guided <model_id>
vuljector injection <project> runs/selection/<project>/<run_id>/candidates.json <model_id>
vuljector fuzz-guided-poc batch --source-run-dir runs/injection/<project>/<run_id>
```

Injection can also trigger the fuzz PoC batch inline with `--auto-fuzz-poc`.

## Using the prebuilt projects (skip OSS-Fuzz and `init`)

The released dataset `cyberforge-oss-fuzz-projects/` already contains initialized project
definitions — `project.json` (with `secure_base_commit`, test-harness metadata, and a prebuilt
`dockerhub_image`), `setup/`, `unit_tests/`, and the injected `vulnerabilities/`. Using it, you do
**not** need to clone OSS-Fuzz or run `init`: `setup` pulls the prebuilt `vuljector/<project>:setup`
image from Docker Hub instead of building one.

CyberForge looks for the projects in a directory named `vuljector-projects/` that sits **next to
the repository folder** (there is no environment override). Point it at the dataset with a symlink.
In this supplementary the repo is `code/CyberForge/` and the dataset is
`data/cyberforge-oss-fuzz-projects/`, so from the `code/` directory:

```bash
ln -s ../data/cyberforge-oss-fuzz-projects vuljector-projects
```

Then, with Docker running and `src/.env` filled in, work directly against any project — no `init`,
no OSS-Fuzz:

```bash
vuljector setup <project>                 # pulls vuljector/<project>:setup (no build)
# inject new vulnerabilities into the prebuilt project:
vuljector run <project> static_analysis <model_id> --num-vulnerabilities 3
```

The existing `vulnerabilities/` are also the input for the agent-task and teacher-collection phases
below, so you can run those against the dataset without producing any new injections.

## Generating teacher trajectories

`teacher-collect` turns a project's injected vulnerabilities into synthetic agent tasks, runs
swe-agent-mini on them, and records the successful solve trajectories for SFT. It ranks the
project's candidates itself (via task-scout), so no separate step is needed; it reads from
`vuljector-projects/<project>/` and needs Docker plus a model key in `src/.env`.

```bash
vuljector teacher-collect <project> --model-id <model_id> \
    --task-modes poc-san,patch --regimes faithful,assisted --limit 10
```

- `--task-modes` — task types to attempt (`poc-san`, `patch`).
- `--regimes` — assistance levels tried in order: `faithful` (no hints, for self-distillation) then
  `assisted` (progressive hints).
- `--limit` — max ranked candidates to attempt.

Set `VULJECTOR_TEMP` (e.g. `0.7`) to sample the teacher. To collect across many projects, loop
`teacher-collect` per project (see `run_teacher_gen.sh` for a parallel batch example).

Output goes to `runs/teacher_collection/<project>/<run_id>/`: `collection_summary.json`,
`success_paths.json` (pointers to the winning trajectories), per-task manifests under
`teacher_assistance/`, and `errors.jsonl`.

## Output — what is produced & where

Each phase writes its run under `runs/<phase>/<project>/<run_id>/`:

- `runs/init/...`, `runs/setup/...`
- `runs/selection/<project>/<run_id>/candidates.json`
- `runs/injection/<project>/<run_id>/` — one `attempt_NN/` per try (with `injection_result.json`,
  `verification_result.json`, `artifacts/exploit_files/`) plus a `run_summary.json`.
- `runs/fuzz_poc_guided/...` for the fuzz-guided PoC flow.

Each verified injection is also persisted as a vulnerability instance under
`vuljector-projects/<project>/vulnerabilities/vulnerability_N/`, containing:

- `inject_vulnerability.diff` — the injected code change
- `vulnerability_metadata.json` — project, CWE, and provenance (selection/injection run ids)
- `exploit_files/` — `exploit.sh` (entrypoint), `fuzz_poc.py`, and `generated_inputs/`
- `sanitizer_report.txt` — the crash/sanitizer output for the instance

The `runs/` root can be redirected with the `VULJECTOR_RUNS_ROOT` environment variable.
