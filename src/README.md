# Vuljector (V2)

Vuljector V2 is a phase-based pipeline for generating vulnerability snapshots from OSS-Fuzz projects.
It runs three independent phases:

1. `setup`
2. `selection`
3. `injection`

The implementation in this repository follows `ARCHITECTURE.md`.

## Installation

Set up a workspace where these repositories are siblings:

```text
Vuljector/
  VulInjector/
    src/
  oss-fuzz/
  vuljector-projects/
```

```bash
mkdir Vuljector
cd Vuljector
git clone https://github.com/AmL-Dev/VulInjector VulInjector
git clone https://github.com/vuljector/oss-fuzz oss-fuzz
git clone https://github.com/vuljector/vuljector-projects vuljector-projects
```

Then install dependencies:

```bash
cd VulInjector/src
uv sync
```

Requirements:

- Docker
- Git
- Python 3.12+

## Project preparation

Initialize a dataset project from OSS-Fuzz:

```bash
cd ../oss-fuzz/vuljector/init
python3 init_project.py <project>
```

This creates `vuljector-projects/<project>/` with:

- `setup/`
- `project.json`

## CLI usage

Run commands from `VulInjector/src`:

### Setup phase (must run first)

```bash
python3 -m vuljector.cli setup <project>
```

What it does:

- builds/reuses Docker image from `vuljector-projects/<project>/setup/`
- resets repo to `secure_base_commit`
- backs up `.git` into `runs/workspaces/<project>/.git_backup/`
- removes `.git` from container for agent-facing phases
- if `unit_tests/test.sh` exists, computes `unit_tests.expected_passing_count` in `project.json`

### Selection phase

```bash
python3 -m vuljector.cli selection <project> <selection_strategy_id> <model_id> [--cwe-groups G1,G2] [--cwe-ids 79,89]
```

Default strategy implemented in V2:

- `vanilla_agent_v1` (single prompt, single agent run)

### Injection phase

```bash
python3 -m vuljector.cli injection <project> <injection_strategy_id> <model_id> <candidates_file> [--num-vulnerabilities 1] [--debug]
```

Default strategy implemented in V2:

- `vanilla_agent_v1` (single prompt, single agent run)

Debug behavior:

- without `--debug`: persist dataset only on success to `vulnerabilities/`
- with `--debug`: always persist snapshots to:
  - `debug/success/` on success
  - `debug/failed/` on failure

### Convenience wrapper

```bash
python3 -m vuljector.cli run <project> <selection_strategy_id> <injection_strategy_id> <model_id> [--cwe-groups ...] [--cwe-ids ...] [--num-vulnerabilities 1] [--debug]
```

This runs `setup` if needed, then `selection`, then `injection`.

## Outputs

### Runs data

```text
VulInjector/runs/
│
├── setup/<project>/<setup_run_id>/
│   ├── setup_request.json
│   ├── setup_result.json
│   └── setup_log.txt
├── selection/<project>/<selection_run_id>/
│   ├── selection_request.json
│   ├── candidates.json
│   └── selection_log.txt
├── injection/<project>/<injection_run_id>/
│   ├── injection_request.json
│   ├── injection_result.json
│   ├── verification_result.json
│   ├── logs/run.log
│   └── artifacts/
│       ├── exploit_files/
│       └── snapshot/
└── workspaces/<project>/
    ├── runtime.json
    └── .git_backup/
```

### Dataset artifacts

```text
vuljector-projects/<project>/
├── vulnerabilities/vulnerability_N/   # success, non-debug
│   ├── vulnerability_metadata.json
│   ├── exploit_files/
│   └── snapshot/
│       ├── files/
│       └── manifest.json
└── debug/
    ├── success/vulnerability_N/
    └── failed/vulnerability_N/
```

## Notes

- V2 stores vulnerabilities as snapshots, not commits.
- Selection and injection are independent phases, but both require completed setup.
- Per phase run, only one run directory is mounted to the container at `/workspace/run`.
