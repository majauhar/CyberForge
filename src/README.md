# Vuljector

Vuljector is a phase-based pipeline for generating vulnerability snapshots from OSS-Fuzz projects.
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

Default strategy implemented:

- `vanilla_agent_v1` (single prompt, single agent run)

### Injection phase

```bash
python3 -m vuljector.cli injection <project> <injection_strategy_id> <model_id> <candidates_file> [--num-vulnerabilities 1] [--debug]
```

Default strategy implemented:

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

## Environment variables (`.env`)

Vuljector runs the agent on the host, but all actions execute inside the project container. The
agent/model are configured via environment variables read from `VulInjector/src/.env` (and the
process environment).

Create `VulInjector/src/.env` and set credentials for **one** provider you want to use:

### RChat OpenAI-compatible proxy (example)

```bash
# RChat proxy (OpenAI-compatible)
RCHAT_OSS_API_BASE=https://rchat.nist.gov/proxy
RCHAT_OSS_API_KEY=<your_key>
```

These are mapped to standard OpenAI-style vars for litellm:

- `OPENAI_BASE_URL` / `OPENAI_API_BASE`
- `OPENAI_API_KEY`

On the CLI you can then use:

- `openai/gpt-oss-120b` (recommended)
- or the alias `rchat/gpt-oss-120b` (treated as `openai/gpt-oss-120b`)

### Azure OpenAI (example, `gpt-5-nano`)

```bash
AZURE_ENDPOINT=https://<your-resource>.cognitiveservices.azure.com/
AZURE_API_VERSION=2024-12-01-preview
AZURE_API_KEY=<your_azure_openai_key>
```

These are mapped to the Azure env names used by litellm:

- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_API_VERSION`
- `AZURE_OPENAI_API_KEY`

## Run via `uv run`

All commands below are equivalent to `python3 -m ...`, but ensure you use the locked environment.
Run them from `VulInjector/src`.

### Setup

```bash
uv run -m vuljector.cli setup <project>
```

Example:

```bash
uv run -m vuljector.cli setup flask
```

### Selection

```bash
uv run -m vuljector.cli selection <project> <selection_strategy_id> <model_id> [--cwe-groups G1,G2] [--cwe-ids 79,89]
```

Examples:

```bash
# Using RChat proxy (OpenAI-compatible)
uv run -m vuljector.cli selection flask vanilla_agent_v1 "rchat/gpt-oss-120b"

# Using Azure OpenAI gpt-5-nano
uv run -m vuljector.cli selection flask vanilla_agent_v1 "azure/gpt-5-nano"
```

### Injection (use `--debug` to persist failures)

```bash
uv run -m vuljector.cli injection <project> <injection_strategy_id> <model_id> <candidates_file> [--num-vulnerabilities 1] [--debug]
```

Example:

```bash
uv run -m vuljector.cli injection flask vanilla_agent_v1 "azure/gpt-5-nano" \
  VulInjector/runs/selection/flask/<selection_run_id>/candidates.json \
  --num-vulnerabilities 1 --debug
```

### Convenience wrapper

```bash
uv run -m vuljector.cli run <project> <selection_strategy_id> <injection_strategy_id> <model_id> [--cwe-groups ...] [--cwe-ids ...] [--num-vulnerabilities 1] [--debug]
```

Examples:

```bash
# End-to-end with RChat proxy
uv run -m vuljector.cli run flask vanilla_agent_v1 vanilla_agent_v1 "rchat/gpt-oss-120b" \
  --num-vulnerabilities 1 --debug

# End-to-end with Azure OpenAI
uv run -m vuljector.cli run flask vanilla_agent_v1 vanilla_agent_v1 "azure/gpt-5-nano" \
  --num-vulnerabilities 1 --debug
```

## Notes

- Vuljector stores vulnerabilities as snapshots, not commits.
- Selection and injection are independent phases, but both require completed setup.
- Per phase run, only one run directory is mounted to the container at `/workspace/run`.
