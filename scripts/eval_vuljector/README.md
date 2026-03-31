# test_vuljector

Evaluates Vuljector selection strategies and models across a set of test projects (```test_projects.csv```).

## Usage

```bash
uv run python scripts/test_vuljector/eval.py <strategy> <injection_model> [options]
```

| Argument | Description |
|---|---|
| `strategy` | `static_analysis` or `llm_explore` |
| `injection_model` | Model ID for injection (e.g. `azure/gpt-5.1-codex-mini`, `claude-sonnet-4-6`) |

| Option | Default | Description |
|---|---|---|
| `--selection-model` | injection model | Model for selection (`llm_explore` only) |
| `--max-candidates` | 10 | Candidates returned by selection per project |
| `--num-vulns` | 5 | Verified vulnerabilities to produce per project |
| `--parallel` | 1 | Parallel workers |
| `--projects-csv` | `test_projects.csv` | Projects to evaluate |

## Examples

```bash
# static analysis, single model
uv run python scripts/test_vuljector/eval.py static_analysis azure/gpt-5.1-codex-mini --parallel 9

# llm_explore with a cheaper selection model
uv run python scripts/test_vuljector/eval.py llm_explore claude-opus-4-6 \
    --selection-model claude-haiku-4-5-20251001 --parallel 4
```

## Output

Results are written to `evals/<timestamp>_<strategy>_<model>/results.json`.
Per-project run mapping and live status are written to `evals/<timestamp>_<strategy>_<model>/project_runs.json`.
Per-project logs are in `evals/.../logs/<project>/{setup,selection,injection}.log`.
