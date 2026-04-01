# test_vuljector

Evaluates Vuljector selection strategies and models across a set of test projects (```test_projects.csv```).

## Usage

```bash
uv run python scripts/eval_vuljector/eval.py <strategy> <injection_model> [options]
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
uv run python scripts/eval_vuljector/eval.py static_analysis azure/gpt-5.1-codex-mini --parallel 9

# llm_explore with a cheaper selection model
uv run python scripts/eval_vuljector/eval.py llm_explore claude-opus-4-6 \
    --selection-model claude-haiku-4-5-20251001 --parallel 4

# sequential matrix over multiple strategies/models
bash scripts/eval_vuljector/run_eval_matrix.sh
```

## Output

Results are written to `evals/<timestamp>_<strategy>_<model>/results.json`.
Per-project run mapping and live status are written to `evals/<timestamp>_<strategy>_<model>/project_runs.json`.
Per-project logs are in `evals/.../logs/<project>/{setup,selection,injection}.log`.

## Metrics

`results.json` contains an `aggregate` section and one entry per project in `results`.

### Aggregate metrics

| Metric | Meaning |
|---|---|
| `total` | Number of projects in the eval |
| `completed` | Projects that finished and produced a per-project result |
| `skipped` | Projects skipped by the eval runner |
| `failed` | Projects that did not complete successfully at the eval-driver level |
| `total_vulns_produced` | Total verified vulnerabilities produced across completed projects |
| `total_vulns_produced_with_unit_tests` | Verified vulnerabilities whose verification also had `unit_tests == "passed"` |
| `total_attempts` | Total number of injection attempts across completed projects |
| `overall_success_rate` | `total_vulns_produced / total_attempts` |
| `overall_success_rate_with_unit_tests` | `total_vulns_produced_with_unit_tests / total_attempts` |
| `avg_steps` | Average mini-swe-agent steps per injection attempt |
| `total_cost_usd` | Sum of recorded model cost across completed projects |
| `cost_per_vuln_produced` | `total_cost_usd / total_vulns_produced` |
| `total_input_tokens` | Sum of recorded input tokens across completed projects |
| `total_output_tokens` | Sum of recorded output tokens across completed projects |
| `total_steps` | Sum of agent steps across completed projects |
| `total_format_errors` | Sum of inferred format/tool-call errors across completed projects |
| `llm_guardrail_refusals` | Attempts blocked by provider guardrails, detected from trajectory exit logs |
| `llm_guardrail_refusal_rate` | `llm_guardrail_refusals / total_attempts` |
| `unit_test_failures` | Attempts where `verification_result.checks["unit_tests"] == "failed"` |
| `unit_test_failure_rate` | `unit_test_failures / total_attempts` |
| `unit_test_parse_errors` | Attempts where unit test parsing failed (`checks["unit_tests"] == "parse_error"`) |
| `unit_test_parse_error_rate` | `unit_test_parse_errors / total_attempts` |
| `unit_test_fail_but_verified` | Attempts where unit tests failed but overall verification still succeeded |
| `unit_test_fail_but_verified_rate` | `unit_test_fail_but_verified / total_attempts` |
| `unit_test_fail_and_exploit_succeeds_on_both` | Attempts where unit tests failed and verification failed with `exploit_succeeds_on_both` |
| `unit_test_fail_and_exploit_succeeds_on_both_rate` | `unit_test_fail_and_exploit_succeeds_on_both / total_attempts` |
| `unit_test_fail_and_exploit_failed_on_vulnerable` | Attempts where unit tests failed and verification failed with `exploit_failed_on_vulnerable` |
| `unit_test_fail_and_exploit_failed_on_vulnerable_rate` | `unit_test_fail_and_exploit_failed_on_vulnerable / total_attempts` |
| `exploit_succeeds_on_both` | Attempts where the exploit triggered on both vulnerable and secure code |
| `exploit_succeeds_on_both_rate` | `exploit_succeeds_on_both / total_attempts` |
| `exploit_failed_on_vulnerable` | Attempts where the exploit did not trigger on the vulnerable code |
| `exploit_failed_on_vulnerable_rate` | `exploit_failed_on_vulnerable / total_attempts` |

### Per-project metrics

| Metric | Meaning |
|---|---|
| `candidates_count` | Number of selected candidates returned for that project |
| `total_attempts` | Number of injection attempts executed for that project |
| `injection_successes` | Attempts where the injector produced a patch artifact |
| `verification_successes` | Attempts whose full verification succeeded |
| `verification_successes_with_unit_tests` | Verification successes whose unit tests also passed |
| `success_rate` | `verification_successes / total_attempts` |
| `success_rate_with_unit_tests` | `verification_successes_with_unit_tests / total_attempts` |
| `first_success_attempt` | 1-based index of the first successful verified attempt |
| `num_vulnerabilities_produced` | Number of persisted vulnerabilities produced for that project |
| `vulnerability_ids` | Output vulnerability IDs for that project |
| `attempts` | Attempt-level detail including `failure_cause`, `checks`, tokens, cost, steps, and unit test counts |
