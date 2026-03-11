"""CLI entrypoint for the vulnerability injection workflow."""

import argparse
import csv
import logging
import sys
from pathlib import Path

# Ensure the src root (parent of injector and utils) is on the path (works when run as script or -m)
_src_root = Path(__file__).resolve().parent.parent
if str(_src_root) not in sys.path:
    sys.path.insert(0, str(_src_root))

from injector.agents_basic_injection_v1.workflow import run
from utils import ClaudeAgentRunner, OpencodeRunner

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)

_DEFAULT_RUN_CSV = Path(__file__).resolve().parent / "vul_injector_runs.csv"


def _save_run_result_info(
    *,
    csv_path: Path,
    directory: str,
    model: str | None,
    result: dict,
) -> None:
    """Append a single run's output info record to the CSV file at csv_path."""
    cwe_group = result.get("selected_cwe_group_to_inject") or ""
    cwe_id = result.get("cwe_id") or ""
    error = result.get("error") or ""
    status = "failure" if error else "success"
    # Today, the only structured error comes from exploit validation; record a coarse step label.
    failure_step = "exploit_validation" if error else ""
    failure_message = error

    is_new_file = not csv_path.exists()
    with csv_path.open(mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if is_new_file:
            writer.writerow(
                [
                    "directory",
                    "model",
                    "cwe_group",
                    "cwe_id",
                    "status",
                    "failure_step",
                    "failure_message",
                ]
            )
        writer.writerow(
            [
                directory,
                model or "",
                cwe_group,
                cwe_id,
                status,
                failure_step,
                failure_message,
            ]
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="LangGraph vulnerability injection workflow")
    parser.add_argument("directory", type=str, help="Target codebase directory")
    parser.add_argument("--model", type=str, default=None, help="Model (default depends on agent)")
    parser.add_argument("--cwe-groups-file", type=str, default=None, help="Optional path to a JSON file listing CWE groups to use instead of the default cwe_groups.json")
    parser.add_argument("--cwe-categories-file", type=str, default=None, help="Optional path to a CSV file listing CWE categories to use instead of the default cwe_categories.csv")
    parser.add_argument("--crash-max-retry", type=int, default=None, help="Maximum number of retries for reasoning/parse failures (default is set in workflow)")
    parser.add_argument("--task-failure-max-loop-back", type=int, default=None, help="Maximum number of exploit failure loop-backs before giving up (default is set in workflow)")
    parser.add_argument(
        "--run-csv",
        type=str,
        default=None,
        help="Path to CSV file where run output info (directory, model, cwe_group, cwe_id, status, etc.) is appended (default: next to vul_injector)",
    )
    parser.add_argument("--agent", type=str, choices=("opencode", "claude"), default="opencode", help="Agent backend (default: opencode)")
    args = parser.parse_args()
    runner = ClaudeAgentRunner() if args.agent == "claude" else OpencodeRunner()
    try:
        # Prepare optional retry parameters, falling back to workflow defaults when None.
        run_kwargs = {}
        if args.crash_max_retry is not None:
            run_kwargs["crash_max_retry"] = args.crash_max_retry
        if args.task_failure_max_loop_back is not None:
            run_kwargs["task_failure_max_loop_back"] = args.task_failure_max_loop_back

        result = run(
            args.directory,
            model=args.model,
            runner=runner,
            cwe_groups_path=args.cwe_groups_file,
            cwe_categories_path=args.cwe_categories_file,
            **run_kwargs,
        )
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    # Always persist the run output info (success or failure).
    run_csv_path = Path(args.run_csv) if args.run_csv else _DEFAULT_RUN_CSV
    _save_run_result_info(csv_path=run_csv_path, directory=args.directory, model=args.model, result=result)

    error = result.get("error")
    if error:
        print(f"❌ Failure: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"✅ Success. Session: {result.get('session_id')}")


if __name__ == "__main__":
    main()
