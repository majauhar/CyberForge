"""CLI entrypoint for vuljector end-to-end runs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parent.parent
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from injector.cwe_data.cwe_helpers import all_valid_cwe_ids, valid_cwe_groups
from vuljector.orchestrator import run_end_to_end


def _split_csv_arg(value: str | None) -> list[str] | None:
    if not value:
        return None
    out = [x.strip() for x in value.split(",") if x.strip()]
    return out or None


def _validate_cwe_inputs(cwe_groups: list[str] | None, cwe_ids: list[str] | None) -> None:
    if cwe_groups:
        valid_groups = valid_cwe_groups()
        invalid_groups = [g for g in cwe_groups if g not in valid_groups]
        if invalid_groups:
            raise ValueError(f"Invalid CWE group(s): {', '.join(invalid_groups)}")
    if cwe_ids:
        valid_ids = all_valid_cwe_ids()
        normalized = [x.removeprefix("CWE-").strip() for x in cwe_ids]
        invalid_ids = [c for c in normalized if c not in valid_ids]
        if invalid_ids:
            raise ValueError(f"Invalid CWE id(s): {', '.join(invalid_ids)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run vuljector end-to-end for a project.")
    parser.add_argument("project", help="Project name in vuljector-projects")
    parser.add_argument("method_id", help="Injection method id (e.g. agent_based_full_v1)")
    parser.add_argument("model_id", help="Model id to use for this run")
    parser.add_argument("--cwe-groups", default=None, help="Comma-separated CWE groups")
    parser.add_argument("--cwe-ids", default=None, help="Comma-separated CWE ids (e.g. 79,89)")
    parser.add_argument("--debug", action="store_true", help="Save failed runs under project/debug")
    args = parser.parse_args()

    cwe_groups = _split_csv_arg(args.cwe_groups)
    cwe_ids = _split_csv_arg(args.cwe_ids)
    _validate_cwe_inputs(cwe_groups, cwe_ids)

    try:
        payload = run_end_to_end(
            project=args.project,
            method_id=args.method_id,
            model_id=args.model_id,
            cwe_groups=cwe_groups,
            cwe_ids=cwe_ids,
            debug=args.debug,
        )
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
