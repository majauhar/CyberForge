"""agent_based_full_v1 injection method.

Run via: python3 -m injector.agent_based_full_v1.run --context '<json>'
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import sys
from pathlib import Path

_SRC_ROOT = Path(__file__).resolve().parents[2]
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from injector.base import InjectionMethod
from vuljector.strategies.base import FailureCause, InjectionContext, InjectionResult

_CWE_DATA_DIR = _SRC_ROOT / "injector" / "cwe_data"


class AgentBasedFullV1(InjectionMethod):
    def run(self, context: InjectionContext) -> InjectionResult:
        from injector.agents_basic_injection_v1.workflow import run as workflow_run
        from utils import OpencodeRunner

        cwe_groups_path, categories_path = self._prepare_cwe_files(context)

        result = workflow_run(
            context.repo_dir_in_container,
            model=context.model_id,
            runner=OpencodeRunner(),
            cwe_groups_path=cwe_groups_path,
            cwe_categories_path=categories_path,
            output_dir=context.vuln_dir_in_container,
        )

        if result.get("error"):
            return InjectionResult(
                status="failure",
                cwe_group=None,
                cwe_id=None,
                failure_cause=FailureCause.OTHER,
                failure_message=result["error"],
                retries=int(result.get("exploit_attempts") or 0),
                models_used=[context.model_id],
                token_usage=None,
                cost=None,
                complexity=None,
            )

        return InjectionResult(
            status="success",
            cwe_group=result.get("selected_cwe_group_to_inject"),
            cwe_id=result.get("cwe_id"),
            failure_cause=None,
            failure_message="",
            retries=int(result.get("exploit_attempts") or 0),
            models_used=[context.model_id],
            token_usage=None,
            cost=None,
            complexity=None,
        )

    def _prepare_cwe_files(self, context: InjectionContext) -> tuple[str, str]:
        """Return paths to CWE data files (filtered if cwe_groups/cwe_ids were specified)."""
        default_groups = str(_CWE_DATA_DIR / "cwe_groups.json")
        default_categories = str(_CWE_DATA_DIR / "cwe_categories.csv")

        if not context.cwe_groups and not context.cwe_ids:
            return default_groups, default_categories

        groups_path = "/tmp/vuljector_cwe_groups.json"
        categories_path = "/tmp/vuljector_cwe_categories.csv"

        with open(default_groups, encoding="utf-8") as f:
            groups: dict = json.load(f)
        if context.cwe_groups:
            groups = {k: v for k, v in groups.items() if k in context.cwe_groups}
        with open(groups_path, "w", encoding="utf-8") as f:
            json.dump(groups, f)

        ids_filter = set(context.cwe_ids or [])
        with open(default_categories, newline="", encoding="utf-8") as src:
            reader = csv.DictReader(src)
            with open(categories_path, "w", newline="", encoding="utf-8") as dst:
                writer = csv.DictWriter(dst, fieldnames=reader.fieldnames)
                writer.writeheader()
                for row in reader:
                    if groups and row["CWE Group"] not in groups:
                        continue
                    if ids_filter and row["CWE#"] not in ids_filter:
                        continue
                    writer.writerow(row)

        return groups_path, categories_path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, help="InjectionContext as JSON")
    args = parser.parse_args()

    context = InjectionContext(**json.loads(args.context))
    result = AgentBasedFullV1().run(context)

    out = dataclasses.asdict(result)
    out["failure_cause"] = result.failure_cause.value if result.failure_cause else None
    print(json.dumps(out))


if __name__ == "__main__":
    main()
