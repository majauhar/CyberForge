"""Run adapter for the agent_based_full_v1 injection method."""

from __future__ import annotations

import json

from setup import ContainerRuntime
from vuljector.strategies.base import FailureCause, InjectionContext, InjectionResult


def _write_filtered_cwe_files(
    runtime: ContainerRuntime,
    *,
    cwe_groups: list[str] | None,
    cwe_ids: list[str] | None,
) -> tuple[str | None, str | None]:
    if not cwe_groups and not cwe_ids:
        return None, None

    groups_path = "/tmp/vuljector_cwe_groups.json"
    categories_path = "/tmp/vuljector_cwe_categories.csv"
    groups_json = "/workspace/VulInjector/src/injector/cwe_data/cwe_groups.json"
    categories_csv = "/workspace/VulInjector/src/injector/cwe_data/cwe_categories.csv"

    py = (
        "python3 - <<'PY'\n"
        "import csv, json\n"
        f"groups_filter = {json.dumps(cwe_groups or [])}\n"
        f"ids_filter = set({json.dumps(cwe_ids or [])})\n"
        f"with open('{groups_json}', encoding='utf-8') as f:\n"
        "    groups = json.load(f)\n"
        "if groups_filter:\n"
        "    groups = {k: v for k, v in groups.items() if k in groups_filter}\n"
        f"with open('{groups_path}', 'w', encoding='utf-8') as f:\n"
        "    json.dump(groups, f)\n"
        f"with open('{categories_csv}', newline='', encoding='utf-8') as src:\n"
        f"    with open('{categories_path}', 'w', newline='', encoding='utf-8') as dst:\n"
        "        reader = csv.DictReader(src)\n"
        "        writer = csv.DictWriter(dst, fieldnames=reader.fieldnames)\n"
        "        writer.writeheader()\n"
        "        for row in reader:\n"
        "            if groups and row['CWE Group'] not in groups:\n"
        "                continue\n"
        "            if ids_filter and row['CWE#'] not in ids_filter:\n"
        "                continue\n"
        "            writer.writerow(row)\n"
        "PY"
    )
    result = runtime.exec(py)
    if result.returncode != 0:
        return None, None
    return groups_path, categories_path


def run_agent_based_full_v1(
    *,
    runtime: ContainerRuntime,
    context: InjectionContext,
) -> InjectionResult:
    groups_path, categories_path = _write_filtered_cwe_files(
        runtime,
        cwe_groups=context.cwe_groups,
        cwe_ids=context.cwe_ids,
    )

    run_py = (
        "python3 - <<'PY'\n"
        "import json, sys\n"
        "sys.path.insert(0, '/workspace/VulInjector/src')\n"
        "from injector.agents_basic_injection_v1.workflow import run\n"
        "from utils import OpencodeRunner\n"
        f"result = run('{context.repo_dir_in_container}', "
        f"model={json.dumps(context.model_id)}, "
        "runner=OpencodeRunner(), "
        f"cwe_groups_path={json.dumps(groups_path)}, "
        f"cwe_categories_path={json.dumps(categories_path)})\n"
        "print('VULJECTOR_RESULT_JSON=' + json.dumps(result))\n"
        "PY"
    )
    exec_result = runtime.exec(run_py)
    if exec_result.returncode != 0:
        return InjectionResult(
            status="failure",
            cwe_group=None,
            cwe_id=None,
            failure_cause=FailureCause.OTHER,
            failure_message=(exec_result.stderr or exec_result.stdout).strip(),
            retries=0,
            models_used=[context.model_id],
            token_usage=None,
            cost=None,
            complexity=None,
            exploit_dir_in_container=f"{context.repo_dir_in_container}/exploit_files",
        )

    marker = "VULJECTOR_RESULT_JSON="
    payload = None
    for line in exec_result.stdout.splitlines():
        if line.startswith(marker):
            payload = line[len(marker) :]
    if not payload:
        return InjectionResult(
            status="failure",
            cwe_group=None,
            cwe_id=None,
            failure_cause=FailureCause.OTHER,
            failure_message="Could not parse strategy output JSON.",
            retries=0,
            models_used=[context.model_id],
            token_usage=None,
            cost=None,
            complexity=None,
            exploit_dir_in_container=f"{context.repo_dir_in_container}/exploit_files",
        )

    data = json.loads(payload)
    status = "failure" if data.get("error") else "success"
    return InjectionResult(
        status=status,
        cwe_group=data.get("selected_cwe_group_to_inject"),
        cwe_id=data.get("cwe_id"),
        failure_cause=FailureCause.OTHER if status == "failure" else None,
        failure_message=data.get("error") or "",
        retries=int(data.get("exploit_attempts") or 0),
        models_used=[context.model_id],
        token_usage=None,
        cost=None,
        complexity=None,
        exploit_dir_in_container=f"{context.repo_dir_in_container}/exploit_files",
    )
