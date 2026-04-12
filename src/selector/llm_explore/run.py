"""
LLMExploreStrategy — multi-specialist LLM-based candidate discovery.

A planner LLM call allocates the candidate budget across 4 specialists based
on the project's file list and README.  Each specialist runs sequentially and
receives its allocated pool size, a CWE reference, in-scope file list, and a
handoff of already-claimed locations.  Results are pooled, deduplicated on
(repo_path, symbol), ranked by confidence, and trimmed to top_n.
"""

from __future__ import annotations

import base64
import csv
import dataclasses
import json
import logging
import os
import re
import subprocess
from typing import Any

from selector.base import SelectionStrategy
from setup.container_runtime import ContainerRuntime
from vuljector.io_contracts import SelectionCandidate, SelectionResult, utc_now_iso
from utils.agent import AgentRequest, run_agent_task
from utils.agent.prompts import SPECIALIST_ROLES, build_specialist_explore_task, SECURITY_SYSTEM_TEMPLATE
from utils.agent.runner import _collect_agent_env, _normalize_litellm_model_name
from utils.codebase_snapshot import build_codebase_snapshot
from utils.paths import cwe_categories_csv, project_root, selection_run_dir

_FALLBACK_CWE_GROUP = "Input Validation"
_FALLBACK_CWE_ID = "CWE-20"
_MIN_PER_SPECIALIST = 5      # hard minimum per specialist to ensure coverage

_SCOPE_EXCLUSION_RE = (
    r"/(\.git|__pycache__|node_modules|vendor|third_party|third-party|external"
    r"|dist|build|coverage|site-packages"
    r"|fixture|fixtures|mock|mocks"
    r"|test|tests|testing|spec|specs"
    r"|example|examples|doc|docs"
    r"|bench|benchmark|fuzz|generated|migrations)/"
)


class LLMExploreStrategy(SelectionStrategy):
    """Selection via sequential specialist mini-swe-agents with adaptive budget."""

    @property
    def id(self) -> str:
        return "llm_explore"

    def setup(self, runtime: ContainerRuntime) -> None:
        pass

    def run(self, runtime: ContainerRuntime, request: Any) -> SelectionResult:
        budget = getattr(request, "max_candidates", 10) or 10
        model_id = getattr(request, "model_id", "openai/gpt-4o")
        project = request.project
        language = _selection_language(runtime)
        run_dir = selection_run_dir(request.project, request.run_id)

        runtime_files, readme = _discover_project(runtime, project, language)
        logging.info("[%s] llm_explore: %d in-scope files", project, len(runtime_files))

        allocation = _plan_budget(model_id, project, language, runtime_files, readme, budget)
        logging.info("[%s] llm_explore: allocation %s", project, allocation)

        codebase_tree = build_codebase_snapshot(str(project_root(project)))
        all_candidates: list[SelectionCandidate] = []
        already_found: list[tuple[str, str]] = []

        for role in SPECIALIST_ROLES:
            role_name: str = role["name"]
            pool_size = allocation[role_name]
            logging.info("[%s] llm_explore: specialist '%s' (pool=%d)", project, role_name, pool_size)

            setup_cmds = runtime.pre_agent_setup_commands(
                "bash /src/build.sh 2>&1 | tail -20 || true"
            ) + [
                _runtime_files_mount_command(runtime_files),
                _cwe_mount_command(role["cwe_groups"]),
            ]

            agent_req = AgentRequest(
                model_id=model_id,
                prompt=build_specialist_explore_task(
                    project=project,
                    language=language,
                    role=role,
                    runtime_files=runtime_files,
                    already_found=already_found,
                    codebase_tree=codebase_tree,
                    pool_size=pool_size,
                ),
                workdir=runtime.repo_dir_in_container,
                system_template=SECURITY_SYSTEM_TEMPLATE,
                step_limit=50,
                cost_limit=0.5,
                setup_commands=setup_cmds,
                extract_paths=["/tmp/candidates.json"],
                trajectory_path=str(run_dir / "logs" / f"llm_explore_{role_name}_trajectory.json"),
            )

            resp = run_agent_task(runtime, agent_req)
            role_candidates = _parse_candidates(
                project, resp.extracted_files.get("/tmp/candidates.json", ""),
                pool_size, id_prefix=f"llm_{role_name}",
            )
            logging.info("[%s] llm_explore: '%s' → %d candidates", project, role_name, len(role_candidates))

            all_candidates.extend(role_candidates)
            already_found.extend(
                (c.repo_path, c.symbol) for c in role_candidates if c.repo_path and c.symbol
            )

        return SelectionResult(
            project=project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            selection_strategy_id=self.id,
            candidates=_merge_candidates(all_candidates, budget),
        )


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------

_PLANNER_PROMPT = """\
You are allocating a vulnerability analysis budget for project "{project}" ({language}).
Your goal is to weight each specialist by how relevant its category is to THIS specific codebase.
Do NOT default to an equal split — skew heavily toward the most relevant categories.

Examples of strong skews:
- Web framework / HTTP server → inject injection_input with 50-60% of budget
- C/C++ memory-heavy library → give memory_numeric 50-60%
- Auth / IAM service → give access_control 50-60%
- Async / event-driven runtime → give concurrency_api 40-50%

In-scope source files ({file_count} total):
{file_sample}

README:
{readme_section}

Specialists — allocate exactly {total_pool} total, minimum {min_each} each:
{specialist_lines}

Respond with JSON only:
{{"injection_input": N, "memory_numeric": N, "access_control": N, "concurrency_api": N}}"""


def _plan_budget(
    model_id: str,
    project: str,
    language: str,
    runtime_files: list[str],
    readme: str,
    budget: int,
) -> dict[str, int]:
    total_pool = budget

    file_sample = "\n".join(runtime_files[:60])
    if len(runtime_files) > 60:
        file_sample += f"\n... and {len(runtime_files) - 60} more"
    readme_section = (readme[:2500] + "\n[truncated]") if len(readme) > 2500 else (readme or "(none)")
    specialist_lines = "\n".join(f'- {r["name"]}: {r["focus"][:120]}' for r in SPECIALIST_ROLES)

    prompt = _PLANNER_PROMPT.format(
        project=project, language=language,
        file_count=len(runtime_files), file_sample=file_sample,
        readme_section=readme_section, total_pool=total_pool,
        min_each=_MIN_PER_SPECIALIST, specialist_lines=specialist_lines,
    )

    env = _collect_agent_env(AgentRequest(model_id=model_id, prompt="", workdir="/tmp"))
    os.environ.update(env)

    try:
        import litellm
        if env.get("PYTHONHTTPSVERIFY") == "0":
            litellm.ssl_verify = False
        resp = litellm.completion(
            model=_normalize_litellm_model_name(model_id),
            messages=[
                {"role": "system", "content": "You are a security analysis planner. Respond with JSON only."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=2000, drop_params=True,
        )
        text = (resp.choices[0].message.content or "").strip()
        m = re.search(r"\{[^{}]+\}", text, re.DOTALL)
        if m:
            allocation: dict = json.loads(m.group())
            if set(allocation.keys()) == {r["name"] for r in SPECIALIST_ROLES}:
                return {k: max(_MIN_PER_SPECIALIST, int(v)) for k, v in allocation.items()}
    except Exception as exc:
        logging.warning("[%s] llm_explore: planner failed (%s), equal split", project, exc)

    base = total_pool // len(SPECIALIST_ROLES)
    remainder = total_pool % len(SPECIALIST_ROLES)
    return {r["name"]: base + (1 if i < remainder else 0) for i, r in enumerate(SPECIALIST_ROLES)}


# ---------------------------------------------------------------------------
# Container helpers
# ---------------------------------------------------------------------------

def _selection_language(runtime: ContainerRuntime) -> str:
    return (getattr(runtime, "language", None) or "python").strip().lower() or "python"


def _discover_project(
    runtime: ContainerRuntime, project: str, language: str,
) -> tuple[list[str], str]:
    """Single docker run that returns (runtime_files, readme_text)."""
    lang = (language or "python").lower()
    if lang in {"javascript", "js", "node", "nodejs", "typescript", "ts"}:
        find_part = f'find /src/{project} \\( -name "*.js" -o -name "*.cjs" -o -name "*.mjs" -o -name "*.ts" \\)'
    elif lang in {"c", "cpp", "c++"}:
        find_part = (
            f'find /src/{project} \\( -name "*.c" -o -name "*.cc" -o -name "*.cpp" '
            f'-o -name "*.cxx" -o -name "*.h" -o -name "*.hpp" \\)'
        )
    else:
        find_part = f'find /src/{project} -name "*.py"'

    sentinel = "___README_SENTINEL___"
    bash_cmd = (
        f'{find_part} 2>/dev/null | grep -Ev "{_SCOPE_EXCLUSION_RE}" | sort; '
        f'echo "{sentinel}"; '
        f'for f in /src/{project}/README.md /src/{project}/README'
        f' /src/{project}/README.rst /src/{project}/readme.md; do'
        f' if [ -f "$f" ]; then head -c 3000 "$f"; break; fi; done'
    )
    result = subprocess.run(
        ["docker", "run", "--rm", runtime.require_ready_image(), "bash", "-c", bash_cmd],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        logging.warning("[%s] llm_explore: discovery failed: %s", project, result.stderr[:200])
        return [], ""

    parts = result.stdout.split(sentinel + "\n", 1)
    runtime_files = [l.strip() for l in parts[0].splitlines() if l.strip()]
    readme = parts[1].strip() if len(parts) > 1 else ""
    return runtime_files, readme


def _runtime_files_mount_command(runtime_files: list[str]) -> str:
    payload_b64 = base64.b64encode("\n".join(runtime_files).encode()).decode()
    return (
        f'python3 -c "import base64; '
        f'open(\'/tmp/runtime_files.txt\', \'w\').write(base64.b64decode(\'{payload_b64}\').decode())"'
    )


def _cwe_mount_command(cwe_groups: list[str]) -> str:
    group_set = {g.lower() for g in cwe_groups}
    entries: list[dict] = []
    with open(cwe_categories_csv(), newline="") as f:
        for row in csv.DictReader(f):
            if row["CWE Group"].strip().lower() in group_set:
                entries.append({"id": f"CWE-{row['CWE#'].strip()}", "description": row["Description"].strip()})
    payload_b64 = base64.b64encode(json.dumps(entries).encode()).decode()
    return (
        f'python3 -c "import base64, json; '
        f'open(\'/tmp/cwe_reference.json\', \'w\').write('
        f'json.dumps(json.loads(base64.b64decode(\'{payload_b64}\').decode()), indent=2))"'
    )


# ---------------------------------------------------------------------------
# Candidate parsing and merging
# ---------------------------------------------------------------------------

def _parse_candidates(
    project: str, raw_json: str, limit: int, id_prefix: str = "llm",
) -> list[SelectionCandidate]:
    if not raw_json.strip():
        logging.warning("[%s] llm_explore: no candidates.json", project)
        return []
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        logging.warning("[%s] llm_explore: invalid candidates.json: %s", project, exc)
        return []

    raw_list: list[dict] = data if isinstance(data, list) else data.get("candidates", [])
    results: list[SelectionCandidate] = []
    for rank, item in enumerate(raw_list[:limit], start=1):
        cwe_candidates: list[str] = item.get("cwe_candidates", [])
        cwe_groups: list[str] = item.get("cwe_groups", [])
        lr = item.get("line_range")
        results.append(SelectionCandidate(
            candidate_id=f"{id_prefix}_{rank:04d}",
            rank=rank,
            cwe_id=cwe_candidates[0] if cwe_candidates else _FALLBACK_CWE_ID,
            cwe_group=cwe_groups[0] if cwe_groups else _FALLBACK_CWE_GROUP,
            repo_path=item.get("file", ""),
            symbol=item.get("function", ""),
            location_hint=item.get("injection_hint", ""),
            rationale=item.get("reasoning", item.get("rationale", "llm_explore candidate")),
            confidence=float(item.get("confidence", 0.5)),
            line_range=tuple(lr) if lr and len(lr) == 2 else None,  # type: ignore[arg-type]
            extra={
                "cwe_candidates": cwe_candidates,
                "checkpoint": item.get("checkpoint", {}),
                "operation": item.get("operation", {}),
                "strategy": item.get("strategy", "llm_explore"),
                "difficulty": item.get("difficulty", ""),
                "complexity_score": item.get("complexity_score", 0.0),
                "evidence": item.get("evidence", {}),
            },
        ))
    return results


def _merge_candidates(all_candidates: list[SelectionCandidate], budget: int) -> list[SelectionCandidate]:
    best: dict[tuple[str, str], SelectionCandidate] = {}
    for c in all_candidates:
        key = (c.repo_path, c.symbol)
        if key not in best or c.confidence > best[key].confidence:
            best[key] = c

    sorted_candidates = sorted(best.values(), key=lambda c: c.confidence, reverse=True)
    if len(sorted_candidates) < budget:
        logging.warning("llm_explore: pool has %d unique candidates, fewer than %d requested", len(sorted_candidates), budget)

    return [
        dataclasses.replace(c, candidate_id=f"llm_multi_{rank:04d}", rank=rank)
        for rank, c in enumerate(sorted_candidates[:budget], start=1)
    ]
