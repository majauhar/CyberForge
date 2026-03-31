"""
LLMExploreStrategy — autonomous LLM-based candidate discovery.

The agent explores the repo source tree, identifies checkpoint × operation
pairs via reasoning, and writes /tmp/candidates.json in pipeline-compatible
format. Candidates are extracted and converted to SelectionCandidate objects.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from selector.base import SelectionStrategy
from setup.container_runtime import ContainerRuntime
from vuljector.io_contracts import SelectionCandidate, SelectionResult, utc_now_iso
from utils.agent import AgentRequest, run_agent_task
from utils.agent.prompts import REPO_EXPLORE_TASK, SECURITY_SYSTEM_TEMPLATE
from utils.paths import selection_run_dir


# CWE group labels mirrored from cwe.py for offline enrichment.
_FALLBACK_CWE_GROUP = "Input Validation"
_FALLBACK_CWE_ID = "CWE-20"


class LLMExploreStrategy(SelectionStrategy):
    """
    Selection via mini-swe-agent autonomous repository exploration.

    The agent is given the repo path inside the container and asked to produce
    a ranked JSON list of vulnerability injection candidates without any static
    analysis tooling — pure LLM reasoning over the source tree.
    """

    @property
    def id(self) -> str:
        return "llm_explore"

    def setup(self, runtime: ContainerRuntime) -> None:
        pass

    def run(self, runtime: ContainerRuntime, request: Any) -> SelectionResult:
        top_n = getattr(request, "max_candidates", 10) or 10
        model_id = getattr(request, "model_id", "openai/gpt-4o")
        project = request.project

        run_dir = selection_run_dir(request.project, request.run_id)
        traj_path = str(run_dir / "logs" / "llm_explore_trajectory.json")

        agent_req = AgentRequest(
            model_id=model_id,
            prompt=REPO_EXPLORE_TASK.format(project=project, top_n=top_n),
            workdir=runtime.repo_dir_in_container,
            system_template=SECURITY_SYSTEM_TEMPLATE,
            step_limit=40,
            cost_limit=2.0,
            setup_commands=["bash /src/build.sh 2>&1 | tail -20 || true"],
            extract_paths=["/tmp/candidates.json"],
            trajectory_path=traj_path,
        )

        resp = run_agent_task(runtime, agent_req)

        raw_json = resp.extracted_files.get("/tmp/candidates.json", "")
        candidates = _parse_candidates(project, raw_json, top_n)

        return SelectionResult(
            project=project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            selection_strategy_id=self.id,
            candidates=candidates,
        )



def _parse_candidates(project: str, raw_json: str, top_n: int) -> list[SelectionCandidate]:
    """
    Parse the agent's /tmp/candidates.json output into SelectionCandidate objects.

    The agent writes PipelineOutput-compatible JSON:
      {"repo": ..., "candidates": [{file, function, cwe_candidates, injection_hint, ...}]}
    """
    if not raw_json.strip():
        logging.warning("[%s] llm_explore: no candidates.json produced", project)
        return []

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        logging.warning("[%s] llm_explore: invalid JSON in candidates.json: %s", project, exc)
        return []

    raw_list: list[dict] = []
    if isinstance(data, list):
        raw_list = data
    elif isinstance(data, dict):
        raw_list = data.get("candidates", [])

    results: list[SelectionCandidate] = []
    for rank, item in enumerate(raw_list[:top_n], start=1):
        cwe_candidates: list[str] = item.get("cwe_candidates", [])
        cwe_groups: list[str] = item.get("cwe_groups", [])
        lr = item.get("line_range")

        results.append(SelectionCandidate(
            candidate_id=f"llm_{rank:04d}",
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
