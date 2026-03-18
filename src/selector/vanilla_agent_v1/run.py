"""Vanilla single-prompt agent strategy for candidate selection."""

from __future__ import annotations

import json
import re

from selector.base import SelectionRequest, SelectionStrategy
from setup.container_runtime import ContainerRuntime
from utils.swe_agent import SweAgentRequest, ensure_swe_agent_ready, run_single_prompt_agent
from vuljector.io_contracts import SelectionCandidate, SelectionResult, utc_now_iso


class VanillaSelectionStrategy(SelectionStrategy):
    @property
    def id(self) -> str:
        return "vanilla_agent_v1"

    def setup(self, runtime: ContainerRuntime) -> None:
        ensure_swe_agent_ready(runtime)

    def run(self, runtime: ContainerRuntime, request: SelectionRequest) -> SelectionResult:
        filters = {
            "cwe_groups": request.cwe_groups or [],
            "cwe_ids": request.cwe_ids or [],
        }
        prompt = (
            "You are selecting vulnerability injection candidates.\n"
            "Analyze the repository and return STRICT JSON with key 'candidates'.\n"
            "Each candidate must include: candidate_id, rank, cwe_group, cwe_id, repo_path, "
            "symbol, location_hint, rationale, confidence.\n"
            f"Filters: {json.dumps(filters)}\n"
            "Return only JSON."
        )
        response = run_single_prompt_agent(
            runtime,
            SweAgentRequest(
                model_id=request.model_id,
                prompt=prompt,
                workdir=runtime.repo_dir_in_container,
            ),
        )
        candidates = _parse_candidates(response.stdout)
        if not candidates:
            candidates = [_fallback_candidate(runtime)]
        return SelectionResult(
            schema_version="v2",
            project=request.project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            selection_strategy_id=self.id,
            candidates=candidates,
        )


def _parse_candidates(stdout: str) -> list[SelectionCandidate]:
    text = stdout.strip()
    match = re.search(r"\{.*\}", text, flags=re.S)
    if not match:
        return []
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    rows = payload.get("candidates", [])
    out: list[SelectionCandidate] = []
    for idx, row in enumerate(rows, start=1):
        out.append(
            SelectionCandidate(
                candidate_id=str(row.get("candidate_id") or f"cand_{idx:04d}"),
                rank=int(row.get("rank") or idx),
                cwe_group=str(row.get("cwe_group") or "Input Validation"),
                cwe_id=str(row.get("cwe_id") or "79"),
                repo_path=str(row.get("repo_path") or ""),
                symbol=str(row.get("symbol") or ""),
                location_hint=str(row.get("location_hint") or ""),
                rationale=str(row.get("rationale") or ""),
                confidence=float(row.get("confidence") or 0.5),
            )
        )
    return out


def _fallback_candidate(runtime: ContainerRuntime) -> SelectionCandidate:
    cmd = "git ls-files | head -n 1"
    result = runtime.exec(cmd, workdir=runtime.repo_dir_in_container)
    repo_path = result.stdout.strip() or "UNKNOWN_PATH"
    return SelectionCandidate(
        candidate_id="cand_0001",
        rank=1,
        cwe_group="Input Validation",
        cwe_id="79",
        repo_path=repo_path,
        symbol="unknown",
        location_hint="fallback candidate from first tracked file",
        rationale="Fallback candidate because model output was missing/invalid.",
        confidence=0.1,
    )

