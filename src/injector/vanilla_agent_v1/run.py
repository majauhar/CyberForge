"""Vanilla single-prompt agent strategy for vulnerability injection."""

from __future__ import annotations

from injector.base import InjectionRequest, InjectionStrategy
from setup.container_runtime import ContainerRuntime
from utils.swe_agent import SweAgentRequest, ensure_swe_agent_ready, run_single_prompt_agent
from vuljector.io_contracts import InjectionResult, SelectionCandidate, utc_now_iso


class VanillaInjectionStrategy(InjectionStrategy):
    @property
    def id(self) -> str:
        return "vanilla_agent_v1"

    def setup(self, runtime: ContainerRuntime) -> None:
        ensure_swe_agent_ready(runtime)

    def run(
        self,
        runtime: ContainerRuntime,
        request: InjectionRequest,
        candidate: SelectionCandidate,
    ) -> InjectionResult:
        prompt = (
            "Inject exactly one realistic vulnerability at the requested location.\n"
            f"Target file: {candidate.repo_path}\n"
            f"CWE group/id: {candidate.cwe_group} / {candidate.cwe_id}\n"
            "Also create /workspace/run/artifacts/exploit_files/exploit.sh that succeeds "
            "on vulnerable code.\n"
            "Return plain text summary."
        )
        response = run_single_prompt_agent(
            runtime,
            SweAgentRequest(
                model_id=request.model_id,
                prompt=prompt,
                workdir=runtime.repo_dir_in_container,
            ),
        )
        if response.returncode != 0:
            return InjectionResult(
                schema_version="v2",
                project=request.project,
                run_id=request.run_id,
                timestamp_utc=utc_now_iso(),
                status="failure",
                selected_candidate_id=candidate.candidate_id,
                cwe_group=candidate.cwe_group,
                cwe_id=candidate.cwe_id,
                strategy={"id": self.id, "model_id": request.model_id, "retries": 0},
                usage={"token_usage": None, "cost": None, "models_used": [request.model_id]},
                paths={
                    "exploit_dir": "runs/injection/<project>/<run_id>/artifacts/exploit_files",
                    "snapshot_manifest": "runs/injection/<project>/<run_id>/artifacts/snapshot/manifest.json",
                },
                failure={"cause": "other", "message": (response.stderr or response.stdout).strip()},
            )
        return InjectionResult(
            schema_version="v2",
            project=request.project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            status="success",
            selected_candidate_id=candidate.candidate_id,
            cwe_group=candidate.cwe_group,
            cwe_id=candidate.cwe_id,
            strategy={"id": self.id, "model_id": request.model_id, "retries": 0},
            usage={"token_usage": None, "cost": None, "models_used": [request.model_id]},
            paths={
                "exploit_dir": "runs/injection/<project>/<run_id>/artifacts/exploit_files",
                "snapshot_manifest": "runs/injection/<project>/<run_id>/artifacts/snapshot/manifest.json",
            },
            failure=None,
        )

