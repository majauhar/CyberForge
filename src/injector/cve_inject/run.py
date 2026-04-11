"""
CVEInjectStrategy — vulnerability injection guided by a real CVE fix diff.

Expects candidate.extra to be populated by selector/cve_select/run.py with CVE data:
  extra["cve_id"]          — CVE or GHSA identifier
  extra["cve_description"] — short description
  extra["cvss"]            — CVSS vector string or "unknown"
  extra["cwes"]            — list[str]
  extra["fix_commit_sha"]  — git SHA of the fixing commit
  extra["fix_diff"]        — filtered unified diff of the fixing commit
"""

from __future__ import annotations

import logging
from pathlib import Path

from injector.base import InjectionStrategy
from injector.llm_inject.run import _get_language_context, _parse_post_results
from setup.container_runtime import ContainerRuntime
from utils.agent import AgentRequest, run_agent_task
from utils.paths import project_root
from utils.agent.prompts import SYSTEM_TEMPLATE, build_harness_note
from utils.agent.prompts.cve_injection import CVE_INJECT_TASK
from utils.agent.result import AgentTelemetry
from vuljector.io_contracts import InjectionResult, SelectionCandidate, utc_now_iso

logger = logging.getLogger(__name__)


class CVEInjectStrategy(InjectionStrategy):
    """
    Injection via mini-swe-agent using a real CVE fix diff as context.

    The agent studies the fixing commit diff, locates an equivalent vulnerable
    pattern in the current codebase, injects a minimal regression, and writes
    a PoC exploit — all in one container session.
    """

    @property
    def id(self) -> str:
        return "cve_inject"

    def run(
        self,
        runtime: ContainerRuntime,
        request,
        candidate: SelectionCandidate,
    ) -> InjectionResult:
        extra = candidate.extra or {}
        cve_id = extra.get("cve_id") or candidate.candidate_id
        cve_description = extra.get("cve_description", "")
        cvss = extra.get("cvss", "unknown")
        cwes_list: list[str] = extra.get("cwes") or ([candidate.cwe_id] if candidate.cwe_id else [])
        fix_diff = extra.get("fix_diff", "")
        cwes_str = ", ".join(cwes_list) or "unknown"

        setup_commands = runtime.pre_agent_setup_commands("bash /src/build.sh 2>&1 | tail -30 || true")
        harness_available = (project_root(request.project) / "unit_tests" / "test.sh").exists()

        lang_ctx = _get_language_context(
            candidate.language or runtime.language or "python",
            project=request.project,
            cwes=cwes_str,
            injection_hint=cve_id,
        )
        exploit_path = lang_ctx["exploit_path"]
        exploit_filename = lang_ctx["exploit_filename"]

        task_prompt = CVE_INJECT_TASK.format(
            project=request.project,
            cve_id=cve_id,
            cvss=cvss,
            cwes=cwes_str,
            cve_description=cve_description,
            fix_diff=fix_diff,
            harness_note=build_harness_note(harness_available),
            **{k: lang_ctx[k] for k in (
                "syntax_check_section", "exploit_template_section",
                "run_exploit_cmd", "exploit_file_rule",
            )},
        )

        post_commands: list[str] = [
            f"cd {runtime.repo_dir_in_container} && git diff HEAD > /tmp/vuln.patch || true"
        ]
        if harness_available:
            post_commands.append(
                "bash /workspace/run/unit_tests/test.sh > /tmp/harness_out.txt 2>&1"
                "; echo HARNESS_EXIT:$?; tail -20 /tmp/harness_out.txt"
            )
        post_commands.append(
            f"{lang_ctx['post_run_cmd']} > /tmp/attack_out.txt 2>&1"
            "; echo ATTACK_EXIT:$?; tail -30 /tmp/attack_out.txt"
        )

        traj_name = f"{request.attempt_dir}_trajectory.json" if request.attempt_dir else "cve_inject_trajectory.json"
        trajectory_path = str(
            runtime.run_mount_dir / "logs" / traj_name
        ) if runtime.run_mount_dir is not None else ""

        agent_req = AgentRequest(
            model_id=request.model_id,
            prompt=task_prompt,
            workdir=runtime.repo_dir_in_container,
            system_template=SYSTEM_TEMPLATE,
            step_limit=40,
            cost_limit=2.0,
            setup_commands=setup_commands,
            extract_paths=["/tmp/vuln.patch", exploit_path],
            post_commands=post_commands,
            trajectory_path=trajectory_path,
        )

        logger.info(
            "[%s] cve_inject: cve=%s cwes=%s",
            request.project, cve_id, cwes_str,
        )

        resp = run_agent_task(runtime, agent_req)

        patch_diff = resp.extracted_files.get("/tmp/vuln.patch", "")
        exploit_script = resp.extracted_files.get(exploit_path, "").strip()
        harness_passed, attack_triggered = _parse_post_results(resp.post_results)

        attempt_prefix = request.attempt_dir + "/" if request.attempt_dir else ""
        artifacts_rel = f"{attempt_prefix}artifacts"
        exploit_rel = f"{artifacts_rel}/exploit_files"
        snapshot_rel = f"{artifacts_rel}/snapshot"

        if runtime.run_mount_dir is not None:
            exploit_dir = runtime.run_mount_dir / exploit_rel
            exploit_dir.mkdir(parents=True, exist_ok=True)
            if exploit_script:
                (exploit_dir / exploit_filename).write_text(exploit_script, encoding="utf-8")
                exploit_sh = (
                    "#!/bin/bash\n"
                    f"cd /src/{request.project}\n"
                    f"{lang_ctx['exploit_run_cmd']}\n"
                )
                (exploit_dir / "exploit.sh").write_text(exploit_sh, encoding="utf-8")
            if patch_diff:
                (runtime.run_mount_dir / artifacts_rel / "vuln.patch").write_text(
                    patch_diff, encoding="utf-8"
                )

        telemetry = AgentTelemetry.from_agent(
            model=request.model_id,
            exit_status=resp.exit_status,
            wall_time_s=0.0,
            messages=resp.messages,
            trajectory_path=trajectory_path,
        )

        succeeded = bool(patch_diff)
        strategy_meta = {"id": self.id, "model_id": request.model_id, "cve_id": cve_id}
        usage = {
            "total_steps": telemetry.total_steps,
            "total_input_tokens": telemetry.total_input_tokens,
            "total_output_tokens": telemetry.total_output_tokens,
            "estimated_cost_usd": telemetry.estimated_cost_usd,
            "models_used": [request.model_id],
        }
        paths = {
            "exploit_dir": exploit_rel,
            "snapshot_manifest": f"{snapshot_rel}/manifest.json",
        }

        if not succeeded:
            failure_msg = "Agent did not produce /tmp/vuln.patch" if not patch_diff else (resp.stderr or resp.stdout or f"exit_status={resp.exit_status}")
            logger.warning("[%s] cve_inject FAILED: %s", request.project, failure_msg)
            return InjectionResult(
                project=request.project,
                run_id=request.run_id,
                timestamp_utc=utc_now_iso(),
                status="failure",
                selected_candidate_id=candidate.candidate_id,
                cwe_group=candidate.cwe_group,
                cwe_id=candidate.cwe_id,
                strategy=strategy_meta,
                usage=usage,
                paths=paths,
                failure={"cause": "agent_failed", "message": failure_msg},
            )

        logger.info(
            "[%s] cve_inject OK: patch=%d chars exploit=%d chars harness_passed=%s attack_triggered=%s",
            request.project, len(patch_diff), len(exploit_script),
            harness_passed, attack_triggered,
        )
        return InjectionResult(
            project=request.project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            status="success",
            selected_candidate_id=candidate.candidate_id,
            cwe_group=candidate.cwe_group,
            cwe_id=candidate.cwe_id,
            strategy=strategy_meta,
            usage=usage,
            paths=paths,
            artifacts={
                "patch_diff": patch_diff,
                "attack_script": exploit_script,
                "exploit_filename": exploit_filename,
                "harness_passed": str(harness_passed),
                "attack_triggered": str(attack_triggered),
                "cve_id": cve_id,
            },
            failure=None,
        )
