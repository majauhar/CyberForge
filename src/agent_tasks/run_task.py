"""Run swe-agent-mini on a SyntheticTaskSpec."""

from __future__ import annotations

import base64
import io
import logging
import os
from pathlib import Path
import shlex
import shutil
import tarfile

from agent_tasks.models import SyntheticTaskSpec, TaskType
from agent_tasks.secb_contract import build_secb_shim
from agent_tasks.templates import format_task_prompt
from setup.container_runtime import ContainerRuntime
from utils.agent import AgentRequest, AgentResponse, run_agent_task
from utils.agent.prompts import (
    INSTANCE_TEMPLATE,
    SECBENCH_TASK_SYSTEM_TEMPLATE,
    SYSTEM_TEMPLATE,
    build_harness_note,
)
from utils.paths import project_root

logger = logging.getLogger(__name__)

# Agent budget for task runs — more generous than injection since the task is harder.
_STEP_LIMIT = int(os.environ.get("VULJECTOR_STEP_LIMIT", "30"))
_COST_LIMIT = 3.0


def run_agent_on_task(
    runtime: ContainerRuntime,
    spec: SyntheticTaskSpec,
    run_dir: Path,
) -> tuple[AgentResponse, Path]:
    """
    Run swe-agent-mini on a synthetic vulnerability task.

    The agent runs in a fresh container (from the project's ready image).
    setup_commands put the container into the vulnerable state before the agent starts.

    Returns:
        (AgentResponse, trajectory_path)
    """
    if spec.task_type == TaskType.PATCH:
        _stage_reference_exploit_bundle(spec, run_dir)
    _stage_teacher_reference_bundle(spec, run_dir)
    setup_commands = _build_setup_commands(runtime, spec)
    post_commands = _build_post_commands(runtime, spec)
    prompt = _build_prompt(spec)
    system_template = _system_template_for_task(spec)
    extract_paths = [spec.task_type.agent_output_container_path]
    trajectory_path = run_dir / "trajectory.json"
    (run_dir / "task_prompt.txt").write_text(prompt, encoding="utf-8")
    (run_dir / "task_system_prompt.txt").write_text(system_template, encoding="utf-8")

    request = AgentRequest(
        model_id=spec.model_id,
        prompt=prompt,
        workdir=runtime.repo_dir_in_container,
        system_template=system_template,
        instance_template=INSTANCE_TEMPLATE,
        step_limit=_STEP_LIMIT,
        cost_limit=_COST_LIMIT,
        setup_commands=setup_commands,
        post_commands=post_commands,
        extract_paths=extract_paths,
        trajectory_path=str(trajectory_path),
    )

    logger.info(
        "[%s] Running agent task type=%s vuln=%s model=%s",
        spec.project, spec.task_type.value, spec.vulnerability_id, spec.model_id,
    )
    response = run_agent_task(runtime, request)

    # Save extracted artifact to run_dir/artifacts/
    _save_artifact(response, spec, run_dir)

    return response, trajectory_path


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_setup_commands(runtime: ContainerRuntime, spec: SyntheticTaskSpec) -> list[str]:
    """Build the list of setup_commands to run before the agent starts."""
    repo = runtime.repo_dir_in_container
    secb_b64 = base64.b64encode(
        build_secb_shim(
            repo_dir=repo,
            bundle_dir=spec.bundle_dir,
            hints=spec.hints,
            patch_mode=(spec.task_type == TaskType.PATCH),
            language=getattr(runtime, "language", None),
            fuzzing_engine=getattr(runtime, "fuzzing_engine", None),
        ).encode("utf-8")
    ).decode()
    patch_b64 = base64.b64encode(spec.patch_diff.encode("utf-8")).decode()
    cmds: list[str] = [
        f"cd {repo} && git reset --hard {spec.secure_base_commit} && git clean -fdx",
        f"echo '{patch_b64}' | base64 -d > /tmp/vuln.patch && cd {repo} && git apply /tmp/vuln.patch",
        f"cd {repo} && bash /src/build.sh 2>&1 | tail -20 || true",
        "rm -rf /testcase /tmp/testcase && mkdir -p /testcase && ln -s /testcase /tmp/testcase",
        f"echo '{secb_b64}' | base64 -d > /usr/local/bin/secb && chmod +x /usr/local/bin/secb",
        f"rm -rf {repo}/.git && git init {repo}"
        f" && git -C {repo} add -A"
        f" && git -C {repo} -c user.email=vuljector@local -c user.name=vuljector"
        f" commit -m baseline --allow-empty-message 2>&1 | tail -3"
        f" && git -C {repo} rev-parse HEAD > /tmp/vuljector_baseline_commit"
        f" && echo 'Git baseline committed OK'",
    ]

    if spec.teacher_regime == "legacy_assisted":
        cmds.append(
            "test -d /workspace/run/attempt/artifacts/legacy_reference"
            " && chmod -R a+rX /workspace/run/attempt/artifacts/legacy_reference"
            " || true"
        )

    # For patch tasks: install the reference exploit so the agent can verify its fix.
    if spec.task_type == TaskType.PATCH and spec.reference_exploit_path.exists():
        exploit_dir = spec.bundle_dir / "exploit_files"
        if exploit_dir.is_dir():
            cmds.append(
                "test -d /workspace/run/attempt/artifacts/exploit_files"
                " && chmod -R a+rX /workspace/run/attempt/artifacts/exploit_files"
                " && chmod +x /workspace/run/attempt/artifacts/exploit_files/exploit.sh 2>/dev/null || true"
                " && echo 'Reference exploit bundle installed OK'"
            )
        else:
            exploit_bytes = spec.reference_exploit_path.read_bytes()
            exploit_b64 = base64.b64encode(exploit_bytes).decode()
            suffix = spec.reference_exploit_path.suffix.lower() or ".bin"
            container_payload_path = f"/tmp/ref_exploit_payload{suffix}"
            cmds.append(
                f"echo '{exploit_b64}' | base64 -d > {container_payload_path}"
                f" && chmod +x {container_payload_path}"
                " && printf '#!/bin/bash\\n"
                f"if [ \"{suffix}\" = \".sh\" ]; then\\n"
                f"  exec bash {container_payload_path} \"$@\"\\n"
                "else\\n"
                f"  exec python3 {container_payload_path} \"$@\"\\n"
                "fi\\n' > /tmp/ref_exploit.sh"
                " && chmod +x /tmp/ref_exploit.sh"
                " && echo 'Reference exploit installed OK'"
            )

    return cmds


def _stage_reference_exploit_bundle(spec: SyntheticTaskSpec, run_dir: Path) -> None:
    """Copy the reference exploit bundle into the mounted run dir for patch tasks."""
    exploit_dir = spec.bundle_dir / "exploit_files"
    if not exploit_dir.is_dir():
        return
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    destination = artifacts_dir / "exploit_files"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(exploit_dir, destination)


def _stage_teacher_reference_bundle(spec: SyntheticTaskSpec, run_dir: Path) -> None:
    """Expose read-only bundle-side reference artifacts for special assisted runs."""
    if spec.teacher_regime != "legacy_assisted":
        return
    source_dir = spec.bundle_dir / "exploit_files"
    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    reference_dir = artifacts_dir / "legacy_reference"
    if reference_dir.exists():
        shutil.rmtree(reference_dir)
    reference_dir.mkdir(parents=True, exist_ok=True)
    generated_inputs_dir = source_dir / "generated_inputs" if source_dir.is_dir() else None
    if generated_inputs_dir and generated_inputs_dir.is_dir():
        shutil.copytree(generated_inputs_dir, reference_dir / "seeds")
    for filename in (
        "fuzz_poc_manifest.json",
        "task_generation_context.json",
        "bug_report.txt",
        "sanitizer_report.txt",
        "task_contract.json",
        "vulnerability_metadata.json",
    ):
        src = spec.bundle_dir / filename
        if src.exists():
            shutil.copy2(src, reference_dir / filename)


def _build_post_commands(runtime: ContainerRuntime, spec: SyntheticTaskSpec) -> list[str]:
    """Build post_commands that run after the agent but before file extraction."""
    if spec.task_type == TaskType.PATCH:
        # Agent edits the file directly; generate a clean git diff for validation.
        return [
            f"cd {runtime.repo_dir_in_container}"
            " && BASE=$(cat /tmp/vuljector_baseline_commit 2>/dev/null || git rev-parse HEAD)"
            " && git diff --no-color \"$BASE\" > /tmp/fix.patch || true"
        ]
    return []


def _build_prompt(spec: SyntheticTaskSpec) -> str:
    """Format the task prompt for the given spec."""
    harness_path = project_root(spec.project) / "unit_tests" / "test.sh"
    harness_note = build_harness_note(
        harness_available=(
            spec.task_type == TaskType.PATCH and harness_path.exists()
        )
    )

    return format_task_prompt(
        spec.task_type,
        project=spec.project,
        cwe_id=spec.cwe_id,
        cwe_group=spec.cwe_group,
        affected_files=spec.affected_files,
        patch_diff=spec.patch_diff,
        bug_description=spec.bug_description,
        sanitizer_report=spec.sanitizer_report,
        hints=spec.hints,
        include_hints=spec.include_hints,
        teacher_assistance=spec.teacher_assistance,
        harness_note=harness_note,
    )


def _system_template_for_task(spec: SyntheticTaskSpec) -> str:
    if spec.task_type in {TaskType.POC_SAN, TaskType.PATCH}:
        return SECBENCH_TASK_SYSTEM_TEMPLATE
    return SYSTEM_TEMPLATE


def _save_artifact(
    response: AgentResponse,
    spec: SyntheticTaskSpec,
    run_dir: Path,
) -> None:
    """Save the agent's extracted output file to run_dir/artifacts/."""
    container_path = spec.task_type.agent_output_container_path

    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    if spec.task_type.extracts_exploit:
        payload = response.extracted_dirs.get(container_path, "")
        if not payload:
            logger.warning(
                "[%s] Agent did not produce %s (exit_status=%s)",
                spec.project, container_path, response.exit_status,
            )
            return
        testcase_dir = artifacts_dir / "testcase"
        if testcase_dir.exists():
            for path in sorted(testcase_dir.rglob("*"), reverse=True):
                if path.is_file() or path.is_symlink():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
        testcase_dir.mkdir(parents=True, exist_ok=True)
        tar_bytes = base64.b64decode(payload)
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as archive:
            _safe_extract_tar(archive, testcase_dir)
        logger.info("[%s] Saved agent testcase artifact to %s", spec.project, testcase_dir)

        attack_py = testcase_dir / "attack.py"
        exploit_sh = artifacts_dir / "exploit.sh"
        testcase_tar = artifacts_dir / "testcase.tar.gz"
        with tarfile.open(testcase_tar, mode="w:gz") as archive:
            archive.add(testcase_dir, arcname=".")
        if attack_py.exists():
            testcase_dir_q = shlex.quote(str(testcase_dir))
            wrapper = (
                "#!/bin/bash\n"
                f"cd {testcase_dir_q}\n"
                "python3 attack.py \"$@\"\n"
            )
            exploit_sh.write_text(wrapper, encoding="utf-8")
            exploit_sh.chmod(0o755)
        return

    content = response.extracted_files.get(container_path, "")
    if not content:
        logger.warning(
            "[%s] Agent did not produce %s (exit_status=%s)",
            spec.project, container_path, response.exit_status,
        )
        return
    out_path = artifacts_dir / spec.task_type.agent_output_filename
    out_path.write_text(content, encoding="utf-8")
    logger.info("[%s] Saved agent artifact to %s", spec.project, out_path)


def _safe_extract_tar(archive: tarfile.TarFile, destination: Path) -> None:
    """Extract a model-produced testcase archive without allowing path traversal."""
    dest_root = destination.resolve()
    for member in archive.getmembers():
        if member.issym() or member.islnk():
            raise ValueError(f"Unsafe testcase archive link member: {member.name}")
        member_path = (dest_root / member.name).resolve()
        if member.isdir():
            continue
        if not str(member_path).startswith(str(dest_root)):
            raise ValueError(f"Unsafe testcase archive member: {member.name}")
    archive.extractall(destination)


def get_artifact_path(run_dir: Path, spec: SyntheticTaskSpec) -> Path | None:
    """Return the path of the agent's saved artifact, or None if it doesn't exist."""
    if spec.task_type.extracts_exploit:
        testcase_tar = run_dir / "artifacts" / "testcase.tar.gz"
        if testcase_tar.exists():
            return testcase_tar
        return None
    path = run_dir / "artifacts" / spec.task_type.agent_output_filename
    return path if path.exists() else None
