"""Load exported vulnerability bundles into SEC-bench-style SyntheticTaskSpec objects."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agent_tasks.assets import ensure_task_assets, load_bug_description_variant
from agent_tasks.models import SyntheticTaskSpec, TaskType
from utils.cwe import resolve_cwe_group
from utils.paths import project_root

logger = logging.getLogger(__name__)


def load_vulnerability(
    project: str,
    vulnerability_id: str,
    task_type: TaskType,
    model_id: str,
    *,
    variant_id: str | None = None,
    include_hints: bool = False,
    teacher_regime: str = "faithful",
    teacher_assistance: dict | None = None,
) -> SyntheticTaskSpec:
    """Load one exported vulnerability bundle and materialize a task spec."""
    vuln_dir = project_root(project) / "vulnerabilities" / vulnerability_id
    if not vuln_dir.exists():
        raise FileNotFoundError(
            f"Vulnerability directory not found: {vuln_dir}\n"
            "Generate or export verified vulnerabilities first."
        )

    assets = ensure_task_assets(project, vulnerability_id, model_id=model_id)
    metadata = assets["metadata"]
    if not metadata:
        raise FileNotFoundError(f"vulnerability_metadata.json missing in {vuln_dir}")

    patch_diff = _load_text(vuln_dir / "inject_vulnerability.diff")
    if patch_diff is None:
        raise FileNotFoundError(f"inject_vulnerability.diff missing in {vuln_dir}")

    reference_exploit = _resolve_reference_exploit(vuln_dir)
    cwe_id = metadata.get("cwe_id", "CWE-UNKNOWN")
    cwe_group = resolve_cwe_group(cwe_id, fallback=metadata.get("cwe_group", "Unknown"))
    secure_base_commit = metadata.get("secure_base_commit", "")
    affected_files = _affected_files_from_patch(patch_diff)

    resolved_variant_id = "v0"
    bug_description = ""
    if task_type.prompt_uses_description:
        resolved_variant_id = variant_id or _default_variant_id(vuln_dir)
        variant_payload = load_bug_description_variant(vuln_dir, resolved_variant_id)
        bug_description = str(variant_payload.get("description", "")).strip()

    instance_variant = resolved_variant_id if task_type.prompt_uses_description else "v0"
    instance_id = f"{project}.{vulnerability_id}.{task_type.value}.{instance_variant}"

    return SyntheticTaskSpec(
        project=project,
        vulnerability_id=vulnerability_id,
        task_type=task_type,
        model_id=model_id,
        instance_id=instance_id,
        secure_base_commit=secure_base_commit,
        cwe_id=cwe_id,
        cwe_group=cwe_group,
        affected_files=affected_files,
        patch_diff=patch_diff,
        reference_exploit_path=reference_exploit,
        bundle_dir=vuln_dir,
        producer=str(metadata.get("producer", "")),
        bug_description=bug_description,
        bug_description_variant_id=instance_variant,
        bug_report=str(assets.get("bug_report", "")),
        sanitizer_report=str(assets.get("sanitizer_report", "")),
        hints=dict(assets.get("hints") or {}),
        include_hints=include_hints,
        teacher_regime=teacher_regime,
        teacher_assistance=dict(teacher_assistance or {}),
    )


def _resolve_reference_exploit(vuln_dir: Path) -> Path:
    candidates = (
        vuln_dir / "exploit_files" / "fuzz_poc.py",
        vuln_dir / "exploit_files" / "attack.py",
        vuln_dir / "exploit_files" / "exploit.sh",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"Reference exploit not found in {vuln_dir / 'exploit_files'}")


def _default_variant_id(vuln_dir: Path) -> str:
    payload = _load_json(vuln_dir / "bug_description_variants.json") or {}
    variants = payload.get("variants") or []
    if not variants:
        raise FileNotFoundError(
            f"No bug description variants found in {vuln_dir}. "
            "Run asset generation with a model first."
        )
    return str(variants[0].get("variant_id") or "v1")


def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return None


def _load_text(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.warning("Failed to read %s: %s", path, exc)
        return None


def _affected_files_from_patch(patch_diff: str) -> list[str]:
    files: list[str] = []
    seen: set[str] = set()
    for line in patch_diff.splitlines():
        if not line.startswith("diff --git "):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        repo_path = parts[3]
        if repo_path.startswith("b/"):
            repo_path = repo_path[2:]
        if repo_path and repo_path not in seen:
            seen.add(repo_path)
            files.append(repo_path)
    return files
