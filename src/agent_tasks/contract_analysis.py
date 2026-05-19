"""Analyze exported vulnerabilities into SEC-bench-style task contracts."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from functools import lru_cache
from pathlib import Path
from typing import Any

from agent_tasks.secb_contract import derive_selected_fuzzer, derive_testcase_filename
from utils.json_io import write_json
from utils.paths import project_root, workspace_for_project

_EXAMPLE_DIR_KEYWORDS = ("test", "tests", "model", "models", "sample", "samples", "example", "examples")
_FORMAT_EXT_ALIASES = {
    "fbx": [".fbx"],
    "wasm": [".wasm"],
    "js": [".js"],
    "javascript": [".js"],
    "rb": [".rb"],
    "ruby": [".rb"],
    "ppm": [".ppm"],
    "xml": [".xml"],
    "json": [".json"],
    "png": [".png"],
    "jpg": [".jpg", ".jpeg"],
    "jpeg": [".jpg", ".jpeg"],
    "gif": [".gif"],
    "txt": [".txt"],
    "archive": [".zip", ".tar", ".lha", ".7z", ".rar"],
    "image": [".png", ".jpg", ".jpeg", ".ppm", ".bmp", ".gif", ".tga"],
}


def ensure_task_contract(
    project: str,
    vulnerability_id: str,
    *,
    assets: dict[str, Any],
) -> dict[str, Any]:
    """Persist and return a SEC-bench-style task contract for one bundle."""
    vuln_dir = project_root(project) / "vulnerabilities" / vulnerability_id
    path = vuln_dir / "task_contract.json"
    contract = build_task_contract(
        project=project,
        vulnerability_id=vulnerability_id,
        vuln_dir=vuln_dir,
        assets=assets,
    )
    write_json(path, contract)
    return contract


def build_task_contract(
    *,
    project: str,
    vulnerability_id: str,
    vuln_dir: Path,
    assets: dict[str, Any],
) -> dict[str, Any]:
    """Build an analysis-only contract approximating what SEC-bench exposes."""
    metadata = dict(assets.get("metadata") or {})
    context = dict(assets.get("context") or {})
    hints = dict(assets.get("hints") or {})
    selected_fuzzer = derive_selected_fuzzer(vuln_dir, hints=hints)
    testcase_filename = derive_testcase_filename(vuln_dir)
    format_family = _derive_format_family(
        testcase_filename=testcase_filename,
        hints=hints,
        context=context,
        selected_fuzzer=selected_fuzzer,
    )
    repo_root = _project_workspace_repo(project)
    example_summary = _repo_example_summary(
        project=project,
        repo_root=repo_root,
        format_family=format_family,
        testcase_filename=testcase_filename,
        target_file=str(hints.get("target_file") or context.get("target_file") or ""),
    )
    fuzzer_binary = f"/out/{selected_fuzzer}" if selected_fuzzer else ""
    repro_command = [fuzzer_binary, f"/testcase/{testcase_filename}"] if fuzzer_binary else []

    return {
        "schema_version": "v1",
        "project": project,
        "vulnerability_id": vulnerability_id,
        "producer": metadata.get("producer", ""),
        "selected_fuzzer": selected_fuzzer,
        "work_dir": f"/src/{project}",
        "build_command": "secb build",
        "repro_binary": fuzzer_binary,
        "repro_command": repro_command,
        "primary_testcase_filename": testcase_filename,
        "primary_testcase_path": f"/testcase/{testcase_filename}",
        "input_mode": "single_file",
        "input_format_family": format_family,
        "sanitizer_kind": metadata.get("sanitizer_kind") or hints.get("sanitizer_summary") or "",
        "target_file": hints.get("target_file") or context.get("target_file") or "",
        "target_function": hints.get("target_function") or context.get("target_function") or "",
        "success_mode": context.get("success_mode") or metadata.get("success_mode") or "",
        "seed_provenance": context.get("seed_provenance") or metadata.get("seed_provenance") or "",
        "workspace_repo_root": str(repo_root) if repo_root else "",
        "workspace_repo_present": bool(repo_root and repo_root.exists()),
        "repo_example_summary": example_summary,
        "repo_example_friendly": bool(example_summary.get("matching_file_count")),
    }


def summarize_success_path(
    *,
    project: str,
    vulnerability_id: str,
    artifact_path: Path,
    contract: dict[str, Any],
) -> dict[str, Any]:
    """Summarize how a successful artifact relates to repo-visible examples."""
    testcase_filename = str(contract.get("primary_testcase_filename") or "")
    artifact_bytes = _load_primary_testcase_bytes(artifact_path, testcase_filename)
    if artifact_bytes is None:
        return {
            "success_source": "missing_artifact",
            "primary_testcase_filename": testcase_filename,
        }

    artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    artifact_size = len(artifact_bytes)
    example_summary = dict(contract.get("repo_example_summary") or {})
    matched_relpath = _match_repo_example_by_hash(
        project=project,
        artifact_bytes=artifact_bytes,
        candidate_relpaths=list(example_summary.get("matching_files_sample") or []),
        testcase_filename=testcase_filename,
        format_family=str(contract.get("input_format_family") or ""),
    )
    return {
        "success_source": "repo_example" if matched_relpath else "unknown",
        "matched_repo_example_path": matched_relpath or "",
        "primary_testcase_filename": testcase_filename,
        "artifact_sha256": artifact_sha256,
        "artifact_size": artifact_size,
    }


def _project_workspace_repo(project: str) -> Path | None:
    workspace = workspace_for_project(project)
    candidate = workspace / project
    if candidate.exists():
        return candidate
    if workspace.exists():
        return workspace
    return None


def _derive_format_family(
    *,
    testcase_filename: str,
    hints: dict[str, Any],
    context: dict[str, Any],
    selected_fuzzer: str,
) -> str:
    suffix = Path(testcase_filename).suffix.lower().lstrip(".")
    if suffix:
        return suffix
    for raw in (
        hints.get("format_family"),
        context.get("format_family"),
        hints.get("input_model"),
        context.get("input_model"),
    ):
        text = str(raw or "").strip().lower()
        if text:
            return text
    if selected_fuzzer:
        parts = [part for part in selected_fuzzer.lower().split("_") if part]
        if parts:
            return parts[-1]
    return "binary"


def _repo_example_summary(
    *,
    project: str,
    repo_root: Path | None,
    format_family: str,
    testcase_filename: str,
    target_file: str,
) -> dict[str, Any]:
    if repo_root is None or not repo_root.exists():
        return {
            "matching_file_count": 0,
            "matching_dir_count": 0,
            "matching_dirs": [],
            "matching_files_sample": [],
        }

    relpaths = _matching_repo_example_relpaths(
        repo_root=repo_root,
        format_family=format_family,
        testcase_filename=testcase_filename,
        target_file=target_file,
    )
    dir_counts: dict[str, int] = {}
    for relpath in relpaths:
        parent = str(Path(relpath).parent)
        dir_counts[parent] = dir_counts.get(parent, 0) + 1
    ranked_dirs = sorted(
        dir_counts.items(),
        key=lambda item: (-item[1], item[0]),
    )
    return {
        "matching_file_count": len(relpaths),
        "matching_dir_count": len(ranked_dirs),
        "matching_dirs": [
            {"path": path, "file_count": count}
            for path, count in ranked_dirs[:8]
        ],
        "matching_files_sample": relpaths[:20],
        "format_family": format_family,
        "target_file_hint": target_file,
        "workspace_repo_root": str(repo_root),
        "taskcase_suffix": Path(testcase_filename).suffix.lower(),
    }


def _matching_repo_example_relpaths(
    *,
    repo_root: Path,
    format_family: str,
    testcase_filename: str,
    target_file: str,
) -> list[str]:
    exts = _candidate_extensions(format_family, testcase_filename)
    if not exts:
        return []
    relpaths: list[str] = []
    for relpath in _repo_files(repo_root):
        path = Path(relpath)
        if path.suffix.lower() not in exts:
            continue
        lowered = relpath.lower()
        if not any(keyword in lowered for keyword in _EXAMPLE_DIR_KEYWORDS):
            continue
        relpaths.append(relpath)
    relpaths.sort(key=lambda item: _repo_example_rank(item, target_file=target_file))
    return relpaths


def _repo_example_rank(relpath: str, *, target_file: str) -> tuple[int, int, int, str]:
    lowered = relpath.lower()
    basename = Path(relpath).name.lower()
    keyword_hits = sum(1 for keyword in _EXAMPLE_DIR_KEYWORDS if keyword in lowered)
    target_hint = 0
    if target_file:
        stem = Path(target_file).stem.lower()
        target_hint = 1 if stem and stem in basename else 0
    nonbsd_bonus = 1 if "nonbsd" in lowered else 0
    return (-target_hint, -keyword_hits, -nonbsd_bonus, lowered)


def _candidate_extensions(format_family: str, testcase_filename: str) -> list[str]:
    suffix = Path(testcase_filename).suffix.lower()
    if suffix:
        return [suffix]
    lowered = (format_family or "").strip().lower()
    if lowered in _FORMAT_EXT_ALIASES:
        return _FORMAT_EXT_ALIASES[lowered]
    if lowered.startswith("."):
        return [lowered]
    if lowered:
        return [f".{lowered}"]
    return []


@lru_cache(maxsize=128)
def _repo_files(repo_root: Path) -> tuple[str, ...]:
    files: list[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if ".git" in path.parts:
            continue
        try:
            relpath = str(path.relative_to(repo_root))
        except ValueError:
            continue
        files.append(relpath)
    return tuple(sorted(files))


def _load_primary_testcase_bytes(artifact_path: Path, testcase_filename: str) -> bytes | None:
    if artifact_path.is_dir():
        candidate = artifact_path / testcase_filename
        if candidate.exists():
            return candidate.read_bytes()
        all_files = [path for path in artifact_path.rglob("*") if path.is_file()]
        if len(all_files) == 1:
            return all_files[0].read_bytes()
        return None
    if artifact_path.suffixes[-2:] == [".tar", ".gz"] or artifact_path.suffix == ".tgz":
        with tarfile.open(artifact_path, mode="r:gz") as archive:
            members = [member for member in archive.getmembers() if member.isfile()]
            if testcase_filename:
                for member in members:
                    if Path(member.name).name == testcase_filename:
                        extracted = archive.extractfile(member)
                        return extracted.read() if extracted else None
            if len(members) == 1:
                extracted = archive.extractfile(members[0])
                return extracted.read() if extracted else None
        return None
    if artifact_path.is_file():
        return artifact_path.read_bytes()
    return None


def _match_repo_example_by_hash(
    *,
    project: str,
    artifact_bytes: bytes,
    candidate_relpaths: list[str],
    testcase_filename: str,
    format_family: str,
) -> str:
    repo_root = _project_workspace_repo(project)
    if repo_root is None or not repo_root.exists():
        return ""
    candidates = candidate_relpaths or _matching_repo_example_relpaths(
        repo_root=repo_root,
        format_family=format_family,
        testcase_filename=testcase_filename,
        target_file="",
    )[:200]
    artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
    for relpath in candidates:
        candidate = repo_root / relpath
        if not candidate.exists() or not candidate.is_file():
            continue
        if hashlib.sha256(candidate.read_bytes()).hexdigest() == artifact_hash:
            return relpath
    return ""
