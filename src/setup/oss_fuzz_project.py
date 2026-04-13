"""Helpers for reading OSS-Fuzz project setup metadata."""

from __future__ import annotations

import re
import shlex
from pathlib import Path


def infer_target_dir(oss_fuzz_project_dir: Path, repo_url: str, default: str) -> str:
    dockerfile = oss_fuzz_project_dir / "Dockerfile"
    if not dockerfile.exists():
        return default

    text = dockerfile.read_text(encoding="utf-8")
    joined = re.sub(r"\\\s*\n", " ", text)
    main_norm = _normalize_repo_url(repo_url)
    main_base = _repo_basename(repo_url)
    workdirs: list[str] = []
    basename_clone_targets: list[str] = []

    for line in joined.splitlines():
        clone = _parse_git_clone(line)
        if clone:
            clone_url, dest = clone
            if _normalize_repo_url(clone_url) == main_norm:
                if dest:
                    return _target_dir_from_dest(dest, default)
                return _repo_basename(clone_url) or default
            if dest and _repo_basename(clone_url) == main_base:
                basename_clone_targets.append(_target_dir_from_dest(dest, default))

        workdir = _parse_src_workdir(line)
        if workdir:
            workdirs.append(workdir)

    for target in basename_clone_targets:
        if target:
            return target

    for workdir in reversed(workdirs):
        target = _target_dir_from_dest(workdir, default="")
        if target:
            return target
    return default


def _normalize_repo_url(url: str) -> str:
    cleaned = url.strip().strip("'\"").rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    if cleaned.startswith("git@") and ":" in cleaned:
        host, path = cleaned[4:].split(":", 1)
        return f"{host}/{path}".lower()
    return cleaned.lower()


def _repo_basename(url: str) -> str:
    cleaned = url.strip().strip("'\"").rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    return cleaned.rsplit("/", 1)[-1]


def _target_dir_from_dest(dest: str, default: str) -> str:
    rel = dest.strip().strip("'\"").rstrip("/")
    for prefix in ("$SRC/", "${SRC}/", "/src/"):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
            break
    if rel.startswith("./"):
        rel = rel[2:]
    rel = rel.lstrip("/")
    return rel or default


def _parse_git_clone(line: str) -> tuple[str, str | None] | None:
    tokens = _split_shell_tokens(line)
    if not tokens:
        return None

    for i in range(len(tokens) - 1):
        if tokens[i] == "git" and tokens[i + 1] == "clone":
            return _clone_url_and_dest(tokens[i + 2 :])
    return None


def _clone_url_and_dest(tokens: list[str]) -> tuple[str, str | None] | None:
    opts_with_value = {
        "--branch",
        "--config",
        "--depth",
        "--filter",
        "--jobs",
        "--origin",
        "--reference",
        "--reference-if-able",
        "--separate-git-dir",
        "--server-option",
        "--shallow-exclude",
        "--template",
        "-b",
        "-c",
        "-j",
        "-o",
    }
    positional: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            positional.extend(tokens[i + 1 :])
            break
        if tok in opts_with_value:
            i += 2
            continue
        if any(tok.startswith(f"{opt}=") for opt in opts_with_value if opt.startswith("--")):
            i += 1
            continue
        if tok.startswith("-") and tok not in {"-", "."}:
            i += 1
            continue
        positional.append(tok)
        i += 1

    if not positional:
        return None
    return positional[0], positional[1] if len(positional) > 1 else None


def _parse_src_workdir(line: str) -> str | None:
    tokens = _split_shell_tokens(line)
    if len(tokens) < 2 or tokens[0].upper() != "WORKDIR":
        return None
    workdir = tokens[1].strip()
    if workdir.startswith(("$SRC/", "${SRC}/", "/src/")):
        return workdir
    return None


def _split_shell_tokens(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=True)
    except ValueError:
        return []
