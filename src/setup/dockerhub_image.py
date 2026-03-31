"""Helpers for pulling/publishing project-ready images via Docker Hub."""

from __future__ import annotations

import subprocess
import uuid
from pathlib import Path


def dockerhub_image_ref(*, namespace: str, project: str, tag: str = "setup") -> str:
    return f"{namespace.strip().strip('/')}/{project}:{tag}"


def pull_ready_image(*, source_image: str, target_image: str) -> None:
    pull = subprocess.run(["docker", "pull", source_image], capture_output=True, text=True)
    if pull.returncode != 0:
        raise RuntimeError(f"docker pull failed: {(pull.stderr or pull.stdout).strip()}")
    tag = subprocess.run(["docker", "tag", source_image, target_image], capture_output=True, text=True)
    if tag.returncode != 0:
        raise RuntimeError(f"docker tag failed: {(tag.stderr or tag.stdout).strip()}")


def publish_ready_image(
    *,
    source_image: str,
    image_ref: str,
    repo_dir: str,
    secure_base_commit: str,
    unit_tests_dir: Path,
) -> None:
    name = f"vuljector-publish-{uuid.uuid4().hex[:8]}"
    try:
        start = subprocess.run(
            ["docker", "run", "-d", "--name", name, source_image, "sleep", "infinity"],
            capture_output=True, text=True,
        )
        if start.returncode != 0:
            raise RuntimeError(f"docker run failed: {(start.stderr or start.stdout).strip()}")
        subprocess.run(
            ["docker", "exec", name, "git", "config", "--global", "--add", "safe.directory", "*"],
            capture_output=True, text=True,
        )
        subprocess.run(
            ["docker", "exec", name, "bash", "-lc", f"cd {repo_dir} && git fetch origin {secure_base_commit}"],
            capture_output=True, text=True,
        )
        reset = subprocess.run(
            ["docker", "exec", name, "bash", "-lc",
             f"cd {repo_dir} && git reset --hard {secure_base_commit} && git clean -fdx"],
            capture_output=True, text=True,
        )
        if reset.returncode != 0:
            raise RuntimeError(f"git reset failed: {(reset.stderr or reset.stdout).strip()}")
        mkdir = subprocess.run(
            ["docker", "exec", name, "bash", "-lc", "mkdir -p /workspace/run"],
            capture_output=True, text=True,
        )
        if mkdir.returncode != 0:
            raise RuntimeError(f"mkdir failed: {(mkdir.stderr or mkdir.stdout).strip()}")
        cp = subprocess.run(
            ["docker", "cp", str(unit_tests_dir), f"{name}:/workspace/run/unit_tests"],
            capture_output=True, text=True,
        )
        if cp.returncode != 0:
            raise RuntimeError(f"docker cp failed: {(cp.stderr or cp.stdout).strip()}")
        chmod = subprocess.run(
            ["docker", "exec", name, "bash", "-lc",
             "chmod -R a+rX /workspace/run/unit_tests"
             " && chmod +x /workspace/run/unit_tests/test.sh /workspace/run/unit_tests/parse_results.py"],
            capture_output=True, text=True,
        )
        if chmod.returncode != 0:
            raise RuntimeError(f"chmod failed: {(chmod.stderr or chmod.stdout).strip()}")
        commit = subprocess.run(["docker", "commit", name, image_ref], capture_output=True, text=True)
        if commit.returncode != 0:
            raise RuntimeError(f"docker commit failed: {(commit.stderr or commit.stdout).strip()}")
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)

    push = subprocess.run(["docker", "push", image_ref], capture_output=True, text=True)
    if push.returncode != 0:
        raise RuntimeError(f"docker push failed: {(push.stderr or push.stdout).strip()}")
