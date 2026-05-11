"""Helpers for pulling/publishing project-ready images via Docker Hub."""

from __future__ import annotations

import subprocess


def dockerhub_tag_for_engine(engine: str) -> str:
    return "setup" if engine == "libfuzzer" else engine


def dockerhub_image_ref(*, namespace: str, project: str, tag: str = "setup") -> str:
    return f"{namespace.strip().strip('/')}/{project}:{tag}"


def dockerhub_image_matches_engine(source_image: str, engine: str) -> bool:
    tag = source_image.rsplit(":", 1)[1] if ":" in source_image else ""
    if engine == "libfuzzer":
        return tag in {"", "setup", "libfuzzer"}
    return tag == engine


def pull_ready_image(*, source_image: str, target_image: str) -> None:
    pull = subprocess.run(["docker", "pull", source_image], capture_output=True, text=True)
    if pull.returncode != 0:
        raise RuntimeError(f"docker pull failed: {(pull.stderr or pull.stdout).strip()}")
    tag = subprocess.run(["docker", "tag", source_image, target_image], capture_output=True, text=True)
    if tag.returncode != 0:
        raise RuntimeError(f"docker tag failed: {(tag.stderr or tag.stdout).strip()}")


def publish_ready_image(*, source_image: str, image_ref: str) -> None:
    tag = subprocess.run(["docker", "tag", source_image, image_ref], capture_output=True, text=True)
    if tag.returncode != 0:
        raise RuntimeError(f"docker tag failed: {(tag.stderr or tag.stdout).strip()}")
    push = subprocess.run(["docker", "push", image_ref], capture_output=True, text=True)
    if push.returncode != 0:
        raise RuntimeError(f"docker push failed: {(push.stderr or push.stdout).strip()}")
