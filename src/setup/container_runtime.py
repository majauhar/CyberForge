"""Minimal Docker runtime wrapper for container-first vuljector runs."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecResult:
    returncode: int
    stdout: str
    stderr: str


class ContainerRuntime:
    """Build/reuse a project container and execute commands in it."""

    def __init__(
        self,
        *,
        project: str,
        setup_dir: Path,
        vulinjector_root: Path,
        target_dir: str,
        secure_base_commit: str,
    ) -> None:
        self.project = project
        self.setup_dir = setup_dir
        self.vulinjector_root = vulinjector_root
        self.target_dir = target_dir
        self.secure_base_commit = secure_base_commit

        self.image_tag = f"vuljector/{project}:latest"
        self.container_name = f"vuljector-{project}"
        self.repo_dir_in_container = f"/src/{target_dir}"

        self.workspace_dir = self.vulinjector_root / "runs" / "workspaces" / project
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.workspace_dir / "runtime.json"
        self.meta = self._load_meta()

    def ensure_ready(self) -> None:
        setup_hash = self._compute_setup_hash(self.setup_dir)
        needs_build = (self.meta.get("setup_hash") != setup_hash) or (not self._image_exists())
        if needs_build:
            self._build_image()
        self._ensure_container_running()
        self._ensure_repo_ready()
        self.meta["setup_hash"] = setup_hash
        self.meta["image_tag"] = self.image_tag
        self.meta["container_id"] = self._container_id()
        self.meta.setdefault("last_strategy_setup", {})
        self._save_meta()

    def exec(self, cmd: str, *, workdir: str | None = None) -> ExecResult:
        shell = cmd if workdir is None else f"cd {workdir} && {cmd}"
        result = subprocess.run(
            ["docker", "exec", self.container_name, "bash", "-lc", shell],
            capture_output=True,
            text=True,
        )
        return ExecResult(result.returncode, result.stdout, result.stderr)

    def copy_from(self, container_path: str, host_path: Path) -> None:
        host_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["docker", "cp", f"{self.container_name}:{container_path}", str(host_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker cp failed: {result.stderr.strip()}")

    def copy_to(self, host_path: Path, container_path: str) -> None:
        result = subprocess.run(
            ["docker", "cp", str(host_path), f"{self.container_name}:{container_path}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker cp failed: {result.stderr.strip()}")

    def ensure_repo_clean(self) -> None:
        res = self.exec("git fetch origin", workdir=self.repo_dir_in_container)
        if res.returncode != 0:
            raise RuntimeError(f"git fetch failed: {res.stderr.strip()}")
        if self.secure_base_commit:
            res = self.exec(
                f"git reset --hard {self.secure_base_commit}",
                workdir=self.repo_dir_in_container,
            )
            if res.returncode != 0:
                raise RuntimeError(f"git reset failed: {res.stderr.strip()}")
        res = self.exec("git clean -fdx", workdir=self.repo_dir_in_container)
        if res.returncode != 0:
            raise RuntimeError(f"git clean failed: {res.stderr.strip()}")

    def is_strategy_setup_done(self, method_id: str) -> bool:
        setup_hash = self.meta.get("setup_hash", "")
        setups = self.meta.get("last_strategy_setup", {})
        return setups.get(method_id) == setup_hash

    def mark_strategy_setup_done(self, method_id: str) -> None:
        setup_hash = self.meta.get("setup_hash", "")
        setups = self.meta.setdefault("last_strategy_setup", {})
        setups[method_id] = setup_hash
        self._save_meta()

    def _ensure_repo_ready(self) -> None:
        exists = self.exec(f"test -d {self.repo_dir_in_container}/.git").returncode == 0
        if not exists:
            raise RuntimeError(
                "Repository not found inside container at "
                f"{self.repo_dir_in_container}. "
                "Expected setup Dockerfile to clone it. "
                "Check project.json target_dir and setup/Dockerfile."
            )
        self.ensure_repo_clean()

    def _build_image(self) -> None:
        result = subprocess.run(
            ["docker", "build", "-t", self.image_tag, str(self.setup_dir)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker build failed: {result.stderr.strip()}")

    def _ensure_container_running(self) -> None:
        if self._container_running():
            return
        if self._container_exists():
            result = subprocess.run(
                ["docker", "start", self.container_name],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(f"docker start failed: {result.stderr.strip()}")
            return
        result = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                self.container_name,
                "-v",
                f"{self.vulinjector_root}:/workspace/VulInjector",
                self.image_tag,
                "sleep",
                "infinity",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker run failed: {result.stderr.strip()}")

    def _container_running(self) -> bool:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.container_name],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"

    def _container_exists(self) -> bool:
        result = subprocess.run(
            ["docker", "inspect", self.container_name],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def _container_id(self) -> str:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.Id}}", self.container_name],
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    def _image_exists(self) -> bool:
        result = subprocess.run(
            ["docker", "image", "inspect", self.image_tag],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    def _load_meta(self) -> dict:
        if not self.meta_path.exists():
            return {}
        try:
            return json.loads(self.meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_meta(self) -> None:
        self.meta_path.write_text(json.dumps(self.meta, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def _compute_setup_hash(setup_dir: Path) -> str:
        sha = hashlib.sha256()
        for path in sorted(p for p in setup_dir.rglob("*") if p.is_file()):
            sha.update(str(path.relative_to(setup_dir)).encode("utf-8"))
            sha.update(path.read_bytes())
        return sha.hexdigest()
