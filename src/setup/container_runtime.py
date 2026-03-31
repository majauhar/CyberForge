"""Docker runtime for setup/selection/injection phases (per-run mount)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecResult:
    returncode: int
    stdout: str
    stderr: str

    def raise_for_status(self, message: str) -> "ExecResult":
        if self.returncode != 0:
            detail = (self.stderr or self.stdout).strip()
            raise RuntimeError(f"{message}: {detail}")
        return self


class ContainerRuntime:
    """Build/reuse project image and run phase containers with per-run mounts."""

    def __init__(
        self,
        *,
        project: str,
        setup_dir: Path,
        target_dir: str,
        secure_base_commit: str,
        workspace_dir: Path,
        oss_fuzz_path: Path | None = None,
        repos: dict | None = None,
        dockerhub_image: str | None = None,
        language: str | None = None,
    ) -> None:
        self.project = project
        self.setup_dir = setup_dir
        self.target_dir = target_dir
        self.secure_base_commit = secure_base_commit
        self.workspace_dir = workspace_dir
        self.oss_fuzz_path = oss_fuzz_path
        self.repos: dict = repos or {}
        self.dockerhub_image: str | None = dockerhub_image
        self.language: str | None = language
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.workspace_dir / "runtime.json"
        self.meta = self._load_meta()

        if oss_fuzz_path is not None:
            # OSS-Fuzz mode: hash the project's Dockerfile + build.sh from oss-fuzz
            oss_proj_dir = oss_fuzz_path / "projects" / project
            self.setup_hash = self._compute_setup_hash(oss_proj_dir if oss_proj_dir.exists() else setup_dir)
            self.image_tag = f"gcr.io/oss-fuzz/{project}"
        else:
            self.setup_hash = self._compute_setup_hash(self.setup_dir)
            self.image_tag = self.meta.get("image_tag") or f"vuljector/{project}:{self.setup_hash[:12]}"

        self.repo_dir_in_container = f"/src/{target_dir}"
        self.container_name = ""
        self.run_mount_dir: Path | None = None

    @property
    def ready_image_tag(self) -> str:
        """Tag for the post-build cached image (has build.sh artifacts baked in)."""
        return f"vuljector/{self.project}:{self.setup_hash[:12]}-ready"

    def has_ready_image(self) -> bool:
        """True if a ready image exists and matches the current setup hash."""
        return (
            self.meta.get("ready_hash") == self.setup_hash
            and self._image_exists(self.ready_image_tag)
        )

    @property
    def active_image_tag(self) -> str:
        """Ready image if available, otherwise the base project image."""
        return self.ready_image_tag if self.has_ready_image() else self.image_tag

    def build_ready_image(self) -> None:
        """
        Spin up a container from the base image, run build.sh, then docker commit
        the result as a reusable 'ready' image.  Subsequent agent runs start from
        this image so build.sh is a near no-op (artifacts already cached).

        No-op if a ready image for the current setup hash already exists.
        """
        if self.has_ready_image():
            return
        import uuid
        tag = self.ready_image_tag
        container_name = f"vuljector-{self.project}-ready-{uuid.uuid4().hex[:8]}"
        try:
            start = subprocess.run(
                ["docker", "run", "-d", "--name", container_name, self.image_tag,
                 "sleep", "infinity"],
                capture_output=True, text=True,
            )
            if start.returncode != 0:
                raise RuntimeError(
                    f"docker run for ready image failed: {(start.stderr or start.stdout).strip()}"
                )
            # Pre-run build.sh so artifacts are baked into the committed image.
            subprocess.run(
                ["docker", "exec", container_name, "bash", "-lc",
                 "bash /src/build.sh 2>&1 | tail -30 || true"],
                capture_output=True, text=True, timeout=600,
            )
            commit = subprocess.run(
                ["docker", "commit", container_name, tag],
                capture_output=True, text=True,
            )
            if commit.returncode != 0:
                raise RuntimeError(
                    f"docker commit failed: {(commit.stderr or commit.stdout).strip()}"
                )
        finally:
            subprocess.run(["docker", "rm", "-f", container_name],
                           capture_output=True, text=True)
        self.meta["ready_hash"] = self.setup_hash
        self.meta["ready_image_tag"] = tag
        self._save_meta()

    def ensure_image(self) -> None:
        if self.meta.get("setup_hash") != self.setup_hash or not self._image_exists(self.image_tag):
            self._build_image(self.image_tag)
            self.meta["setup_hash"] = self.setup_hash
            self.meta["image_tag"] = self.image_tag
            self._save_meta()

    def start_for_run(self, *, phase: str, run_mount_dir: Path) -> None:
        self.stop()
        self.ensure_image()
        run_mount_dir.mkdir(parents=True, exist_ok=True)
        self.run_mount_dir = run_mount_dir
        self.container_name = f"vuljector-{self.project}-{phase}"
        # If a previous process crashed before cleanup, the name may still exist.
        # Remove it proactively so docker run doesn't fail with a conflict.
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True,
            text=True,
        )
        args = [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            self.container_name,
            "-v",
            f"{run_mount_dir}:/workspace/run",
            self.image_tag,
            "sleep",
            "infinity",
        ]
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"docker run failed: {(result.stderr or result.stdout).strip()}")
        self.meta["container_id"] = self._container_id(self.container_name)
        self._save_meta()
        # Allow git to run in /src/* directories regardless of uid ownership.
        subprocess.run(
            ["docker", "exec", self.container_name,
             "git", "config", "--global", "--add", "safe.directory", "*"],
            capture_output=True, text=True,
        )

    def stop(self) -> None:
        if not self.container_name:
            return
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True,
            text=True,
        )
        self.container_name = ""
        self.run_mount_dir = None

    def exec(
        self,
        cmd: str,
        *,
        workdir: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        shell = cmd if workdir is None else f"cd {workdir} && {cmd}"
        args = ["docker", "exec"]
        if env:
            for key, value in env.items():
                args.extend(["-e", f"{key}={value}"])
        args.extend([self.container_name, "bash", "-lc", shell])
        result = subprocess.run(args, capture_output=True, text=True)
        return ExecResult(result.returncode, result.stdout, result.stderr)

    def copy_from(self, container_path: str, host_path: Path) -> None:
        host_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["docker", "cp", f"{self.container_name}:{container_path}", str(host_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker cp (from) failed: {(result.stderr or result.stdout).strip()}")

    def copy_to(self, host_path: Path, container_path: str) -> None:
        result = subprocess.run(
            ["docker", "cp", str(host_path), f"{self.container_name}:{container_path}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker cp (to) failed: {(result.stderr or result.stdout).strip()}")

    def ensure_repo_exists(self) -> None:
        self.exec(f"test -d {self.repo_dir_in_container}").raise_for_status(
            f"missing repo directory in container: {self.repo_dir_in_container}"
        )

    def strategy_key(self, phase: str, strategy_id: str) -> str:
        return f"{phase}:{strategy_id}"

    def is_strategy_setup_done(self, *, phase: str, strategy_id: str) -> bool:
        setups = self.meta.get("strategy_setup_done", {})
        return setups.get(self.strategy_key(phase, strategy_id)) == self.setup_hash

    def mark_strategy_setup_done(self, *, phase: str, strategy_id: str) -> None:
        setups = self.meta.setdefault("strategy_setup_done", {})
        setups[self.strategy_key(phase, strategy_id)] = self.setup_hash
        self._save_meta()

    def mark_setup_completed(self, completed: bool = True) -> None:
        self.meta["setup_completed"] = completed
        self._save_meta()

    def setup_completed(self) -> bool:
        return bool(self.meta.get("setup_completed"))

    def _build_image(self, image_tag: str) -> None:
        if self.oss_fuzz_path is not None:
            # OSS-Fuzz: build via infra/helper.py build_image --no-pull <project>
            helper = self.oss_fuzz_path / "infra" / "helper.py"
            if not helper.exists():
                raise RuntimeError(
                    f"OSS-Fuzz helper.py not found: {helper}\n"
                    "Clone OSS-Fuzz: git clone https://github.com/google/oss-fuzz"
                )
            cmd = [sys.executable, str(helper), "build_image", "--no-pull", self.project]
            result = subprocess.run(
                cmd,
                cwd=str(self.oss_fuzz_path),
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout).strip()[-800:]
                raise RuntimeError(f"helper.py build_image failed: {err}")
        else:
            result = subprocess.run(
                ["docker", "build", "-t", image_tag, str(self.setup_dir)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(f"docker build failed: {(result.stderr or result.stdout).strip()}")

    @staticmethod
    def _image_exists(image_tag: str) -> bool:
        result = subprocess.run(
            ["docker", "image", "inspect", image_tag],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    @staticmethod
    def _container_id(container_name: str) -> str:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.Id}}", container_name],
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() if result.returncode == 0 else ""

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
