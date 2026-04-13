"""Docker runtime for setup/selection/injection phases (per-run mount)."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from setup.dockerhub_image import pull_ready_image


@dataclass
class ExecResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

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
        main_repo_url: str = "",
        dockerhub_image: str | None = None,
        language: str | None = None,
    ) -> None:
        self.project = project
        self.setup_dir = setup_dir
        self.target_dir = target_dir
        self.secure_base_commit = secure_base_commit
        self.workspace_dir = workspace_dir
        self.main_repo_url = main_repo_url
        self.dockerhub_image: str | None = dockerhub_image
        self.language: str | None = language
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.workspace_dir / "runtime.json"
        self.meta = self._load_meta()

        self.setup_hash = self._compute_setup_hash(self.setup_dir)
        self.image_tag = self.meta.get("image_tag") or f"vuljector/{project}:{self.setup_hash[:12]}"

        self.repo_dir_in_container = f"/src/{target_dir}"
        self.container_name = ""
        self.run_mount_dir: Path | None = None

    @property
    def ready_image_tag(self) -> str:
        """Tag for the post-build cached image (has build.sh artifacts baked in)."""
        return f"vuljector/{self.project}:{self.setup_hash[:12]}-ready"

    def _has_cached_ready_image(self) -> bool:
        return (
            self.meta.get("ready_hash") == self.setup_hash
            and self._image_exists(self.ready_image_tag)
        )

    def has_ready_image(self) -> bool:
        """True if a ready image exists and matches the current setup hash."""
        manifest = self.meta.get("ready_out_manifest") or {}
        return (
            self._has_cached_ready_image()
            and self.meta.get("ready_secure_commit") == self.secure_base_commit
            and isinstance(manifest, dict)
            and int(manifest.get("executable_count", 0)) > 0
            and self._image_exists(self.ready_image_tag)
        )

    @property
    def active_image_tag(self) -> str:
        """Ready image if available, otherwise the base project image."""
        return self.ready_image_tag if self.has_ready_image() else self.image_tag

    def pre_agent_setup_commands(self, build_cmd: str) -> list[str]:
        """
        Return per-agent setup commands.

        If a ready image is available, it already has build artifacts baked in
        from setup, so there is no need to rerun build.sh before every agent
        task. Fall back to the provided build command only when the runtime is
        using the base image.
        """
        return [] if self.has_ready_image() else [build_cmd]

    def build_ready_image(self) -> None:
        """
        Spin up a container from the base image, run build.sh, then docker commit
        the result as a reusable 'ready' image.  Subsequent agent runs start from
        this image so build.sh is a near no-op (artifacts already cached).

        No-op if a ready image for the current setup hash already exists.
        """
        if self._has_cached_ready_image():
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
            manifest = self._build_and_validate_out(container_name)
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
        self.meta["ready_out_manifest"] = manifest
        self.meta["ready_secure_commit"] = None
        self._save_meta()

    def sync_ready_image_to_secure_commit(self) -> None:
        """
        Re-commit the ready image after aligning the repo checkout to
        secure_base_commit.

        This keeps setup-produced images in a predictable baseline state even
        when the upstream image was built from a shallow clone.
        """
        if not self.secure_base_commit:
            return
        self.build_ready_image()
        import uuid
        tag = self.ready_image_tag
        container_name = f"vuljector-{self.project}-secure-{uuid.uuid4().hex[:8]}"
        try:
            start = subprocess.run(
                ["docker", "run", "-d", "--name", container_name, tag, "sleep", "infinity"],
                capture_output=True, text=True,
            )
            if start.returncode != 0:
                raise RuntimeError(
                    f"docker run for secure ready image failed: {(start.stderr or start.stdout).strip()}"
                )
            subprocess.run(
                ["docker", "exec", container_name, "git", "config", "--global", "--add", "safe.directory", "*"],
                capture_output=True, text=True,
            )
            subprocess.run(
                ["docker", "exec", container_name, "bash", "-lc",
                 f"cd {self.repo_dir_in_container} && git fetch origin {self.secure_base_commit}"],
                capture_output=True, text=True,
            )
            reset = subprocess.run(
                ["docker", "exec", container_name, "bash", "-lc",
                 f"cd {self.repo_dir_in_container} && git reset --hard {self.secure_base_commit} && git clean -fdx"],
                capture_output=True, text=True,
            )
            if reset.returncode != 0:
                raise RuntimeError(
                    "secure commit reset failed: "
                    f"{(reset.stderr or reset.stdout).strip()}"
                )
            manifest = self._build_and_validate_out(container_name)
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
        self.meta["ready_out_manifest"] = manifest
        self.meta["ready_secure_commit"] = self.secure_base_commit
        self._save_meta()

    def ensure_image(self) -> None:
        if self.dockerhub_image and (
            self.meta.get("ready_hash") != self.setup_hash or not self._image_exists(self.ready_image_tag)
        ):
            try:
                pull_ready_image(source_image=self.dockerhub_image, target_image=self.ready_image_tag)
                self.meta["setup_hash"] = self.setup_hash
                self.meta["ready_hash"] = self.setup_hash
                self.meta["ready_image_tag"] = self.ready_image_tag
                self._save_meta()
                return
            except Exception:
                pass
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
        run_label = run_mount_dir.name or "run"
        self.container_name = f"vuljector-{self.project}-{phase}-{run_label}"
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
            self.active_image_tag,
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
        timeout: int | float | None = None,
    ) -> ExecResult:
        shell = cmd if workdir is None else f"cd {workdir} && {cmd}"
        args = ["docker", "exec"]
        if env:
            for key, value in env.items():
                args.extend(["-e", f"{key}={value}"])
        args.extend([self.container_name, "bash", "-lc", shell])
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return ExecResult(result.returncode, result.stdout, result.stderr)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            timeout_msg = f"command timed out after {timeout}s"
            stderr = f"{stderr}\n{timeout_msg}".strip()
            return ExecResult(124, stdout, stderr, timed_out=True)

    def inspect_out_manifest(self) -> dict:
        if not self.container_name:
            raise RuntimeError("No running container to inspect /out from.")
        return self._inspect_out_manifest_for_container(self.container_name)

    def rebuild_out(self, *, timeout: int | float = 1800) -> tuple[ExecResult, dict]:
        result = self.exec(
            "compile 2>&1 | tee /tmp/vuljector_build.log",
            env={"FUZZING_LANGUAGE": self.language or "c++"},
            timeout=timeout,
        )
        manifest = self.inspect_out_manifest()
        return result, manifest

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

    def _build_and_validate_out(self, container_name: str, *, timeout: int = 1800) -> dict:
        # Pass FUZZING_LANGUAGE so the OSS-Fuzz compile script doesn't abort on
        # an unbound variable. The image already has SANITIZER/FUZZING_ENGINE/
        # ARCHITECTURE set; we only need to supply the language.
        fuzzing_language = self.language or "c++"
        try:
            result = subprocess.run(
                [
                    "docker", "exec",
                    "-e", f"FUZZING_LANGUAGE={fuzzing_language}",
                    container_name, "bash", "-lc",
                    "compile 2>&1 | tee /tmp/vuljector_build.log",
                ],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            output = ((exc.stdout or "") + "\n" + (exc.stderr or "")).strip()
            raise RuntimeError(
                f"compile timed out after {timeout}s:\n{self._tail_lines(output)}"
            ) from exc

        output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if result.returncode != 0:
            raise RuntimeError(f"compile failed:\n{self._tail_lines(output)}")

        manifest = self._inspect_out_manifest_for_container(container_name)
        self._validate_out_manifest(manifest)
        return manifest

    def _inspect_out_manifest_for_container(self, container_name: str) -> dict:
        script = r"""
python3 - <<'PY'
import json
import os
from pathlib import Path

out_dir = Path("/out")
entries = []
if out_dir.exists():
    for child in sorted(out_dir.iterdir(), key=lambda item: item.name):
        try:
            stat = child.stat()
        except OSError:
            continue
        kind = "dir" if child.is_dir() else "symlink" if child.is_symlink() else "file"
        executable = child.is_file() and os.access(child, os.X_OK)
        entries.append(
            {
                "name": child.name,
                "path": str(child),
                "kind": kind,
                "size": int(stat.st_size),
                "executable": executable,
            }
        )

manifest = {
    "entry_count": len(entries),
    "executable_count": sum(1 for entry in entries if entry["executable"]),
    "executables": [entry["name"] for entry in entries if entry["executable"]],
    "dictionaries": [entry["name"] for entry in entries if entry["name"].endswith(".dict")],
    "seed_corpora": [entry["name"] for entry in entries if entry["name"].endswith(".zip")],
    "entries": entries,
}
print(json.dumps(manifest))
PY
"""
        result = subprocess.run(
            ["docker", "exec", container_name, "bash", "-lc", script],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"failed to inspect /out: {(result.stderr or result.stdout).strip()}"
            )
        try:
            return json.loads(result.stdout.strip())
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid /out manifest JSON: {result.stdout!r}") from exc

    @staticmethod
    def _validate_out_manifest(manifest: dict) -> None:
        if int(manifest.get("executable_count", 0)) > 0:
            return
        entries = ", ".join(entry["name"] for entry in (manifest.get("entries") or [])[:12])
        detail = entries or "<empty /out>"
        raise RuntimeError(f"build.sh produced no executable fuzz targets in /out ({detail})")

    @staticmethod
    def _tail_lines(text: str, lines: int = 40) -> str:
        chunks = [line for line in text.splitlines() if line.strip()]
        if not chunks:
            return "<no build output>"
        return "\n".join(chunks[-lines:])

    @staticmethod
    def _compute_setup_hash(setup_dir: Path) -> str:
        sha = hashlib.sha256()
        for path in sorted(p for p in setup_dir.rglob("*") if p.is_file()):
            sha.update(str(path.relative_to(setup_dir)).encode("utf-8"))
            sha.update(path.read_bytes())
        return sha.hexdigest()
