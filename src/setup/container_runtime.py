"""Docker runtime for setup/selection/injection phases."""

from __future__ import annotations

import logging
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from setup.dockerhub_image import dockerhub_image_matches_engine, pull_ready_image
from setup.mounts import RUN_MOUNT_POINT

HARNESS_DIR = "/workspace/run/unit_tests"

logger = logging.getLogger(__name__)


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


class DockerSession:
    """Wrapper around a single running Docker container."""

    def __init__(self, *, project: str, container_id: str, run_mount_dir: Path | None = None) -> None:
        self.project = project
        self.container_id = container_id
        self.run_mount_dir = run_mount_dir

    @classmethod
    def start(
        cls,
        *,
        project: str,
        image_tag: str,
        run_mount_dir: Path | None = None,
    ) -> "DockerSession":
        args = ["docker", "run", "-d", "--rm"]
        if run_mount_dir is not None:
            run_mount_dir.mkdir(parents=True, exist_ok=True)
            args.extend(["-v", f"{run_mount_dir}:{RUN_MOUNT_POINT}"])
        args.extend([image_tag, "sleep", "infinity"])
        result = subprocess.run(args, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"docker run failed: {(result.stderr or result.stdout).strip()}")
        container_id = result.stdout.strip()
        subprocess.run(
            ["docker", "exec", container_id, "git", "config", "--global", "--add", "safe.directory", "*"],
            capture_output=True,
            text=True,
        )
        return cls(project=project, container_id=container_id, run_mount_dir=run_mount_dir)

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
        args.extend([self.container_id, "bash", "-lc", shell])
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return ExecResult(result.returncode, result.stdout, result.stderr)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            return ExecResult(124, stdout, f"{stderr}\ncommand timed out after {timeout}s".strip(), timed_out=True)

    def copy_from(self, container_path: str, host_path: Path) -> None:
        host_path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["docker", "cp", f"{self.container_id}:{container_path}", str(host_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker cp (from) failed: {(result.stderr or result.stdout).strip()}")

    def copy_to(self, host_path: Path, container_path: str) -> None:
        # Docker only copies directory contents into an existing destination
        # directory when the source path literally ends with "/.".
        source = f"{host_path}/." if host_path.is_dir() else str(host_path)
        result = subprocess.run(
            ["docker", "cp", source, f"{self.container_id}:{container_path}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"docker cp (to) failed: {(result.stderr or result.stdout).strip()}")

    def write_file(self, container_path: str, content: str | bytes) -> None:
        payload = content.encode("utf-8") if isinstance(content, str) else content
        result = subprocess.run(
            ["docker", "exec", "-i", self.container_id, "tee", container_path],
            input=payload,
            capture_output=True,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).decode(errors="replace").strip()
            raise RuntimeError(f"failed to write file to container: {detail}")

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.container_id], capture_output=True, text=True)


class ContainerRuntime:
    """Build/reuse project images and create ready-image-backed sessions."""

    def __init__(
        self,
        *,
        project: str,
        setup_dir: Path,
        target_dir: str,
        secure_base_commit: str,
        workspace_dir: Path,
        main_repo_url: str = "",
        fuzzing_engine: str = "libfuzzer",
        dockerhub_image: str | None = None,
        language: str | None = None,
    ) -> None:
        self.project = project
        self.setup_dir = setup_dir
        self.target_dir = target_dir
        self.secure_base_commit = secure_base_commit
        self.workspace_dir = workspace_dir
        self.main_repo_url = main_repo_url
        self.fuzzing_engine = fuzzing_engine
        self.dockerhub_image = dockerhub_image
        self.language = language
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.meta_path = self.workspace_dir / "runtime.json"
        self.meta = self._load_meta()

        self.setup_hash = self._compute_setup_hash(self.setup_dir)
        self.repo_dir_in_container = f"/src/{target_dir}"
        self.run_mount_dir: Path | None = None
        self._session: DockerSession | None = None

    @property
    def ready_image_tag(self) -> str:
        return f"vuljector/{self.project}:{self.setup_hash[:12]}-{self._engine_tag()}-ready"

    def has_ready_image(self) -> bool:
        self._adopt_legacy_ready_image()
        return self.meta.get("ready_hash") == self.setup_hash and self._image_exists(self.ready_image_tag)

    def ready_image_is_valid(self) -> bool:
        if not self.has_ready_image():
            return False
        check_cmd = [
            "bash",
            "-lc",
            (
                f"test -x {HARNESS_DIR}/test.sh && test -x {HARNESS_DIR}/parse_results.py"
                " && find /out -maxdepth 1 -type f -executable | grep -q ."
            ),
        ]
        try:
            result = self.run_container_command(
                check_cmd,
                image_tag=self.ready_image_tag,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            logger.warning(
                "[%s] ready image validation timed out after 300s; retrying once",
                self.project,
            )
            try:
                result = self.run_container_command(
                    check_cmd,
                    image_tag=self.ready_image_tag,
                    timeout=300,
                )
            except subprocess.TimeoutExpired:
                logger.warning("[%s] ready image validation timed out twice", self.project)
                return False
        return result.returncode == 0

    def require_ready_image(self) -> str:
        if not self.has_ready_image():
            raise RuntimeError(
                f"Ready image missing for project '{self.project}'. Run: python3 -m vuljector.cli setup {self.project}"
            )
        if not self.ready_image_is_valid():
            raise RuntimeError(
                f"Ready image for project '{self.project}' is invalid. Run: python3 -m vuljector.cli setup {self.project}"
            )
        return self.ready_image_tag

    def resolve_agent_image(self, *, allow_setup_image: bool = False) -> str:
        if allow_setup_image:
            self.ensure_setup_image()
            return self._setup_image_tag()
        return self.require_ready_image()


    def ensure_setup_image(self) -> None:
        self._adopt_legacy_setup_image()
        setup_image_tag = self._setup_image_tag()
        if self.meta.get("setup_hash") != self.setup_hash or not self._image_exists(setup_image_tag):
            self._build_image(setup_image_tag)
            self.meta["setup_hash"] = self.setup_hash
            self._save_meta()

    def detect_commit(self) -> str:
        result = self.run_container_command(
            ["git", "-C", self.repo_dir_in_container, "rev-parse", "HEAD"],
            use_setup_image=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"[{self.project}] Could not detect commit from setup image: {(result.stderr or '').strip()}"
            )
        return result.stdout.strip()

    def run_container_command(
        self,
        args: list[str],
        *,
        image_tag: str | None = None,
        use_setup_image: bool = False,
        timeout: int | float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if use_setup_image:
            self.ensure_setup_image()
            resolved_image = self._setup_image_tag()
        else:
            resolved_image = image_tag or self.require_ready_image()
        return subprocess.run(
            ["docker", "run", "--rm", resolved_image, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def build_ready_image(self, *, unit_tests_dir: Path) -> str:
        self.ensure_setup_image()
        session = DockerSession.start(
            project=self.project,
            image_tag=self._setup_image_tag(),
        )
        try:
            if self.secure_base_commit:
                session.exec(
                    f"git fetch origin {self.secure_base_commit}",
                    workdir=self.repo_dir_in_container,
                )
                session.exec(
                    f"git reset --hard {self.secure_base_commit}",
                    workdir=self.repo_dir_in_container,
                ).raise_for_status("git reset to secure_base_commit failed")
            session.exec("git clean -fdx", workdir=self.repo_dir_in_container).raise_for_status("git clean failed")
            build_result = session.exec(
                "compile",
                env={
                    "FUZZING_LANGUAGE": self.language or "c++",
                    "FUZZING_ENGINE": self.fuzzing_engine,
                },
                timeout=1800,
            )
            if build_result.returncode != 0:
                detail = (build_result.stderr or build_result.stdout or "").strip()[-500:]
                logger.warning("[%s] compile failed while creating ready image; continuing with partial image: %s", self.project, detail)
            session.exec(f"mkdir -p {HARNESS_DIR}").raise_for_status("failed to create harness directory")
            session.copy_to(unit_tests_dir, HARNESS_DIR)
            session.exec(
                f"chmod -R a+rX {HARNESS_DIR} && chmod +x {HARNESS_DIR}/test.sh {HARNESS_DIR}/parse_results.py"
            ).raise_for_status("failed to chmod baked harness")
            commit = subprocess.run(
                ["docker", "commit", session.container_id, self.ready_image_tag],
                capture_output=True,
                text=True,
            )
            if commit.returncode != 0:
                raise RuntimeError(f"docker commit failed: {(commit.stderr or commit.stdout).strip()}")
        finally:
            session.stop()

        self.meta["setup_hash"] = self.setup_hash
        self.meta["ready_hash"] = self.setup_hash
        self.meta["ready_image_tag"] = self.ready_image_tag
        self._save_meta()
        return self.ready_image_tag

    def ensure_ready_image(self, *, unit_tests_dir: Path) -> str:
        if self.ready_image_is_valid():
            return self.ready_image_tag
        if self.dockerhub_image and dockerhub_image_matches_engine(self.dockerhub_image, self.fuzzing_engine):
            pull_ready_image(source_image=self.dockerhub_image, target_image=self.ready_image_tag)
            self.meta["setup_hash"] = self.setup_hash
            self.meta["ready_hash"] = self.setup_hash
            self.meta["ready_image_tag"] = self.ready_image_tag
            self._save_meta()
            if self.ready_image_is_valid():
                return self.ready_image_tag
        ready = self.build_ready_image(unit_tests_dir=unit_tests_dir)
        self._delete_image(self._setup_image_tag())
        return ready

    def new_session(self, *, run_mount_dir: Path | None = None) -> DockerSession:
        image_tag = self.require_ready_image()
        return DockerSession.start(
            project=self.project,
            image_tag=image_tag,
            run_mount_dir=run_mount_dir,
        )

    def new_setup_session(self, *, run_mount_dir: Path | None = None) -> DockerSession:
        self.ensure_setup_image()
        return DockerSession.start(
            project=self.project,
            image_tag=self._setup_image_tag(),
            run_mount_dir=run_mount_dir,
        )

    def start_for_run(self, *, phase: str, run_mount_dir: Path) -> None:
        self.stop()
        run_mount_dir.mkdir(parents=True, exist_ok=True)
        self.run_mount_dir = run_mount_dir
        self._session = self.new_session(run_mount_dir=run_mount_dir)

    def stop(self) -> None:
        if self._session is not None:
            self._session.stop()
        self._session = None
        self.run_mount_dir = None

    def exec(
        self,
        cmd: str,
        *,
        workdir: str | None = None,
        env: dict[str, str] | None = None,
        timeout: int | float | None = None,
    ) -> ExecResult:
        if self._session is None:
            raise RuntimeError("No active container session.")
        return self._session.exec(cmd, workdir=workdir, env=env, timeout=timeout)

    def copy_from(self, container_path: str, host_path: Path) -> None:
        if self._session is None:
            raise RuntimeError("No active container session.")
        self._session.copy_from(container_path, host_path)

    def copy_to(self, host_path: Path, container_path: str) -> None:
        if self._session is None:
            raise RuntimeError("No active container session.")
        self._session.copy_to(host_path, container_path)

    def write_file(self, container_path: str, content: str | bytes) -> None:
        if self._session is None:
            raise RuntimeError("No active container session.")
        self._session.write_file(container_path, content)

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

    def _setup_image_tag(self) -> str:
        return f"vuljector/{self.project}:{self.setup_hash[:12]}-{self._engine_tag()}"

    def _engine_tag(self) -> str:
        return self.fuzzing_engine.replace("+", "plus")

    def _legacy_ready_image_tag(self) -> str:
        return f"vuljector/{self.project}:{self.setup_hash[:12]}-ready"

    def _legacy_setup_image_tag(self) -> str:
        return f"vuljector/{self.project}:{self.setup_hash[:12]}"

    def _adopt_legacy_ready_image(self) -> None:
        if self.fuzzing_engine != "libfuzzer":
            return
        if self._image_exists(self.ready_image_tag):
            return
        legacy = self._legacy_ready_image_tag()
        if self._image_exists(legacy):
            self._tag_image(legacy, self.ready_image_tag)

    def _adopt_legacy_setup_image(self) -> None:
        if self.fuzzing_engine != "libfuzzer":
            return
        if self._image_exists(self._setup_image_tag()):
            return
        legacy = self._legacy_setup_image_tag()
        if self._image_exists(legacy):
            self._tag_image(legacy, self._setup_image_tag())

    @staticmethod
    def _image_exists(image_tag: str) -> bool:
        result = subprocess.run(
            ["docker", "image", "inspect", image_tag],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0

    @staticmethod
    def _delete_image(image_tag: str) -> None:
        subprocess.run(["docker", "image", "rm", "-f", image_tag], capture_output=True, text=True)

    @staticmethod
    def _tag_image(source_image: str, target_image: str) -> None:
        subprocess.run(["docker", "tag", source_image, target_image], check=True, capture_output=True, text=True)

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
