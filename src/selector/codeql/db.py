"""CodeQL database creation and caching."""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from pathlib import Path

from selector.codeql.installer import codeql_version, docker_image_arch, ensure_linux_codeql_zip

logger = logging.getLogger(__name__)

# Fallback Docker image for C/C++ DB creation when no project-specific image is
# configured.  Used when dockerhub_image is not set in project.json.
# The generic ubuntu image does not have build tools pre-installed, so the
# Docker command installs them inline.  This is cached by the DB hash check so
# it only runs when the source changes.
_DEFAULT_CPP_BUILD_IMAGE = "ubuntu:22.04"

# apt packages installed in the default build image before running CodeQL autobuild.
_DEFAULT_CPP_APT_DEPS = (
    "build-essential cmake make autoconf automake libtool git pkg-config ninja-build"
)

# Maps Vuljector language labels to CodeQL language identifiers
_LANG_TO_CODEQL: dict[str, str] = {
    "python":     "python",
    "javascript": "javascript",
    "js":         "javascript",
    "typescript": "javascript",
    "ts":         "javascript",
    "c":          "cpp",
    "cpp":        "cpp",
    "c++":        "cpp",
}

# DB root relative to repo workspace root (i.e. runs/codeql_dbs/<project>/<lang>/)
_DB_ROOT_NAME = "codeql_dbs"


def get_db_root(runs_dir: Path) -> Path:
    return runs_dir / _DB_ROOT_NAME


def codeql_language(vuljector_lang: str) -> str:
    """Map a Vuljector language label to its CodeQL identifier."""
    lang = _LANG_TO_CODEQL.get(vuljector_lang.lower())
    if lang is None:
        raise ValueError(
            f"Language {vuljector_lang!r} is not supported by the CodeQL strategy. "
            f"Supported: {sorted(_LANG_TO_CODEQL)}"
        )
    return lang


def _source_hash(source_root: Path) -> str:
    """Compute a short hash of the git HEAD SHA (or mtime sum as fallback)."""
    git_head = source_root / ".git" / "HEAD"
    if git_head.exists():
        # Follow symref / packed refs to get the actual SHA
        try:
            result = subprocess.run(
                ["git", "-C", str(source_root), "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True,
            )
            return result.stdout.strip()[:12]
        except subprocess.CalledProcessError:
            pass
    # Fallback: hash the number of files (fast, not perfect)
    count = sum(1 for _ in source_root.rglob("*") if _.is_file())
    return hashlib.md5(str(count).encode()).hexdigest()[:12]


def _db_meta_path(db_path: Path) -> Path:
    return db_path.parent / f"{db_path.name}.meta.json"


def _read_db_meta(db_path: Path) -> dict:
    meta = _db_meta_path(db_path)
    if meta.exists():
        with open(meta) as f:
            return json.load(f)
    return {}


def _write_db_meta(db_path: Path, source_hash: str) -> None:
    meta = _db_meta_path(db_path)
    with open(meta, "w") as f:
        json.dump({"source_hash": source_hash}, f)


def create_or_reuse_db(
    cli: Path,
    source_root: Path,
    language: str,
    db_root: Path,
    project: str,
    build_command: list[str] | None = None,
    docker_image: str | None = None,
) -> Path:
    """
    Create a CodeQL database for the given source root, or reuse an existing
    one if the source hasn't changed (checked via git HEAD SHA).

    Args:
        cli:           Path to the CodeQL CLI binary.
        source_root:   Root of the source tree to analyse.
        language:      CodeQL language identifier (e.g. "python", "javascript", "cpp").
        db_root:       Parent directory under which databases are stored.
        project:       Project name (used to namespace the database path).
        build_command: Optional build command for compiled languages (C/C++).
                       If None, CodeQL uses its auto-builder.
        docker_image:  Optional Docker image to use for C/C++ DB creation.
                       When set, the DB is built inside the container so the
                       project's compiler toolchain is available.

    Returns:
        Path to the created/reused database directory.
    """
    codeql_lang = codeql_language(language)
    db_path = db_root / project / codeql_lang
    db_root.mkdir(parents=True, exist_ok=True)
    (db_root / project).mkdir(exist_ok=True)

    src_hash = _source_hash(source_root)
    meta = _read_db_meta(db_path)

    if db_path.exists() and meta.get("source_hash") == src_hash:
        logger.info(
            "[%s] Reusing cached CodeQL DB at %s (hash=%s)",
            project, db_path, src_hash,
        )
        return db_path

    logger.info(
        "[%s] Creating CodeQL DB for language=%s at %s",
        project, codeql_lang, db_path,
    )

    if codeql_lang == "cpp" and not build_command:
        # C/C++ always runs inside Docker — never on the host.
        # The host macOS CodeQL bundle cannot run in a Linux container, so we
        # download (once, cached) the matching Linux CodeQL bundle and mount it.
        # Inspect the image to get its arch, download the matching CodeQL zip
        # once to the host cache, then mount it into the container.
        # All oss-fuzz-based project images are amd64; ubuntu:22.04 is arm64
        # on Apple Silicon — inspect tells us which without guessing.
        version = codeql_version(cli)
        image = docker_image or _DEFAULT_CPP_BUILD_IMAGE
        arch = docker_image_arch(image)
        zip_path = ensure_linux_codeql_zip(version, arch)
        db_path.mkdir(parents=True, exist_ok=True)

        if docker_image:
            setup_cmd = "apt-get update -qq && apt-get install -y --no-install-recommends unzip && "
        else:
            setup_cmd = (
                f"apt-get update -qq && "
                f"apt-get install -y --no-install-recommends {_DEFAULT_CPP_APT_DEPS} unzip && "
            )

        codeql_shell_cmd = (
            f"{setup_cmd}"
            f"unzip -q /tmp/codeql.zip -d /tmp && "
            f"/tmp/codeql/codeql database create /db "
            f"--language=cpp --source-root=/src --build-mode=autobuild --overwrite"
        )

        cmd: list[str] = [
            "docker", "run", "--rm",
            "-v", f"{source_root}:/src",
            "-v", f"{zip_path}:/tmp/codeql.zip:ro",
            "-v", f"{db_path}:/db",
            image,
            "sh", "-c", codeql_shell_cmd,
        ]
    else:
        cmd = [
            str(cli), "database", "create",
            str(db_path),
            f"--language={codeql_lang}",
            f"--source-root={source_root}",
            "--overwrite",
        ]

        if build_command:
            cmd += ["--", *build_command]
        elif codeql_lang == "javascript":
            # JS/TS is interpreted — no build step needed.
            cmd.append("--build-mode=none")

    # For JavaScript/TypeScript extraction without Node.js on the host, tell
    # CodeQL to use basic (parse-only) TypeScript mode instead of full type
    # resolution.  Full resolution requires Node.js; basic still extracts all
    # TS files as JavaScript and supports taint tracking.
    # If Node.js is available on PATH, CodeQL ignores this and uses full mode.
    env = None
    if codeql_lang == "javascript":
        import os
        env = {**os.environ, "LGTM_INDEX_TYPESCRIPT": "basic"}

    logger.debug("[%s] CodeQL DB create command: %s", project, " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)

    if result.returncode != 0:
        # stdout is often megabytes of apt-get/scc JSON noise — skip it.
        # Keep only the last 40 lines of stderr where the real error lives.
        stderr_tail = "\n".join(result.stderr.splitlines()[-40:])
        raise RuntimeError(
            f"CodeQL database creation failed for {project!r} ({codeql_lang}).\n"
            f"{stderr_tail}"
        )

    _write_db_meta(db_path, src_hash)
    logger.info("[%s] CodeQL DB created successfully at %s", project, db_path)
    return db_path
