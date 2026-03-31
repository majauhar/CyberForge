"""Locate the CodeQL CLI binary on the host system."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)


_INSTALL_INSTRUCTIONS = """
CodeQL CLI not found. Install it with one of:

  brew install codeql                        # macOS (Homebrew)
  winget install GitHub.codeql              # Windows (winget)

Or download the binary from:
  https://github.com/github/codeql-action/releases

After installing, either:
  - Ensure `codeql` is on your PATH, or
  - Set the CODEQL_PATH environment variable to the full path of the binary.
""".strip()


def find_codeql_cli() -> Path:
    """
    Return the path to the CodeQL CLI binary.

    Search order:
      1. CODEQL_PATH environment variable
      2. `codeql` on PATH (via shutil.which)
      3. ~/codeql/codeql  (common manual install location)
      4. /opt/codeql/codeql

    Raises RuntimeError with installation instructions if not found.
    """
    env_path = os.environ.get("CODEQL_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p
        raise RuntimeError(
            f"CODEQL_PATH is set to {env_path!r} but no file exists there."
        )

    which = shutil.which("codeql")
    if which:
        return Path(which)

    for candidate in [
        Path.home() / "codeql" / "codeql",
        Path("/opt/codeql/codeql"),
        Path("/usr/local/bin/codeql"),
    ]:
        if candidate.is_file():
            return candidate

    raise RuntimeError(f"CodeQL CLI not found.\n\n{_INSTALL_INSTRUCTIONS}")


def codeql_version(cli: Path) -> str:
    """Return the CodeQL CLI version string (e.g. '2.18.1')."""
    result = subprocess.run(
        [str(cli), "version", "--format=terse"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def docker_image_arch(image: str) -> str:
    """
    Return the architecture of a Docker image ('amd64' or 'arm64').

    Pulls the image if not already present locally.  Falls back to 'amd64'
    if detection fails (safe default — all oss-fuzz base images are amd64).
    """
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.Architecture}}", image],
        capture_output=True, text=True,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()

    # Image not local yet — pull it so we can inspect it.
    logger.info("Pulling Docker image %s to detect architecture ...", image)
    subprocess.run(["docker", "pull", "--quiet", image], capture_output=True)
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.Architecture}}", image],
        capture_output=True, text=True,
    )
    arch = result.stdout.strip() if result.returncode == 0 else ""
    if arch:
        return arch

    logger.warning("Could not detect architecture for %s — defaulting to amd64", image)
    return "amd64"


_ZIP_CACHE = Path.home() / ".cache" / "vuljector" / "codeql-zips"

_ZIP_FILENAMES = {
    "amd64": "codeql-linux64.zip",
    "arm64": "codeql-linux-arm64.zip",
}

_ZIP_URL = (
    "https://github.com/github/codeql-cli-binaries/releases/download"
    "/v{version}/{filename}"
)


def ensure_linux_codeql_zip(version: str, arch: str) -> Path:
    """
    Return a locally cached Linux CodeQL zip for *arch* ('amd64' or 'arm64').

    Downloaded once per version/arch and cached at
    ~/.cache/vuljector/codeql-zips/<version>/<filename>.
    """
    filename = _ZIP_FILENAMES.get(arch, _ZIP_FILENAMES["amd64"])
    zip_path = _ZIP_CACHE / version / filename
    if zip_path.exists():
        logger.debug("CodeQL zip cached at %s", zip_path)
        return zip_path

    url = _ZIP_URL.format(version=version, filename=filename)
    logger.info("Downloading CodeQL Linux zip v%s (%s, ~400MB, one-time) ...", version, arch)

    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response:
        shutil.copyfileobj(response, zip_path.open("wb"))

    logger.info("Cached at %s", zip_path)
    return zip_path
