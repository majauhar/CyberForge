"""Locate the CodeQL CLI binary on the host system."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


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
    # 1. Explicit env override
    env_path = os.environ.get("CODEQL_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p
        raise RuntimeError(
            f"CODEQL_PATH is set to {env_path!r} but no file exists there."
        )

    # 2. PATH lookup
    which = shutil.which("codeql")
    if which:
        return Path(which)

    # 3. Common manual install locations
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
    import subprocess
    result = subprocess.run(
        [str(cli), "version", "--format=terse"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()
