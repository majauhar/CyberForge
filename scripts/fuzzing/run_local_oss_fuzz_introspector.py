#!/usr/bin/env python3
"""Run OSS-Fuzz Introspector locally for a project checkout.

This is a thin helper around OSS-Fuzz's official `infra/helper.py introspector`
workflow so Vuljector users can refresh local reachability/coverage guidance
without manually juggling an extra checkout.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OSS_FUZZ_DIR = REPO_ROOT / "runs" / "oss_fuzz_checkout"
OSS_FUZZ_REPO = "https://github.com/google/oss-fuzz.git"


def ensure_checkout(path: Path, refresh: bool) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth=1", OSS_FUZZ_REPO, str(path)],
            check=True,
        )
        return
    if refresh:
        subprocess.run(["git", "-C", str(path), "pull", "--ff-only"], check=True)


def run_introspector(
    *,
    oss_fuzz_dir: Path,
    project: str,
    mode: str,
    seconds: int,
) -> Path:
    helper = oss_fuzz_dir / "infra" / "helper.py"
    if not helper.exists():
        raise FileNotFoundError(f"missing OSS-Fuzz helper script: {helper}")

    cmd = ["python3", str(helper), "introspector", project]
    if mode == "public-corpora":
        cmd.append("--public-corpora")
    else:
        cmd.append(f"--seconds={seconds}")

    subprocess.run(cmd, cwd=oss_fuzz_dir, check=True)
    return oss_fuzz_dir / "build" / "out" / project / "introspector-report" / "inspector"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, help="OSS-Fuzz project name")
    parser.add_argument(
        "--oss-fuzz-dir",
        type=Path,
        default=DEFAULT_OSS_FUZZ_DIR,
        help="Checkout location for google/oss-fuzz",
    )
    parser.add_argument(
        "--mode",
        choices=("public-corpora", "seconds"),
        default="public-corpora",
        help="Use public corpora or run fuzzers locally for N seconds",
    )
    parser.add_argument(
        "--seconds",
        type=int,
        default=30,
        help="Seconds to run fuzzers when --mode=seconds",
    )
    parser.add_argument(
        "--refresh-checkout",
        action="store_true",
        help="Pull the latest google/oss-fuzz changes before running",
    )
    args = parser.parse_args()

    ensure_checkout(args.oss_fuzz_dir.resolve(), args.refresh_checkout)
    report_dir = run_introspector(
        oss_fuzz_dir=args.oss_fuzz_dir.resolve(),
        project=args.project,
        mode=args.mode,
        seconds=args.seconds,
    )
    print(report_dir)


if __name__ == "__main__":
    main()
