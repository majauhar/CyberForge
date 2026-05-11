#!/usr/bin/env python3
"""Map an injected patch to existing OSS-Fuzz harnesses using offline cached metadata."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from selector.fuzz_guided.guidance import DEFAULT_CACHE_DIR, map_injection_result_to_harness


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--injection-result", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    args = parser.parse_args()

    payload = map_injection_result_to_harness(args.injection_result, args.cache_dir)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
