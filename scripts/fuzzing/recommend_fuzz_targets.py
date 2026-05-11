#!/usr/bin/env python3
"""Rank likely fuzz targets for an injection attempt based on patch location and local resources."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_ROOT = REPO_ROOT.parent / "vuljector-projects"

PATCH_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)


@dataclass
class TargetScore:
    name: str
    score: int
    reasons: list[str]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def patch_targets(patch_diff: str) -> list[str]:
    return sorted(set(PATCH_FILE_RE.findall(patch_diff or "")))


def setup_target_names(project: str) -> list[str]:
    setup_dir = PROJECTS_ROOT / project / "setup"
    names = {path.stem for path in setup_dir.glob("*.options")}
    for path in setup_dir.glob("*.dict"):
        names.add(path.stem)
    return sorted(names)


def image_target_names(project: str) -> list[str]:
    config = load_json(PROJECTS_ROOT / project / "project.json")
    image = str(config.get("dockerhub_image", "")).replace(":setup", "")
    candidates = [
        f"{image}:{config.get('project')}",
        f"{image}:setup",
    ]
    docker_targets: set[str] = set()
    for ref in candidates:
        cmd = [
            "docker",
            "run",
            "--rm",
            ref,
            "bash",
            "-lc",
            "find /out -maxdepth 1 -type f -perm -111 -printf '%f\n' 2>/dev/null | sort",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            docker_targets.update(line.strip() for line in result.stdout.splitlines() if line.strip())
            break
    return sorted(name for name in docker_targets if name != "llvm-symbolizer")


def keyword_score(target: str, patch_path: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    low_target = target.lower()
    low_path = patch_path.lower()

    if any(token in low_path for token in ("gsub", "gpos", "layout", "shape")):
        if "shape" in low_target:
            score += 6
            reasons.append("layout/shape patch")
        if "subset" in low_target or "repacker" in low_target:
            score += 3
            reasons.append("font-table patch")
    if any(token in low_path for token in ("m3d", "obj", "fbx", "gltf", "collada", "stl")):
        for token in ("m3d", "obj", "fbx", "gltf", "collada", "stl"):
            if token in low_path and token in low_target:
                score += 7
                reasons.append(f"format keyword {token}")
        if "assimp_fuzzer" == low_target:
            score += 3
            reasons.append("generic importer target")
    if any(token in low_path for token in ("png", "read", "transform", "colormap")):
        if "png" in low_target or "read" in low_target:
            score += 5
            reasons.append("png/read patch")
    if any(token in low_path for token in ("regexp", "parse", "compile", "eval")):
        for token in ("regexp", "compile", "eval"):
            if token in low_path and token in low_target:
                score += 6
                reasons.append(f"keyword {token}")
    if patch_path.endswith((".hh", ".h", ".cc", ".cpp", ".c")) and "fuzzer" in low_target:
        score += 1
        reasons.append("source patch with executable target")

    return score, reasons


def rank_targets(project: str, patch_paths: list[str]) -> list[TargetScore]:
    targets = sorted(set(setup_target_names(project)) | set(image_target_names(project)))
    scored: list[TargetScore] = []
    for target in targets:
        score = 0
        reasons: list[str] = []
        for patch_path in patch_paths:
            delta, why = keyword_score(target, patch_path)
            score += delta
            reasons.extend(why)
        if not patch_paths:
            if "fuzzer" in target:
                score += 1
                reasons.append("generic fallback")
        if score > 0:
            scored.append(TargetScore(name=target, score=score, reasons=sorted(set(reasons))))
    return sorted(scored, key=lambda item: (-item.score, item.name))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--injection-result", type=Path, help="Path to an injection_result.json file.")
    parser.add_argument("--patch", type=Path, help="Path to a patch diff file.")
    args = parser.parse_args()

    if args.injection_result:
        payload = load_json(args.injection_result)
        patch_diff = ((payload.get("artifacts") or {}).get("patch_diff") or "")
    elif args.patch:
        patch_diff = args.patch.read_text(encoding="utf-8")
    else:
        raise SystemExit("one of --injection-result or --patch is required")

    patch_paths = patch_targets(patch_diff)
    ranked = rank_targets(args.project, patch_paths)
    output = {
        "project": args.project,
        "patch_targets": patch_paths,
        "recommended_targets": [
            {"name": item.name, "score": item.score, "reasons": item.reasons}
            for item in ranked
        ],
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
