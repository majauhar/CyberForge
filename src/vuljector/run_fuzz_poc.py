"""Generate and verify fuzz-backed PoC artifacts in a dedicated runs namespace."""

from __future__ import annotations

import configparser
from collections import Counter
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any

from selector.fuzz_guided.guidance import DEFAULT_CACHE_DIR, map_injection_result_to_harness
from setup.dockerhub_image import dockerhub_image_matches_engine
from setup.container_runtime import DockerSession
from utils.json_io import read_json, write_json
from utils.paths import new_run_id, runs_root
from verifier.pipeline import run_verification
from vuljector.core import build_runtime, ensure_setup_completed, load_project_config
from vuljector.fuzz_execution_context import (
    attack_script_fuzzer_hint as _shared_attack_script_fuzzer_hint,
    candidate_fuzz_metadata as _shared_candidate_fuzz_metadata,
    derive_patch_path_from_diff,
    infer_trigger_profile as _shared_infer_trigger_profile,
    preferred_extensions as _shared_preferred_extensions,
    retarget_profile_for_fuzzer as _shared_retarget_profile_for_fuzzer,
    trigger_profile_from_fuzz_metadata as _shared_trigger_profile_from_fuzz_metadata,
)
from vuljector.io_contracts import VerificationResult, utc_now_iso


REPO_ROOT = Path(__file__).resolve().parents[2]
FUZZ_POC_ROOT = runs_root() / "fuzz_poc"
CURATED_CORPUS_ROOT = FUZZ_POC_ROOT / "_curated"
BUILTIN_CORPUS_CACHE_ROOT = FUZZ_POC_ROOT / "_builtin_corpus_cache"

_SOURCE_TEMPLATE_REJECT_NAME_TOKENS = (
    "log",
    "out",
    "trace",
    "gdb",
    "asan",
    "ubsan",
    "build",
    "compile",
    "stderr",
    "stdout",
    "clean",
    "vuln",
)

_SOURCE_TEMPLATE_REJECT_PATH_PART_PATTERNS = (
    "clean",
    "vuln",
)


def _sanitize_tag(value: str) -> str:
    out = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return re.sub(r"_+", "_", out).strip("._-") or "fuzz_poc"


def _attack_script_fuzzer_hint(injection: dict[str, Any]) -> str | None:
    attack_script = (injection.get("artifacts") or {}).get("attack_script") or ""
    return _shared_attack_script_fuzzer_hint(attack_script)


def _candidate_fuzz_metadata(injection: dict[str, Any]) -> dict[str, Any]:
    return _shared_candidate_fuzz_metadata(injection)


def _infer_trigger_profile(injection: dict[str, Any]) -> dict[str, Any]:
    artifacts = injection.get("artifacts") or {}
    patch_diff = artifacts.get("patch_diff") or ""
    attack_script = artifacts.get("attack_script") or ""
    return _shared_infer_trigger_profile(
        cwe_id=injection.get("cwe_id") or "",
        patch_diff=patch_diff,
        attack_script=attack_script,
        patch_path=derive_patch_path_from_diff(patch_diff),
    )


def _trigger_profile_from_fuzz_metadata(injection: dict[str, Any], fuzz: dict[str, Any]) -> dict[str, Any]:
    artifacts = injection.get("artifacts") or {}
    patch_diff = artifacts.get("patch_diff") or ""
    attack_script = artifacts.get("attack_script") or ""
    return _shared_trigger_profile_from_fuzz_metadata(
        fuzz,
        cwe_id=injection.get("cwe_id") or "",
        patch_diff=patch_diff,
        attack_script=attack_script,
        patch_path=derive_patch_path_from_diff(patch_diff),
    )


def _retarget_profile_for_fuzzer(profile: dict[str, Any], fuzzer: str) -> dict[str, Any]:
    return _shared_retarget_profile_for_fuzzer(profile, fuzzer)
    


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _resolve_patch_diff(injection: dict[str, Any], *, attempt_dir: Path | None = None) -> str:
    artifacts = injection.get("artifacts") or {}
    patch_diff = artifacts.get("patch_diff") or ""
    if patch_diff.strip():
        return patch_diff

    candidate_paths: list[Path] = []
    if attempt_dir is not None:
        candidate_paths.append(attempt_dir / "artifacts" / "vuln.patch")
    patch_path = str((injection.get("paths") or {}).get("patch_path") or "").strip()
    if patch_path and attempt_dir is not None:
        candidate_paths.append(attempt_dir / patch_path)

    for path in candidate_paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if text.strip():
            return text
    return ""


def _relative_paths_for_attempt(attempt_dir: Path, exploit_dir: Path) -> dict[str, str]:
    return {
        "attempt_dir": str(attempt_dir.relative_to(attempt_dir.parent)),
        "exploit_dir": str(exploit_dir.relative_to(attempt_dir)),
        "patch_path": str((attempt_dir / "artifacts" / "vuln.patch").relative_to(attempt_dir)),
        "manifest_path": str((exploit_dir / "fuzz_poc_manifest.json").relative_to(attempt_dir)),
        "fuzz_driver_path": str((exploit_dir / "fuzz_poc.py").relative_to(attempt_dir)),
        "source_injection_result_path": str((attempt_dir / "source_injection_result.json").relative_to(attempt_dir)),
    }


def _synthesized_injection_result(
    *,
    source_injection: dict[str, Any],
    run_id: str,
    attempt_dir: Path,
    exploit_dir: Path,
    selected: dict[str, Any],
    selection_source: str,
    generated_input_count: int,
) -> dict[str, Any]:
    source_strategy = source_injection.get("strategy") or {}
    source_artifacts = source_injection.get("artifacts") or {}
    source_paths = source_injection.get("paths") or {}
    attack_script = source_artifacts.get("attack_script") or ""
    patch_diff = _resolve_patch_diff(source_injection, attempt_dir=attempt_dir)
    return {
        "project": source_injection["project"],
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "status": "success",
        "selected_candidate_id": source_injection.get("selected_candidate_id"),
        "cwe_group": source_injection.get("cwe_group"),
        "cwe_id": source_injection.get("cwe_id"),
        "strategy": {
            "id": "fuzz_poc_posthoc",
            "source_strategy_id": source_strategy.get("id"),
            "selected_fuzzer": selected.get("fuzzer"),
            "selected_fuzzer_source": selection_source,
            "generated_input_count": generated_input_count,
            "source_attempt_dir": str(Path(source_paths.get("exploit_dir", "")).parent) if source_paths.get("exploit_dir") else None,
        },
        "usage": {},
        "paths": _relative_paths_for_attempt(attempt_dir, exploit_dir),
        "artifacts": {
            "patch_diff": patch_diff,
            "attack_script": attack_script,
            "exploit_filename": "exploit.sh",
            "fuzz_driver_filename": "fuzz_poc.py",
            "manifest_filename": "fuzz_poc_manifest.json",
        },
        "failure": None,
    }


def _write_fuzz_poc_request(
    *,
    run_dir: Path,
    project: str,
    run_id: str,
    source_run_dir: str | None,
    source_attempt_dir: str | None,
    tag: str | None,
    force_fuzzer: str | None,
    max_total_time: int,
    exploit_timeout: int | None,
) -> dict[str, Any]:
    payload = {
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "mode": "fuzz_poc_posthoc",
        "source_run_dir": source_run_dir,
        "source_attempt_dir": source_attempt_dir,
        "tag": tag,
        "force_fuzzer": force_fuzzer,
        "max_total_time": max_total_time,
        "exploit_timeout": exploit_timeout,
    }
    write_json(run_dir / "injection_request.json", payload)
    write_json(run_dir / "fuzz_poc_request.json", payload)
    return payload


def _project_setup_dir(project: str) -> Path:
    return REPO_ROOT.parent / "vuljector-projects" / project / "setup"


def _load_local_fuzz_assets(project: str, fuzzer: str) -> dict[str, Any]:
    setup_dir = _project_setup_dir(project)
    options_path = setup_dir / f"{fuzzer}.options"
    dict_path = setup_dir / f"{fuzzer}.dict"
    options: dict[str, str] = {}
    if options_path.exists():
        parser = configparser.ConfigParser()
        parser.read(options_path, encoding="utf-8")
        if parser.has_section("libfuzzer"):
            options = {key: value for key, value in parser.items("libfuzzer")}
    return {
        "options_path": str(options_path) if options_path.exists() else None,
        "dict_path": str(dict_path) if dict_path.exists() else None,
        "options": options,
    }


def _preferred_extensions(format_family: str | None, fuzzer: str) -> list[str]:
    return _shared_preferred_extensions(format_family, fuzzer)


def _curated_corpus_dir(project: str, fuzzer: str) -> Path:
    return CURATED_CORPUS_ROOT / project / fuzzer


def _copy_into_curated(src: Path, dest_dir: Path, prefix: str) -> str | None:
    try:
        data = src.read_bytes()
    except OSError:
        return None
    if len(data) > 1_000_000:
        return None
    digest = hashlib.sha256(data).hexdigest()
    suffix = src.suffix if src.suffix else ".bin"
    dest = dest_dir / f"{prefix}_{digest}{suffix}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        dest.write_bytes(data)
    return dest.name


def _copy_curated_seeds(project: str, fuzzer: str, out_dir: Path, limit: int = 8) -> list[str]:
    curated_dir = _curated_corpus_dir(project, fuzzer)
    if not curated_dir.exists():
        return []
    created: list[str] = []
    for seed in sorted(curated_dir.iterdir())[:limit]:
        if not seed.is_file():
            continue
        name = f"curated_{seed.name}"
        shutil.copy2(seed, out_dir / name)
        created.append(name)
    return created


def _seed_identifier_tokens(*values: str) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        for token in re.split(r"[^a-z0-9]+", value.lower()):
            if len(token) >= 3:
                tokens.add(token)
    return tokens


def _profile_seed_keywords(profile: dict[str, Any], candidate_fuzz: dict[str, Any], fuzzer: str) -> set[str]:
    keywords = _seed_identifier_tokens(
        str(profile.get("bug_shape") or ""),
        str(profile.get("format_family") or ""),
        str(profile.get("subsystem") or ""),
        str(profile.get("input_model") or ""),
        str(profile.get("patch_path") or ""),
        str(candidate_fuzz.get("target_function") or ""),
        str(candidate_fuzz.get("target_file") or ""),
        str(candidate_fuzz.get("subsystem") or ""),
        str(candidate_fuzz.get("input_model") or ""),
        str(candidate_fuzz.get("bug_shape") or ""),
        fuzzer,
    )
    for hotspot in candidate_fuzz.get("blocker_hotspots") or []:
        if isinstance(hotspot, dict):
            keywords.update(
                _seed_identifier_tokens(
                    str(hotspot.get("function_name") or ""),
                    str(hotspot.get("source_file") or ""),
                )
            )
    return {
        token
        for token in keywords
        if token
        not in {
            "fuzz",
            "seed",
            "input",
            "valid",
            "small",
            "with",
            "from",
            "into",
            "text",
            "binary",
            "parser",
            "table",
        }
    }


def _template_similarity_context(source_templates: list[Path]) -> dict[str, Any]:
    preferred_names = [path.name.lower() for path in source_templates]
    size_hints: list[int] = []
    text_tokens: set[str] = set()
    for path in source_templates[:6]:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        size_hints.append(len(data))
        if path.suffix.lower() in {".js", ".mjs", ".json", ".txt"}:
            text = data.decode("utf-8", errors="ignore")
            text_tokens.update(_seed_identifier_tokens(text[:4096]))
    return {
        "names": preferred_names,
        "name_tokens": _seed_identifier_tokens(*preferred_names),
        "size_hints": size_hints,
        "text_tokens": text_tokens,
    }


def _copy_builtin_corpus_zip(project: str, fuzzer: str) -> Path | None:
    config = load_project_config(project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, project)
    image_tag = runtime.require_ready_image()
    digest = hashlib.sha256(image_tag.encode("utf-8")).hexdigest()[:12]
    cache_dir = BUILTIN_CORPUS_CACHE_ROOT / project / fuzzer
    cache_dir.mkdir(parents=True, exist_ok=True)
    zip_path = cache_dir / f"{digest}_{fuzzer}_seed_corpus.zip"
    if zip_path.exists():
        return zip_path
    session = DockerSession.start(project=project, image_tag=image_tag)
    try:
        check = session.exec(f"test -f /out/{fuzzer}_seed_corpus.zip")
        if check.returncode != 0:
            return None
        session.copy_from(f"/out/{fuzzer}_seed_corpus.zip", zip_path)
    finally:
        session.stop()
    return zip_path if zip_path.exists() else None


def _score_builtin_corpus_member(
    *,
    info: zipfile.ZipInfo,
    data: bytes,
    preferred_exts: set[str],
    keyword_hints: set[str],
    template_context: dict[str, Any],
    profile: dict[str, Any],
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    low_name = info.filename.lower()
    ext = Path(info.filename).suffix.lower()
    if ext in preferred_exts:
        score += 8
        reasons.append(f"extension matches {ext or 'preferred corpus style'}")
    elif not ext and ".bin" in preferred_exts:
        score += 3
        reasons.append("extensionless entry still fits binary corpus")

    name_tokens = _seed_identifier_tokens(info.filename)
    overlap = sorted(name_tokens & keyword_hints)
    if overlap:
        score += min(8, 2 * len(overlap))
        reasons.append(f"name overlaps target context: {', '.join(overlap[:4])}")

    template_name_overlap = sorted(name_tokens & set(template_context.get("name_tokens") or set()))
    if template_name_overlap:
        score += min(6, len(template_name_overlap))
        reasons.append(f"name overlaps source templates: {', '.join(template_name_overlap[:4])}")

    if any(token in low_name for token in ("seed", "sample", "case", "corpus", "input", "crash")):
        score += 2
        reasons.append("filename already looks seed-like")

    size_hints = [int(value) for value in (template_context.get("size_hints") or []) if int(value) > 0]
    if size_hints:
        nearest = min(abs(len(data) - hint) for hint in size_hints)
        if nearest <= 64:
            score += 4
            reasons.append("size is close to source template")
        elif nearest <= 512:
            score += 2
            reasons.append("size is moderately close to source template")

    text = ""
    format_family = str(profile.get("format_family") or "")
    bug_shape = str(profile.get("bug_shape") or "")
    if format_family in {"script_text", "json_text"}:
        text = data.decode("utf-8", errors="ignore")
        text_tokens = _seed_identifier_tokens(text[:4096])
        overlap = sorted(text_tokens & set(template_context.get("text_tokens") or set()))
        if overlap:
            score += min(8, len(overlap))
            reasons.append(f"content overlaps source templates: {', '.join(overlap[:4])}")
        if format_family == "script_text":
            if any(token in text for token in ("function", "var ", "let ", "const ", "=>", "class ")):
                score += 3
                reasons.append("content looks like parseable script text")
            if any(token in text for token in ("/(", "RegExp", "regexp", "match(", "replace(")):
                score += 2
                reasons.append("content already touches regexp-heavy script paths")
        if format_family == "json_text":
            if text.lstrip().startswith(("{", "[")):
                score += 3
                reasons.append("content looks like valid JSON")
            if text.count("{") + text.count("[") >= 4:
                score += 2
                reasons.append("content has nested structured containers")
    elif format_family == "font_binary":
        if b"GSUB" in data or b"GPOS" in data:
            score += 5
            reasons.append("font tables include GSUB/GPOS markers")
        if bug_shape == "unchecked_index" and len(data) >= 512:
            score += 2
            reasons.append("sized large enough for table/count perturbations")
    elif format_family == "image_png":
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            score += 5
            reasons.append("valid PNG signature")
        if b"IDAT" in data or b"IHDR" in data:
            score += 3
            reasons.append("PNG chunk layout is recognizable")
    elif format_family == "zip_archive":
        if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x01\x02"):
            score += 5
            reasons.append("ZIP header is recognizable")

    if bug_shape in {"removed_length_restriction", "removed_copy_size_constraint"} and len(data) >= 256:
        score += 2
        reasons.append("payload is large enough for length-growth perturbations")
    if bug_shape == "parser_state_misuse":
        if text and any(token in text for token in ("}", "]", "case ", "default", "else")):
            score += 2
            reasons.append("text contains stateful delimiters worth reordering")
        elif data.count(b"IDAT") > 0 or data.count(b"GSUB") > 0:
            score += 2
            reasons.append("binary layout contains state-like repeated sections")
    return score, reasons


def _select_builtin_corpus_members(
    *,
    project: str,
    fuzzer: str,
    profile: dict[str, Any],
    source_templates: list[Path],
    candidate_fuzz: dict[str, Any],
    limit: int = 16,
    replay_limit: int = 6,
) -> list[dict[str, Any]]:
    zip_path = _copy_builtin_corpus_zip(project, fuzzer)
    if zip_path is None or not zip_path.exists():
        return []
    preferred_exts = set(_preferred_extensions(profile.get("format_family"), fuzzer))
    keyword_hints = _profile_seed_keywords(profile, candidate_fuzz, fuzzer)
    template_context = _template_similarity_context(source_templates)
    ranked: list[tuple[int, str, dict[str, Any]]] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.file_size <= 0 or info.file_size > 2_000_000:
                continue
            try:
                data = zf.read(info)
            except OSError:
                continue
            score, reasons = _score_builtin_corpus_member(
                info=info,
                data=data,
                preferred_exts=preferred_exts,
                keyword_hints=keyword_hints,
                template_context=template_context,
                profile=profile,
            )
            ext = Path(info.filename).suffix.lower() or ".bin"
            base_name = Path(info.filename).name or Path(info.filename).stem or "builtin_seed"
            digest = hashlib.sha256(f"{info.filename}:{info.CRC}:{info.file_size}".encode("utf-8")).hexdigest()[:10]
            name = f"builtin_{len(ranked):02d}_{_sanitize_tag(base_name)}_{digest}{ext}"
            ranked.append(
                (
                    score,
                    info.filename,
                    {
                        "name": name,
                        "archive_member": info.filename,
                        "size": len(data),
                        "provenance": "builtin_corpus_member",
                        "selection_score": score,
                        "selection_reasons": reasons,
                        "bug_conditioned": False,
                        "data": data,
                    },
                )
            )
    ranked.sort(key=lambda item: (-item[0], item[1]))
    selected: list[dict[str, Any]] = []
    for index, (_, _, item) in enumerate(ranked[:limit]):
        item["replay_target"] = index < replay_limit
        item["replay_order"] = index
        selected.append(item)
    return selected


def _generated_input_records(
    generated_names: list[str],
    *,
    curated_names: set[str] | None = None,
) -> list[dict[str, Any]]:
    curated_names = curated_names or set()
    records: list[dict[str, Any]] = []
    for name in generated_names:
        provenance = "curated_carryover" if name in curated_names else "generated_local"
        records.append(
            {
                "name": name,
                "relative_path": str(Path("artifacts/exploit_files/generated_inputs") / name),
                "provenance": provenance,
            }
        )
    return records


def _candidate_template_files(source_attempt_dir: Path) -> list[Path]:
    roots = [
        source_attempt_dir / "artifacts" / "exploit_files",
        source_attempt_dir / "exploit_seed",
        source_attempt_dir / "reference",
    ]
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            lowered_parts = [part.lower() for part in path.parts]
            if any(
                part == token
                or part.startswith(f"{token}_")
                or part.endswith(f"_{token}")
                for part in lowered_parts
                for token in _SOURCE_TEMPLATE_REJECT_PATH_PART_PATTERNS
            ):
                continue
            low_name = path.name.lower()
            if path.name in {"exploit.sh", "attack.sh", "attack.py", "driver.c", "poc.c", "trigger.c"}:
                continue
            if any(token in low_name for token in _SOURCE_TEMPLATE_REJECT_NAME_TOKENS):
                continue
            if path.suffix.lower() in {".py", ".sh", ".c", ".cc", ".cpp", ".h", ".hpp", ".md", ".json"} and path.parent.name != "generated_inputs":
                # Keep structured data like .json only when it is likely a real input, skip obvious code/docs.
                if path.suffix.lower() == ".json" and path.name not in {"package.json", "tsconfig.json"}:
                    pass
                else:
                    continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > 1_000_000:
                continue
            files.append(path)
    return files


def _collect_source_templates(source_attempt_dir: Path, profile: dict[str, Any], fuzzer: str) -> list[Path]:
    preferred_exts = set(_preferred_extensions(profile.get("format_family"), fuzzer))
    ranked: list[tuple[int, Path]] = []
    for path in _candidate_template_files(source_attempt_dir):
        score = 0
        ext = path.suffix.lower()
        if ext in preferred_exts:
            score += 5
        elif not ext and ".bin" in preferred_exts:
            score += 2
        low_name = path.name.lower()
        if any(token in low_name for token in ("poc", "seed", "crash", "input", "sample", "trigger", "proof")):
            score += 2
        if path.parent.name in {"exploit_seed", "reference"}:
            score += 2
        if score > 0:
            ranked.append((score, path))
    ranked.sort(key=lambda item: (-item[0], len(item[1].name), str(item[1])))
    return [path for _, path in ranked[:8]]


def _register_curated_results(attempt_dir: Path) -> None:
    try:
        manifest = read_json(attempt_dir / "artifacts" / "exploit_files" / "fuzz_poc_manifest.json")
    except Exception:
        return
    project = manifest.get("project")
    selected = manifest.get("selected_fuzzer") or {}
    fuzzer = selected.get("fuzzer")
    if not project or not fuzzer:
        return
    curated_dir = _curated_corpus_dir(str(project), str(fuzzer))

    generated_dir = attempt_dir / "artifacts" / "exploit_files" / "generated_inputs"
    for path in sorted(generated_dir.glob("*")):
        if path.is_file():
            _copy_into_curated(path, curated_dir, "seed")

    for phase in ("secure", "vulnerable"):
        findings_dir = attempt_dir / "artifacts" / "exploit_files" / "fuzz_results" / phase
        for artifact in sorted(findings_dir.glob("crash-*")):
            _copy_into_curated(artifact, curated_dir, f"{phase}_crash")


def _generate_utf16_variants(out_dir: Path) -> list[str]:
    payloads = {
        "bom_only.obj": bytes.fromhex("feff"),
        "bom_a.obj": bytes.fromhex("feff0061"),
        "bom_ab.obj": bytes.fromhex("feff00610062"),
        "bom_ab_nul.obj": bytes.fromhex("feff006100620000"),
        "bom_obj_v.obj": bytes.fromhex("feff") + "v 1 2 3\n".encode("utf-16-be"),
        "bom_obj_face.obj": bytes.fromhex("feff") + "v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3\n".encode("utf-16-be"),
    }
    created: list[str] = []
    for name, body in payloads.items():
        _write_bytes(out_dir / name, body)
        created.append(name)
        _write_bytes(out_dir / name.replace(".obj", "_odd.obj"), body + b"\x00")
        created.append(name.replace(".obj", "_odd.obj"))
        _write_bytes(out_dir / name.replace(".obj", "_extra_nul.obj"), body + b"\x00\x00")
        created.append(name.replace(".obj", "_extra_nul.obj"))
    return created


def _generate_gsub_variants(out_dir: Path, source_templates: list[Path]) -> list[str]:
    created: list[str] = []
    if source_templates:
        base = source_templates[0].read_bytes()
    else:
        base = b"\x00\x01\x00\x00GSUB\x00\x00\x00\x10" + (b"\x00" * 64)
    for pos in range(min(len(base), 44), min(len(base), 52)):
        for val, suffix in ((0x00, "z"), (0xFF, "f")):
            buf = bytearray(base)
            buf[pos] = val
            name = f"gsub_byte_{pos:04d}_{suffix}.bin"
            _write_bytes(out_dir / name, bytes(buf))
            created.append(name)
    for suffix in (b"\xff", b"\xff\xff", b"\x00\xff\x00\xff", b"\xff" * 8):
        name = f"gsub_tail_{suffix.hex()}.bin"
        _write_bytes(out_dir / name, base + suffix)
        created.append(name)
    return created


def _generate_text_bound_variants(out_dir: Path) -> list[str]:
    variants = {
        "long_line.txt": ("A" * 4096 + "\n").encode(),
        "long_token.txt": ("tok" * 2048).encode(),
        "multiline.txt": ("line1\n" + ("B" * 2048) + "\nline3\n").encode(),
    }
    created: list[str] = []
    for name, body in variants.items():
        _write_bytes(out_dir / name, body)
        created.append(name)
    return created


def _generate_zip_like_variants(out_dir: Path) -> list[str]:
    variants = {
        "tiny.zip": b"PK\x03\x04" + b"\x00" * 26,
        "long_name.zip": b"PK\x03\x04" + b"\x00" * 22 + b"\xff\x0f\x00\x00" + (b"A" * 512),
        "central_dir.zip": b"PK\x01\x02" + b"\x00" * 42 + (b"B" * 256),
    }
    created: list[str] = []
    for name, body in variants.items():
        _write_bytes(out_dir / name, body)
        created.append(name)
    return created


def _generate_png_like_variants(out_dir: Path) -> list[str]:
    variants = {
        "tiny.png": bytes.fromhex(
            "89504e470d0a1a0a"
            "0000000d4948445200000001000000010802000000907753de"
            "0000000c4944415408d763f8ffff3f0005fe02fea7a6459b"
            "0000000049454e44ae426082"
        ),
        "bad_len.png": bytes.fromhex(
            "89504e470d0a1a0a"
            "7fffffff4948445200000001000000010802000000907753de"
        ),
        "short_chunk.png": bytes.fromhex("89504e470d0a1a0a0000000d49484452"),
    }
    created: list[str] = []
    for name, body in variants.items():
        _write_bytes(out_dir / name, body)
        created.append(name)
    return created


def _generate_script_variants(out_dir: Path) -> list[str]:
    variants = {
        "empty.js": b"",
        "simple.js": b"var x = 1;\n",
        "nested.js": b"function f(a){ if(a){ return (a + 1) * (a - 2); } return 0; }\nf(3);\n",
        "regexp.js": b"var r = /(ab|cd)+/;\n'r'.match(r);\n",
        "truncated.js": b"function g(){ return [1,2,3",
    }
    created: list[str] = []
    for name, body in variants.items():
        _write_bytes(out_dir / name, body)
        created.append(name)
    return created


def _generate_json_variants(out_dir: Path) -> list[str]:
    variants = {
        "empty.json": b"",
        "obj.json": b"{\"k\":1}\n",
        "array.json": b"[1,2,3,4]\n",
        "deep.json": b"{\"a\":{\"b\":{\"c\":[1,2,{\"d\":4}]}}}\n",
        "truncated.json": b"{\"a\":[1,2,3}",
    }
    created: list[str] = []
    for name, body in variants.items():
        _write_bytes(out_dir / name, body)
        created.append(name)
    return created


def _generate_generic_binary_variants(out_dir: Path) -> list[str]:
    variants = {
        "empty.bin": b"",
        "one_ff.bin": b"\xff",
        "short_zeros.bin": b"\x00" * 8,
        "edge_mix.bin": b"\x00\xff\x00\xff\xff\x00\x01\x7f",
        "long_ff.bin": b"\xff" * 256,
    }
    created: list[str] = []
    for name, body in variants.items():
        _write_bytes(out_dir / name, body)
        created.append(name)
    return created


def _template_specific_variants(template: Path, data: bytes, format_family: str | None) -> dict[str, bytes]:
    ext = template.suffix.lower()
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", template.name)
    variants: dict[str, bytes] = {f"{stem}.orig": data}

    if format_family == "text_obj_utf16" or (ext == ".obj" and data.startswith(b"\xfe\xff")):
        variants[f"{stem}.trim2"] = data[: max(0, len(data) - 2)]
        variants[f"{stem}.extra_nul"] = data + b"\x00\x00"
        if len(data) >= 4:
            variants[f"{stem}.swap_tail"] = data[:-4] + data[-2:] + data[-4:-2]
        return variants

    if ext in {".obj", ".txt"} and (format_family == "model_asset" or format_family == "text_obj_utf16"):
        variants[f"{stem}.append_vertex"] = data + b"\nv 0 0 0\n"
        variants[f"{stem}.append_face"] = data + b"\nf 1 1 1\n"
        variants[f"{stem}.trim"] = data[: max(0, len(data) - 1)]
        return variants

    if ext in {".js", ".mjs"} or format_family == "script_text":
        variants[f"{stem}.append_block"] = data + b"\n(function(){return 1+2;})();\n"
        variants[f"{stem}.append_regexp"] = data + b"\nvar __r = /(ab|cd)+/;\n"
        variants[f"{stem}.trim"] = data[: max(0, len(data) - 1)]
        return variants

    if ext == ".json" or format_family == "json_text":
        variants[f"{stem}.append_obj"] = data + b"\n{\"x\":1}\n"
        variants[f"{stem}.append_array"] = data + b"\n[1,2,3]\n"
        variants[f"{stem}.trim"] = data[: max(0, len(data) - 1)]
        return variants

    if ext == ".png" or format_family == "image_png":
        variants[f"{stem}.tail_ff"] = data + b"\xff\xff\xff\xff"
        variants[f"{stem}.trim"] = data[: max(0, len(data) - 4)]
        if len(data) > 16:
            corrupted = bytearray(data)
            corrupted[12] ^= 0xFF
            variants[f"{stem}.chunkflip"] = bytes(corrupted)
        return variants

    if ext == ".zip" or format_family == "zip_archive":
        variants[f"{stem}.tail_ff"] = data + b"\xff\xff"
        variants[f"{stem}.trim"] = data[: max(0, len(data) - 2)]
        if len(data) > 8:
            corrupted = bytearray(data)
            corrupted[6] ^= 0xFF
            variants[f"{stem}.hdrflip"] = bytes(corrupted)
        return variants

    variants[f"{stem}.trim"] = data[: max(0, len(data) - 1)]
    variants[f"{stem}.ff"] = data + b"\xff"
    variants[f"{stem}.nul"] = data + b"\x00"
    if data:
        mid = len(data) // 2
        flipped = bytearray(data)
        flipped[mid] ^= 0xFF
        variants[f"{stem}.midflip"] = bytes(flipped)
    return variants


def _copy_template_mutations(
    out_dir: Path,
    source_templates: list[Path],
    format_family: str | None,
    limit: int = 6,
) -> list[str]:
    created: list[str] = []
    for template in source_templates[:limit]:
        data = template.read_bytes()
        variants = _template_specific_variants(template, data, format_family)
        for name, body in variants.items():
            _write_bytes(out_dir / name, body)
            created.append(name)
    return created


def _seed_bases(
    source_templates: list[Path],
    builtin_corpus_members: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    bases: list[dict[str, Any]] = []
    for path in source_templates:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        bases.append(
            {
                "name": path.name,
                "data": data,
                "source_name": path.name,
                "source_ref": str(path),
                "source_kind": "source_template",
            }
        )
    for item in builtin_corpus_members or []:
        if not item.get("data"):
            continue
        bases.append(
            {
                "name": item["name"],
                "data": item["data"],
                "source_name": item["archive_member"],
                "source_ref": item["archive_member"],
                "source_kind": "builtin_corpus",
            }
        )
    return bases


def _seed_record(
    *,
    name: str,
    relative_path: str,
    provenance: str,
    generator: str,
    bug_conditioned: bool,
    source_kind: str,
    source_name: str,
    replay_order: int | None = None,
    replay_target: bool = True,
    corpus_target: bool = True,
) -> dict[str, Any]:
    return {
        "name": name,
        "relative_path": relative_path,
        "provenance": provenance,
        "generator": generator,
        "bug_conditioned": bug_conditioned,
        "source_kind": source_kind,
        "source_name": source_name,
        "replay_target": replay_target,
        "corpus_target": corpus_target,
        "replay_order": 0 if replay_order is None else replay_order,
    }


def _store_generated_seed(
    *,
    out_dir: Path,
    records: list[dict[str, Any]],
    seen_hashes: dict[str, str],
    body: bytes,
    origin_name: str,
    label: str,
    provenance: str,
    generator: str,
    bug_conditioned: bool,
    source_kind: str,
    source_name: str,
) -> None:
    digest = hashlib.sha256(body).hexdigest()
    if digest in seen_hashes:
        return
    ext = Path(origin_name).suffix or ".bin"
    stem = _sanitize_tag(Path(origin_name).stem or Path(origin_name).name or "seed")
    name = f"{stem}_{label}_{digest[:10]}{ext}"
    _write_bytes(out_dir / name, body)
    seen_hashes[digest] = name
    records.append(
        _seed_record(
            name=name,
            relative_path=str(Path("artifacts/exploit_files/generated_inputs") / name),
            provenance=provenance,
            generator=generator,
            bug_conditioned=bug_conditioned,
            source_kind=source_kind,
            source_name=source_name,
            replay_order=len(records),
        )
    )


def _generate_script_bug_conditioned_variants(base: bytes, bug_shape: str) -> list[tuple[str, bytes]]:
    text = base.decode("utf-8", errors="ignore").strip()
    if not text:
        text = "var seed = 1;"
    variants: list[tuple[str, bytes]] = []
    if bug_shape == "removed_length_restriction":
        grown = text + "\nvar __payload = [" + ",".join("1" for _ in range(192)) + "];\n"
        variants.append(("script_grow_array", grown.encode()))
        nested = text + "\nfunction __nest(){ return [[[[" + ",".join("7" for _ in range(64)) + "]]]]; }\n__nest();\n"
        variants.append(("script_nested_growth", nested.encode()))
    elif bug_shape == "unchecked_index":
        indexed = text + "\nvar __arr = [0,1,2,3];\n__arr[255] = 1;\n__arr[256] = __arr.length;\n"
        variants.append(("script_index_edges", indexed.encode()))
        refs = text + "\nvar __refs = [0,1,2,3];\nfor (var i = 0; i < 48; i++) __refs.push(i);\n"
        variants.append(("script_index_ref_growth", refs.encode()))
    elif bug_shape == "removed_copy_size_constraint":
        long_str = text + "\nvar __s = '" + ("A" * 2048) + "';\n__s.slice(0, 32);\n"
        variants.append(("script_long_string", long_str.encode()))
        long_regex = text + "\nvar __rx = /(" + ("ab|" * 128) + "cd)+/;\n'abcdef'.match(__rx);\n"
        variants.append(("script_long_regexp", long_regex.encode()))
    elif bug_shape == "parser_state_misuse":
        late_invalid = text + "\n(function(){ return {a:1,b:[1,2,3]}; })();\nif (true) { var x = 1; }\nelse\n"
        variants.append(("script_late_state_break", late_invalid.encode()))
        dup_tokens = text + "\nswitch (1) { case 1: break; case 1: break; default: break; }\n"
        variants.append(("script_duplicate_control", dup_tokens.encode()))
    else:
        regexp = text + "\nvar __r = /([a-z]+)+/;\n'alpha'.match(__r);\n"
        variants.append(("script_regexp_probe", regexp.encode()))
    return variants


def _generate_json_bug_conditioned_variants(base: bytes, bug_shape: str) -> list[tuple[str, bytes]]:
    text = base.decode("utf-8", errors="ignore").strip() or "{\"seed\":1}"
    variants: list[tuple[str, bytes]] = []
    if bug_shape == "removed_length_restriction":
        variants.append(("json_large_array", ("{\"items\":[" + ",".join("1" for _ in range(256)) + "]}\n").encode()))
        variants.append(("json_nested_growth", b'{"a":{"b":{"c":{"d":[1,2,3,4,5,6,7,8]}}}}\n'))
    elif bug_shape == "unchecked_index":
        variants.append(("json_index_edges", b'{"count":256,"refs":[0,1,2,3,254,255,256]}\n'))
        variants.append(("json_sparse_refs", b'{"rows":[{"idx":0},{"idx":127},{"idx":255},{"idx":511}]}\n'))
    elif bug_shape == "parser_state_misuse":
        variants.append(("json_duplicate_keys", b'{"mode":"a","mode":"b","items":[1,2,3]}\n'))
        variants.append(("json_late_truncation", (text + '\n{"tail":[1,2,3]').encode()))
    else:
        variants.append(("json_text_growth", (text + '\n{"padding":"' + ("B" * 1024) + '"}\n').encode()))
    return variants


def _parse_png_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return []
    chunks: list[tuple[bytes, bytes]] = []
    cursor = 8
    while cursor + 12 <= len(data):
        length = int.from_bytes(data[cursor:cursor + 4], "big")
        end = cursor + 12 + length
        if end > len(data):
            break
        chunk_type = data[cursor + 4:cursor + 8]
        chunks.append((chunk_type, data[cursor:end]))
        cursor = end
        if chunk_type == b"IEND":
            break
    return chunks


def _generate_png_bug_conditioned_variants(base: bytes, bug_shape: str) -> list[tuple[str, bytes]]:
    chunks = _parse_png_chunks(base)
    if not chunks:
        return []
    variants: list[tuple[str, bytes]] = []
    prefix = b"\x89PNG\r\n\x1a\n"
    if bug_shape == "removed_copy_size_constraint":
        for chunk_type, raw in chunks:
            if chunk_type not in {b"IDAT", b"tEXt", b"iTXt", b"zTXt"}:
                continue
            oversized = bytearray(raw)
            declared = int.from_bytes(oversized[:4], "big")
            oversized[:4] = min(0x7FFFFFF0, declared + 512).to_bytes(4, "big")
            variants.append(("png_declared_len_growth", prefix + b"".join(part for _, part in chunks[:-1]) + bytes(oversized) + chunks[-1][1]))
            break
    if bug_shape in {"parser_state_misuse", "removed_length_restriction"}:
        idat = next((raw for chunk_type, raw in chunks if chunk_type == b"IDAT"), None)
        if idat is not None:
            body = prefix + b"".join(part for _, part in chunks[:-1]) + idat + chunks[-1][1]
            variants.append(("png_duplicate_idat", body))
    if not variants:
        first = chunks[0][1]
        flipped = bytearray(first)
        if len(flipped) >= 8:
            flipped[7] ^= 0x01
        variants.append(("png_chunk_state_flip", prefix + bytes(flipped) + b"".join(part for _, part in chunks[1:])))
    return variants


def _generate_font_bug_conditioned_variants(base: bytes, bug_shape: str) -> list[tuple[str, bytes]]:
    variants: list[tuple[str, bytes]] = []
    marker = b"GSUB" if b"GSUB" in base else b"GPOS" if b"GPOS" in base else None
    if marker is not None:
        idx = base.find(marker)
        if bug_shape == "unchecked_index":
            buf = bytearray(base)
            for offset in (idx + 8, idx + 10, idx + 12):
                if offset < len(buf):
                    buf[offset] = 0xFF
            variants.append(("font_table_count_edges", bytes(buf)))
            tail = base[idx: min(len(base), idx + 64)]
            variants.append(("font_duplicate_table_tail", base + tail))
        elif bug_shape == "parser_state_misuse":
            tail = base[idx: min(len(base), idx + 24)]
            variants.append(("font_duplicate_state_marker", base + marker + tail))
    if not variants and base:
        flipped = bytearray(base)
        for offset in range(min(len(flipped), 48), min(len(flipped), 56)):
            flipped[offset] ^= 0xFF
        variants.append(("font_boundary_flip", bytes(flipped)))
    return variants


def _generate_text_bug_conditioned_variants(base: bytes, bug_shape: str) -> list[tuple[str, bytes]]:
    text = base.decode("utf-8", errors="ignore")
    if not text:
        text = "seed\n"
    variants: list[tuple[str, bytes]] = []
    if bug_shape in {"removed_length_restriction", "removed_copy_size_constraint"}:
        variants.append(("text_long_line", (text + ("A" * 4096) + "\n").encode()))
        variants.append(("text_repeat_block", (text + ("section=repeat\n" * 256)).encode()))
    elif bug_shape == "parser_state_misuse":
        variants.append(("text_reordered_sections", (text + "END\nBEGIN\n").encode()))
    else:
        variants.append(("text_boundary_probe", (text + "\n" + ("B" * 1024)).encode()))
    return variants


def _bug_conditioned_variants_for_seed(
    seed: dict[str, Any],
    profile: dict[str, Any],
) -> list[tuple[str, bytes]]:
    format_family = str(profile.get("format_family") or "")
    bug_shape = str(profile.get("bug_shape") or "")
    data = seed["data"]
    if format_family == "script_text":
        return _generate_script_bug_conditioned_variants(data, bug_shape)
    if format_family == "json_text":
        return _generate_json_bug_conditioned_variants(data, bug_shape)
    if format_family == "image_png":
        return _generate_png_bug_conditioned_variants(data, bug_shape)
    if format_family == "font_binary":
        return _generate_font_bug_conditioned_variants(data, bug_shape)
    return _generate_text_bug_conditioned_variants(data, bug_shape)


def _capture_new_files(out_dir: Path, previous: set[str]) -> list[str]:
    return sorted(path.name for path in out_dir.iterdir() if path.is_file() and path.name not in previous)


def _generator_family_order(profile: dict[str, Any]) -> list[str]:
    generators = list(dict.fromkeys(profile.get("input_generators") or []))
    format_family = profile.get("format_family")
    if format_family == "image_png" and "png_like_variants" not in generators:
        generators.append("png_like_variants")
    elif format_family == "script_text" and "script_text_variants" not in generators:
        generators.append("script_text_variants")
    elif format_family == "json_text" and "json_text_variants" not in generators:
        generators.append("json_text_variants")
    elif format_family == "zip_archive" and "zip_like_binary_variants" not in generators:
        generators.append("zip_like_binary_variants")
    elif format_family == "font_binary" and "gsub_marker_mutations" not in generators:
        generators.append("gsub_marker_mutations")
    if "generic_small_binary_variants" not in generators:
        generators.append("generic_small_binary_variants")
    return generators


def _generate_input_records(
    profile: dict[str, Any],
    out_dir: Path,
    source_templates: list[Path],
    *,
    builtin_corpus_members: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    seen_hashes: dict[str, str] = {}
    format_family = profile.get("format_family")
    for item in builtin_corpus_members or []:
        body = item.get("data")
        name = str(item.get("name") or "").strip()
        if not name or not isinstance(body, (bytes, bytearray)):
            continue
        digest = hashlib.sha256(bytes(body)).hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes[digest] = name
        path = out_dir / name
        path.write_bytes(bytes(body))
        records.append(
            _seed_record(
                name=name,
                relative_path=str(Path("artifacts/exploit_files/generated_inputs") / name),
                provenance=str(item.get("provenance") or "builtin_corpus_member"),
                generator="builtin_corpus_replay",
                bug_conditioned=bool(item.get("bug_conditioned")),
                source_kind="builtin_corpus",
                source_name=str(item.get("archive_member") or item.get("name") or ""),
                replay_target=bool(item.get("replay_target")),
                corpus_target=True,
                replay_order=item.get("replay_order"),
            )
        )

    bases = _seed_bases(source_templates, builtin_corpus_members)
    for seed in bases[:6]:
        pseudo_path = Path(seed["name"])
        provenance = "source_template_variant" if seed["source_kind"] == "source_template" else "builtin_derived_bug_conditioned_variant"
        for label, body in _template_specific_variants(pseudo_path, seed["data"], format_family).items():
            label_suffix = label.rsplit(".", 1)[-1]
            if seed["source_kind"] == "builtin_corpus" and label_suffix == "orig":
                continue
            _store_generated_seed(
                out_dir=out_dir,
                records=records,
                seen_hashes=seen_hashes,
                body=body,
                origin_name=seed["name"],
                label=label_suffix,
                provenance=provenance,
                generator="template_specific_mutation",
                bug_conditioned=seed["source_kind"] == "builtin_corpus",
                source_kind=seed["source_kind"],
                source_name=seed["source_name"],
            )

    policy_bases = [seed for seed in bases if seed["source_kind"] == "builtin_corpus"][:4]
    policy_bases.extend(seed for seed in bases if seed["source_kind"] == "source_template")
    for seed in policy_bases[:6]:
        provenance = (
            "builtin_derived_bug_conditioned_variant"
            if seed["source_kind"] == "builtin_corpus"
            else "source_derived_bug_conditioned_variant"
        )
        for label, body in _bug_conditioned_variants_for_seed(seed, profile):
            _store_generated_seed(
                out_dir=out_dir,
                records=records,
                seen_hashes=seen_hashes,
                body=body,
                origin_name=seed["name"],
                label=label,
                provenance=provenance,
                generator="bug_conditioned_policy",
                bug_conditioned=True,
                source_kind=seed["source_kind"],
                source_name=seed["source_name"],
            )

    for generator in _generator_family_order(profile):
        existing = {path.name for path in out_dir.iterdir() if path.is_file()}
        if generator == "utf16_be_obj_variants":
            _generate_utf16_variants(out_dir)
        elif generator == "gsub_marker_mutations":
            _generate_gsub_variants(out_dir, source_templates)
        elif generator == "png_like_variants":
            _generate_png_like_variants(out_dir)
        elif generator == "script_text_variants":
            _generate_script_variants(out_dir)
        elif generator == "json_text_variants":
            _generate_json_variants(out_dir)
        elif generator == "zip_like_binary_variants":
            _generate_zip_like_variants(out_dir)
        elif generator in {"long_line_variants", "long_filename_token_variants"}:
            _generate_text_bound_variants(out_dir)
        elif generator == "generic_small_binary_variants":
            _generate_generic_binary_variants(out_dir)
        for name in _capture_new_files(out_dir, existing):
            path = out_dir / name
            try:
                body = path.read_bytes()
            except OSError:
                continue
            digest = hashlib.sha256(body).hexdigest()
            seen_hashes.setdefault(digest, name)
            records.append(
                _seed_record(
                    name=name,
                    relative_path=str(Path("artifacts/exploit_files/generated_inputs") / name),
                    provenance="generic_generated" if generator == "generic_small_binary_variants" else "format_aware_generated",
                    generator=generator,
                    bug_conditioned=generator != "generic_small_binary_variants",
                    source_kind="generator_family",
                    source_name=generator,
                    replay_order=len(records),
                )
            )

    deduped: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for record in records:
        if record["name"] in seen_names:
            continue
        seen_names.add(record["name"])
        deduped.append(record)
    return deduped


def _generate_inputs(
    profile: dict[str, Any],
    out_dir: Path,
    source_templates: list[Path],
    builtin_corpus_members: list[dict[str, Any]] | None = None,
) -> list[str]:
    return [item["name"] for item in _generate_input_records(profile, out_dir, source_templates, builtin_corpus_members=builtin_corpus_members)]


def _render_fuzz_poc_py(manifest_rel: str) -> str:
    return f"""#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path("/workspace/run/attempt")
MANIFEST = ROOT / {manifest_rel!r}
CFG = json.loads(MANIFEST.read_text(encoding="utf-8"))
PHASE = os.environ.get("VULJECTOR_PHASE_LABEL", "unknown")
EXPLOIT_DIR = ROOT / "artifacts" / "exploit_files"
RESULT_DIR = EXPLOIT_DIR / "fuzz_results" / PHASE
TMP_ROOT = Path("/tmp/vuljector_fuzz_poc") / PHASE
CORPUS_DIR = TMP_ROOT / "corpus"
EXTRA_DIR = TMP_ROOT / "extra_inputs"
FINDINGS_DIR = TMP_ROOT / "findings"
GENERATED_RECORDS = [item for item in (CFG.get("generated_input_records") or []) if isinstance(item, dict) and item.get("name")]
BUILTIN_RECORDS = [item for item in (CFG.get("selected_builtin_corpus_members") or []) if isinstance(item, dict) and item.get("name")]
if not GENERATED_RECORDS:
    GENERATED_RECORDS = [
        {{
            "name": Path(rel).name,
            "relative_path": rel,
            "provenance": "generated_local",
            "generator": "legacy_manifest",
            "bug_conditioned": False,
            "source_kind": "legacy_manifest",
            "source_name": Path(rel).name,
            "replay_target": True,
            "corpus_target": True,
            "replay_order": index,
        }}
        for index, rel in enumerate(CFG.get("generated_inputs") or [])
        if rel
    ]
INPUT_PROVENANCE = {{
    item.get("name"): item
    for item in (GENERATED_RECORDS + BUILTIN_RECORDS)
    if isinstance(item, dict) and item.get("name")
}}

for path in (RESULT_DIR, TMP_ROOT):
    path.mkdir(parents=True, exist_ok=True)
for path in (CORPUS_DIR, EXTRA_DIR, FINDINGS_DIR):
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)

fuzzer = CFG["selected_fuzzer"]["fuzzer"]
binary = Path("/out") / fuzzer
if not binary.exists():
    (RESULT_DIR / "failure.txt").write_text("missing fuzzer binary\\n", encoding="utf-8")
    print("NOT_TRIGGERED")
    sys.exit(0)

def _copy_seed(name, data, *, replay_target=True, corpus_target=True):
    if corpus_target:
        (CORPUS_DIR / name).write_bytes(data)
    if replay_target:
        (EXTRA_DIR / name).write_bytes(data)

corpus_zip = Path("/out") / f"{{fuzzer}}_seed_corpus.zip"
if CFG.get("use_builtin_corpus", False) and corpus_zip.exists():
    with zipfile.ZipFile(corpus_zip) as zf:
        if BUILTIN_RECORDS:
            for item in BUILTIN_RECORDS:
                archive_member = item.get("archive_member")
                if not archive_member:
                    continue
                try:
                    data = zf.read(archive_member)
                except KeyError:
                    continue
                _copy_seed(
                    item["name"],
                    data,
                    replay_target=bool(item.get("replay_target")),
                    corpus_target=bool(item.get("corpus_target", True)),
                )
        else:
            infos = [info for info in zf.infolist() if not info.is_dir()]
            wanted_exts = {{ext.lower() for ext in CFG.get("builtin_corpus_extensions", [])}}
            if wanted_exts:
                preferred = [info for info in infos if Path(info.filename).suffix.lower() in wanted_exts]
                fallback = [info for info in infos if Path(info.filename).suffix.lower() not in wanted_exts]
                infos = preferred + fallback
            infos.sort(key=lambda info: (Path(info.filename).suffix.lower() not in wanted_exts if wanted_exts else False, info.file_size, info.filename))
            for info in infos[: int(CFG.get("builtin_corpus_sample_limit", 0) or 0)]:
                name = Path(info.filename).name
                if not name:
                    continue
                data = zf.read(info)
                INPUT_PROVENANCE.setdefault(
                    name,
                    {{
                        "name": name,
                        "archive_member": info.filename,
                        "provenance": "builtin_corpus_member",
                        "replay_target": False,
                        "corpus_target": True,
                    }},
                )
                _copy_seed(name, data, replay_target=False, corpus_target=True)

for item in GENERATED_RECORDS:
    rel = item.get("relative_path")
    if not rel:
        continue
    src = ROOT / rel
    if src.is_file():
        data = src.read_bytes()
        _copy_seed(
            item["name"],
            data,
            replay_target=bool(item.get("replay_target", True)),
            corpus_target=bool(item.get("corpus_target", True)),
        )

replay_results = []
crash_artifacts = []

def run_and_capture(args, log_name):
    log_path = RESULT_DIR / log_name
    replay_timeout = CFG.get("replay_timeout_seconds")
    started = time.monotonic()
    def _text(value):
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value
    try:
        proc = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=replay_timeout if replay_timeout else None,
        )
        output = proc.stdout
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        output = _text(exc.stdout) + _text(exc.stderr)
        proc = subprocess.CompletedProcess(args=args, returncode=124, stdout=output, stderr=None)
        timed_out = True
    duration = time.monotonic() - started
    log_path.write_text(output, encoding="utf-8")
    crash = ("AddressSanitizer" in output or "UndefinedBehaviorSanitizer" in output or "runtime error:" in output)
    return proc, crash, log_path, timed_out, duration

ordered_replay_records = sorted(
    [item for item in (BUILTIN_RECORDS + GENERATED_RECORDS) if item.get("replay_target")],
    key=lambda item: (int(item.get("replay_order", 9999)), 0 if item.get("archive_member") else 1, item.get("name", "")),
)
replay_queue = []
seen_replay_names = set()
for item in ordered_replay_records:
    seed = EXTRA_DIR / item["name"]
    if seed.is_file() and seed.name not in seen_replay_names:
        replay_queue.append(seed)
        seen_replay_names.add(seed.name)
for seed in sorted(EXTRA_DIR.glob("*")):
    if seed.name not in seen_replay_names:
        replay_queue.append(seed)

for idx, seed in enumerate(replay_queue):
    proc, crash, log_path, timed_out, duration = run_and_capture([str(binary), str(seed)], f"replay_{{idx:02d}}.log")
    provenance = INPUT_PROVENANCE.get(seed.name) or {{"name": seed.name, "provenance": "unknown"}}
    replay_results.append(
        {{
            "seed": seed.name,
            "returncode": proc.returncode,
            "log": str(log_path),
            "crash": crash,
            "timed_out": timed_out,
            "duration_seconds": round(duration, 4),
            "provenance": provenance,
        }}
    )
    if timed_out:
        continue
    if crash or proc.returncode != 0:
        print("TRIGGERED")
        report = {{
            "phase": PHASE,
            "fuzzer": fuzzer,
            "mode": "replay",
            "success_bucket": f"replay_{{provenance.get('provenance', 'unknown')}}",
            "seed": seed.name,
            "seed_provenance": provenance,
            "attribution_kind": "exact_seed",
            "returncode": proc.returncode,
            "log": str(log_path),
            "crash_artifacts": [],
            "time_to_signal_seconds": round(duration, 4),
        }}
        (RESULT_DIR / "crash_report.json").write_text(json.dumps(report, indent=2) + "\\n", encoding="utf-8")
        sys.exit(1)

fuzz_log = RESULT_DIR / "fuzz.log"
max_len = 4096
sizes = []
for seed in CORPUS_DIR.glob("*"):
    try:
        sizes.append(seed.stat().st_size)
    except OSError:
        pass
if sizes:
    max_len = max(64, min(4096, max(sizes) * 2))
max_len = int(CFG.get("libfuzzer_options", {{}}).get("max_len", max_len) or max_len)
args = [
    str(binary),
    f"-artifact_prefix={{FINDINGS_DIR}}/",
    f"-max_total_time={{CFG.get('max_total_time', 60)}}",
    f"-max_len={{max_len}}",
    "-print_final_stats=1",
]
timeout_opt = CFG.get("libfuzzer_options", {{}}).get("timeout")
if timeout_opt:
    args.append(f"-timeout={{timeout_opt}}")
rss_opt = CFG.get("libfuzzer_options", {{}}).get("rss_limit_mb")
if rss_opt:
    args.append(f"-rss_limit_mb={{rss_opt}}")
dict_name = CFG.get("libfuzzer_options", {{}}).get("dict")
dict_path = Path("/out") / (dict_name or f"{{fuzzer}}.dict")
if dict_path.exists():
    args.append(f"-dict={{dict_path}}")
args.append(str(CORPUS_DIR))
if any(EXTRA_DIR.iterdir()):
    args.append(str(EXTRA_DIR))

fuzz_started = time.monotonic()
proc = subprocess.run(
    args,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    encoding="utf-8",
    errors="replace",
)
fuzz_duration = time.monotonic() - fuzz_started
fuzz_log.write_text(proc.stdout, encoding="utf-8")
artifact_paths = []
for artifact in sorted(FINDINGS_DIR.iterdir()):
    dest = RESULT_DIR / artifact.name
    shutil.copy2(artifact, dest)
    artifact_paths.append(str(dest))
    if artifact.name.startswith("crash-"):
        crash_artifacts.append(str(dest))

asan_like = ("AddressSanitizer" in proc.stdout or "UndefinedBehaviorSanitizer" in proc.stdout or "runtime error:" in proc.stdout)
oom_detected = "libFuzzer: out-of-memory" in proc.stdout
leak_detected = "SUMMARY: AddressSanitizer:" in proc.stdout and " leaked in " in proc.stdout
crash = bool(crash_artifacts) or (asan_like and not oom_detected and not leak_detected)

corpus_provenance_counts = {{}}
for seed in CORPUS_DIR.glob("*"):
    provenance = (INPUT_PROVENANCE.get(seed.name) or {{}}).get("provenance", "unknown")
    corpus_provenance_counts[provenance] = corpus_provenance_counts.get(provenance, 0) + 1

def _primary_fuzz_provenance():
    order = [
        "builtin_derived_bug_conditioned_variant",
        "source_derived_bug_conditioned_variant",
        "builtin_corpus_member",
        "source_template_variant",
        "curated_carryover",
        "format_aware_generated",
        "generic_generated",
    ]
    for name in order:
        if corpus_provenance_counts.get(name):
            return name
    return "unknown"

primary_provenance = _primary_fuzz_provenance()
report = {{
    "phase": PHASE,
    "fuzzer": fuzzer,
    "mode": "fuzz",
    "success_bucket": (
        f"fresh_fuzz_{{primary_provenance}}"
        if crash else
        "negative"
    ),
    "seed_provenance": primary_provenance,
    "seed_provenance_exact": False,
    "attribution_kind": "seeded_fuzz_run",
    "returncode": proc.returncode,
    "log": str(fuzz_log),
    "replays": replay_results,
    "crash_artifacts": crash_artifacts,
    "all_artifacts": artifact_paths,
    "oom_detected": oom_detected,
    "leak_detected": leak_detected,
    "asan_like": asan_like,
    "corpus_sources_present": {{
        "builtin_corpus": bool(CFG.get("use_builtin_corpus", False)),
        "curated_corpus": bool(CFG.get("use_curated_corpus", False)),
        "generated_inputs": bool(CFG.get("generated_inputs")),
    }},
    "corpus_provenance_counts": corpus_provenance_counts,
    "time_to_signal_seconds": round(fuzz_duration, 4) if crash else None,
    "result_kind": (
        "real_crash" if crash_artifacts else
        "oom_only" if oom_detected else
        "leak_only" if leak_detected else
        "asan_without_artifact" if asan_like else
        "negative"
    ),
}}
(RESULT_DIR / "crash_report.json").write_text(json.dumps(report, indent=2) + "\\n", encoding="utf-8")

if crash or proc.returncode != 0:
    if oom_detected or leak_detected:
        print("NOT_TRIGGERED")
        sys.exit(0)
    print("TRIGGERED")
    sys.exit(1)

print("NOT_TRIGGERED")
sys.exit(0)
"""


def _render_exploit_sh(project: str) -> str:
    return f"""#!/bin/bash
set -euo pipefail
cd /src/{project}
python3 /workspace/run/attempt/artifacts/exploit_files/fuzz_poc.py
"""


def _resolve_image_tag(config) -> str:
    runtime = build_runtime(config)
    try:
        return runtime.require_ready_image()
    except RuntimeError:
        if config.dockerhub_image and dockerhub_image_matches_engine(config.dockerhub_image, config.fuzzing_engine):
            return config.dockerhub_image
        raise RuntimeError(
            f"no ready image or matching dockerhub_image available for project {config.project} "
            f"with fuzzing_engine={config.fuzzing_engine}"
        )


def _fuzzer_preference_key(project: str, profile: dict[str, Any], fuzzer: str) -> tuple[int, str]:
    if project == "harfbuzz":
        order = {
            "hb-shape-fuzzer": 0,
            "hb-subset-fuzzer": 1,
            "hb-repacker-fuzzer": 2,
            "hb-raster-fuzzer": 3,
            "hb-vector-fuzzer": 4,
            "hb-gpu-fuzzer": 5,
        }
        return (order.get(fuzzer, 50), fuzzer)
    return (50, fuzzer)


def _pick_fuzzer(
    injection_result: Path,
    cache_dir: Path,
    force_fuzzer: str | None,
    profile: dict[str, Any],
) -> dict[str, Any]:
    injection = read_json(injection_result)
    mapping = map_injection_result_to_harness(injection_result, cache_dir)
    project = injection["project"]
    candidate_fuzz = _candidate_fuzz_metadata(injection)
    source = "patch_inference"
    recs = list(candidate_fuzz.get("recommendations") or [])
    if recs:
        source = "selection_metadata"
    else:
        recs = list(mapping.get("recommendations") or [])
    recs.sort(key=lambda item: (-item.get("score", 0), _fuzzer_preference_key(project, profile, item["fuzzer"])))
    if not recs and not candidate_fuzz.get("preferred_fuzzer"):
        raise RuntimeError(f"no recommended fuzzers for {injection_result}")
    if force_fuzzer:
        chosen = next((item for item in recs if item["fuzzer"] == force_fuzzer), None)
        if chosen is None and candidate_fuzz.get("preferred_fuzzer") == force_fuzzer:
            chosen = {
                "fuzzer": force_fuzzer,
                "score": 0,
                "reasons": ["forced override matches selector preferred fuzzer"],
                "has_blockers": bool(candidate_fuzz.get("has_blockers")),
                "has_dict": bool(candidate_fuzz.get("dict_available")),
                "has_options": bool(candidate_fuzz.get("options_available")),
            }
        if chosen is None:
            raise RuntimeError(f"forced fuzzer {force_fuzzer!r} not present in recommendations")
        return {"mapping": mapping, "selected": chosen, "source": "force_override"}
    preferred_fuzzer = candidate_fuzz.get("preferred_fuzzer")
    if preferred_fuzzer:
        chosen = next((item for item in recs if item["fuzzer"] == preferred_fuzzer), None)
        if chosen is not None:
            return {"mapping": mapping, "selected": chosen, "source": source}
        alternates = set(candidate_fuzz.get("alternate_fuzzers") or [])
        alternate = next((item for item in recs if item["fuzzer"] in alternates), None)
        if alternate is not None:
            return {"mapping": mapping, "selected": alternate, "source": source}
        return {
            "mapping": mapping,
            "selected": {
                "fuzzer": preferred_fuzzer,
                "score": 0,
                "reasons": ["selector preferred fuzzer not present in patch mapping; using selector hint"],
                "has_blockers": bool(candidate_fuzz.get("has_blockers")),
                "has_dict": bool(candidate_fuzz.get("dict_available")),
                "has_options": bool(candidate_fuzz.get("options_available")),
            },
            "source": "selection_metadata",
        }
    best = recs[0]
    hinted = _attack_script_fuzzer_hint(injection)
    if hinted:
        chosen = next((item for item in recs if item["fuzzer"] == hinted), None)
        if chosen is not None and chosen.get("score", 0) >= best.get("score", 0):
            return {"mapping": mapping, "selected": chosen, "source": source}
    return {"mapping": mapping, "selected": best, "source": source}


def _pick_fuzzer_sequence(
    injection_result: Path,
    cache_dir: Path,
    force_fuzzer: str | None,
    profile: dict[str, Any],
    *,
    top_fuzzers: int,
) -> list[dict[str, Any]]:
    first_pick = _pick_fuzzer(injection_result, cache_dir, force_fuzzer, profile)
    if force_fuzzer or top_fuzzers <= 1:
        return [first_pick]

    injection = read_json(injection_result)
    mapping = first_pick["mapping"]
    candidate_fuzz = _candidate_fuzz_metadata(injection)
    ordered_names: list[tuple[str, str]] = []
    preferred = candidate_fuzz.get("preferred_fuzzer")
    if preferred:
        ordered_names.append((preferred, "selection_metadata_preferred"))
    for name in candidate_fuzz.get("alternate_fuzzers") or []:
        if name:
            ordered_names.append((name, "selection_metadata_alternate"))
    for rec in candidate_fuzz.get("recommendations") or []:
        name = rec.get("fuzzer")
        if name:
            ordered_names.append((name, "selection_metadata_recommendation"))
    for rec in mapping.get("recommendations") or []:
        name = rec.get("fuzzer")
        if name:
            ordered_names.append((name, "patch_inference_recommendation"))

    recs_by_name: dict[str, dict[str, Any]] = {}
    for rec in list(candidate_fuzz.get("recommendations") or []) + list(mapping.get("recommendations") or []):
        name = rec.get("fuzzer")
        if name and name not in recs_by_name:
            recs_by_name[name] = rec

    picks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, source in ordered_names:
        if not name or name in seen:
            continue
        selected = recs_by_name.get(name)
        if selected is None:
            selected = {
                "fuzzer": name,
                "score": 0,
                "reasons": [source.replace("_", " ")],
                "has_blockers": bool(candidate_fuzz.get("has_blockers")),
                "has_dict": bool(candidate_fuzz.get("dict_available")),
                "has_options": bool(candidate_fuzz.get("options_available")),
            }
        picks.append({"mapping": mapping, "selected": selected, "source": source})
        seen.add(name)
        if len(picks) >= top_fuzzers:
            break
    return picks or [first_pick]


def _has_runtime_signal(mapping: dict[str, Any], selected_fuzzer: str) -> bool:
    for item in mapping.get("matched_functions") or []:
        if selected_fuzzer in (item.get("runtime_reached_by_fuzzers") or []):
            return True
    for rec in mapping.get("recommendations") or []:
        if rec.get("fuzzer") == selected_fuzzer:
            reasons = " ".join(rec.get("reasons") or [])
            if "runtime reaches function" in reasons:
                return True
    return False


def _candidate_is_viable(
    profile: dict[str, Any],
    mapping: dict[str, Any],
    selected: dict[str, Any],
    candidate_fuzz: dict[str, Any] | None = None,
) -> tuple[bool, str | None]:
    if candidate_fuzz and candidate_fuzz.get("runtime_reachable"):
        return True, None
    if _has_runtime_signal(mapping, selected["fuzzer"]):
        return True, None
    format_family = profile.get("format_family")
    if format_family == "text_obj_utf16" and selected["fuzzer"].endswith("_obj"):
        return True, None
    if format_family == "font_binary" and selected["fuzzer"].startswith("hb-"):
        return True, None
    if candidate_fuzz and candidate_fuzz.get("reachability_kind") == "file_coverage" and format_family in {
        "zip_archive", "image_png", "json_text", "script_text", "model_asset"
    }:
        return True, None
    if mapping.get("synthetic_recommendations") and selected.get("score", 0) >= 4 and format_family in {
        "zip_archive", "image_png", "json_text", "script_text", "model_asset"
    }:
        return True, None
    return False, f"weak fuzz candidate for {profile.get('patch_path') or 'unknown patch'}: no runtime reachability for {selected['fuzzer']}"


def _load_crash_report(attempt_dir: Path, phase: str) -> dict[str, Any] | None:
    path = attempt_dir / "artifacts" / "exploit_files" / "fuzz_results" / phase / "crash_report.json"
    if not path.exists():
        return None
    try:
        return read_json(path)
    except Exception:
        return None


def _verification_metadata_for_attempt(attempt_dir: Path) -> dict[str, Any]:
    manifest_path = attempt_dir / "artifacts" / "exploit_files" / "fuzz_poc_manifest.json"
    manifest = read_json(manifest_path) if manifest_path.exists() else {}
    return {
        "selected_fuzzer": (manifest.get("selected_fuzzer") or {}).get("fuzzer"),
        "selected_fuzzer_source": manifest.get("selected_fuzzer_source"),
        "use_builtin_corpus": bool(manifest.get("use_builtin_corpus")),
        "use_curated_corpus": bool(manifest.get("use_curated_corpus")),
        "generated_input_records": manifest.get("generated_input_records") or [],
        "selected_builtin_corpus_members": manifest.get("selected_builtin_corpus_members") or [],
        "reports": {
            phase: report
            for phase in ("secure", "vulnerable")
            if (report := _load_crash_report(attempt_dir, phase)) is not None
        },
    }


def _failure_summary_bucket(failure_cause: str | None) -> str:
    mapping = {
        "exploit_succeeds_on_secure": "secure_positive_signal",
        "exploit_failed_on_vulnerable": "vulnerable_never_triggered",
        "exploit_timed_out_on_secure": "secure_timed_out",
        "exploit_timed_out_on_vulnerable": "vulnerable_timed_out",
        "oracle_invalid_on_secure": "secure_invalid_signal",
        "oracle_invalid_on_vulnerable": "vulnerable_invalid_signal",
        "rebuild_failed_after_patch": "rebuild_failed_after_patch",
        "verification_internal_error": "verification_internal_error",
    }
    return mapping.get(str(failure_cause or ""), str(failure_cause or "other_failure"))


def _report_for_success_result(result: dict[str, Any]) -> dict[str, Any] | None:
    reports = ((result.get("metadata") or {}).get("reports") or {})
    vulnerable = reports.get("vulnerable")
    if isinstance(vulnerable, dict) and vulnerable.get("mode") in {"replay", "fuzz"}:
        return vulnerable
    secure = reports.get("secure")
    if isinstance(secure, dict) and secure.get("mode") in {"replay", "fuzz"}:
        return secure
    return None


def _build_verification_rollup(run_dir: Path, verification_results: list[dict[str, Any]]) -> dict[str, Any]:
    success_buckets: Counter[str] = Counter()
    failure_buckets: Counter[str] = Counter()
    seed_provenance_of_success: Counter[str] = Counter()
    selected_fuzzer_of_success: Counter[str] = Counter()
    attempt_summaries: list[dict[str, Any]] = []
    success_count = 0
    replay_success_count = 0
    fresh_fuzz_success_count = 0
    vulnerable_only_signal_times: list[float] = []

    for item in verification_results:
        result = item.get("verification_result") or {}
        attempt_dir = str(item.get("attempt_dir") or "")
        status = result.get("status")
        metadata = result.get("metadata") or {}
        entry: dict[str, Any] = {
            "attempt_dir": attempt_dir,
            "status": status,
            "selected_fuzzer": metadata.get("selected_fuzzer"),
        }
        if status == "success":
            success_count += 1
            report = _report_for_success_result(result) or {}
            mode = report.get("mode")
            success_bucket = report.get("success_bucket") or "success"
            provenance = report.get("seed_provenance")
            if not provenance and isinstance(report.get("seed_provenance"), dict):
                provenance = (report.get("seed_provenance") or {}).get("provenance")
            if isinstance(report.get("seed_provenance"), dict):
                provenance = (report.get("seed_provenance") or {}).get("provenance")
            provenance = provenance or ((report.get("seed_provenance") or {}).get("provenance") if isinstance(report.get("seed_provenance"), dict) else None) or "unknown"
            success_buckets[success_bucket] += 1
            seed_provenance_of_success[str(provenance)] += 1
            if metadata.get("selected_fuzzer"):
                selected_fuzzer_of_success[str(metadata["selected_fuzzer"])] += 1
            if mode == "replay":
                replay_success_count += 1
            elif mode == "fuzz":
                fresh_fuzz_success_count += 1
            signal_time = report.get("time_to_signal_seconds")
            if isinstance(signal_time, (int, float)):
                vulnerable_only_signal_times.append(float(signal_time))
            entry.update(
                {
                    "mode": mode,
                    "success_bucket": success_bucket,
                    "seed_provenance": provenance,
                    "attribution_kind": report.get("attribution_kind"),
                    "time_to_signal_seconds": signal_time,
                }
            )
        else:
            bucket = _failure_summary_bucket(result.get("failure_cause"))
            failure_buckets[bucket] += 1
            entry.update(
                {
                    "failure_cause": result.get("failure_cause"),
                    "failure_bucket": bucket,
                }
            )
        attempt_summaries.append(entry)

    builtin_member_successes = seed_provenance_of_success.get("builtin_corpus_member", 0)
    builtin_derived_successes = seed_provenance_of_success.get("builtin_derived_bug_conditioned_variant", 0)
    source_derived_successes = seed_provenance_of_success.get("source_derived_bug_conditioned_variant", 0)

    return {
        "run_dir": str(run_dir),
        "generated_at_utc": utc_now_iso(),
        "attempt_count": len(verification_results),
        "success_count": success_count,
        "failure_count": max(0, len(verification_results) - success_count),
        "replay_success_count": replay_success_count,
        "fresh_fuzz_success_count": fresh_fuzz_success_count,
        "failure_buckets": dict(failure_buckets),
        "success_buckets": dict(success_buckets),
        "seed_provenance_of_success": dict(seed_provenance_of_success),
        "seed_provenance_comparison": {
            "builtin_corpus_member_successes": builtin_member_successes,
            "builtin_derived_bug_conditioned_successes": builtin_derived_successes,
            "source_derived_bug_conditioned_successes": source_derived_successes,
        },
        "selected_fuzzer_of_success": dict(selected_fuzzer_of_success),
        "time_to_first_vulnerable_only_signal_seconds": min(vulnerable_only_signal_times) if vulnerable_only_signal_times else None,
        "attempt_summaries": attempt_summaries,
    }


def _build_generated_attempt(
    *,
    source_attempt_dir: Path,
    destination_attempt_dir: Path,
    run_id: str,
    cache_dir: Path,
    force_fuzzer: str | None,
    max_total_time: int,
    use_curated_corpus: bool = True,
    picked: dict[str, Any] | None = None,
) -> dict[str, Any]:
    injection_result_path = source_attempt_dir / "injection_result.json"
    if not injection_result_path.exists():
        raise FileNotFoundError(f"missing injection_result.json in {source_attempt_dir}")
    injection = read_json(injection_result_path)
    project = injection["project"]
    candidate_fuzz = _candidate_fuzz_metadata(injection)
    profile = _trigger_profile_from_fuzz_metadata(injection, candidate_fuzz) if candidate_fuzz else _infer_trigger_profile(injection)
    picked = picked or _pick_fuzzer(injection_result_path, cache_dir, force_fuzzer, profile)
    mapping = picked["mapping"]
    selected = picked["selected"]
    profile = _retarget_profile_for_fuzzer(profile, selected["fuzzer"])
    selection_source = picked.get("source", "patch_inference")
    viable, reason = _candidate_is_viable(profile, mapping, selected, candidate_fuzz)
    if not viable:
        raise RuntimeError(reason or "candidate not viable for fuzz PoC")
    local_assets = _load_local_fuzz_assets(project, selected["fuzzer"])

    exploit_dir = destination_attempt_dir / "artifacts" / "exploit_files"
    generated_inputs_dir = exploit_dir / "generated_inputs"
    exploit_dir.mkdir(parents=True, exist_ok=True)
    (destination_attempt_dir / "artifacts").mkdir(parents=True, exist_ok=True)

    source_templates = _collect_source_templates(source_attempt_dir, profile, selected["fuzzer"])
    builtin_corpus_members = _select_builtin_corpus_members(
        project=project,
        fuzzer=selected["fuzzer"],
        profile=profile,
        source_templates=source_templates,
        candidate_fuzz=candidate_fuzz,
        limit=16,
        replay_limit=6,
    )
    input_records = _generate_input_records(
        profile,
        generated_inputs_dir,
        source_templates,
        builtin_corpus_members=builtin_corpus_members,
    )
    curated_names: list[str] = []
    if use_curated_corpus:
        curated_names = _copy_curated_seeds(project, selected["fuzzer"], generated_inputs_dir, limit=16)
        for curated_name in curated_names:
            input_records.append(
                {
                    "name": curated_name,
                    "relative_path": str(Path("artifacts/exploit_files/generated_inputs") / curated_name),
                    "provenance": "curated_carryover",
                    "generator": "curated_carryover",
                    "bug_conditioned": False,
                    "source_kind": "curated_corpus",
                    "source_name": curated_name,
                    "replay_target": True,
                    "corpus_target": True,
                    "replay_order": len(input_records),
                }
            )
    generated_names = [record["name"] for record in input_records]
    preferred_exts = _preferred_extensions(profile.get("format_family"), selected["fuzzer"])
    selected_builtin_manifest = [
        {key: value for key, value in item.items() if key != "data"}
        for item in builtin_corpus_members
    ]

    manifest = {
        "project": project,
        "source_attempt_dir": str(source_attempt_dir),
        "source_injection_result": str(injection_result_path),
        "generated_at_utc": utc_now_iso(),
        "selected_fuzzer": selected,
        "selected_fuzzer_source": selection_source,
        "recommendations": mapping.get("recommendations", []),
        "matched_functions": mapping.get("matched_functions", []),
        "trigger_profile": profile,
        "candidate_fuzz": candidate_fuzz,
        "generated_inputs": [str(Path("artifacts/exploit_files/generated_inputs") / name) for name in generated_names],
        "generated_input_records": input_records,
        "selected_builtin_corpus_members": selected_builtin_manifest,
        "max_total_time": max_total_time,
        "replay_timeout_seconds": 10 if profile.get("format_family") == "font_binary" else 5,
        "use_builtin_corpus": True,
        "use_curated_corpus": use_curated_corpus,
        "builtin_corpus_sample_limit": max(16, len(selected_builtin_manifest)),
        "builtin_corpus_extensions": preferred_exts,
        "libfuzzer_options": local_assets["options"],
        "local_dict_path": local_assets["dict_path"],
        "local_options_path": local_assets["options_path"],
        "source_templates": [str(path) for path in source_templates],
        "cwe_id": injection.get("cwe_id"),
        "reference_kind": (injection.get("strategy") or {}).get("reference_kind"),
    }

    write_json(destination_attempt_dir / "source_injection_result.json", injection)
    patch_diff = _resolve_patch_diff(injection, attempt_dir=source_attempt_dir)
    (destination_attempt_dir / "artifacts" / "vuln.patch").write_text(patch_diff, encoding="utf-8")
    write_json(exploit_dir / "fuzz_poc_manifest.json", manifest)
    (exploit_dir / "fuzz_poc.py").write_text(
        _render_fuzz_poc_py("artifacts/exploit_files/fuzz_poc_manifest.json"),
        encoding="utf-8",
    )
    (exploit_dir / "exploit.sh").write_text(_render_exploit_sh(project), encoding="utf-8")
    write_json(
        destination_attempt_dir / "injection_result.json",
        _synthesized_injection_result(
            source_injection=injection,
            run_id=run_id,
            attempt_dir=destination_attempt_dir,
            exploit_dir=exploit_dir,
            selected=selected,
            selection_source=selection_source,
            generated_input_count=len(generated_names),
        ),
    )

    return {
        "project": project,
        "attempt_dir": str(destination_attempt_dir),
        "selected_fuzzer": selected["fuzzer"],
        "selected_fuzzer_source": selection_source,
        "generated_input_count": len(generated_names),
        "selected_builtin_corpus_count": len(selected_builtin_manifest),
        "manifest_path": str(exploit_dir / "fuzz_poc_manifest.json"),
        "source_attempt_dir": str(source_attempt_dir),
    }


def generate_fuzz_poc(
    *,
    source_attempt_dir: Path,
    tag: str | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    force_fuzzer: str | None = None,
    max_total_time: int = 90,
    top_fuzzers: int = 1,
    use_curated_corpus: bool = True,
) -> dict[str, Any]:
    injection = read_json(source_attempt_dir / "injection_result.json")
    project = injection["project"]
    run_suffix = _sanitize_tag(tag or source_attempt_dir.name)
    run_id = new_run_id("fuzz_poc", suffix=run_suffix)
    run_dir = FUZZ_POC_ROOT / project / run_id
    profile = _trigger_profile_from_fuzz_metadata(injection, _candidate_fuzz_metadata(injection))
    picks = _pick_fuzzer_sequence(
        source_attempt_dir / "injection_result.json",
        cache_dir,
        force_fuzzer,
        profile,
        top_fuzzers=max(1, top_fuzzers),
    )
    attempts: list[dict[str, Any]] = []
    for index, picked in enumerate(picks):
        attempt_dir = run_dir / f"attempt_{index:02d}"
        payload = _build_generated_attempt(
            source_attempt_dir=source_attempt_dir,
            destination_attempt_dir=attempt_dir,
            run_id=run_id,
            cache_dir=cache_dir,
            force_fuzzer=force_fuzzer,
            max_total_time=max_total_time,
            use_curated_corpus=use_curated_corpus,
            picked=picked,
        )
        attempts.append(payload)
    _write_fuzz_poc_request(
        run_dir=run_dir,
        project=project,
        run_id=run_id,
        source_run_dir=None,
        source_attempt_dir=str(source_attempt_dir),
        tag=tag,
        force_fuzzer=force_fuzzer,
        max_total_time=max_total_time,
        exploit_timeout=None,
    )
    summary = {
        "project": project,
        "run_id": run_id,
        "source_attempt_dir": str(source_attempt_dir),
        "generated_attempt_dir": str(run_dir / "attempt_00"),
        "attempts": attempts,
    }
    write_json(run_dir / "run_summary.json", summary)
    return summary


def verify_fuzz_poc_attempt(
    *,
    attempt_dir: Path,
    exploit_timeout: int = 600,
    register_curated_results: bool = True,
) -> dict[str, Any]:
    existing_result = attempt_dir / "verification_result.json"
    if existing_result.exists():
        cached = read_json(existing_result)
        if cached.get("status") in {"success", "failure"}:
            return cached

    injection = read_json(attempt_dir / "source_injection_result.json")
    project = injection["project"]
    config = load_project_config(project)
    image_tag = _resolve_image_tag(config)
    repo_dir = f"/src/{config.target_dir}"

    exploit_dir = attempt_dir / "artifacts" / "exploit_files"
    exploit_wrapper = exploit_dir / "exploit.sh"
    if not exploit_wrapper.exists():
        raise FileNotFoundError(f"missing generated exploit wrapper: {exploit_wrapper}")
    patch_diff = _resolve_patch_diff(injection, attempt_dir=attempt_dir)
    if not patch_diff.strip():
        raise RuntimeError("missing patch diff in source injection result")

    def _write_progress(payload: dict[str, Any]) -> None:
        write_json(existing_result, payload)

    _write_progress(
        {
            "project": project,
            "run_id": attempt_dir.parent.name,
            "timestamp_utc": utc_now_iso(),
            "status": "running",
            "checks": {
                "unit_tests": "pending",
                "exploit_on_vulnerable": "pending",
                "exploit_on_secure": "pending",
            },
            "failure_cause": None,
            "failure_message": "",
            "unit_test_passed_count": None,
            "unit_test_message": "",
            "unit_test_raw_output": "",
            "progress_phase": "starting",
            "complete": False,
        }
    )

    try:
        session = DockerSession.start(project=project, image_tag=image_tag, run_mount_dir=attempt_dir)
        try:
            session.copy_to(exploit_wrapper, "/tmp/exploit.sh")
            session.exec("chmod +x /tmp/exploit.sh")
            verification = run_verification(
                runtime=session,
                project=project,
                run_id=attempt_dir.parent.name,
                repo_dir=repo_dir,
                patch_diff=patch_diff,
                unit_tests=config.unit_tests,
                skip_unit_tests=True,
                project_root=Path(str(REPO_ROOT.parent / "vuljector-projects" / project)),
                exploit_path="/tmp/exploit.sh",
                rebuild_command=f"FUZZING_LANGUAGE={config.language or 'c++'} compile",
                exploit_timeout=exploit_timeout,
                progress_callback=_write_progress,
            )
        finally:
            session.stop()
    except Exception as exc:
        failure = {
            "project": project,
            "run_id": attempt_dir.parent.name,
            "timestamp_utc": utc_now_iso(),
            "status": "failure",
            "checks": {
                "unit_tests": "skipped",
                "exploit_on_vulnerable": "skipped",
                "exploit_on_secure": "invalid",
            },
            "failure_cause": "verification_internal_error",
            "failure_message": str(exc),
            "unit_test_passed_count": None,
            "unit_test_message": "",
            "unit_test_raw_output": "",
        }
        write_json(existing_result, failure)
        raise

    result_payload = verification.to_dict()
    result_payload["metadata"] = {
        **(result_payload.get("metadata") or {}),
        **_verification_metadata_for_attempt(attempt_dir),
    }
    write_json(existing_result, result_payload)
    if register_curated_results:
        _register_curated_results(attempt_dir)
    return result_payload


def batch_generate_fuzz_poc(
    *,
    source_run_dir: Path,
    tag: str | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    force_fuzzer: str | None = None,
    max_total_time: int = 90,
    limit: int | None = None,
    exploit_timeout: int | None = 600,
    top_fuzzers: int = 1,
    use_curated_corpus: bool = True,
    register_curated_results: bool = True,
) -> dict[str, Any]:
    attempt_dirs = sorted(path for path in source_run_dir.glob("attempt_*") if path.is_dir())
    if limit is not None:
        attempt_dirs = attempt_dirs[:limit]
    if not attempt_dirs:
        raise RuntimeError(f"no attempt directories found in {source_run_dir}")

    first_injection = read_json(attempt_dirs[0] / "injection_result.json")
    project = first_injection["project"]
    run_suffix = _sanitize_tag(tag or source_run_dir.name)
    run_id = new_run_id("fuzz_poc", suffix=run_suffix)
    run_dir = FUZZ_POC_ROOT / project / run_id
    _write_fuzz_poc_request(
        run_dir=run_dir,
        project=project,
        run_id=run_id,
        source_run_dir=str(source_run_dir),
        source_attempt_dir=None,
        tag=tag,
        force_fuzzer=force_fuzzer,
        max_total_time=max_total_time,
        exploit_timeout=exploit_timeout,
    )

    attempts: list[dict[str, Any]] = []
    verification_results: list[dict[str, Any]] = []
    progress_path = run_dir / "verification_progress.json"
    summary = {
        "project": project,
        "run_id": run_id,
        "source_run_dir": str(source_run_dir),
        "generated_run_dir": str(run_dir),
        "attempts": attempts,
    }
    write_json(run_dir / "run_summary.json", summary)
    created_count = 0
    for index, source_attempt in enumerate(attempt_dirs):
        print(f"[fuzz-poc batch] generating attempt {index + 1}/{len(attempt_dirs)} from {source_attempt}")
        try:
            injection = read_json(source_attempt / "injection_result.json")
            profile = _trigger_profile_from_fuzz_metadata(injection, _candidate_fuzz_metadata(injection))
            picks = _pick_fuzzer_sequence(
                source_attempt / "injection_result.json",
                cache_dir,
                force_fuzzer,
                profile,
                top_fuzzers=max(1, top_fuzzers),
            )
            for picked in picks:
                payload = _build_generated_attempt(
                    source_attempt_dir=source_attempt,
                    destination_attempt_dir=run_dir / f"attempt_{created_count:02d}",
                    run_id=run_id,
                    cache_dir=cache_dir,
                    force_fuzzer=force_fuzzer,
                    max_total_time=max_total_time,
                    use_curated_corpus=use_curated_corpus,
                    picked=picked,
                )
                created_count += 1
                attempts.append(payload)
                write_json(run_dir / "run_summary.json", summary)
                if exploit_timeout is not None:
                    verification = verify_fuzz_poc_attempt(
                        attempt_dir=Path(payload["attempt_dir"]),
                        exploit_timeout=exploit_timeout,
                        register_curated_results=register_curated_results,
                    )
                    verification_results.append(
                        {
                            "attempt_dir": payload["attempt_dir"],
                            "verification_result": verification,
                        }
                    )
                    write_json(
                        progress_path,
                        {
                            "run_dir": str(run_dir),
                            "completed": len(verification_results),
                            "total": max(created_count, len(attempt_dirs)),
                            "current_attempt_dir": payload["attempt_dir"],
                            "attempts": verification_results,
                        },
                    )
                    write_json(
                        run_dir / "verification_summary.json",
                        {
                            "run_dir": str(run_dir),
                            "attempts": verification_results,
                            "summary": _build_verification_rollup(run_dir, verification_results),
                        },
                    )
        except Exception as exc:
            payload = {
                "source_attempt_dir": str(source_attempt),
                "generated": False,
                "failure_message": str(exc),
            }
            attempts.append(payload)
            write_json(run_dir / "run_summary.json", summary)
    if exploit_timeout is not None:
        verification_summary = {
            "run_dir": str(run_dir),
            "attempts": verification_results,
            "summary": _build_verification_rollup(run_dir, verification_results),
        }
        write_json(run_dir / "verification_summary.json", verification_summary)
        summary["verification"] = {
            "completed": len(verification_results),
            "total": len([attempt for attempt in attempts if attempt.get("generated", True)]),
            "summary_path": str(run_dir / "verification_summary.json"),
            "rollup": verification_summary["summary"],
        }
    write_json(run_dir / "run_summary.json", summary)
    return summary


def batch_generate_fuzz_poc_filtered(
    *,
    source_run_dir: Path,
    tag: str | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    force_fuzzer: str | None = None,
    max_total_time: int = 90,
    limit: int | None = None,
    exploit_timeout: int | None = 600,
    top_fuzzers: int = 1,
    use_curated_corpus: bool = True,
    register_curated_results: bool = True,
) -> dict[str, Any]:
    raw_attempt_dirs = sorted(path for path in source_run_dir.glob("attempt_*") if path.is_dir())
    if limit is not None:
        raw_attempt_dirs = raw_attempt_dirs[:limit]
    if not raw_attempt_dirs:
        raise RuntimeError(f"no attempt directories found in {source_run_dir}")

    attempt_dirs: list[Path] = []
    skipped_attempts: list[dict[str, str]] = []
    for attempt_dir in raw_attempt_dirs:
        injection_path = attempt_dir / "injection_result.json"
        if not injection_path.exists():
            skipped_attempts.append({"attempt_dir": str(attempt_dir), "reason": "missing injection_result.json"})
            continue
        injection = read_json(injection_path)
        if injection.get("status") != "success":
            skipped_attempts.append(
                {"attempt_dir": str(attempt_dir), "reason": f"skipping injection status {injection.get('status')}"}
            )
            continue
        patch_diff = _resolve_patch_diff(injection, attempt_dir=attempt_dir).strip()
        if not patch_diff:
            skipped_attempts.append({"attempt_dir": str(attempt_dir), "reason": "missing patch_diff"})
            continue
        attempt_dirs.append(attempt_dir)
    if not attempt_dirs:
        raise RuntimeError(f"no successful injection attempts available in {source_run_dir}")

    first_injection = read_json(attempt_dirs[0] / "injection_result.json")
    project = first_injection["project"]
    run_suffix = _sanitize_tag(tag or source_run_dir.name)
    run_id = new_run_id("fuzz_poc", suffix=run_suffix)
    run_dir = FUZZ_POC_ROOT / project / run_id
    _write_fuzz_poc_request(
        run_dir=run_dir,
        project=project,
        run_id=run_id,
        source_run_dir=str(source_run_dir),
        source_attempt_dir=None,
        tag=tag,
        force_fuzzer=force_fuzzer,
        max_total_time=max_total_time,
        exploit_timeout=exploit_timeout,
    )

    attempts: list[dict[str, Any]] = []
    verification_results: list[dict[str, Any]] = []
    progress_path = run_dir / "verification_progress.json"
    summary = {
        "project": project,
        "run_id": run_id,
        "source_run_dir": str(source_run_dir),
        "generated_run_dir": str(run_dir),
        "skipped_source_attempts": skipped_attempts,
        "attempts": attempts,
    }
    write_json(run_dir / "run_summary.json", summary)
    created_count = 0
    for index, source_attempt in enumerate(attempt_dirs):
        print(f"[fuzz-poc batch] generating attempt {index + 1}/{len(attempt_dirs)} from {source_attempt}")
        try:
            injection = read_json(source_attempt / "injection_result.json")
            profile = _trigger_profile_from_fuzz_metadata(injection, _candidate_fuzz_metadata(injection))
            picks = _pick_fuzzer_sequence(
                source_attempt / "injection_result.json",
                cache_dir,
                force_fuzzer,
                profile,
                top_fuzzers=max(1, top_fuzzers),
            )
            for picked in picks:
                payload = _build_generated_attempt(
                    source_attempt_dir=source_attempt,
                    destination_attempt_dir=run_dir / f"attempt_{created_count:02d}",
                    run_id=run_id,
                    cache_dir=cache_dir,
                    force_fuzzer=force_fuzzer,
                    max_total_time=max_total_time,
                    use_curated_corpus=use_curated_corpus,
                    picked=picked,
                )
                created_count += 1
                attempts.append(payload)
                write_json(run_dir / "run_summary.json", summary)
                if exploit_timeout is not None:
                    verification = verify_fuzz_poc_attempt(
                        attempt_dir=Path(payload["attempt_dir"]),
                        exploit_timeout=exploit_timeout,
                        register_curated_results=register_curated_results,
                    )
                    verification_results.append(
                        {
                            "attempt_dir": payload["attempt_dir"],
                            "verification_result": verification,
                        }
                    )
                    write_json(
                        progress_path,
                        {
                            "run_dir": str(run_dir),
                            "completed": len(verification_results),
                            "total": max(created_count, len(attempt_dirs)),
                            "current_attempt_dir": payload["attempt_dir"],
                            "attempts": verification_results,
                        },
                    )
                    write_json(
                        run_dir / "verification_summary.json",
                        {
                            "run_dir": str(run_dir),
                            "attempts": verification_results,
                            "summary": _build_verification_rollup(run_dir, verification_results),
                        },
                    )
        except Exception as exc:
            payload = {
                "source_attempt_dir": str(source_attempt),
                "generated": False,
                "failure_message": str(exc),
            }
            attempts.append(payload)
            write_json(run_dir / "run_summary.json", summary)
    if exploit_timeout is not None:
        verification_summary = {
            "run_dir": str(run_dir),
            "attempts": verification_results,
            "summary": _build_verification_rollup(run_dir, verification_results),
        }
        write_json(run_dir / "verification_summary.json", verification_summary)
        summary["verification"] = {
            "completed": len(verification_results),
            "total": len([attempt for attempt in attempts if attempt.get("generated", True)]),
            "summary_path": str(run_dir / "verification_summary.json"),
            "rollup": verification_summary["summary"],
        }
    write_json(run_dir / "run_summary.json", summary)
    return summary


def batch_verify_fuzz_poc(*, run_dir: Path, exploit_timeout: int = 600) -> dict[str, Any]:
    attempt_dirs = sorted(path for path in run_dir.glob("attempt_*") if path.is_dir())
    if not attempt_dirs:
        raise RuntimeError(f"no attempt directories found in {run_dir}")
    lock_path = run_dir / ".batch_verify.lock"
    if lock_path.exists():
        raise RuntimeError(f"batch verify already running for {run_dir}")

    results = []
    progress_path = run_dir / "verification_progress.json"
    lock_path.write_text(str(os.getpid()), encoding="utf-8")
    try:
        total = len(attempt_dirs)
        for index, attempt_dir in enumerate(attempt_dirs, start=1):
            print(f"[fuzz-poc verify] {index}/{total} verifying {attempt_dir}")
            result = verify_fuzz_poc_attempt(attempt_dir=attempt_dir, exploit_timeout=exploit_timeout)
            results.append({"attempt_dir": str(attempt_dir), "verification_result": result})
            write_json(
                progress_path,
                {
                    "run_dir": str(run_dir),
                    "completed": index,
                    "total": total,
                    "current_attempt_dir": str(attempt_dir),
                    "attempts": results,
                },
            )
        summary = {
            "run_dir": str(run_dir),
            "attempts": results,
            "summary": _build_verification_rollup(run_dir, results),
        }
        print(f"[fuzz-poc verify] completed {len(results)}/{total} attempts for {run_dir}")
        write_json(run_dir / "verification_summary.json", summary)
        return summary
    finally:
        lock_path.unlink(missing_ok=True)
