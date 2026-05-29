"""Helpers for SEC-bench-style build/repro contracts inside Vuljector tasks."""

from __future__ import annotations

import json
import shlex
from pathlib import Path


def load_fuzz_poc_manifest(bundle_dir: Path) -> dict:
    """Load fuzz_poc_manifest.json if present."""
    path = bundle_dir / "fuzz_poc_manifest.json"
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def derive_selected_fuzzer(bundle_dir: Path, hints: dict | None = None) -> str:
    """Best-effort selected fuzzer name for SEC-bench-style repro."""
    manifest = load_fuzz_poc_manifest(bundle_dir)
    selected = manifest.get("selected_fuzzer") or {}
    if isinstance(selected, dict):
        name = str(selected.get("fuzzer") or "").strip()
        if name:
            return name
    if hints:
        return str(hints.get("selected_fuzzer") or "").strip()
    return ""


def derive_testcase_filename(bundle_dir: Path) -> str:
    """Infer the expected testcase filename for `secb repro`."""
    manifest = load_fuzz_poc_manifest(bundle_dir)
    records = manifest.get("generated_input_records") or []
    if isinstance(records, list):
        for item in records:
            if not isinstance(item, dict):
                continue
            source_name = str(item.get("source_name") or "").strip()
            source_kind = str(item.get("source_kind") or "").strip()
            if source_name and source_kind == "source_template":
                return Path(source_name).name
        for item in records:
            if not isinstance(item, dict):
                continue
            source_name = str(item.get("source_name") or "").strip()
            if source_name and Path(source_name).name.startswith("poc."):
                return Path(source_name).name
        for item in records:
            if not isinstance(item, dict):
                continue
            source_name = str(item.get("source_name") or "").strip()
            if source_name:
                suffix = Path(source_name).suffix
                if suffix:
                    return f"poc{suffix}"
                return Path(source_name).name

    generated_dir = bundle_dir / "exploit_files" / "generated_inputs"
    if generated_dir.is_dir():
        for path in sorted(generated_dir.iterdir()):
            if path.is_file() and path.name.startswith("poc_") and path.suffix:
                return f"poc{path.suffix}"

    exploit_files = bundle_dir / "exploit_files"
    if exploit_files.is_dir():
        for path in sorted(exploit_files.iterdir()):
            if path.is_file() and path.suffix.lower() not in {".json", ".py", ".sh", ".log"}:
                return path.name

    return "poc.bin"


def build_secb_shim(
    *,
    repo_dir: str,
    bundle_dir: Path,
    hints: dict | None = None,
    patch_mode: bool,
    language: str | None = None,
    fuzzing_engine: str | None = None,
) -> str:
    """Render a lightweight `/usr/local/bin/secb` shim for agent runs and validation."""
    repo_q = shlex.quote(repo_dir)
    testcase_name = derive_testcase_filename(bundle_dir)
    testcase_q = shlex.quote(f"/testcase/{testcase_name}")
    selected_fuzzer = derive_selected_fuzzer(bundle_dir, hints=hints)
    fuzzer_q = shlex.quote(f"/out/{selected_fuzzer}") if selected_fuzzer else ""
    language_q = shlex.quote((language or "c++").strip() or "c++")
    engine_q = shlex.quote((fuzzing_engine or "libfuzzer").strip() or "libfuzzer")

    if patch_mode:
        repro_body = (
            "if [ -x /workspace/run/attempt/artifacts/exploit_files/exploit.sh ]; then\n"
            f"  cd {repo_q}\n"
            "  exec bash /workspace/run/attempt/artifacts/exploit_files/exploit.sh\n"
            "fi\n"
            "if [ -f /workspace/run/attempt/artifacts/exploit_files/fuzz_poc.py ]; then\n"
            f"  cd {repo_q}\n"
            "  exec python3 /workspace/run/attempt/artifacts/exploit_files/fuzz_poc.py\n"
            "fi\n"
            'echo "Missing reference exploit bundle under /workspace/run/attempt/artifacts/exploit_files" >&2\n'
            "exit 1"
        )
    else:
        repro_body = (
            f'if [ ! -x {fuzzer_q} ]; then echo "Missing fuzzer binary {fuzzer_q}" >&2; exit 1; fi\n'
            f'if [ ! -f {testcase_q} ]; then echo "Expected testcase file {testcase_q}" >&2; exit 1; fi\n'
            f"exec {fuzzer_q} {testcase_q}"
        ) if selected_fuzzer else (
            'echo "No selected fuzzer available for secb repro" >&2\n'
            "exit 1"
        )

    build_body = f"""cd {repo_q}
# General pre-build hygiene for OSS-Fuzz style scripts that are not fully idempotent.
rm -rf /src/seeds /out/lib 2>/dev/null || true
if [ -d my_build ]; then rm -rf my_build; fi
# Some projects expect ./BuildFuzzers.sh relative to the build.sh cwd even when the helper lives deeper in the repo.
if [ ! -f /src/BuildFuzzers.sh ]; then
    buildfuzzers_path=""
    if [ -f BuildFuzzers.sh ]; then
        buildfuzzers_path="{repo_q}/BuildFuzzers.sh"
    else
        buildfuzzers_rel="$(find . -path '*/BuildFuzzers.sh' | head -n1 || true)"
        if [ -n "$buildfuzzers_rel" ]; then
            buildfuzzers_path="{repo_q}/${{buildfuzzers_rel#./}}"
        fi
    fi
    if [ -n "$buildfuzzers_path" ]; then
        ln -sf "$buildfuzzers_path" /src/BuildFuzzers.sh 2>/dev/null || true
        if [ ! -f BuildFuzzers.sh ]; then
            ln -sf "$buildfuzzers_path" ./BuildFuzzers.sh 2>/dev/null || true
        fi
    fi
fi
FUZZING_LANGUAGE={language_q} FUZZING_ENGINE={engine_q} compile"""

    return f"""#!/bin/bash
set -euo pipefail

build() {{
{_indent(build_body, 4)}
}}

repro() {{
    cd {repo_q}
{_indent(repro_body, 4)}
}}

patch() {{
    cd {repo_q}
    if git apply /testcase/model_patch.diff; then
        echo "PATCH APPLIED SUCCESSFULLY!"
    else
        echo "PATCH APPLICATION FAILED!"
        exit 1
    fi
}}

case "${{1:-}}" in
    build)
        shift
        build "$@"
        ;;
    repro)
        shift
        repro "$@"
        ;;
    patch)
        shift
        patch "$@"
        ;;
    *)
        echo "Usage: /usr/local/bin/secb [build|repro|patch]" >&2
        exit 1
        ;;
esac
"""


def _indent(text: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line if line else "" for line in text.splitlines())
