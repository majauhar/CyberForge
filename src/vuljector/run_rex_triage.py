"""Rex pilot pipeline for successful crash triage attempts."""

from __future__ import annotations

import shlex
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

from setup.container_runtime import DockerSession, ExecResult
from setup.mounts import RUN_MOUNT_POINT
from utils.json_io import read_json, write_json
from utils.paths import new_run_id, runs_root
from verifier.pipeline import PROJECT_CLEANUP_COMMANDS, _apply_patch
from vuljector.core import load_project_config
from vuljector.io_contracts import utc_now_iso
from vuljector.run_fuzz_poc import _resolve_image_tag


REX_TRIAGE_ROOT = runs_root() / "rex_triage"
REX_INPUT_ROOT = Path("artifacts") / "rex" / "inputs"
REX_BINARY_ROOT = Path("artifacts") / "rex" / "binary"
REX_ADAPTER_ROOT = Path("artifacts") / "rex" / "adapter"
REX_LOG_ROOT = Path("artifacts") / "rex" / "logs"

_ASAN_TOKENS = (
    "addresssanitizer",
    "undefinedbehaviorsanitizer",
    "runtime error:",
)

_INFRA_ERROR_TOKENS = (
    "required directory",
    "does not exist",
    "no such file or directory",
    "command not found",
)


def _sanitize_tag(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value).strip("._-") or "rex_triage"


def _read_success_verification(attempt_dir: Path) -> dict[str, Any]:
    verification_path = attempt_dir / "verification_result.json"
    if not verification_path.exists():
        raise FileNotFoundError(f"missing verification_result.json in {attempt_dir}")
    verification = read_json(verification_path)
    if verification.get("status") != "success":
        raise RuntimeError(f"attempt is not a successful validation: {attempt_dir}")
    return verification


def _load_source_injection(attempt_dir: Path) -> dict[str, Any]:
    source_path = attempt_dir / "source_injection_result.json"
    if source_path.exists():
        return read_json(source_path)
    injection_path = attempt_dir / "injection_result.json"
    if injection_path.exists():
        return read_json(injection_path)
    raise FileNotFoundError(f"missing source or synthesized injection result in {attempt_dir}")


def _prefer_vulnerable_report(verification: dict[str, Any]) -> dict[str, Any]:
    reports = ((verification.get("metadata") or {}).get("reports") or {})
    vulnerable = reports.get("vulnerable")
    if isinstance(vulnerable, dict) and vulnerable:
        return vulnerable
    secure = reports.get("secure")
    if isinstance(secure, dict) and secure:
        return secure
    raise RuntimeError("verification result does not contain a crash report")


def _find_input_record(records: list[dict[str, Any]], seed_name: str | None) -> dict[str, Any] | None:
    if not seed_name:
        return None
    for record in records:
        if record.get("name") == seed_name:
            return record
    return None


def _resolve_trigger_input_path(attempt_dir: Path, verification: dict[str, Any]) -> Path:
    metadata = verification.get("metadata") or {}
    report = _prefer_vulnerable_report(verification)
    if report.get("mode") != "replay":
        raise RuntimeError(f"only replay-backed successes are supported right now, got mode={report.get('mode')!r}")
    seed_name = report.get("seed")
    record = _find_input_record(metadata.get("generated_input_records") or [], seed_name)
    if record is not None:
        rel = record.get("relative_path")
        if rel:
            path = attempt_dir / rel
            if path.exists():
                return path
    if seed_name:
        fallback = attempt_dir / "artifacts" / "exploit_files" / "generated_inputs" / seed_name
        if fallback.exists():
            return fallback
    raise RuntimeError(f"unable to locate replay seed for success attempt {attempt_dir}")


def _resolve_trigger_input_source(attempt_dir: Path, verification: dict[str, Any]) -> dict[str, Any]:
    metadata = verification.get("metadata") or {}
    report = _prefer_vulnerable_report(verification)
    seed_name = report.get("seed")
    try:
        path = _resolve_trigger_input_path(attempt_dir, verification)
    except RuntimeError:
        path = None
    if path is not None:
        return {"mode": "local_file", "seed_name": seed_name, "path": path}
    for member in metadata.get("selected_builtin_corpus_members") or []:
        if member.get("name") == seed_name:
            return {
                "mode": "builtin_corpus_member",
                "seed_name": seed_name,
                "archive_member": member.get("archive_member"),
            }
    raise RuntimeError(f"unable to locate replay seed for success attempt {attempt_dir}")


def _detect_triggered(result: ExecResult) -> bool:
    output = ((result.stdout or "") + "\n" + (result.stderr or "")).lower()
    if any(token in output for token in _INFRA_ERROR_TOKENS):
        return False
    if result.returncode in {139, -11}:
        return True
    return any(token in output for token in _ASAN_TOKENS)


def _serialize_exec_result(result: ExecResult, *, log_path: Path, command: str) -> dict[str, Any]:
    combined = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    return {
        "command": command,
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "triggered": _detect_triggered(result),
        "log_path": str(log_path),
        "output_excerpt": combined[-4000:],
    }


def _write_log(path: Path, title: str, result: ExecResult) -> None:
    content = (
        f"{title}\n"
        f"returncode={result.returncode}\n"
        f"timed_out={result.timed_out}\n"
        "--- stdout ---\n"
        f"{result.stdout or ''}\n"
        "--- stderr ---\n"
        f"{result.stderr or ''}\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _pick_rex_python(explicit: str | None) -> tuple[str | None, str | None]:
    candidate = explicit or sys.executable
    probe = subprocess.run(
        [candidate, "-c", "import importlib.util,sys; sys.exit(0 if importlib.util.find_spec('rex') else 1)"],
        capture_output=True,
        text=True,
    )
    if probe.returncode == 0:
        return candidate, None
    return None, "python environment does not provide the rex module"


def _stdin_adapter_source(*, use_cpp: bool = False) -> str:
    extern_decl = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);' if use_cpp else \
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);"
    return textwrap.dedent(
        f"""
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>

        {extern_decl}

        int main(void) {{
            size_t cap = 4096;
            size_t len = 0;
            uint8_t *buf = (uint8_t *)malloc(cap);
            if (buf == NULL) {{
                return 2;
            }}

            while (!feof(stdin)) {{
                if (len == cap) {{
                    size_t new_cap = cap * 2;
                    uint8_t *tmp = (uint8_t *)realloc(buf, new_cap);
                    if (tmp == NULL) {{
                        free(buf);
                        return 2;
                    }}
                    buf = tmp;
                    cap = new_cap;
                }}
                size_t n = fread(buf + len, 1, cap - len, stdin);
                len += n;
                if (ferror(stdin)) {{
                    free(buf);
                    return 2;
                }}
            }}

            int rc = LLVMFuzzerTestOneInput(buf, len);
            free(buf);
            return rc;
        }}
        """
    )


def _rawstart_rex_source(*, use_cpp: bool = False) -> str:
    extern_decl = 'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);' if use_cpp else \
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);"
    start_decl = 'extern "C" __attribute__((noreturn)) void _start(void)' if use_cpp else \
        "__attribute__((noreturn)) void _start(void)"
    return textwrap.dedent(
        f"""
        #include <stddef.h>
        #include <stdint.h>

        {extern_decl}

        static unsigned char g_rex_buf[1 << 20];

        static long sys_read(unsigned long fd, void *ptr, unsigned long length) {{
            long ret;
            __asm__ volatile (
                "syscall"
                : "=a"(ret)
                : "a"(0), "D"(fd), "S"(ptr), "d"(length)
                : "rcx", "r11", "memory"
            );
            return ret;
        }}

        static __attribute__((noreturn)) void sys_exit(long code) {{
            __asm__ volatile (
                "syscall"
                :
                : "a"(60), "D"(code)
                : "rcx", "r11", "memory"
            );
            __builtin_unreachable();
        }}

        {start_decl} {{
            size_t len = 0;
            while (len < sizeof(g_rex_buf)) {{
                long n = sys_read(0, g_rex_buf + len, sizeof(g_rex_buf) - len);
                if (n <= 0) {{
                    break;
                }}
                len += (size_t)n;
            }}
            sys_exit(LLVMFuzzerTestOneInput(g_rex_buf, len));
        }}
        """
    )


def _extract_toolchain_settings(compile_output: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for line in compile_output.splitlines():
        if line.startswith("CC="):
            settings["cc"] = line.partition("=")[2].strip()
        elif line.startswith("CXX="):
            settings["cxx"] = line.partition("=")[2].strip()
        elif line.startswith("CFLAGS="):
            settings["cflags"] = line.partition("=")[2].strip()
        elif line.startswith("CXXFLAGS="):
            settings["cxxflags"] = line.partition("=")[2].strip()
    return settings


def _adapter_recipe(project: str, selected_fuzzer: str) -> dict[str, Any] | None:
    if project == "quickjs":
        support_args = {
            "fuzz_compile": ".obj/fuzz_common.o libquickjs.fuzz.a",
            "fuzz_eval": ".obj/fuzz_common.o libquickjs.fuzz.a",
            "fuzz_regexp": ".obj/libregexp.fuzz.o .obj/cutils.fuzz.o .obj/libunicode.fuzz.o",
        }.get(selected_fuzzer)
        if support_args is None:
            return None
        return {
            "use_cpp_adapter": False,
            "source_compiler": "cc",
            "source_flags": "cflags",
            "link_compiler": "cxx",
            "link_flags": "cxxflags",
            "harness_source": f"fuzz/{selected_fuzzer}.c",
            "harness_includes": "-I.",
            "support_args": support_args,
            "link_tail": "-fsanitize=fuzzer-no-link",
        }

    if project == "libpng" and selected_fuzzer.startswith("libpng_"):
        return {
            "use_cpp_adapter": True,
            "source_compiler": "cxx",
            "source_flags": "cxxflags",
            "link_compiler": "cxx",
            "link_flags": "cxxflags",
            "harness_source": f"contrib/oss-fuzz/{selected_fuzzer}.cc",
            "harness_includes": "-std=c++11 -I.",
            "support_args": ".libs/libpng16.a -lz",
            "link_tail": "-fsanitize=fuzzer-no-link",
        }

    if project == "libzip":
        return {
            "use_cpp_adapter": True,
            "source_compiler": "cxx",
            "source_flags": "cxxflags",
            "link_compiler": "cxx",
            "link_flags": "cxxflags",
            "harness_source": f"ossfuzz/{selected_fuzzer}.c",
            "harness_includes": "-I. -I./lib -I./build -I./build/lib",
            "support_args": (
                "build/lib/libzip.a -lbz2 -llzma -lz -lzstd -lssl -lcrypto "
                "-lstdc++ -lm -lpthread -lrt -ldl -lresolv"
            ),
            "link_tail": "-fsanitize=fuzzer-no-link",
        }

    return None


def _compile_stdin_adapter(
    session: DockerSession,
    *,
    project: str,
    repo_dir: str,
    selected_fuzzer: str,
    destination_attempt_dir: Path,
    toolchain: dict[str, str],
) -> dict[str, Any]:
    recipe = _adapter_recipe(project, selected_fuzzer)
    if recipe is None:
        return {
            "status": "skipped",
            "reason": f"no stdin adapter recipe for project={project} fuzzer={selected_fuzzer}",
        }

    adapter_src_path = "/tmp/vuljector_stdin_adapter.cc" if recipe["use_cpp_adapter"] else "/tmp/vuljector_stdin_adapter.c"
    adapter_obj_path = f"/tmp/vuljector_{selected_fuzzer}_stdin_adapter_main.o"
    harness_obj_path = f"/tmp/vuljector_{selected_fuzzer}_stdin_harness.o"
    adapter_bin_path = f"/tmp/vuljector_{selected_fuzzer}_stdin_adapter"

    source_compiler = toolchain.get(recipe["source_compiler"], "").strip()
    source_flags = toolchain.get(recipe["source_flags"], "").strip()
    link_compiler = toolchain.get(recipe["link_compiler"], "").strip()
    link_flags = toolchain.get(recipe["link_flags"], "").strip()
    if not all((source_compiler, link_compiler)):
        return {
            "status": "failure",
            "reason": "compile toolchain settings are missing from compile output",
        }

    command = textwrap.dedent(
        f"""
        set -e
        {source_compiler} {source_flags} {recipe["harness_includes"]} -c {shlex.quote(recipe["harness_source"])} -o {shlex.quote(harness_obj_path)}
        {source_compiler} {source_flags} {recipe["harness_includes"]} -c {shlex.quote(adapter_src_path)} -o {shlex.quote(adapter_obj_path)}
        {link_compiler} {link_flags} {shlex.quote(adapter_obj_path)} {shlex.quote(harness_obj_path)} -o {shlex.quote(adapter_bin_path)} {recipe["support_args"]} {recipe["link_tail"]}
        """
    ).strip()

    source = _stdin_adapter_source(use_cpp=bool(recipe["use_cpp_adapter"]))
    session.write_file(adapter_src_path, source)
    compile_result = session.exec(command, workdir=repo_dir, timeout=1800)
    log_path = destination_attempt_dir / REX_LOG_ROOT / "stdin_adapter_compile.log"
    _write_log(log_path, command, compile_result)
    payload = _serialize_exec_result(compile_result, log_path=log_path, command=command)
    payload["status"] = "compiled" if compile_result.returncode == 0 else "failure"
    if compile_result.returncode == 0:
        host_adapter_path = destination_attempt_dir / REX_ADAPTER_ROOT / selected_fuzzer
        host_adapter_path.parent.mkdir(parents=True, exist_ok=True)
        session.copy_from(adapter_bin_path, host_adapter_path)
        payload["container_binary_path"] = adapter_bin_path
        payload["host_binary_path"] = str(host_adapter_path)
    return payload


def _compile_rex_ready_binary(
    session: DockerSession,
    *,
    project: str,
    repo_dir: str,
    selected_fuzzer: str,
    destination_attempt_dir: Path,
) -> dict[str, Any]:
    if not (project == "libpng" and selected_fuzzer == "libpng_readapi_fuzzer"):
        return {
            "status": "skipped",
            "reason": f"no Rex-ready plain binary recipe for project={project} fuzzer={selected_fuzzer}",
        }

    source_path = "/tmp/vuljector_rex_rawstart.cc"
    harness_obj_path = f"/tmp/vuljector_{selected_fuzzer}_rex_harness.o"
    entry_obj_path = f"/tmp/vuljector_{selected_fuzzer}_rex_entry.o"
    binary_path = f"/tmp/vuljector_{selected_fuzzer}_rex_ready"
    session.write_file(source_path, _rawstart_rex_source(use_cpp=True))
    command = textwrap.dedent(
        f"""
        set -e
        cat scripts/pnglibconf.dfa | sed -e "s/option STDIO/option STDIO disabled/" -e "s/option WARNING /option WARNING disabled/" -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" > scripts/pnglibconf.dfa.temp
        mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa
        CC=clang CXX=clang++ CFLAGS='-O0 -g -fno-omit-frame-pointer -fno-pie' CXXFLAGS='-O0 -g -fno-omit-frame-pointer -fno-pie -std=c++11 -stdlib=libc++' LDFLAGS='-no-pie' ./configure --with-libpng-prefix=OSS_FUZZ_
        make -j$(nproc) clean
        make -j$(nproc) libpng16.la
        clang++ -O0 -g -fno-omit-frame-pointer -fno-pie -no-pie -std=c++11 -stdlib=libc++ -I. -c contrib/oss-fuzz/libpng_readapi_fuzzer.cc -o {shlex.quote(harness_obj_path)}
        clang++ -O0 -g -fno-omit-frame-pointer -fno-pie -no-pie -std=c++11 -stdlib=libc++ -I. -c {shlex.quote(source_path)} -o {shlex.quote(entry_obj_path)}
        clang++ -O0 -g -fno-omit-frame-pointer -fno-pie -no-pie -nostartfiles -Wl,-e,_start {shlex.quote(entry_obj_path)} {shlex.quote(harness_obj_path)} -o {shlex.quote(binary_path)} .libs/libpng16.a -lz
        """
    ).strip()
    compile_result = session.exec(command, workdir=repo_dir, timeout=1800)
    log_path = destination_attempt_dir / REX_LOG_ROOT / "rex_ready_binary_compile.log"
    _write_log(log_path, command, compile_result)
    payload = _serialize_exec_result(compile_result, log_path=log_path, command=command)
    payload["status"] = "compiled" if compile_result.returncode == 0 else "failure"
    if compile_result.returncode == 0:
        host_binary_path = destination_attempt_dir / REX_BINARY_ROOT / f"{selected_fuzzer}_rex_ready"
        host_binary_path.parent.mkdir(parents=True, exist_ok=True)
        session.copy_from(binary_path, host_binary_path)
        payload["container_binary_path"] = binary_path
        payload["host_binary_path"] = str(host_binary_path)
    return payload


def _rex_runner_script() -> str:
    return textwrap.dedent(
        """
        import json
        import os
        import traceback
        from pathlib import Path

        import archr
        import rex

        binary_path, argv_input_path, input_path, output_path = __import__("sys").argv[1:5]
        python_bin = str(Path(__import__("sys").executable).resolve())
        os.environ["PATH"] = str(Path(python_bin).parent) + os.pathsep + os.environ.get("PATH", "")
        os.environ["ARCHR_PYTHON"] = python_bin
        crash_bytes = Path(input_path).read_bytes()
        binary_real = str(Path(binary_path).resolve())
        binary_name = Path(binary_real).name
        binary_dir = str(Path(binary_real).parent)
        argv = [binary_name]
        if argv_input_path:
            argv.append(argv_input_path)
        result = {
            "binary_path": binary_real,
            "argv_input_path": argv_input_path,
            "input_path": input_path,
            "input_size": len(crash_bytes),
            "status": "failure",
        }
        try:
            with archr.targets.LocalTarget(argv, target_path=binary_real, target_cwd=binary_dir, target_os="linux") as target:
                crash = rex.Crash(target, crash=crash_bytes, use_rop=False)
                result.update(
                    {
                        "status": "success",
                        "crash_types": [str(item) for item in crash.crash_types],
                        "exploitable": bool(crash.exploitable()),
                        "explorable": bool(crash.explorable()),
                        "use_rop": False,
                        "argv": argv,
                    }
                )
        except Exception as exc:  # pragma: no cover - executed in a subprocess
            result["error"] = str(exc)
            result["traceback"] = traceback.format_exc()

        Path(output_path).write_text(json.dumps(result, indent=2) + "\\n", encoding="utf-8")
        """
    )


def _write_request(run_dir: Path, *, run_id: str, source_run_dir: str | None, source_attempt_dir: str | None) -> None:
    write_json(
        run_dir / "rex_triage_request.json",
        {
            "run_id": run_id,
            "timestamp_utc": utc_now_iso(),
            "source_run_dir": source_run_dir,
            "source_attempt_dir": source_attempt_dir,
        },
    )


def triage_rex_attempt(
    *,
    source_attempt_dir: Path,
    destination_attempt_dir: Path,
    rex_python: str | None = None,
    replay_timeout: int = 120,
    rex_timeout: int = 300,
) -> dict[str, Any]:
    result_path = destination_attempt_dir / "rex_result.json"
    if result_path.exists():
        cached = read_json(result_path)
        if cached.get("status") in {"success", "failure"}:
            return cached

    verification = _read_success_verification(source_attempt_dir)
    source_injection = _load_source_injection(source_attempt_dir)
    report = _prefer_vulnerable_report(verification)
    project = source_injection["project"]
    selected_fuzzer = str((report.get("fuzzer") or (verification.get("metadata") or {}).get("selected_fuzzer") or "")).strip()
    if not selected_fuzzer:
        raise RuntimeError(f"unable to determine crashing fuzzer for {source_attempt_dir}")

    trigger_input_source = _resolve_trigger_input_source(source_attempt_dir, verification)
    config = load_project_config(project)
    image_tag = _resolve_image_tag(config)
    repo_dir = f"/src/{config.target_dir}"

    destination_attempt_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_attempt_dir / "verification_result.json", destination_attempt_dir / "source_verification_result.json")
    if (source_attempt_dir / "source_injection_result.json").exists():
        shutil.copy2(source_attempt_dir / "source_injection_result.json", destination_attempt_dir / "source_injection_result.json")
    if (source_attempt_dir / "artifacts" / "vuln.patch").exists():
        patch_dest = destination_attempt_dir / "artifacts" / "vuln.patch"
        patch_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_attempt_dir / "artifacts" / "vuln.patch", patch_dest)

    trigger_input_name = trigger_input_source.get("seed_name") or "trigger_input.bin"
    host_input_path = destination_attempt_dir / REX_INPUT_ROOT / trigger_input_name
    host_input_path.parent.mkdir(parents=True, exist_ok=True)
    if trigger_input_source["mode"] == "local_file":
        shutil.copy2(trigger_input_source["path"], host_input_path)
    host_binary_path = destination_attempt_dir / REX_BINARY_ROOT / selected_fuzzer
    host_binary_path.parent.mkdir(parents=True, exist_ok=True)

    destination_mount = Path(RUN_MOUNT_POINT)
    container_input_path = destination_mount / REX_INPUT_ROOT / trigger_input_name
    direct_command = f"/out/{shlex.quote(selected_fuzzer)} {shlex.quote(str(container_input_path))}"
    stdin_commands = {
        "dev_stdin": f"cat {shlex.quote(str(container_input_path))} | /out/{shlex.quote(selected_fuzzer)} /dev/stdin",
        "proc_self_fd_0": f"cat {shlex.quote(str(container_input_path))} | /out/{shlex.quote(selected_fuzzer)} /proc/self/fd/0",
    }

    output: dict[str, Any] = {
        "project": project,
        "timestamp_utc": utc_now_iso(),
        "status": "failure",
        "source_attempt_dir": str(source_attempt_dir),
        "triage_attempt_dir": str(destination_attempt_dir),
        "selected_fuzzer": selected_fuzzer,
        "image_tag": image_tag,
        "trigger_input": {
            "source_path": str(trigger_input_source.get("path") or trigger_input_source.get("archive_member") or ""),
            "bundle_path": str(host_input_path),
            "seed_name": trigger_input_name,
            "source_kind": trigger_input_source["mode"],
        },
        "source_report": {
            "mode": report.get("mode"),
            "returncode": report.get("returncode"),
            "log": report.get("log"),
        },
        "container_replay": {},
        "stdin_adapter": {},
        "rex_ready_binary": {},
        "rex": {},
    }
    write_json(result_path, output)

    session = DockerSession.start(project=project, image_tag=image_tag, run_mount_dir=destination_attempt_dir)
    try:
        patch_diff = (source_injection.get("artifacts") or {}).get("patch_diff") or ""
        if not patch_diff.strip():
            raise RuntimeError("missing patch diff in source injection result")

        _apply_patch(session, repo_dir=repo_dir, patch_diff=patch_diff)
        session.exec("git clean -fdx", workdir=repo_dir).raise_for_status("git clean before rebuild failed")
        for cmd in PROJECT_CLEANUP_COMMANDS.get(project, []):
            session.exec(cmd).raise_for_status(f"project cleanup failed: {cmd}")

        compile_result = session.exec(
            "compile",
            env={"FUZZING_LANGUAGE": config.language or "c++"},
            timeout=1800,
        )
        compile_log_path = destination_attempt_dir / REX_LOG_ROOT / "compile.log"
        _write_log(compile_log_path, "compile", compile_result)
        output["compile"] = _serialize_exec_result(compile_result, log_path=compile_log_path, command="compile")
        if compile_result.returncode != 0:
            write_json(result_path, output)
            return output
        toolchain = _extract_toolchain_settings((compile_result.stdout or "") + "\n" + (compile_result.stderr or ""))

        if trigger_input_source["mode"] == "builtin_corpus_member":
            archive_member = trigger_input_source.get("archive_member")
            if not archive_member:
                raise RuntimeError("builtin corpus member is missing archive_member")
            extract_script = textwrap.dedent(
                f"""
                import pathlib
                import zipfile

                corpus_zip = pathlib.Path("/out/{selected_fuzzer}_seed_corpus.zip")
                out_path = pathlib.Path({str(host_input_path.relative_to(destination_attempt_dir)).__repr__()})
                with zipfile.ZipFile(corpus_zip) as zf:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_bytes(zf.read({archive_member!r}))
                """
            )
            session.write_file("/tmp/vuljector_extract_seed.py", extract_script)
            session.exec(
                "python3 /tmp/vuljector_extract_seed.py",
                workdir=RUN_MOUNT_POINT,
            ).raise_for_status("failed to extract builtin corpus member")

        session.copy_from(f"/out/{selected_fuzzer}", host_binary_path)
        adapter_payload = _compile_stdin_adapter(
            session,
            project=project,
            repo_dir=repo_dir,
            selected_fuzzer=selected_fuzzer,
            destination_attempt_dir=destination_attempt_dir,
            toolchain=toolchain,
        )
        output["stdin_adapter"] = adapter_payload
        rex_ready_payload = _compile_rex_ready_binary(
            session,
            project=project,
            repo_dir=repo_dir,
            selected_fuzzer=selected_fuzzer,
            destination_attempt_dir=destination_attempt_dir,
        )
        output["rex_ready_binary"] = rex_ready_payload

        direct_result = session.exec(direct_command, timeout=replay_timeout)
        direct_log_path = destination_attempt_dir / REX_LOG_ROOT / "direct_replay.log"
        _write_log(direct_log_path, direct_command, direct_result)

        stdin_attempts: dict[str, dict[str, Any]] = {}
        for label, command in stdin_commands.items():
            stdin_result = session.exec(command, timeout=replay_timeout)
            stdin_log_path = destination_attempt_dir / REX_LOG_ROOT / f"stdin_replay_{label}.log"
            _write_log(stdin_log_path, command, stdin_result)
            stdin_attempts[label] = _serialize_exec_result(stdin_result, log_path=stdin_log_path, command=command)

        adapter_replay = None
        if adapter_payload.get("status") == "compiled":
            adapter_command = f"cat {shlex.quote(str(container_input_path))} | {shlex.quote(str(adapter_payload['container_binary_path']))}"
            adapter_result = session.exec(adapter_command, timeout=replay_timeout)
            adapter_log_path = destination_attempt_dir / REX_LOG_ROOT / "stdin_adapter_replay.log"
            _write_log(adapter_log_path, adapter_command, adapter_result)
            adapter_replay = _serialize_exec_result(adapter_result, log_path=adapter_log_path, command=adapter_command)
            output["stdin_adapter"]["replay"] = adapter_replay

        rex_ready_replay = None
        if rex_ready_payload.get("status") == "compiled":
            rex_ready_command = f"cat {shlex.quote(str(container_input_path))} | {shlex.quote(str(rex_ready_payload['container_binary_path']))}"
            rex_ready_result = session.exec(rex_ready_command, timeout=replay_timeout)
            rex_ready_log_path = destination_attempt_dir / REX_LOG_ROOT / "rex_ready_binary_replay.log"
            _write_log(rex_ready_log_path, rex_ready_command, rex_ready_result)
            rex_ready_replay = _serialize_exec_result(
                rex_ready_result,
                log_path=rex_ready_log_path,
                command=rex_ready_command,
            )
            output["rex_ready_binary"]["replay"] = rex_ready_replay

        output["container_replay"] = {
            "direct_path_replay": _serialize_exec_result(direct_result, log_path=direct_log_path, command=direct_command),
            "stdin_compatibility_replays": stdin_attempts,
        }
    finally:
        session.stop()

    if not output["container_replay"]["direct_path_replay"]["triggered"]:
        write_json(result_path, output)
        return output

    output["status"] = "success"

    stdin_compat = output["container_replay"].get("stdin_compatibility_replays") or {}
    compatible_argv_input = next(
        ("/dev/stdin" if key == "dev_stdin" else "/proc/self/fd/0" for key, item in stdin_compat.items() if item.get("triggered")),
        None,
    )
    rex_binary_path = str(host_binary_path)
    rex_argv_input = compatible_argv_input or ""
    adapter_replay = (output.get("stdin_adapter") or {}).get("replay") or {}
    adapter_binary_path = (output.get("stdin_adapter") or {}).get("host_binary_path")
    rex_ready_replay = (output.get("rex_ready_binary") or {}).get("replay") or {}
    rex_ready_binary_path = (output.get("rex_ready_binary") or {}).get("host_binary_path")
    if rex_ready_binary_path and rex_ready_replay.get("triggered"):
        rex_binary_path = str(rex_ready_binary_path)
        rex_argv_input = ""
    elif adapter_binary_path and adapter_replay.get("triggered"):
        rex_binary_path = str(adapter_binary_path)
        rex_argv_input = ""
    rex_status: dict[str, Any]
    if not rex_ready_replay.get("triggered") and not adapter_replay.get("triggered") and compatible_argv_input is None:
        rex_status = {
            "status": "skipped",
            "reason": "no stdin-backed replay path reproduced the crash, so rex cannot be fed this case safely",
        }
    else:
        rex_python_bin, rex_skip_reason = _pick_rex_python(rex_python)
        if rex_python_bin is None:
            rex_status = {"status": "skipped", "reason": rex_skip_reason}
            output["rex"] = rex_status
            write_json(result_path, output)
            return output
        rex_output_path = destination_attempt_dir / "rex_subprocess_result.json"
        subprocess_result = subprocess.run(
            [
                rex_python_bin,
                "-c",
                _rex_runner_script(),
                rex_binary_path,
                rex_argv_input,
                str(host_input_path),
                str(rex_output_path),
            ],
            capture_output=True,
            text=True,
            timeout=rex_timeout,
        )
        rex_stdout_path = destination_attempt_dir / REX_LOG_ROOT / "rex_stdout.log"
        rex_stderr_path = destination_attempt_dir / REX_LOG_ROOT / "rex_stderr.log"
        rex_stdout_path.write_text(subprocess_result.stdout or "", encoding="utf-8")
        rex_stderr_path.write_text(subprocess_result.stderr or "", encoding="utf-8")
        if rex_output_path.exists():
            rex_status = read_json(rex_output_path)
        else:
            rex_status = {
                "status": "failure",
                "error": "rex subprocess did not write an output file",
            }
        rex_status.update(
            {
                "python": rex_python_bin,
                "argv_input_path": rex_argv_input,
                "target_binary_path": rex_binary_path,
                "subprocess_returncode": subprocess_result.returncode,
                "stdout_log": str(rex_stdout_path),
                "stderr_log": str(rex_stderr_path),
            }
        )
    output["rex"] = rex_status
    write_json(result_path, output)
    return output


def batch_rex_triage(
    *,
    source_run_dir: Path,
    rex_python: str | None = None,
    replay_timeout: int = 120,
    rex_timeout: int = 300,
) -> dict[str, Any]:
    source_attempts = sorted(path for path in source_run_dir.glob("attempt_*") if path.is_dir())
    successful_attempts: list[Path] = []
    for attempt_dir in source_attempts:
        verification_path = attempt_dir / "verification_result.json"
        if not verification_path.exists():
            continue
        try:
            verification = read_json(verification_path)
        except Exception:
            continue
        if verification.get("status") == "success":
            successful_attempts.append(attempt_dir)

    if not successful_attempts:
        raise RuntimeError(f"no successful attempts found in {source_run_dir}")

    first_injection = _load_source_injection(successful_attempts[0])
    project = first_injection["project"]
    run_id = new_run_id("rex_triage", suffix=_sanitize_tag(source_run_dir.name))
    run_dir = REX_TRIAGE_ROOT / project / run_id
    _write_request(run_dir, run_id=run_id, source_run_dir=str(source_run_dir), source_attempt_dir=None)

    attempts: list[dict[str, Any]] = []
    for index, source_attempt in enumerate(successful_attempts):
        try:
            payload = triage_rex_attempt(
                source_attempt_dir=source_attempt,
                destination_attempt_dir=run_dir / f"attempt_{index:02d}",
                rex_python=rex_python,
                replay_timeout=replay_timeout,
                rex_timeout=rex_timeout,
            )
        except Exception as exc:
            payload = {
                "project": project,
                "timestamp_utc": utc_now_iso(),
                "status": "failure",
                "source_attempt_dir": str(source_attempt),
                "error": str(exc),
            }
        attempts.append(payload)

    summary = {
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "source_run_dir": str(source_run_dir),
        "triage_run_dir": str(run_dir),
        "successful_source_attempt_count": len(successful_attempts),
        "attempts": attempts,
        "summary": {
            "prepared_count": sum(1 for item in attempts if item.get("status") == "success"),
            "rex_success_count": sum(1 for item in attempts if (item.get("rex") or {}).get("status") == "success"),
            "rex_skipped_count": sum(1 for item in attempts if (item.get("rex") or {}).get("status") == "skipped"),
            "rex_failure_count": sum(1 for item in attempts if (item.get("rex") or {}).get("status") == "failure"),
        },
    }
    write_json(run_dir / "run_summary.json", summary)
    return summary
