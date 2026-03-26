"""Heuristic-based test framework detection and test.sh generation."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from .layout import PARSER_PATH, write_test_harness

logger = logging.getLogger(__name__)

_SANITIZER_CLEAR = """\
# Clear OSS-Fuzz sanitizer/fuzzer flags that break normal builds
unset SANITIZER_FLAGS LIB_FUZZING_ENGINE
export CFLAGS="" CXXFLAGS="" LDFLAGS="" RUSTFLAGS=""\
"""

_HEURISTICS: list[dict] = [
    # ── Python ───────────────────────────────────────────────────────────────
    {
        "name": "pytest",
        "signals": ["pytest.ini", "conftest.py", "setup.cfg", "pyproject.toml", "setup.py"],
        "setup": (
            "(pip3 install -e '.[test,tests,dev,testing,devel,extras]' pytest -q 2>/dev/null"
            " || pip3 install -e . pytest -q 2>/dev/null"
            " || pip3 install pytest -q 2>/dev/null) 2>/dev/null || true"
        ),
        "cmd": "python3 -m pytest -v --tb=short",
        "framework": "pytest",
    },
    # ── Rust ─────────────────────────────────────────────────────────────────
    {
        "name": "cargo",
        "signals": ["Cargo.toml"],
        "needs_sanitizer_clear": True,
        "cmd": "cargo test",
        "framework": "cargo",
    },
    # ── Go ───────────────────────────────────────────────────────────────────
    {
        "name": "go",
        "signals": ["go.mod"],
        "cmd": "go test ./... -v -count=1",
        "framework": "gotest",
    },
    # ── CMake ────────────────────────────────────────────────────────────────
    {
        "name": "cmake",
        "signals": ["CMakeLists.txt"],
        "needs_sanitizer_clear": True,
        "cmd": (
            "mkdir -p /tmp/build && cd /tmp/build"
            " && cmake /src/{target_dir} -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON"
            " && cmake --build . -j$(nproc)"
            " && ctest --output-on-failure"
        ),
        "framework": "ctest",
    },
    # ── Java: Maven ──────────────────────────────────────────────────────────
    {
        "name": "maven-wrapper",
        "signals": ["mvnw", ".mvn/wrapper/maven-wrapper.properties"],
        "setup": 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64; export PATH="$JAVA_HOME/bin:$PATH"',
        "cmd": "GIT_DIR=/dev/null ./mvnw test -B -fn --no-transfer-progress",
        "framework": "maven",
    },
    {
        "name": "maven",
        "signals": ["pom.xml"],
        "setup": (
            'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64; export PATH="$JAVA_HOME/bin:$PATH";'
            " apt-get update -qq 2>/dev/null && apt-get install -y -qq maven >/dev/null 2>&1"
        ),
        "cmd": "mvn test -B -fn --no-transfer-progress",
        "framework": "maven",
    },
    # ── Java: Gradle ─────────────────────────────────────────────────────────
    {
        "name": "gradle-wrapper",
        "signals": ["gradlew", "gradle/wrapper/gradle-wrapper.properties"],
        "setup": 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64; export PATH="$JAVA_HOME/bin:$PATH"',
        "cmd": "GIT_DIR=/dev/null ./gradlew test --no-daemon",
        "framework": "gradle",
    },
    {
        "name": "gradle",
        "signals": ["build.gradle", "build.gradle.kts"],
        "setup": 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64; export PATH="$JAVA_HOME/bin:$PATH"',
        "cmd": "gradle test",
        "framework": "gradle",
    },
    # ── Meson ────────────────────────────────────────────────────────────────
    {
        "name": "meson",
        "signals": ["meson.build"],
        "needs_sanitizer_clear": True,
        "cmd": "meson setup /tmp/build --buildtype=debug && meson test -C /tmp/build --print-errorlogs",
        "framework": "meson",
    },
    # ── Autotools ────────────────────────────────────────────────────────────
    {
        "name": "autotools",
        "signals": ["configure.ac", "configure.in"],
        "needs_sanitizer_clear": True,
        "setup": (
            "if [ ! -f configure ]; then autoreconf -fi 2>&1 | tail -1; fi"
            " && ./configure 2>&1 | tail -1"
            " && make -j$(nproc) 2>&1 | tail -1"
        ),
        "cmd": "make check",
        "framework": "autotools",
    },
    # ── Node.js ──────────────────────────────────────────────────────────────
    {
        "name": "npm",
        "signals": ["package.json"],
        "setup": "npm install 2>&1 | tail -1",
        "cmd": "npm test",
        "framework": "jest",
    },
]


def _render_test_sh(target_dir: str, rule: dict) -> str:
    setup = str(rule.get("setup") or "").strip()
    cmd = str(rule.get("cmd", "")).replace("{target_dir}", target_dir).strip()
    framework = str(rule.get("framework") or "generic").strip() or "generic"

    lines = ["#!/bin/bash", f"cd /src/{target_dir}"]
    if rule.get("needs_sanitizer_clear"):
        lines.append(_SANITIZER_CLEAR)
    if setup:
        lines.append(setup)
    lines.append(f"{cmd} 2>&1 | python3 {PARSER_PATH} --framework {framework}")
    return "\n".join(lines) + "\n"


def _detect_framework(image_tag: str, target_dir: str) -> dict | None:
    """Check heuristic rules against the image; return first matching rule."""
    for rule in _HEURISTICS:
        signals = [str(s) for s in rule.get("signals", []) if str(s).strip()]
        if not signals:
            continue
        check = " || ".join(f"[ -f /src/{target_dir}/{s} ]" for s in signals)
        result = subprocess.run(
            ["docker", "run", "--rm", image_tag, "bash", "-c", f"if {check}; then echo yes; fi"],
            capture_output=True, text=True, timeout=30,
        )
        if result.stdout.strip() == "yes":
            return rule
    return None


def try_heuristic_harness(*, runtime, project: str, src_dir: str, unit_tests_dir: Path) -> bool:
    """
    Detect framework via heuristics, write test.sh, verify with baseline run.
    Returns True if accepted (passed > 0), False otherwise.
    """
    from .harness_agent import run_baseline_unit_tests

    rule = _detect_framework(runtime.image_tag, src_dir)
    if not rule:
        return False

    write_test_harness(unit_tests_dir, _render_test_sh(src_dir, rule))
    count, enabled = run_baseline_unit_tests(runtime=runtime, project=project)
    if enabled and (count or 0) > 0:
        logger.info(
            "[%s] Heuristic harness accepted: rule=%s framework=%s passed=%d",
            project, rule.get("name", "?"), rule.get("framework", "?"), count,
        )
        return True
    logger.info("[%s] Heuristic harness yielded count=%s — falling back to agent.", project, count)
    return False
