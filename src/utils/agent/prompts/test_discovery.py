"""Prompt for test harness discovery."""

from __future__ import annotations


TEST_DISCOVERY_TASK = r"""\
You are inside the OSS-Fuzz Docker container for **{project}**.
`bash /src/build.sh` has already been run — the project's packages are installed.
`/workspace/run/unit_tests/parse_results.py` is pre-installed and ready to use.

## Goal
Write `/tmp/test_harness.sh` — a bash script that runs the project's existing
unit/integration tests (NOT the OSS-Fuzz fuzz targets) and produces a JSON summary
`{{"passed": N, "failed": M}}` as its last output line.

## Critical: OSS-Fuzz environment quirks
- **Sanitizer flags** break native builds — clear them before compiling:
  `unset SANITIZER_FLAGS LIB_FUZZING_ENGINE && export CFLAGS="" CXXFLAGS="" LDFLAGS="" RUSTFLAGS=""`
- **Do NOT use build.sh or fuzz targets** — use the native build system (make, cargo, go, mvn…).
- **Missing deps** — install with apt-get, pip3, cargo, npm, etc. as needed.

## Required output contract
The test command MUST be piped through the pre-installed parser as the **last line**:
```
<test_command> 2>&1 | python3 /workspace/run/unit_tests/parse_results.py --framework <FRAMEWORK>
```
Supported `--framework` values (use EXACTLY one of these — unknown values fall back to `generic`):
`pytest` `cargo` `gotest` `ctest` `maven` `gradle` `jest` `tap`
`phptest` `btest` `gtest` `meson` `unittest` `autotools` `generic`
For TAP-based runners (borp, tape, node-tap…) use `tap`. For unknown frameworks use `generic`.
You MAY edit `/workspace/run/unit_tests/parse_results.py` to add a missing framework.

---

## Steps

**1. Identify language and test structure:**
```bash
ls /src/{src_dir}/ && find /src/{src_dir} -maxdepth 2 -name "*.toml" -o -name "*.mod" \
  -o -name "pom.xml" -o -name "build.gradle*" -o -name "CMakeLists.txt" \
  -o -name "conftest.py" -o -name "package.json" 2>/dev/null | head -20
```

**2. Locate tests:**
```bash
find /src/{src_dir} -maxdepth 4 \( -name "test_*.py" -o -name "*_test.go" \
  -o -name "*Test.java" -o -name "*.test.js" -o -name "*_test.rs" \) \
  2>/dev/null | head -20
```

**3. Run tests experimentally** to find a working command (see reference below).
   Install missing dependencies, clear sanitizer flags for compiled languages.

**4. Write `/tmp/test_harness.sh`** with the working command piped through the parser:
```bash
cat <<'SCRIPT_EOF' > /tmp/test_harness.sh
#!/bin/bash
cd /src/{src_dir}
# add setup here (clear flags, install deps, build if needed)
<working_test_command> 2>&1 | python3 /workspace/run/unit_tests/parse_results.py --framework <FRAMEWORK>
SCRIPT_EOF
chmod +x /tmp/test_harness.sh
```

**5. Run and verify — passed must be > 0:**
```bash
bash /tmp/test_harness.sh 2>&1 | tee /tmp/baseline_output.txt | tail -5; echo "EXIT:$?"
```
If 0 tests ran or the last line is not valid JSON, fix and retry.

**6. Submit — do this immediately after step 5 passes. NO text response, just this command:**
```bash
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```
Important: After a successful step 5, your next action MUST be this exact command. Do not write a summary first.

---

## Framework quick-reference

**Python/pytest** — signals: `conftest.py`, `pytest.ini`, `setup.py`, `pyproject.toml`
```bash
(pip3 install -e ".[test,tests,dev]" pytest -q 2>/dev/null || pip3 install pytest -q 2>/dev/null) || true
python3 -m pytest tests/ -v --tb=short 2>&1 | python3 /workspace/run/unit_tests/parse_results.py --framework pytest
```

**Rust/cargo** — signals: `Cargo.toml`
```bash
unset SANITIZER_FLAGS LIB_FUZZING_ENGINE && export CFLAGS="" CXXFLAGS="" LDFLAGS="" RUSTFLAGS=""
cargo test 2>&1 | python3 /workspace/run/unit_tests/parse_results.py --framework cargo
```

**Go** — signals: `go.mod`
```bash
go test ./... -v -count=1 2>&1 | python3 /workspace/run/unit_tests/parse_results.py --framework gotest
```

**Java/Maven** — signals: `pom.xml`
```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 && export PATH="$JAVA_HOME/bin:$PATH"
mvn test -B -fn --no-transfer-progress 2>&1 | python3 /workspace/run/unit_tests/parse_results.py --framework maven
```

**Java/Gradle** — signals: `gradlew`, `build.gradle`
```bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 && export PATH="$JAVA_HOME/bin:$PATH"
GIT_DIR=/dev/null ./gradlew test --no-daemon 2>&1 | python3 /workspace/run/unit_tests/parse_results.py --framework gradle
```

**C/C++/CMake** — signals: `CMakeLists.txt`
```bash
unset SANITIZER_FLAGS LIB_FUZZING_ENGINE && export CFLAGS="" CXXFLAGS="" LDFLAGS=""
mkdir -p /tmp/build && cd /tmp/build && cmake /src/{src_dir} -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
  && cmake --build . -j$(nproc) \
  && ctest --output-on-failure 2>&1 | python3 /workspace/run/unit_tests/parse_results.py --framework ctest
```

**Autotools** — signals: `configure.ac`
```bash
unset SANITIZER_FLAGS LIB_FUZZING_ENGINE && export CFLAGS="" CXXFLAGS="" LDFLAGS=""
cd /src/{src_dir} && [ -f configure ] || autoreconf -fi
./configure && make -j$(nproc) && make check 2>&1 | python3 /workspace/run/unit_tests/parse_results.py --framework autotools
```

## Rules
- Never accept 0 passing tests — go back and fix.
- `/tmp/test_harness.sh` must exist, be executable, and pipe its last command through
  `/workspace/run/unit_tests/parse_results.py --framework <key>`.
"""
