from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from setup.container_runtime import ExecResult
from vuljector.run_rex_triage import (
    _detect_triggered,
    _prefer_vulnerable_report,
    _resolve_trigger_input_path,
)


class RunRexTriageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self.attempt = self.root / "attempt_00"
        (self.attempt / "artifacts" / "exploit_files" / "generated_inputs").mkdir(parents=True, exist_ok=True)
        (self.attempt / "artifacts" / "exploit_files" / "generated_inputs" / "seed.bin").write_bytes(b"boom")

    def test_prefer_vulnerable_report(self) -> None:
        verification = {
            "metadata": {
                "reports": {
                    "secure": {"mode": "replay", "seed": "secure.bin"},
                    "vulnerable": {"mode": "replay", "seed": "seed.bin"},
                }
            }
        }
        report = _prefer_vulnerable_report(verification)
        self.assertEqual(report["seed"], "seed.bin")

    def test_resolve_trigger_input_path_from_record(self) -> None:
        verification = {
            "metadata": {
                "generated_input_records": [
                    {
                        "name": "seed.bin",
                        "relative_path": "artifacts/exploit_files/generated_inputs/seed.bin",
                    }
                ],
                "reports": {
                    "vulnerable": {"mode": "replay", "seed": "seed.bin"},
                },
            }
        }
        resolved = _resolve_trigger_input_path(self.attempt, verification)
        self.assertEqual(resolved, self.attempt / "artifacts" / "exploit_files" / "generated_inputs" / "seed.bin")

    def test_detect_triggered_prefers_crash_text_over_exit_code(self) -> None:
        self.assertFalse(_detect_triggered(ExecResult(1, "", "")))
        self.assertTrue(_detect_triggered(ExecResult(0, "AddressSanitizer: heap-buffer-overflow", "")))
        self.assertTrue(_detect_triggered(ExecResult(139, "", "")))
        self.assertFalse(_detect_triggered(ExecResult(1, "ERROR: The required directory \"/dev/stdin\" does not exist", "")))
        self.assertFalse(_detect_triggered(ExecResult(0, "all good", "")))


if __name__ == "__main__":
    unittest.main()
