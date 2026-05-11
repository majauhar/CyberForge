from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from quality_control.fuzz_hot_path_triage import (
    run_fuzz_hot_path_triage,
    triage_injection_result_payload,
)


class FuzzHotPathTriageTests(unittest.TestCase):
    def test_runtime_candidate_scores_as_high_confidence(self) -> None:
        payload = {
            "project": "demo",
            "strategy": {
                "selection_candidate": {
                    "candidate_id": "fg_0001",
                    "extra": {
                        "fuzz_native": {
                            "preferred_fuzzer": "shape-fuzzer",
                            "alternate_fuzzers": ["alt-fuzzer"],
                            "reachability_kind": "runtime_function",
                            "existing_harness_viability": "high",
                            "format_family": "script_text",
                            "subsystem": "parser",
                            "bug_shape": "removed_length_restriction",
                            "target_function": "parse_input",
                            "target_file": "/src/demo/src/parser.c",
                            "target_line_range": [10, 20],
                            "blocker_count": 0,
                            "triggerability_score": 0.82,
                            "parser_proximity_score": 0.7,
                            "path_signal_score": 0.6,
                            "helper_judgment": "endpoint_or_stateful_slice",
                            "hot_path_bucket": "high_confidence_hot_path",
                        }
                    },
                }
            },
        }
        triage = triage_injection_result_payload(payload)
        self.assertEqual(triage["hot_path_bucket"], "high_confidence_hot_path")

    def test_file_coverage_candidate_scores_as_weak(self) -> None:
        payload = {
            "project": "demo",
            "strategy": {
                "selection_candidate": {
                    "candidate_id": "fg_0002",
                    "extra": {
                        "fuzz_native": {
                            "preferred_fuzzer": "shape-fuzzer",
                            "reachability_kind": "file_coverage",
                            "existing_harness_viability": "low",
                            "target_file": "/src/demo/src/core.c",
                            "target_line_range": [1, 80],
                            "blocker_count": 40,
                        }
                    },
                }
            },
        }
        triage = triage_injection_result_payload(payload)
        self.assertEqual(triage["hot_path_bucket"], "weak_or_coarse_match")

    def test_generic_helper_candidate_scores_as_helper_slice(self) -> None:
        payload = {
            "project": "demo",
            "strategy": {
                "selection_candidate": {
                    "candidate_id": "fg_0003",
                    "extra": {
                        "fuzz_native": {
                            "preferred_fuzzer": "shape-fuzzer",
                            "reachability_kind": "runtime_function",
                            "existing_harness_viability": "high",
                            "target_function": "dbuf_put",
                            "target_line_range": [10, 20],
                            "triggerability_score": 0.7,
                            "helper_judgment": "generic_helper_family",
                            "hot_path_bucket": "helper_reachable_slice",
                        }
                    },
                }
            },
        }
        triage = triage_injection_result_payload(payload)
        self.assertEqual(triage["hot_path_bucket"], "helper_reachable_slice")

    def test_batch_report_writes_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attempt = root / "attempt_00"
            attempt.mkdir(parents=True, exist_ok=True)
            payload = {
                "project": "demo",
                "strategy": {
                    "selection_candidate": {
                        "candidate_id": "fg_0001",
                        "extra": {
                            "fuzz_native": {
                                "preferred_fuzzer": "shape-fuzzer",
                                "reachability_kind": "runtime_function",
                                "existing_harness_viability": "high",
                                "format_family": "script_text",
                                "subsystem": "parser",
                                "bug_shape": "removed_length_restriction",
                                "target_function": "parse_input",
                                "target_line_range": [10, 20],
                            }
                        },
                    }
                },
            }
            (attempt / "injection_result.json").write_text(json.dumps(payload), encoding="utf-8")
            report = run_fuzz_hot_path_triage(source_dir=root)
            self.assertEqual(report["summary"]["attempt_count"], 1)
            self.assertTrue((Path(report["output_dir"]) / "fuzz_hot_path_triage_report.json").exists())


if __name__ == "__main__":
    unittest.main()
