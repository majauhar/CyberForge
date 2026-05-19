from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from utils.agent.prompts.injection import build_fuzz_guidance_section
from vuljector.run_fuzz_poc import (
    _build_generated_attempt,
    _candidate_is_viable,
    _infer_trigger_profile,
    _pick_fuzzer,
    _pick_fuzzer_sequence,
    _resolve_patch_diff,
    batch_verify_fuzz_poc,
    generate_fuzz_poc,
)


class RunFuzzPocTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self.source_attempt = self.root / "source" / "attempt_00"
        (self.source_attempt / "artifacts").mkdir(parents=True, exist_ok=True)
        self.injection_result = {
            "project": "demo",
            "cwe_id": "CWE-125",
            "strategy": {
                "selection_candidate": {
                    "extra": {
                        "fuzz_native": {
                            "preferred_fuzzer": "preferred-fuzzer",
                            "alternate_fuzzers": ["alternate-fuzzer"],
                            "reachability_kind": "runtime_function",
                            "target_function": "parse_input",
                            "target_file": "src/parser.c",
                            "target_line_range": [10, 20],
                            "format_family": "font_binary",
                            "subsystem": "gsub",
                            "input_model": "valid_font_with_gsub_tables",
                            "bug_shape": "unchecked_index",
                            "expected_cwe": ["CWE-129", "CWE-125"],
                            "validation_likelihood": "high",
                            "preserve_reachability": True,
                            "preserve_compile_viability": True,
                            "preserve_input_path": True,
                            "favor_sanitizer_visible_failure": True,
                        }
                    }
                }
            },
            "artifacts": {
                "patch_diff": "--- a/src/parser.c\n+++ b/src/parser.c\n@@ -10,1 +10,1 @@\n-if (len < size) return;\n+if (len <= size) return;\n",
                "attack_script": "",
            },
        }
        (self.source_attempt / "injection_result.json").write_text(
            json.dumps(self.injection_result),
            encoding="utf-8",
        )

    @mock.patch("vuljector.run_fuzz_poc.map_injection_result_to_harness")
    def test_pick_fuzzer_prefers_selection_metadata(self, mock_map: mock.Mock) -> None:
        mock_map.return_value = {
            "recommendations": [
                {"fuzzer": "patch-fuzzer", "score": 10, "reasons": []},
            ],
            "matched_functions": [],
        }
        picked = _pick_fuzzer(
            self.source_attempt / "injection_result.json",
            self.root,
            None,
            _infer_trigger_profile(self.injection_result),
        )
        self.assertEqual(picked["selected"]["fuzzer"], "preferred-fuzzer")
        self.assertEqual(picked["source"], "selection_metadata")

    @mock.patch("vuljector.run_fuzz_poc.map_injection_result_to_harness")
    def test_pick_fuzzer_falls_back_to_patch_inference(self, mock_map: mock.Mock) -> None:
        legacy = dict(self.injection_result)
        legacy["strategy"] = {}
        (self.source_attempt / "injection_result.json").write_text(json.dumps(legacy), encoding="utf-8")
        mock_map.return_value = {
            "recommendations": [
                {"fuzzer": "patch-fuzzer", "score": 10, "reasons": []},
            ],
            "matched_functions": [],
        }
        picked = _pick_fuzzer(
            self.source_attempt / "injection_result.json",
            self.root,
            None,
            _infer_trigger_profile(legacy),
        )
        self.assertEqual(picked["selected"]["fuzzer"], "patch-fuzzer")
        self.assertEqual(picked["source"], "patch_inference")

    @mock.patch("vuljector.run_fuzz_poc._select_builtin_corpus_members")
    @mock.patch("vuljector.run_fuzz_poc.map_injection_result_to_harness")
    def test_build_generated_attempt_records_selector_metadata(
        self,
        mock_map: mock.Mock,
        mock_select_builtin: mock.Mock,
    ) -> None:
        mock_map.return_value = {
            "recommendations": [],
            "matched_functions": [
                {"runtime_reached_by_fuzzers": ["preferred-fuzzer"], "reached_by_fuzzers": ["preferred-fuzzer"]}
            ],
        }
        mock_select_builtin.return_value = [
            {
                "name": "builtin_demo.js",
                "archive_member": "corpus/demo.js",
                "size": 12,
                "provenance": "builtin_corpus_member",
                "selection_score": 10,
                "selection_reasons": ["script-like seed"],
                "bug_conditioned": False,
                "replay_target": True,
                "replay_order": 0,
                "data": b"var x = 1;\n",
            }
        ]
        destination = self.root / "generated" / "attempt_00"
        payload = _build_generated_attempt(
            source_attempt_dir=self.source_attempt,
            destination_attempt_dir=destination,
            run_id="fuzz_poc_test",
            cache_dir=self.root,
            force_fuzzer=None,
            max_total_time=5,
        )
        manifest = json.loads(
            (destination / "artifacts" / "exploit_files" / "fuzz_poc_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["selected_fuzzer"], "preferred-fuzzer")
        self.assertEqual(manifest["selected_fuzzer_source"], "selection_metadata")
        self.assertEqual(manifest["candidate_fuzz"]["preferred_fuzzer"], "preferred-fuzzer")
        self.assertEqual(manifest["selected_builtin_corpus_members"][0]["archive_member"], "corpus/demo.js")
        self.assertNotIn("data", manifest["selected_builtin_corpus_members"][0])
        self.assertGreaterEqual(payload["selected_builtin_corpus_count"], 1)

    def test_resolve_patch_diff_falls_back_to_attempt_patch_file(self) -> None:
        payload = {
            "project": "demo",
            "artifacts": {"patch_diff": ""},
            "paths": {"patch_path": "artifacts/vuln.patch"},
        }
        patch_path = self.source_attempt / "artifacts" / "vuln.patch"
        patch_path.write_text("--- a/demo.c\n+++ b/demo.c\n@@ -1 +1 @@\n-a\n+b\n", encoding="utf-8")
        self.assertIn("+++ b/demo.c", _resolve_patch_diff(payload, attempt_dir=self.source_attempt))

    @mock.patch("vuljector.run_fuzz_poc.map_injection_result_to_harness")
    def test_pick_fuzzer_sequence_prefers_preferred_then_alternates(self, mock_map: mock.Mock) -> None:
        mock_map.return_value = {
            "recommendations": [
                {"fuzzer": "patch-fuzzer", "score": 10, "reasons": []},
                {"fuzzer": "alternate-fuzzer", "score": 9, "reasons": []},
            ],
            "matched_functions": [],
        }
        picks = _pick_fuzzer_sequence(
            self.source_attempt / "injection_result.json",
            self.root,
            None,
            _infer_trigger_profile(self.injection_result),
            top_fuzzers=3,
        )
        self.assertEqual([item["selected"]["fuzzer"] for item in picks], ["preferred-fuzzer", "alternate-fuzzer", "patch-fuzzer"])

    @mock.patch("vuljector.run_fuzz_poc._select_builtin_corpus_members")
    @mock.patch("vuljector.run_fuzz_poc.map_injection_result_to_harness")
    def test_generate_fuzz_poc_can_emit_multiple_attempts_without_curated_corpus(
        self,
        mock_map: mock.Mock,
        mock_select_builtin: mock.Mock,
    ) -> None:
        mock_map.return_value = {
            "recommendations": [
                {"fuzzer": "alternate-fuzzer", "score": 11, "reasons": ["runtime reaches function parse_input"]},
                {"fuzzer": "patch-fuzzer", "score": 10, "reasons": ["runtime reaches function parse_input"]},
            ],
            "matched_functions": [
                {
                    "runtime_reached_by_fuzzers": ["preferred-fuzzer", "alternate-fuzzer", "patch-fuzzer"],
                    "reached_by_fuzzers": ["preferred-fuzzer", "alternate-fuzzer", "patch-fuzzer"],
                }
            ],
        }
        mock_select_builtin.return_value = []
        summary = generate_fuzz_poc(
            source_attempt_dir=self.source_attempt,
            tag="unit_test",
            cache_dir=self.root,
            top_fuzzers=2,
            use_curated_corpus=False,
        )
        self.assertEqual(len(summary["attempts"]), 2)
        first_manifest = json.loads(
            (Path(summary["attempts"][0]["attempt_dir"]) / "artifacts" / "exploit_files" / "fuzz_poc_manifest.json").read_text(encoding="utf-8")
        )
        self.assertFalse(first_manifest["use_curated_corpus"])
        self.assertTrue(first_manifest["generated_input_records"])

    def test_candidate_viability_rejects_weak_unhinted_candidates(self) -> None:
        viable, reason = _candidate_is_viable(
            {"format_family": "binary"},
            {"matched_functions": [], "recommendations": []},
            {"fuzzer": "weak-fuzzer"},
            {},
        )
        self.assertFalse(viable)
        self.assertIn("no runtime reachability", reason or "")

    def test_candidate_viability_accepts_supported_synthetic_json_fallback(self) -> None:
        viable, reason = _candidate_is_viable(
            {"format_family": "json_text"},
            {"matched_functions": [], "recommendations": [], "synthetic_recommendations": True},
            {"fuzzer": "json-fuzzer", "score": 5},
            {},
        )
        self.assertTrue(viable)
        self.assertIsNone(reason)

    def test_build_fuzz_guidance_section_contains_constraints(self) -> None:
        section = build_fuzz_guidance_section(self.injection_result["strategy"]["selection_candidate"]["extra"]["fuzz_native"])
        self.assertIn("Preferred harness", section)
        self.assertIn("valid_font_with_gsub_tables", section)
        self.assertIn("unchecked_index", section)

    def test_batch_verify_progress_and_stdout(self) -> None:
        run_dir = self.root / "run"
        (run_dir / "attempt_00").mkdir(parents=True)
        (run_dir / "attempt_01").mkdir(parents=True)

        def fake_verify(*, attempt_dir: Path, exploit_timeout: int = 600) -> dict:
            return {"status": "success", "attempt_dir": str(attempt_dir), "timeout": exploit_timeout}

        buf = io.StringIO()
        with mock.patch("vuljector.run_fuzz_poc.verify_fuzz_poc_attempt", side_effect=fake_verify):
            with contextlib.redirect_stdout(buf):
                summary = batch_verify_fuzz_poc(run_dir=run_dir, exploit_timeout=12)
        progress = json.loads((run_dir / "verification_progress.json").read_text(encoding="utf-8"))
        self.assertEqual(progress["completed"], 2)
        self.assertEqual(progress["total"], 2)
        self.assertEqual(len(summary["attempts"]), 2)
        self.assertEqual(summary["summary"]["success_count"], 2)
        self.assertEqual(summary["summary"]["replay_success_count"], 0)
        self.assertIn("[fuzz-poc verify] 1/2 verifying", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
