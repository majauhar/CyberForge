from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vuljector.run_fuzz_guided_poc import (
    _build_guided_attempt,
    _guided_libfuzzer_options,
    _guided_pick_sequence,
    _pick_guided_fuzzer,
)
from vuljector.run_fuzz_poc import _infer_trigger_profile


class RunFuzzGuidedPocTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.root = Path(self.tmpdir.name)
        self.attempt = self.root / "attempt_00"
        self.attempt.mkdir(parents=True, exist_ok=True)
        self.payload = {
            "project": "demo",
            "strategy": {
                "selection_candidate": {
                    "extra": {
                        "fuzz_native": {
                            "preferred_fuzzer": "preferred-fuzzer",
                            "alternate_fuzzers": ["alt-fuzzer"],
                            "format_family": "script_text",
                            "input_model": "small_valid_script_compile_units",
                            "bug_shape": "conversion_boundary_regression",
                            "reachability_kind": "runtime_function",
                        }
                    }
                }
            },
            "artifacts": {
                "patch_diff": "--- a/demo.c\n+++ b/demo.c\n@@ -1 +1 @@\n-a\n+b\n",
                "attack_script": "",
            },
        }
        (self.attempt / "injection_result.json").write_text(json.dumps(self.payload), encoding="utf-8")

    def test_pick_guided_fuzzer_prefers_metadata(self) -> None:
        picked = _pick_guided_fuzzer(
            self.attempt / "injection_result.json",
            self.root,
            None,
            _infer_trigger_profile(self.payload),
        )
        self.assertEqual(picked["selected"]["fuzzer"], "preferred-fuzzer")
        self.assertEqual(picked["source"], "selection_metadata_preferred")

    def test_guided_pick_sequence_includes_alternates(self) -> None:
        picks = _guided_pick_sequence(
            self.attempt / "injection_result.json",
            self.root,
            None,
            _infer_trigger_profile(self.payload),
            top_fuzzers=2,
        )
        self.assertEqual([item["selected"]["fuzzer"] for item in picks], ["preferred-fuzzer", "alt-fuzzer"])

    def test_guided_libfuzzer_options_adds_coverage_defaults(self) -> None:
        options = _guided_libfuzzer_options(
            profile={"format_family": "script_text"},
            candidate_fuzz={"dict_name": "demo.dict"},
            local_assets={"options": {}},
        )
        self.assertEqual(options["use_value_profile"], 1)
        self.assertEqual(options["max_len"], 8192)
        self.assertEqual(options["dict"], "demo.dict")

    @mock.patch("vuljector.run_fuzz_guided_poc._select_builtin_corpus_members")
    def test_build_guided_attempt_records_builtin_seed_manifest(self, mock_select_builtin: mock.Mock) -> None:
        mock_select_builtin.return_value = [
            {
                "name": "builtin_demo.js",
                "archive_member": "corpus/demo.js",
                "size": 12,
                "provenance": "builtin_corpus_member",
                "selection_score": 12,
                "selection_reasons": ["script-like seed"],
                "bug_conditioned": False,
                "replay_target": True,
                "replay_order": 0,
                "data": b"var x = 1;\n",
            }
        ]
        destination = self.root / "guided" / "attempt_00"
        payload = _build_guided_attempt(
            source_attempt_dir=self.attempt,
            destination_attempt_dir=destination,
            run_id="guided_test",
            cache_dir=self.root,
            force_fuzzer=None,
            max_total_time=5,
            use_curated_corpus=False,
        )
        manifest = json.loads(
            (destination / "artifacts" / "exploit_files" / "fuzz_poc_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(payload["selected_fuzzer"], "preferred-fuzzer")
        self.assertFalse(manifest["use_curated_corpus"])
        self.assertEqual(manifest["selected_builtin_corpus_members"][0]["archive_member"], "corpus/demo.js")
        self.assertTrue(manifest["generated_input_records"])
        self.assertEqual(payload["selected_builtin_corpus_count"], 1)


if __name__ == "__main__":
    unittest.main()
