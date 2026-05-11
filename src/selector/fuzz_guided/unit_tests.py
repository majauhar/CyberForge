from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from selector.fuzz_guided.planner import plan_fuzz_guided_candidates
from selector.fuzz_guided.path_signals import summarize_project_path_signals
from selector.fuzz_guided.run import FuzzGuidedStrategy, _rank_candidates
from selector.fuzz_guided.surface import infer_format_family, infer_subsystem, load_project_fuzz_surface
from selector.fuzz_guided.guidance import map_patch_to_harness
from vuljector.io_contracts import SelectionCandidate


def _cache_payload(functions: list[dict], coverage: dict, fuzzers: list[dict]) -> dict:
    return {
        "project": "demo",
        "introspector": {
            "available": True,
            "functions": functions,
            "fuzzers": fuzzers,
        },
        "coverage": {
            "available": True,
            "fuzzer_stats": coverage,
        },
    }


class FuzzGuidedPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.cache_dir = Path(self.tmpdir.name) / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.repo_root = Path(self.tmpdir.name) / "demo"
        (self.repo_root / "src").mkdir(parents=True, exist_ok=True)
        (self.repo_root / "src" / "parser.c").write_text(
            "\n".join(
                [
                    "int parse_input(int idx, int len, char *buf) {",
                    "  if (idx >= len) return -1;",
                    "  return buf[idx];",
                    "}",
                ]
            ) + "\n",
            encoding="utf-8",
        )
        (self.repo_root / "src" / "writer.c").write_text(
            "\n".join(
                [
                    "int write_token(struct out *s, int len, char c) {",
                    "  if ((s->cap - s->size) < len) return -1;",
                    "  s->buf[s->size++] = c;",
                    "  return 0;",
                    "}",
                ]
            ) + "\n",
            encoding="utf-8",
        )
        (self.repo_root / "src" / "exporter.c").write_text(
            "\n".join(
                [
                    "int export_asset(int len, char *buf) {",
                    "  if (len > 16) return -1;",
                    "  return buf[len];",
                    "}",
                ]
            ) + "\n",
            encoding="utf-8",
        )

    def _write_cache(self, payload: dict) -> None:
        (self.cache_dir / "demo.json").write_text(json.dumps(payload), encoding="utf-8")

    @mock.patch("selector.fuzz_guided.surface.local_fuzz_assets")
    def test_surface_model_loads_harnesses_runtime_and_assets(self, mock_assets: mock.Mock) -> None:
        mock_assets.return_value = {"shape-fuzzer": {"dict": True, "options": False}}
        self._write_cache(
            _cache_payload(
                functions=[
                    {
                        "name": "parse_input",
                        "source_file": "/src/demo/src/parser.c",
                        "source_line_begin": 1,
                        "source_line_end": 4,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                        "combined_reached_by_fuzzers": ["shape-fuzzer"],
                        "functions_reached_count": 8,
                        "function_signature": "int parse_input(int idx, int len, char *buf)",
                        "callsites": {"memcpy": ["parser.c#parse_input:3"]},
                    },
                    {
                        "name": "std::vector::size",
                        "source_file": "/usr/include/c++/vector",
                        "source_line_begin": 1,
                        "source_line_end": 2,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                    },
                ],
                coverage={
                    "shape-fuzzer": {
                        "files": [
                            {"filename": "/src/demo/src/parser.c", "summary": {"lines": {"percent": 74.0}}}
                        ]
                    },
                },
                fuzzers=[{"name": "shape-fuzzer", "blockers": ["deep blocker"]}],
            )
        )
        surface = load_project_fuzz_surface("demo", self.cache_dir)
        harness = surface.harnesses["shape-fuzzer"]
        self.assertEqual(len(surface.project_functions), 1)
        self.assertEqual(harness.runtime_functions[0].name, "parse_input")
        self.assertTrue(harness.has_dict)
        self.assertFalse(harness.has_options)
        self.assertEqual(harness.file_coverage["/src/demo/src/parser.c"], 74.0)
        self.assertEqual(harness.input_model, "small_valid_script_texts")

    @mock.patch("selector.fuzz_guided.guidance.local_fuzz_assets")
    def test_patch_mapping_can_synthesize_single_fuzzer_fallback(self, mock_assets: mock.Mock) -> None:
        mock_assets.return_value = {"demo_read_fuzzer": {"dict": False, "options": False, "seed_corpus": False}}
        self._write_cache(
            {
                "project": "demo",
                "introspector": {
                    "available": True,
                    "functions": [],
                    "fuzzers": [{"name": "demo_read_fuzzer", "blockers": []}],
                    "all_files": ["/src/demo/src/parser_utils.c", "/src/demo/src/parser.c"],
                },
                "coverage": {
                    "available": True,
                    "fuzzer_stats": {
                        "demo_read_fuzzer": {
                            "files": [
                                {"filename": "/src/demo/src/parser.c", "summary": {"lines": {"percent": 70.0}}}
                            ]
                        }
                    },
                },
            }
        )
        mapping = map_patch_to_harness(
            project="demo",
            patch_diff="--- a/src/parser_utils.c\n+++ b/src/parser_utils.c\n@@ -10,1 +10,1 @@\n-if (x) return;\n+if (!x) return;\n",
            cache_dir=self.cache_dir,
        )
        self.assertTrue(mapping["synthetic_recommendations"])
        self.assertEqual(mapping["recommendations"][0]["fuzzer"], "demo_read_fuzzer")
        joined = " ".join(mapping["recommendations"][0]["reasons"])
        self.assertIn("synthetic fallback", joined)
        self.assertIn("same directory", joined)

    @mock.patch("selector.fuzz_guided.surface.load_local_fuzzer_options")
    @mock.patch("selector.fuzz_guided.surface.local_fuzz_assets")
    def test_surface_model_loads_options_and_blocker_summary(self, mock_assets: mock.Mock, mock_options: mock.Mock) -> None:
        mock_assets.return_value = {"shape-fuzzer": {"dict": False, "options": True, "seed_corpus": False}}
        mock_options.return_value = {"shape-fuzzer": {"libfuzzer.timeout": "5", "libfuzzer.max_len": "512"}}
        self._write_cache(
            _cache_payload(
                functions=[
                    {
                        "name": "parse_input",
                        "source_file": "/src/demo/src/parser.c",
                        "source_line_begin": 1,
                        "source_line_end": 4,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                        "combined_reached_by_fuzzers": ["shape-fuzzer"],
                    },
                ],
                coverage={},
                fuzzers=[{
                    "name": "shape-fuzzer",
                    "blockers": [
                        {
                            "function_name": "parse_input",
                            "source_file": "/src/demo/src/parser.c",
                            "blocked_reachable_complexity": 111,
                            "blocked_unique_not_covered_complexity": 88,
                            "sides_hitcount_diff": 10,
                        }
                    ],
                }],
            )
        )
        surface = load_project_fuzz_surface("demo", self.cache_dir)
        harness = surface.harnesses["shape-fuzzer"]
        self.assertEqual(harness.timeout_seconds, 5)
        self.assertEqual(harness.max_len, 512)
        self.assertEqual(harness.blocker_count, 1)
        self.assertEqual(harness.blocker_hotspots[0]["function_name"], "parse_input")

    def test_format_family_and_subsystem_inference_are_deterministic(self) -> None:
        self.assertEqual(
            infer_format_family(harness_name="hb-shape-fuzzer", reached_files=["/src/demo/src/hb-ot-shape.cc"]),
            "font_binary",
        )
        self.assertEqual(
            infer_subsystem(harness_name="fuzz_compile", reached_files=["/src/demo/src/parser.c"]),
            "parser_compile",
        )

    @mock.patch("selector.fuzz_guided.surface.local_fuzz_assets")
    def test_planner_is_harness_first_and_emits_natural_language_hints(self, mock_assets: mock.Mock) -> None:
        mock_assets.return_value = {"shape-fuzzer": {"dict": True, "options": True, "seed_corpus": True}}
        self._write_cache(
            _cache_payload(
                functions=[
                    {
                        "name": "parse_input",
                        "source_file": "/src/demo/src/parser.c",
                        "source_line_begin": 1,
                        "source_line_end": 4,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                        "combined_reached_by_fuzzers": ["shape-fuzzer"],
                        "call_depth": 1,
                        "functions_reached_count": 12,
                        "cyclomatic_complexity": 4,
                        "function_signature": "int parse_input(int idx, int len, char *buf)",
                        "callsites": {"memcpy": ["parser.c#parse_input:3"]},
                    }
                ],
                coverage={},
                fuzzers=[{"name": "shape-fuzzer", "blockers": []}],
            )
        )
        surface = load_project_fuzz_surface("demo", self.cache_dir)
        candidates = plan_fuzz_guided_candidates(project="demo", repo_root=self.repo_root, surface=surface)
        self.assertTrue(candidates)
        fuzz_native = candidates[0].extra["fuzz_native"]
        self.assertEqual(fuzz_native["preferred_fuzzer"], "shape-fuzzer")
        self.assertEqual(fuzz_native["target_function"], "parse_input")
        self.assertTrue(fuzz_native["mutation_goal"])
        self.assertTrue(fuzz_native["instruction_hints"])
        self.assertEqual(fuzz_native["input_model"], "small_valid_script_texts")
        self.assertIn("existing_harness_viability", fuzz_native)
        self.assertIn("hot_path_bucket", fuzz_native)
        self.assertIn("triggerability_score", fuzz_native)
        self.assertIn("slice_excerpt", fuzz_native)
        self.assertIn("helper_judgment", fuzz_native)
        self.assertIn("path_signal_score", fuzz_native)

    @mock.patch("selector.fuzz_guided.surface.local_fuzz_assets")
    def test_planner_prefers_parser_paths_over_exporters(self, mock_assets: mock.Mock) -> None:
        mock_assets.return_value = {"shape-fuzzer": {"dict": False, "options": False, "seed_corpus": False}}
        self._write_cache(
            _cache_payload(
                functions=[
                    {
                        "name": "parse_input",
                        "source_file": "/src/demo/src/parser.c",
                        "source_line_begin": 1,
                        "source_line_end": 4,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                        "combined_reached_by_fuzzers": ["shape-fuzzer"],
                        "call_depth": 1,
                        "functions_reached_count": 10,
                    },
                    {
                        "name": "export_asset",
                        "source_file": "/src/demo/src/exporter.c",
                        "source_line_begin": 1,
                        "source_line_end": 4,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                        "combined_reached_by_fuzzers": ["shape-fuzzer"],
                        "call_depth": 1,
                        "functions_reached_count": 4,
                    },
                ],
                coverage={},
                fuzzers=[{"name": "shape-fuzzer", "blockers": []}],
            )
        )
        surface = load_project_fuzz_surface("demo", self.cache_dir)
        candidates = plan_fuzz_guided_candidates(project="demo", repo_root=self.repo_root, surface=surface)
        self.assertEqual(candidates[0].symbol, "parse_input")
        self.assertTrue(all(candidate.symbol != "export_asset" for candidate in candidates))

    @mock.patch("selector.fuzz_guided.surface.local_fuzz_assets")
    def test_planner_diversifies_by_role(self, mock_assets: mock.Mock) -> None:
        mock_assets.return_value = {"shape-fuzzer": {"dict": False, "options": False, "seed_corpus": False}}
        self._write_cache(
            _cache_payload(
                functions=[
                    {
                        "name": "parse_input",
                        "source_file": "/src/demo/src/parser.c",
                        "source_line_begin": 1,
                        "source_line_end": 4,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                        "combined_reached_by_fuzzers": ["shape-fuzzer"],
                        "call_depth": 1,
                        "functions_reached_count": 12,
                    },
                    {
                        "name": "write_token",
                        "source_file": "/src/demo/src/writer.c",
                        "source_line_begin": 1,
                        "source_line_end": 5,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                        "combined_reached_by_fuzzers": ["shape-fuzzer"],
                        "call_depth": 2,
                        "functions_reached_count": 6,
                    },
                ],
                coverage={},
                fuzzers=[{"name": "shape-fuzzer", "blockers": []}],
            )
        )
        surface = load_project_fuzz_surface("demo", self.cache_dir)
        candidates = plan_fuzz_guided_candidates(project="demo", repo_root=self.repo_root, surface=surface)
        roles = {candidate.extra["fuzz_native"]["function_role"] for candidate in candidates[:2]}
        self.assertIn("buffer_writer", roles)
        self.assertGreaterEqual(len(roles), 2)

    @mock.patch("selector.fuzz_guided.surface.local_fuzz_assets")
    def test_planner_emits_compact_slice_and_hot_path_bucket(self, mock_assets: mock.Mock) -> None:
        mock_assets.return_value = {"shape-fuzzer": {"dict": False, "options": False, "seed_corpus": False}}
        (self.repo_root / "src" / "wide_parser.c").write_text(
            "\n".join(
                [
                    "int wide_parse(int idx, int len, char *buf) {",
                    "  int out = 0;",
                    "  int scratch = len;",
                    "  scratch += idx;",
                    "  if (idx < 0) return -1;",
                    "  if (idx >= len) return -1;",
                    "  out += scratch;",
                    "  out += 1;",
                    "  out += 2;",
                    "  return buf[idx];",
                    "}",
                    "int unrelated_1(void) { return 1; }",
                    "int unrelated_2(void) { return 2; }",
                    "int unrelated_3(void) { return 3; }",
                    "int unrelated_4(void) { return 4; }",
                ]
            ) + "\n",
            encoding="utf-8",
        )
        self._write_cache(
            _cache_payload(
                functions=[
                    {
                        "name": "wide_parse",
                        "source_file": "/src/demo/src/wide_parser.c",
                        "source_line_begin": 1,
                        "source_line_end": 15,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                        "combined_reached_by_fuzzers": ["shape-fuzzer"],
                        "call_depth": 1,
                        "functions_reached_count": 16,
                        "callsites": {"memcpy": ["wide_parser.c#wide_parse:10", "wide_parser.c#wide_parse:10"]},
                    },
                ],
                coverage={},
                fuzzers=[{"name": "shape-fuzzer", "blockers": []}],
            )
        )
        surface = load_project_fuzz_surface("demo", self.cache_dir)
        candidates = plan_fuzz_guided_candidates(project="demo", repo_root=self.repo_root, surface=surface)
        fuzz_native = candidates[0].extra["fuzz_native"]
        self.assertEqual(fuzz_native["hot_path_bucket"], "high_confidence_hot_path")
        self.assertLess(candidates[0].line_range[1] - candidates[0].line_range[0], 15)
        self.assertEqual(fuzz_native["guard_to_sink_distance"], 4)
        self.assertIn("return buf[idx];", fuzz_native["slice_excerpt"])
        self.assertEqual(fuzz_native["helper_judgment"], "reachable_endpoint_slice")

    @mock.patch("selector.fuzz_guided.surface.local_fuzz_assets")
    def test_generic_helper_needs_stronger_evidence_than_reachability(self, mock_assets: mock.Mock) -> None:
        mock_assets.return_value = {"shape-fuzzer": {"dict": False, "options": False, "seed_corpus": False}}
        (self.repo_root / "src" / "helper.c").write_text(
            "\n".join(
                [
                    "int dbuf_put(struct out *s, int len, char c) {",
                    "  if ((s->cap - s->size) < len) return -1;",
                    "  s->buf[s->size++] = c;",
                    "  return 0;",
                    "}",
                ]
            ) + "\n",
            encoding="utf-8",
        )
        self._write_cache(
            _cache_payload(
                functions=[
                    {
                        "name": "dbuf_put",
                        "source_file": "/src/demo/src/helper.c",
                        "source_line_begin": 1,
                        "source_line_end": 5,
                        "reached_by_fuzzers": ["shape-fuzzer"],
                        "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                        "combined_reached_by_fuzzers": ["shape-fuzzer"],
                        "call_depth": 1,
                        "functions_reached_count": 2,
                        "callsites": {"memcpy": ["helper.c#dbuf_put:3", "helper.c#dbuf_put:3"]},
                    }
                ],
                coverage={},
                fuzzers=[{"name": "shape-fuzzer", "blockers": []}],
            )
        )
        surface = load_project_fuzz_surface("demo", self.cache_dir)
        candidates = plan_fuzz_guided_candidates(project="demo", repo_root=self.repo_root, surface=surface)
        fuzz_native = candidates[0].extra["fuzz_native"]
        self.assertEqual(fuzz_native["helper_judgment"], "generic_helper_family")
        self.assertEqual(fuzz_native["hot_path_bucket"], "helper_reachable_slice")

    def test_rank_candidates_prefers_runtime_and_confidence(self) -> None:
        high = SelectionCandidate(
            candidate_id="fg_1",
            rank=2,
            cwe_group="Input validation",
            cwe_id="CWE-125",
            repo_path="/src/demo/src/a.c",
            symbol="parse_input",
            location_hint="hint",
            rationale="test",
            confidence=0.9,
            extra={"fuzz_native": {"reachability_kind": "runtime_function"}},
        )
        low = SelectionCandidate(
            candidate_id="fg_2",
            rank=1,
            cwe_group="Input validation",
            cwe_id="CWE-125",
            repo_path="/src/demo/src/b.c",
            symbol="helper",
            location_hint="hint",
            rationale="test",
            confidence=0.6,
            extra={"fuzz_native": {"reachability_kind": "static_function"}},
        )
        ranked = _rank_candidates([low, high])
        self.assertEqual(ranked[0].candidate_id, "fg_1")
        self.assertEqual(ranked[0].rank, 1)

    @mock.patch("selector.fuzz_guided.surface.local_fuzz_assets")
    def test_file_fallback_skips_headers_and_harness_sources(self, mock_assets: mock.Mock) -> None:
        mock_assets.return_value = {"shape-fuzzer": {"dict": False, "options": False, "seed_corpus": False}}
        (self.repo_root / "src" / "driver.h").write_text("#define X 1\n", encoding="utf-8")
        (self.repo_root / "src" / "core.c").write_text("int parse_core(int len) { if (len > 4) return -1; return len; }\n", encoding="utf-8")
        self._write_cache(
            _cache_payload(
                functions=[],
                coverage={
                    "shape-fuzzer": {
                        "files": [
                            {"filename": "/src/demo/src/driver.h", "summary": {"lines": {"percent": 60.0}}},
                            {"filename": "/src/demo/src/core.c", "summary": {"lines": {"percent": 65.0}}},
                            {"filename": "/src/demo/fuzzing/shape-fuzzer.c", "summary": {"lines": {"percent": 90.0}}},
                        ]
                    },
                },
                fuzzers=[{"name": "shape-fuzzer", "blockers": []}],
            )
        )
        surface = load_project_fuzz_surface("demo", self.cache_dir)
        candidates = plan_fuzz_guided_candidates(project="demo", repo_root=self.repo_root, surface=surface)
        paths = {candidate.repo_path for candidate in candidates}
        self.assertIn("/src/demo/src/core.c", paths)
        self.assertNotIn("/src/demo/src/driver.h", paths)
        self.assertNotIn("/src/demo/fuzzing/shape-fuzzer.c", paths)
        fallback = next(candidate for candidate in candidates if candidate.repo_path == "/src/demo/src/core.c")
        self.assertEqual(fallback.extra["fuzz_native"]["hot_path_bucket"], "weak_or_coarse_match")

    @mock.patch("selector.fuzz_guided.surface.local_fuzz_assets")
    def test_harness_name_does_not_force_parser_entry_role(self, mock_assets: mock.Mock) -> None:
        mock_assets.return_value = {"fuzz-compile": {"dict": False, "options": False, "seed_corpus": False}}
        (self.repo_root / "src" / "helper.c").write_text(
            "\n".join(
                [
                    "int dbuf_claim(int len) {",
                    "  if (len < 0) return -1;",
                    "  return len;",
                    "}",
                ]
            ) + "\n",
            encoding="utf-8",
        )
        self._write_cache(
            _cache_payload(
                functions=[
                    {
                        "name": "dbuf_claim",
                        "source_file": "/src/demo/src/helper.c",
                        "source_line_begin": 1,
                        "source_line_end": 4,
                        "reached_by_fuzzers": ["fuzz-compile"],
                        "runtime_reached_by_fuzzers": ["fuzz-compile"],
                        "combined_reached_by_fuzzers": ["fuzz-compile"],
                        "call_depth": 0,
                        "functions_reached_count": 0,
                    },
                ],
                coverage={},
                fuzzers=[{"name": "fuzz-compile", "blockers": []}],
            )
        )
        surface = load_project_fuzz_surface("demo", self.cache_dir)
        candidates = plan_fuzz_guided_candidates(project="demo", repo_root=self.repo_root, surface=surface)
        self.assertTrue(candidates)
        self.assertNotEqual(candidates[0].extra["fuzz_native"]["function_role"], "parser_entry")

    def test_fuzz_guided_strategy_emits_fuzz_native_candidates(self) -> None:
        strategy = FuzzGuidedStrategy()
        runtime = SimpleNamespace()
        request = SimpleNamespace(project="demo", run_id="run", max_candidates=1, filters={})
        candidate = SelectionCandidate(
            candidate_id="fg_0001",
            rank=1,
            cwe_group="Input validation",
            cwe_id="CWE-125",
            repo_path="/src/demo/src/parser.c",
            symbol="parse_input",
            location_hint="hint",
            rationale="test",
            confidence=0.8,
            extra={"fuzz_native": {"preferred_fuzzer": "shape-fuzzer", "reachability_kind": "runtime_function"}},
        )
        with mock.patch("selector.fuzz_guided.run._resolve_repo_path", return_value=self.repo_root):
            with mock.patch("selector.fuzz_guided.run.load_project_fuzz_surface", return_value=SimpleNamespace()):
                with mock.patch("selector.fuzz_guided.run.plan_fuzz_guided_candidates", return_value=[candidate]):
                    result = strategy.run(runtime, request)
        self.assertEqual(result.candidates[0].extra["fuzz_native"]["preferred_fuzzer"], "shape-fuzzer")
        self.assertEqual(result.candidates[0].rank, 1)

    def test_missing_cache_fails_fast(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_project_fuzz_surface("demo", self.cache_dir)

    def test_path_signal_summary_discovers_optional_calltree_sources(self) -> None:
        payload = _cache_payload(
            functions=[
                {
                    "name": "parse_input",
                    "source_file": "/src/demo/src/parser.c",
                    "source_line_begin": 1,
                    "source_line_end": 4,
                    "reached_by_fuzzers": ["shape-fuzzer"],
                    "runtime_reached_by_fuzzers": ["shape-fuzzer"],
                    "functions_reached_count": 8,
                    "call_depth": 1,
                    "callsites": {"decode": ["parser.c:3"]},
                }
            ],
            coverage={},
            fuzzers=[{"name": "shape-fuzzer", "blockers": [], "calltree_url": "https://example.invalid"}],
        )
        payload["introspector"]["full_calltree"] = {"nodes": ["parse_input"]}
        summary = summarize_project_path_signals(payload, top_n=4)
        self.assertIn("introspector.full_calltree", summary["calltree_sources"])
        self.assertTrue(summary["harnesses"][0]["top_functions"])


if __name__ == "__main__":
    unittest.main()
