from __future__ import annotations

import unittest

from injector.base import InjectionRequest
from injector.fuzzer_llm_inject.run import FuzzerLLMInjectStrategy
from injector.registry import get_injection_strategy_for_selection
from utils.agent.prompts.injection import build_fuzz_execution_context_section, build_fuzz_guidance_section
from vuljector.fuzz_execution_context import build_forward_fuzzing_context
from vuljector.io_contracts import SelectionCandidate


class FuzzerLLMInjectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fuzz_native = {
            "preferred_fuzzer": "fuzz_compile",
            "alternate_fuzzers": ["fuzz_eval"],
            "reachability_kind": "runtime_function",
            "target_function": "unicode_from_utf8",
            "target_file": "src/quickjs/cutils.c",
            "target_line_range": [10, 30],
            "format_family": "script_text",
            "subsystem": "parser",
            "input_model": "small_valid_script_texts",
            "bug_shape": "removed_length_restriction",
            "validation_likelihood": "high",
            "function_role": "decoder_conversion",
            "hot_path_bucket": "high_confidence_hot_path",
            "helper_judgment": "endpoint_or_stateful_slice",
            "path_signal_score": 0.64,
            "parser_proximity_score": 0.78,
            "triggerability_score": 0.84,
            "guard_to_sink_distance": 3,
            "slice_excerpt": "12: if (len <= 0) return -1;\n13: return decode[idx];",
            "mutation_goal": "Preserve fuzz_compile reachability and weaken a local length guard.",
            "existing_harness_viability": "high",
            "blocker_hotspots": ["parse_expr", "unicode_scan"],
        }
        self.candidate = SelectionCandidate(
            candidate_id="fg_001",
            rank=1,
            cwe_group="memory-safety",
            cwe_id="CWE-125",
            repo_path="src/quickjs/cutils.c",
            symbol="unicode_from_utf8",
            location_hint="length guard before unicode decode",
            rationale="runtime reachable via fuzz_compile",
            confidence=0.85,
            language="c",
            line_range=(10, 30),
            extra={"fuzz_native": self.fuzz_native},
        )
        self.request = InjectionRequest(
            project="quickjs",
            run_id="run-test",
            strategy_id="fuzzer_llm_inject",
            model_id="smoke-model",
            num_vulnerabilities=1,
            debug=False,
        )

    def test_registry_routes_fuzz_guided_to_fuzzer_llm_inject(self) -> None:
        strategy = get_injection_strategy_for_selection("fuzz_guided")
        self.assertEqual(strategy.id, "fuzzer_llm_inject")

    def test_forward_fuzzing_context_uses_generator_hints(self) -> None:
        context = build_forward_fuzzing_context(
            self.fuzz_native,
            cwe_id=self.candidate.cwe_id,
            repo_path=self.candidate.repo_path,
        )
        self.assertEqual(context["format_family"], "script_text")
        self.assertIn("script_text_variants", context["input_generators"])
        self.assertIn(".js", context["preferred_extensions"])
        self.assertTrue(any("starter input" in hint or "input model" in hint.lower() for hint in context["exploit_hints"]))

    def test_prompt_sections_include_downstream_fuzz_context(self) -> None:
        strategy = FuzzerLLMInjectStrategy()
        sections = strategy.build_prompt_sections(self.request, self.candidate, self.fuzz_native)
        self.assertIn("Preferred harness", sections["fuzz_guidance_section"])
        self.assertIn("script_text_variants", sections["execution_context_section"])
        self.assertIn("Downstream Fuzzing Context", sections["execution_context_section"])
        self.assertIn("Preferred seed extensions", sections["execution_context_section"])

    def test_prompt_builders_render_execution_context(self) -> None:
        context = build_forward_fuzzing_context(
            self.fuzz_native,
            cwe_id=self.candidate.cwe_id,
            repo_path=self.candidate.repo_path,
        )
        section = build_fuzz_guidance_section(self.fuzz_native, execution_context=context)
        execution = build_fuzz_execution_context_section(context)
        self.assertIn("small_valid_script_texts", section)
        self.assertIn("Hot-path bucket", section)
        self.assertIn("Helper judgment", section)
        self.assertIn("Compact slice excerpt", section)
        self.assertIn("Likely input-generator families", execution)
        self.assertIn("fuzz_compile", section)


if __name__ == "__main__":
    unittest.main()
