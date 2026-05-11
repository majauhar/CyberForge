"""Fuzz-native injector tuned for fuzz_guided candidates."""

from __future__ import annotations

from injector.base import InjectionRequest
from injector.llm_inject.run import LLMInjectStrategy, _get_language_context
from utils.agent.prompts import (
    FUZZER_VULN_INJECT_TASK,
    build_fuzz_execution_context_section,
    build_fuzz_guidance_section,
)
from vuljector.fuzz_execution_context import build_forward_fuzzing_context
from vuljector.io_contracts import SelectionCandidate


class FuzzerLLMInjectStrategy(LLMInjectStrategy):
    @property
    def id(self) -> str:
        return "fuzzer_llm_inject"

    def build_prompt_sections(
        self,
        request: InjectionRequest,
        candidate: SelectionCandidate,
        fuzz_guidance: dict,
    ) -> dict[str, str]:
        execution_context = build_forward_fuzzing_context(
            fuzz_guidance,
            cwe_id=candidate.cwe_id or "",
            repo_path=candidate.repo_path or "",
        )
        return {
            "fuzz_guidance_section": build_fuzz_guidance_section(fuzz_guidance),
            "execution_context_section": build_fuzz_execution_context_section(execution_context),
        }

    def build_prompt_template(self) -> str:
        return FUZZER_VULN_INJECT_TASK

    def build_language_context(self, candidate: SelectionCandidate, *, project: str, cwes_str: str, injection_hint: str) -> dict:
        return _get_language_context(
            candidate.language or "python",
            project=project,
            cwes=cwes_str,
            injection_hint=injection_hint,
        )
