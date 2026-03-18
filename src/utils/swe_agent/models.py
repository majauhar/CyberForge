"""Typed request/response models for minimal SWE-agent wrapper."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SweAgentRequest:
    model_id: str
    prompt: str
    workdir: str


@dataclass
class SweAgentResponse:
    returncode: int
    stdout: str
    stderr: str

