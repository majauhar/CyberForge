"""Typed request/response models for mini-swe-agent wrapper."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentRequest:
    model_id: str
    prompt: str
    workdir: str
    system_template: str = "You are a software engineer. Be concise."
    instance_template: str = "{{task}}"
    step_limit: int = 30
    cost_limit: float = 1.0
    setup_commands: list[str] = field(default_factory=list)
    extract_paths: list[str] = field(default_factory=list)
    post_commands: list[str] = field(default_factory=list)
    trajectory_path: str = ""


@dataclass
class AgentResponse:
    returncode: int
    stdout: str                          # agent's final submission text
    stderr: str
    messages: list[dict] = field(default_factory=list)             # raw for AgentTelemetry
    extracted_files: dict[str, str] = field(default_factory=dict)  # {container_path: content}
    extracted_dirs: dict[str, str] = field(default_factory=dict)   # {container_path: base64(tar.gz)}
    post_results: list[dict] = field(default_factory=list)         # [{command, returncode, output}]
    exit_status: str = ""
    total_steps: int = 0
