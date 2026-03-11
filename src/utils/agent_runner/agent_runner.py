from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SessionStart:
    session_id: str
    output: Optional[str] = None


class AgentRunner(ABC):
    """Minimal sync interface for session-based agent backends."""

    @abstractmethod
    def create_session(
        self,
        *,
        first_message: str,
        model: str,
        directory: Optional[str] = None,
        capture_output: bool = False,
    ) -> SessionStart:
        """Create a session, send the first message, and return the session id."""

    @abstractmethod
    def continue_session(
        self,
        *,
        session_id: str,
        message: str,
        model: str,
        directory: Optional[str] = None,
        capture_output: bool = False,
    ) -> Optional[str]:
        """Continue an existing session and optionally return captured output."""
