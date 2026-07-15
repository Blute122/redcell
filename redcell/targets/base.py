"""The Target abstraction.

A Target is anything RedCell can send a prompt to and get text back from:
an OpenAI-compatible endpoint, your own FastAPI wrapper, a local mock, or
(later) an MCP server / agent. Probes never talk to HTTP directly - they
only ever see this interface, which is what keeps the framework extensible.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class Target(ABC):
    #: Human-readable name shown in reports.
    name: str = "target"

    #: Secrets or instructions known to be present in the target's context
    #: that MUST NOT appear in any response. Leak/sensitive-info probes look
    #: for these. Empty list = pure black-box (probes fall back to heuristics).
    canaries: list[str]

    def __init__(self) -> None:
        if not hasattr(self, "canaries"):
            self.canaries = []

    @abstractmethod
    def send(self, prompt: str) -> str:
        """Send a single user turn, return the assistant's text response.

        Implementations should raise on transport errors; the engine catches
        them and records an ERROR verdict rather than crashing the whole scan.
        """
        raise NotImplementedError
