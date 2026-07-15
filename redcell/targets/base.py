"""The Target abstraction.

A Target is anything RedCell can send a prompt to and get text back from:
an OpenAI-compatible endpoint, your own FastAPI wrapper, a local mock, or
(later) an MCP server / agent. Probes never talk to HTTP directly - they
only ever see this interface, which is what keeps the framework extensible.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import ToolCallResult, ToolSpec


class Target(ABC):
    #: Human-readable name shown in reports.
    name: str = "target"

    #: Secrets or instructions known to be present in the target's context
    #: that MUST NOT appear in any response. Leak/sensitive-info probes look
    #: for these. Empty list = pure black-box (probes fall back to heuristics).
    canaries: list[str]

    #: Whether free-text prompts can be sent to this target. True for chat
    #: models. A raw MCP server exposes tools but has no LLM to talk to, so it
    #: sets this False and the engine skips the chat-only probes for it.
    chat_capable: bool = True

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


class AgentTarget(Target):
    """A target that exposes callable tools - an MCP server or tool-using agent.

    This is the surface the agent-only probes (LLM06) need: rather than only
    sending prompts, they enumerate the tools a target advertises and actually
    invoke them, then judge whether a call that should have been gated went
    through. Keeping it a separate subclass keeps the plain ``Target``
    contract - and every existing chat probe - unchanged.
    """

    @abstractmethod
    def list_tools(self) -> list[ToolSpec]:
        """Return the tools this target advertises."""
        raise NotImplementedError

    @abstractmethod
    def call_tool(self, name: str, arguments: dict) -> ToolCallResult:
        """Invoke a tool and report whether it executed."""
        raise NotImplementedError
