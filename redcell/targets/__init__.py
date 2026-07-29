"""Targets: the systems RedCell can point probes at."""

from .base import AgentTarget, Target
from .mcp import MCPTarget
from .mcp_http import MCPHttpTarget
from .mock import HardenedMockTarget, MockVulnerableTarget
from .openai_compat import OpenAICompatTarget

__all__ = [
    "Target",
    "AgentTarget",
    "MockVulnerableTarget",
    "HardenedMockTarget",
    "OpenAICompatTarget",
    "MCPTarget",
    "MCPHttpTarget",
]
