from .base import AgentTarget, Target
from .mcp import MCPTarget
from .mock import MockVulnerableTarget
from .openai_compat import OpenAICompatTarget

__all__ = [
    "Target",
    "AgentTarget",
    "MockVulnerableTarget",
    "OpenAICompatTarget",
    "MCPTarget",
]
