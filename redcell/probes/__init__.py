"""Importing this package registers every built-in probe.

Each module calls @register on its probe classes at import time, so simply
importing them here populates the registry that the engine reads.
"""

from .base import Probe, all_probes, register  # noqa: F401

# Side-effect imports: these populate the registry.
from . import prompt_injection      # noqa: F401,E402  LLM01
from . import sensitive_info        # noqa: F401,E402  LLM02
from . import output_and_misinfo    # noqa: F401,E402  LLM05 + LLM09
from . import excessive_agency      # noqa: F401,E402  LLM06
from . import system_prompt_leak    # noqa: F401,E402  LLM07

__all__ = ["Probe", "all_probes", "register"]
