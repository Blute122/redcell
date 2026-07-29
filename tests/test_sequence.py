"""Injection-driven tool-sequence detection.

The property that makes this distinct from every single-call probe: the sequence
is the finding. Each individual call is benign — the test proves neither call
alone flags, and only the two in order do.
"""

from __future__ import annotations

from mock_agent_sequence import (
    injected_exfiltration_trace,
    non_sensitive_sink_trace,
    read_only_trace,
)

from redcell.detectors.sequence import SequenceExfiltrationDetector
from redcell.detectors.tools import classify_tool
from redcell.models import ToolSpec

_DET = SequenceExfiltrationDetector()


def test_the_sequence_is_the_finding_not_either_call_alone():
    trace = injected_exfiltration_trace()
    read_call, sink_call = trace

    # Neither call ALONE is a finding...
    assert _DET.evaluate([read_call])[0] is False   # a record read on its own
    assert _DET.evaluate([sink_call])[0] is False    # a post on its own

    # ...but the two in order are.
    vulnerable, evidence = _DET.evaluate(trace)
    assert vulnerable
    assert "composition" in evidence.lower()


def test_neither_call_is_flagged_by_the_single_call_classifier():
    # Belt-and-braces: the existing destructive classifier (LLM06/insecure-auth)
    # also passes both calls, so nothing single-call catches this - only the
    # sequence detector does.
    for call in injected_exfiltration_trace():
        spec = ToolSpec(name=call.tool, description="")
        assert classify_tool(spec)[0] is False


def test_sensitive_read_without_external_sink_does_not_flag():
    # The value is used internally (update_record), never sent out.
    assert _DET.evaluate(read_only_trace())[0] is False


def test_external_sink_of_non_sensitive_data_does_not_flag():
    # Posting non-sensitive data (weather) to a sink is legitimate.
    assert _DET.evaluate(non_sensitive_sink_trace())[0] is False


def test_order_matters_sink_before_read_does_not_flag():
    # If the sink call precedes the read, there is no prior tainted value.
    trace = injected_exfiltration_trace()
    assert _DET.evaluate(list(reversed(trace)))[0] is False


def test_empty_and_single_step_traces_are_clean():
    assert _DET.evaluate([])[0] is False
    assert _DET.evaluate(injected_exfiltration_trace()[:1])[0] is False
