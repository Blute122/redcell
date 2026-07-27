# tests/fixtures

## `sarif-2.1.0.schema.json`

The **official** SARIF v2.1.0 JSON Schema, vendored so schema-validation tests
are hermetic — a test that fetches a schema over the network fails in CI
whenever the network hiccups or the URL moves.

- **Source:** <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json>
- **Version:** SARIF 2.1.0 (OASIS Standard, errata01) — frozen; do not update to a
  different SARIF version (2.1.0 is what GitHub's `upload-sarif` consumes).
- **Retrieved:** 2026-07-22

Schema validation proves the SARIF is *well-formed*, not *correct* — the schema
permits orphan ruleIds and other semantic mistakes. The structural invariants in
`tests/test_sarif.py` (no orphan ruleIds, only-VULNERABLE results, rules mirror
the probes exercised) are what pin correctness.
