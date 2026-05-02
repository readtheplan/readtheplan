# Codex task — ADR 0007 evidence envelope module + CLI

**Authoring agent:** Cowork (Claude)
**Implementation agent:** Codex
**Reviewer:** Cowork (Claude), via the `engineering:code-review` skill
**Branch:** `codex/readtheplan-evidence-envelope`
**Commit trailer:** `AI-Assisted: Codex`
**Reference ADR:** [`docs/adr/0007-evidence-envelope.md`](../adr/0007-evidence-envelope.md)

---

## Goal

Land the evidence envelope as a versioned JSON artifact: one stable
document per analyze run that wraps plan hash + framework view + agent
attestation + reviewer + summary + change list. New module
`evidence.py`, new `--evidence` CLI flag, no signing yet.

ADR 0007 is the source of truth. If anything in this brief contradicts
the ADR, the ADR wins; stop and write up the issue.

---

## Inputs already on main (read-only for this task)

- `docs/adr/0007-evidence-envelope.md` — the ADR. Includes the full
  `rtp-evidence-v1` schema specification.
- `src/readtheplan/attestation.py` — existing module that defines
  `PlanReadAttestation`, `plan_sha256`, `build_plan_read_attestation`.
  **Read-only**. The envelope embeds the attestation but does not
  modify how it's built.
- `src/readtheplan/controls.py` — provides `ControlCatalog` and the
  `controls_for` lookup. **Read-only**.
- `src/readtheplan/plan.py` — provides `PlanSummary` and
  `analyze_plan_file`. **Read-only**.
- `src/readtheplan/cli.py` — modify only the new flag plumbing; do not
  refactor the existing `_analyze` function beyond the minimal additions.

---

## Files you will write

```
src/readtheplan/evidence.py                  (new)
src/readtheplan/cli.py                       (modify — add --evidence + --reviewer-id + --agent-id + --run-id flags)
tests/test_evidence.py                       (new)
tests/fixtures/evidence_plan.json            (new — small fixture; can mirror soc2_plan.json shape)
README.md                                    (modify — short subsection)
```

No other files. Do **not** modify `controls.py`, `plan.py`, `rules.py`,
or `attestation.py`. The envelope embeds existing data; it does not
restructure it.

---

## Module: `src/readtheplan/evidence.py`

### Public surface

```python
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from readtheplan.attestation import PlanReadAttestation
from readtheplan.controls import ControlCatalog
from readtheplan.plan import PlanSummary

EVIDENCE_SCHEMA = "rtp-evidence-v1"

@dataclass(frozen=True)
class Reviewer:
    id: str
    kind: str = "human"  # "human" | "agent"

@dataclass(frozen=True)
class EvidenceEnvelope:
    schema: str
    generated_at: str          # ISO 8601 UTC with 'Z'
    plan_sha256: str
    plan_source: str
    framework: Mapping[str, Any]
    agent_attestation: Mapping[str, Any]
    reviewer: Mapping[str, Any] | None
    summary: Mapping[str, Any]
    changes: Sequence[Mapping[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the rtp-evidence-v1 JSON shape."""

def build_evidence(
    *,
    plan_summary: PlanSummary,
    plan_json: str | bytes,
    catalog: ControlCatalog,
    agent_id: str,
    reviewer: Reviewer | None = None,
    run_id: str | None = None,
    generated_at: datetime | None = None,
) -> EvidenceEnvelope:
    """Produce an evidence envelope.

    Re-uses readtheplan.attestation.build_plan_read_attestation for the
    embedded attestation. controls_for() is called per change to populate
    the controls list. controls_touched is the sorted union across all
    changes.

    generated_at defaults to datetime.now(timezone.utc) when None — pass
    a fixed value in tests for determinism.
    """

class EvidenceError(ValueError):
    """Raised on schema-violating inputs (e.g., empty agent_id)."""
```

### Behavior notes

- `EVIDENCE_SCHEMA` is the literal `"rtp-evidence-v1"`. Do not template
  the version into a variable that callers can change; the schema string
  is a contract.
- `to_dict()` produces a plain `dict` suitable for `json.dumps` with
  no further transformation. Field order should match the schema in
  ADR 0007 §"Schema (rtp-evidence-v1)" for human-readability.
- `agent_attestation` is the dict produced by serializing the existing
  `PlanReadAttestation` object — re-use whatever serialization helper
  `attestation.py` exposes, or call `dataclasses.asdict` and prune the
  fields that should not appear (none for v1, but document any
  transformations).
- `summary.controls_touched` is the sorted, deduplicated union of every
  control ID across all changes. Empty list when no changes have
  controls.
- `reviewer` is `null` in JSON when no `Reviewer` is passed. When
  passed, `id` is required and non-empty; `kind` defaults to `"human"`
  but can be `"agent"`. Validate non-empty `id`; raise `EvidenceError`
  otherwise.
- `run_id` is optional and flows through to
  `agent_attestation.run_id`. Pass through unchanged (no validation).
- Use `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")` for
  ISO 8601 UTC formatting (or `.isoformat()` with explicit `Z`
  substitution). Match whichever format `attestation.py`'s
  `read_at` already uses, for consistency.

---

## CLI changes — `src/readtheplan/cli.py`

Add four flags to the `analyze` subparser:

```
--evidence <path>      Write rtp-evidence-v1 JSON envelope to <path>.
                       Use - for stdout. Requires --framework.

--agent-id <id>        Override default agent ID in the envelope's
                       attestation. Default: "readtheplan@<version>"
                       where <version> is the installed package version.

--reviewer-id <id>     Optional reviewer identifier. When set, the
                       envelope's reviewer field is populated.

--reviewer-kind {human,agent}
                       Optional. Defaults to "human". Only meaningful
                       with --reviewer-id.

--run-id <id>          Optional CI run identifier flowed into
                       agent_attestation.run_id.
```

Behavior:

- `--evidence` without `--framework` exits non-zero with a clear
  message: `"Error: --evidence requires --framework"`. No traceback.
- `--reviewer-kind` without `--reviewer-id` is silently ignored (the
  reviewer field stays `null`).
- `--evidence -` writes the envelope JSON to stdout. The existing
  `--format` text/json output is then suppressed when `--evidence -`
  is set, since stdout is exclusive to one consumer at a time. (Output
  *to a path* leaves stdout for the human-readable summary as usual.)
- The default `--agent-id` value is sourced from the package version.
  Use `importlib.metadata.version("readtheplan")` to read it; fall back
  to `"readtheplan@unknown"` if unavailable.

The existing `_analyze` function should keep its existing behavior when
`--evidence` is absent. When present, after the existing summary
generation, build the envelope and write it.

---

## Test fixture — `tests/fixtures/evidence_plan.json`

A small Terraform plan JSON exercising 4 cases (smaller than
`soc2_plan.json` — 4 is enough to verify the envelope shape):

| address                            | type                        | actions                | expected control IDs (SOC 2)                  |
|------------------------------------|-----------------------------|------------------------|-----------------------------------------------|
| `aws_kms_key.customer_data`        | `aws_kms_key`               | `["delete", "create"]` | CC6.1, CC6.7, CC8.1, A1.2, C1.1               |
| `aws_iam_role.deploy`              | `aws_iam_role`              | `["update"]`           | CC6.1, CC8.1                                  |
| `aws_security_group.web`           | `aws_security_group`        | `["create"]`           | CC6.6, CC8.1                                  |
| `aws_lambda_function.handler`      | `aws_lambda_function`       | `["update"]`           | (empty — not in catalog)                      |

`controls_touched` for this fixture against the SOC 2 catalog is
`["A1.2", "C1.1", "CC6.1", "CC6.6", "CC6.7", "CC8.1"]` — sorted, deduped.

---

## Tests — `tests/test_evidence.py`

Required test cases. Names and intent are fixed; style is yours.

```python
# 1. Smoke: build_evidence returns an EvidenceEnvelope with required fields.
def test_build_evidence_smoke():
    # Pass a fixed generated_at; assert envelope.schema == "rtp-evidence-v1",
    # generated_at matches the input formatted, plan_sha256 matches the input
    # plan's sha, framework dict has the three keys.

# 2. Plan SHA matches readtheplan.attestation.plan_sha256(plan_json).
def test_build_evidence_plan_sha_matches_attestation_helper():

# 3. controls_touched is the sorted, deduplicated union across all changes.
def test_build_evidence_controls_touched_union_sorted():

# 4. Empty changes list yields empty controls_touched, valid schema.
def test_build_evidence_empty_plan():
    # Pass a plan with resource_changes: [] — envelope is still valid,
    # summary.resource_change_count == 0, controls_touched == [].

# 5. Reviewer is null when not passed.
def test_build_evidence_reviewer_null_by_default():

# 6. Reviewer is populated when passed; default kind is "human".
def test_build_evidence_reviewer_human_default():

# 7. Reviewer kind="agent" round-trips.
def test_build_evidence_reviewer_agent_kind():

# 8. Empty reviewer id raises EvidenceError.
def test_build_evidence_reviewer_empty_id_raises():

# 9. CLI: --evidence without --framework exits non-zero with helpful message.
def test_cli_evidence_requires_framework(capsys):
    # No traceback in stderr.

# 10. CLI: --evidence <path> writes the envelope JSON to that path.
def test_cli_evidence_writes_to_path(tmp_path, capsys):
    # Run analyze with --framework soc2 --evidence <tmp_path>/evidence.json.
    # Read the file; assert schema == "rtp-evidence-v1" and the kms_key change
    # has the expected controls.

# 11. CLI: --evidence - writes the envelope JSON to stdout and suppresses
#     the markdown/json summary normally written by --format.
def test_cli_evidence_stdout(capsys):

# 12. Determinism: same plan + same generated_at + same agent_id produces
#     byte-identical envelope JSON. (Uses build_evidence directly, not CLI.)
def test_build_evidence_deterministic():
```

The full pytest suite (existing 46 + 12 new = 58) must pass on Python
3.10 and 3.13. CI already covers both.

---

## README changes

Add a new subsection after "Compliance control IDs (preview)":

```markdown
### Evidence envelope (preview)

`readtheplan analyze --framework soc2 --evidence evidence.json plan.json`
writes a `rtp-evidence-v1` JSON document containing the plan hash, the
framework view, controls touched, the change list, and the agent's
read-attestation. Auditors and GRC platforms consume this envelope as
the single artifact per change.

```bash
readtheplan analyze \
    --framework soc2 \
    --evidence evidence.json \
    --reviewer-id alice@example.com \
    --run-id "github-actions/${GITHUB_RUN_ID}" \
    plan.json
```

Schema is documented in `docs/adr/0007-evidence-envelope.md`. Signed
envelopes (sigstore-backed) are planned in a subsequent ADR.
```

Keep the (preview) heading. No marketing copy.

---

## Out of scope (do not add)

- Cryptographic signing of the envelope (ADR 0008, separate PR).
- Sigstore transparency log integration.
- DSSE / in-toto bundle formats.
- A `verify` subcommand (ADR 0008).
- GRC webhook posting (Vanta, Drata, etc.).
- Multi-framework evidence in one envelope.
- PR-comment rendering of the envelope.
- Renaming or modifying any existing dataclass in `attestation.py`,
  `controls.py`, `rules.py`, or `plan.py`.
- Adding new dependencies. The envelope is plain JSON; everything
  needed is in the standard library plus the existing PyYAML dep.

If a follow-on idea looks unavoidable to land this slice, write it as a
TODO in the PR description and continue without it.

---

## Acceptance / definition of done

- [ ] All 12 listed tests pass on Python 3.10 and 3.13.
- [ ] Existing 46 pytest tests still pass with no modifications.
- [ ] `mypy --strict src/readtheplan/evidence.py src/readtheplan/cli.py`
      passes.
- [ ] `ruff check` / `black --check` clean per existing project style.
- [ ] `readtheplan analyze --help` shows all new flags
      (`--evidence`, `--agent-id`, `--reviewer-id`, `--reviewer-kind`,
      `--run-id`).
- [ ] No new runtime dependency added in `pyproject.toml`.
- [ ] PR description maps each substantive decision back to ADR 0007
      and lists anything skipped vs. the brief.
- [ ] Commit message includes `AI-Assisted: Codex` trailer.
- [ ] PR is opened against `main` from
      `codex/readtheplan-evidence-envelope`.

---

## Review handoff

When the PR is open and CI is green, comment `@cowork ready for review`.
Cowork will review using the `engineering:code-review` skill, with these
specific checks:

1. **Layering**: `controls.py`, `plan.py`, `rules.py`, `attestation.py`
   all untouched. (ADR 0007 §"Decision" — purely additive.)
2. **Schema fidelity**: `EVIDENCE_SCHEMA == "rtp-evidence-v1"` literal,
   field order matches ADR 0007's example, `controls_touched` is sorted
   and deduplicated.
3. **Attestation re-use**: the embedded `agent_attestation` dict is
   produced by re-using `PlanReadAttestation` and the existing
   `plan_sha256` helper, not a parallel implementation.
4. **Determinism**: same inputs → byte-identical envelope JSON.
   `generated_at` is injectable for testing.
5. **CLI exclusivity**: `--evidence -` (stdout) suppresses the existing
   `--format` summary; `--evidence <path>` does not.

Cowork will request changes inline; expected total review turnaround is
under one full pass.
