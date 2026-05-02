# Codex task — ADR 0005 SOC 2 wedge implementation

**Authoring agent:** Cowork (Claude)
**Implementation agent:** Codex
**Reviewer:** Cowork (Claude), via `engineering:code-review` skill on the PR
**Reference ADR:** [`docs/adr/0005-compliance-control-mapping.md`](../adr/0005-compliance-control-mapping.md)
**Seed data:** [`src/readtheplan/data/controls/soc2.yaml`](../../src/readtheplan/data/controls/soc2.yaml)
**Notion task:** to be filed by Cowork in the readtheplan project DB after this brief is reviewed.
**Branch:** `codex/readtheplan-soc2-controls`
**Commit trailer:** `AI-Assisted: Codex` (existing convention)

---

## Goal

Land the smallest end-to-end slice of ADR 0005 — a `--framework soc2` flag on
`readtheplan analyze` that reads the seed catalog and emits SOC 2 control IDs
alongside every change in both markdown and JSON output. No risk-tier or
explanation behavior changes. No signing, no evidence envelope, no second
framework. One PR.

After this lands, follow-on PRs will (a) add the same flag wiring to the
GitHub Action, (b) extend the catalog to ISO 27001, and (c) wrap the output in
a signed evidence envelope using the existing `attestation.py` work.

---

## Inputs already in the tree

These two files exist on `main` (or whichever branch you cut from) and are
**read-only for this task** unless explicitly listed under "Files you will
write" below:

1. `docs/adr/0005-compliance-control-mapping.md` — the ADR. Anything in this
   brief that contradicts the ADR is a brief mistake; flag it and stop.
2. `src/readtheplan/data/controls/soc2.yaml` — the seed catalog covering KMS,
   RDS, S3, IAM, security groups, Route 53, EKS, and CloudTrail. Treat it as
   versioned API surface; do not edit unless a real bug is found, and if you
   do, call it out in the PR description.

---

## Files you will write

```
src/readtheplan/controls.py                       (new)
tests/fixtures/soc2_plan.json                     (new — see "Test fixture" below)
tests/test_controls.py                            (new)
src/readtheplan/cli.py                            (modify — add --framework flag)
pyproject.toml                                    (modify — package_data for YAML)
docs/adr/0005-compliance-control-mapping.md       (status update only — see end)
README.md                                         (modify — small section)
```

No other files. If you find yourself touching `rules.py` or `plan.py`, stop —
the ADR layering says control mapping must not modify them. If you believe
they need changes, push back in the PR description and we'll re-cut the ADR.

---

## Module: `src/readtheplan/controls.py`

Responsibilities:

1. Load a framework YAML by name from `src/readtheplan/data/controls/<name>.yaml`.
2. Validate it against the schema in ADR 0005 §"Control catalog format".
3. Resolve `(resource_type, action_set)` to a deduplicated list of control
   entries.

Public surface (the only names callers should import):

```python
@dataclass(frozen=True)
class ControlEntry:
    id: str
    title: str
    rationale: str

@dataclass(frozen=True)
class ControlCatalog:
    framework: str
    framework_version: str
    schema_version: int
    # internal: mappings dict not part of the public surface
    def controls_for(
        self, *, resource_type: str, actions: Sequence[str]
    ) -> tuple[ControlEntry, ...]:
        ...

def load_catalog(framework: str) -> ControlCatalog:
    """Load by short name, e.g. 'soc2'. Raises FrameworkNotFoundError."""

def available_frameworks() -> tuple[str, ...]:
    """Sorted list of YAML basenames in the data dir."""

class FrameworkNotFoundError(ValueError): ...
class CatalogSchemaError(ValueError): ...
```

Match semantics, restated for clarity:

- A catalog mapping with `actions: [delete, "delete/create"]` matches a change
  whose action string is exactly `"delete"` or exactly `"delete/create"`.
- A change can match multiple mapping entries with the same `resource_type`;
  the resulting tuple is the union, deduplicated by `ControlEntry.id`,
  preserving first-seen order.
- A change matching no entries returns an empty tuple. Don't raise.

Notes:

- Use `PyYAML` for parsing. Add it to `[project.dependencies]` in
  `pyproject.toml`. (We've avoided a dep so far; the catalog format makes it
  worth the trade. If you'd rather hand-roll a tiny YAML subset parser, push
  back in the PR.)
- Locate the data dir via `importlib.resources.files("readtheplan.data.controls")`,
  not `__file__` arithmetic.
- `CatalogSchemaError` must include the offending path/key in its message.

---

## CLI changes — `src/readtheplan/cli.py`

Add a single new flag:

```
--framework {name}    Annotate each change with control IDs from the named
                      framework catalog. Currently available: soc2.
                      Default: omitted (no annotation, output unchanged).
```

Behavior:

- When omitted: existing markdown and JSON output is unchanged. The existing
  17 pytest tests must still pass without modification.
- When set to a known framework: each change in the output gains its
  resolved controls.
  - **Markdown**: append a column header `Controls` after `Explanation`. Cells
    render `id1, id2, id3` joined by `", "`. Empty cell stays empty
    (no placeholder dash).
  - **JSON**: each `changes[i]` gains `"controls": [{id, title, rationale}, ...]`.
    Top-level `summary` gains `"framework": {"name", "version", "schema_version"}`.
    When the flag is omitted, neither field appears.
- When set to an unknown framework: exit non-zero with a message like:
  `unknown framework "soc3"; available: soc2`. Do not raise a Python traceback
  to the user.

Don't introduce new flag groups or rename existing flags.

---

## Test fixture — `tests/fixtures/soc2_plan.json`

A small, hand-written Terraform plan JSON exercising 6 distinct cases against
the seed catalog. Each case has its own resource address so tests can index
into the change list deterministically.

Required cases:

| address                                  | type                                | actions             | expected control IDs (set)              |
|------------------------------------------|-------------------------------------|---------------------|------------------------------------------|
| `aws_kms_key.customer_data`              | `aws_kms_key`                       | `["delete", "create"]` | CC6.1, CC6.7, CC8.1, A1.2, C1.1         |
| `aws_kms_key.new_key`                    | `aws_kms_key`                       | `["create"]`           | CC6.1, CC8.1                             |
| `aws_s3_bucket_policy.assets`            | `aws_s3_bucket_policy`              | `["update"]`           | CC6.1, CC6.6, CC8.1                      |
| `aws_security_group_rule.web_ingress`    | `aws_security_group_rule`           | `["create"]`           | CC6.6, CC8.1                             |
| `aws_cloudtrail.org`                     | `aws_cloudtrail`                    | `["delete"]`           | CC7.1, CC7.2, CC8.1                      |
| `aws_lambda_function.handler`            | `aws_lambda_function`               | `["update"]`           | (empty — not in seed catalog)            |

Match the existing fixture style in `tests/fixtures/valid_plan.json` for the
JSON schema details (resource_changes shape, format_version, etc.).

---

## Tests — `tests/test_controls.py`

Required test cases. Names and intent are fixed; you have latitude on style.

```python
# 1. Catalog loads cleanly.
def test_load_soc2_catalog_smoke():
    cat = controls.load_catalog("soc2")
    assert cat.framework == "soc2"
    assert cat.framework_version == "2017-tsc"
    assert cat.schema_version == 1

# 2. Unknown framework raises a typed error and lists available ones.
def test_unknown_framework_raises():
    with pytest.raises(controls.FrameworkNotFoundError) as exc:
        controls.load_catalog("soc3")
    assert "soc2" in str(exc.value)

# 3. available_frameworks() returns at least 'soc2'.
def test_available_frameworks_includes_soc2():
    assert "soc2" in controls.available_frameworks()

# 4. Match semantics — single mapping hit.
def test_controls_for_kms_create_returns_cc61_and_cc81():
    cat = controls.load_catalog("soc2")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["create"])
    ids = [c.id for c in out]
    assert ids == ["CC6.1", "CC8.1"]

# 5. Match semantics — irreversible KMS replacement hits the full set.
def test_controls_for_kms_replace_returns_full_set():
    cat = controls.load_catalog("soc2")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["delete", "create"])
    ids = {c.id for c in out}
    assert ids == {"CC6.1", "CC6.7", "CC8.1", "A1.2", "C1.1"}

# 6. Resource type not in catalog returns empty tuple, no exception.
def test_controls_for_unmapped_resource_returns_empty():
    cat = controls.load_catalog("soc2")
    out = cat.controls_for(resource_type="aws_lambda_function", actions=["update"])
    assert out == ()

# 7. Dedup preserves first-seen order across overlapping mappings.
def test_controls_for_dedup_first_seen_order():
    # Construct or fixture a catalog where two mappings share a control id;
    # assert it appears once and at its first position. If the seed catalog
    # doesn't expose this case, write a tiny in-memory catalog for the test.

# 8. CLI: --framework soc2 adds Controls column in markdown.
def test_cli_markdown_includes_controls_column(tmp_path):
    # Run the CLI against tests/fixtures/soc2_plan.json with --framework soc2.
    # Assert "Controls" header is present and "CC6.1" appears in at least one row.

# 9. CLI: --framework soc2 adds controls field in JSON.
def test_cli_json_includes_controls_field(tmp_path):
    # Run the CLI with --framework soc2 --format json against the fixture.
    # Assert summary.framework.name == "soc2" and the kms_key.customer_data
    # change has all five control ids.

# 10. CLI: omitting --framework leaves output unchanged.
def test_cli_default_output_unchanged(tmp_path):
    # Run the CLI without --framework. Assert no "Controls" header in markdown
    # and no "framework" / "controls" keys in JSON.

# 11. CLI: unknown framework exits non-zero with a helpful message.
def test_cli_unknown_framework_errors(capsys):
    # readtheplan analyze --framework soc3 plan.json -> exit code != 0,
    # stderr mentions "soc3" and lists "soc2" as available. No traceback.

# 12. Catalog schema: missing 'framework' key raises CatalogSchemaError.
def test_catalog_schema_error_on_missing_framework_key(tmp_path):
    # Write a malformed YAML to a tmp dir; load via a private hook that
    # accepts an explicit path; assert CatalogSchemaError with the path
    # in the message.
```

Test 12 implies a private `_load_from_path(path: Path)` helper that
`load_catalog` delegates to. That's fine and recommended; don't expose it.

The full pytest suite (existing 17 + the new ones) must pass on Python 3.10
and 3.13. CI already covers both.

---

## `pyproject.toml` changes

1. Add `PyYAML>=6.0` to `[project.dependencies]`. (If you choose to hand-roll
   a YAML parser, skip this and explain in the PR description.)
2. Ensure the YAML data ships in the wheel/sdist. Setuptools example:

   ```toml
   [tool.setuptools.package-data]
   readtheplan = ["data/controls/*.yaml"]
   ```

   Adapt to whichever build backend the project is using. Verify the YAML
   is reachable via `importlib.resources` after `pip install .` from a fresh
   venv (a one-line manual check in your dev loop, no need to add a CI job
   for this PR).

---

## ADR status update

After the PR is approved (not in this same commit — wait for review), flip
`docs/adr/0005-compliance-control-mapping.md`:

```diff
 ## Status

-Proposed
+Accepted
```

If review surfaces a material change to scope, leave the status as Proposed
and we'll re-discuss.

---

## README changes

Add one short subsection under whichever section currently describes the CLI
output (likely under "Usage" or similar). Keep it ≤ 12 lines, no marketing
copy. Sketch:

```markdown
### Compliance control IDs (preview)

`readtheplan analyze --framework soc2 plan.json` annotates each change with
SOC 2 (TSC 2017) control IDs touched by that change. The mapping ships as
data in `src/readtheplan/data/controls/soc2.yaml`. ISO 27001 and HIPAA
catalogs are planned in subsequent releases. See `docs/adr/0005-compliance-control-mapping.md`
for the schema and intent.
```

---

## Out of scope (do not add)

- Signing, attestation envelope, evidence-pack output
- ISO 27001, HIPAA, PCI-DSS, NIST 800-53, CIS AWS catalogs
- Multi-framework simultaneous rendering
- Customer-supplied control overlays
- GitHub Action `--framework` wiring (separate follow-on PR)
- Any change to risk tier, rule_id, or explanation logic in `rules.py`

If a follow-on idea looks unavoidable to land this slice, write it as a TODO
comment in the PR description and continue without it.

---

## Acceptance / definition of done

- [ ] All 12 listed tests pass on Python 3.10 and 3.13.
- [ ] Existing 17 pytest tests still pass with no modifications.
- [ ] `mypy --strict src/readtheplan/controls.py` passes (if mypy is in CI;
      if not, type-annotate per existing project style).
- [ ] `ruff check` / `black --check` clean per existing project style.
- [ ] Wheel built from a fresh venv contains `data/controls/soc2.yaml`.
- [ ] PR description states which ADR section drove which decision and lists
      anything skipped vs. the ADR.
- [ ] Commit message (or trailer) includes `AI-Assisted: Codex`.
- [ ] PR is opened against `main` from `codex/readtheplan-soc2-controls`.

---

## Review handoff

When the PR is open, comment `@cowork ready for review` (or ping in the
Cowork↔Codex Slack-equivalent). Cowork will review using the
`engineering:code-review` skill, with these specific checks:

1. Layering: no edits to `rules.py` / `plan.py` / `attestation.py`.
2. Schema fidelity: the YAML loader rejects malformed catalogs early.
3. Dedup behavior: control IDs in the output preserve first-seen order.
4. Backwards compatibility: omitting `--framework` produces byte-identical
   output to the prior version against `tests/fixtures/valid_plan.json`.
5. Wheel data inclusion: the YAML is shipped, not assumed-on-disk.

Cowork will request changes inline; expected total review turnaround is
under one full pass.
