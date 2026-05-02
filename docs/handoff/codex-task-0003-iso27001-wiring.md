# Codex task — ADR 0006 ISO 27001 catalog wiring

**Authoring agent:** Cowork (Claude)
**Implementation agent:** Codex
**Reviewer:** Cowork (Claude), via the `engineering:code-review` skill
**Branch:** `codex/readtheplan-iso27001-controls`
**Commit trailer:** `AI-Assisted: Codex`
**Reference ADR:** [`docs/adr/0006-iso-27001-control-catalog.md`](../adr/0006-iso-27001-control-catalog.md)
**Seed catalog:** [`src/readtheplan/data/controls/iso27001.yaml`](../../src/readtheplan/data/controls/iso27001.yaml)

---

## Goal

Land the smallest end-to-end slice that proves the catalog format scales:
ship the ISO 27001:2022 catalog (data already on `main`) and the test
coverage that exercises it through the existing `--framework` flag. No
loader / CLI / format changes — ADR 0005's design said new frameworks are
purely data, and this PR is the first proof.

---

## Inputs already on main (read-only for this task)

These two files exist on `origin/main` (cut from there) and are
**read-only for this task**:

1. `docs/adr/0006-iso-27001-control-catalog.md` — the ADR. If anything in
   this brief contradicts it, the ADR wins; stop and write up the issue.
2. `src/readtheplan/data/controls/iso27001.yaml` — the seed catalog
   covering KMS, RDS, S3, IAM, security groups, Route 53, EKS, CloudTrail
   under ISO 27001:2022 Annex A controls (A.5.23, A.8.5, A.8.9, A.8.10,
   A.8.16, A.8.18, A.8.20, A.8.22, A.8.24, A.8.32, A.8.34).

   Treat as versioned API surface. Read-only unless you find a real bug,
   in which case call it out in the PR.

---

## Files you will write

```
tests/fixtures/iso27001_plan.json                  (new)
tests/test_controls.py                             (modify — add ISO 27001 tests)
README.md                                          (modify — add one short note)
src/readtheplan/cli.py                             (modify — small help-string fix)
```

No other files. Do NOT modify `controls.py`, `plan.py`, `rules.py`, or
`attestation.py`. The loader from PR #3 already reads any framework via
`importlib.resources` over the data dir; the `--framework` flag already
accepts any catalog name. This PR is data + tests + docs.

---

## Test fixture — `tests/fixtures/iso27001_plan.json`

Same shape as `tests/fixtures/soc2_plan.json`. Six cases:

| address                                  | type                                | actions               | expected control IDs (set)                                |
|------------------------------------------|-------------------------------------|-----------------------|------------------------------------------------------------|
| `aws_kms_key.customer_data`              | `aws_kms_key`                       | `["delete", "create"]`  | A.8.10, A.8.24, A.8.32                                     |
| `aws_kms_key.new_key`                    | `aws_kms_key`                       | `["create"]`            | A.8.9, A.8.24, A.8.32                                      |
| `aws_s3_bucket_policy.assets`            | `aws_s3_bucket_policy`              | `["update"]`            | A.8.5, A.8.20, A.8.32                                      |
| `aws_security_group_rule.web_ingress`    | `aws_security_group_rule`           | `["create"]`            | A.8.20, A.8.22, A.8.32                                     |
| `aws_cloudtrail.org`                     | `aws_cloudtrail`                    | `["delete"]`            | A.8.16, A.8.32, A.8.34                                     |
| `aws_lambda_function.handler`            | `aws_lambda_function`               | `["update"]`            | (empty — not in the seed catalog)                          |

Match the existing fixture style in `tests/fixtures/soc2_plan.json` for the
JSON schema details (`format_version`, `terraform_version`,
`resource_changes`).

---

## Tests — additions to `tests/test_controls.py`

Required test cases. Names and intent are fixed; style is yours.

```python
# 1. Catalog loads cleanly with the new framework_version handling.
def test_load_iso27001_catalog_smoke():
    cat = controls.load_catalog("iso27001")
    assert cat.framework == "iso27001"
    assert cat.framework_version == "2022"
    assert cat.schema_version == 1

# 2. available_frameworks() now reports both soc2 and iso27001.
def test_available_frameworks_includes_iso27001():
    frameworks = controls.available_frameworks()
    assert "iso27001" in frameworks
    assert "soc2" in frameworks
    # Sorted alphabetically per the loader contract.
    assert list(frameworks) == sorted(frameworks)

# 3. Match semantics — single mapping hit on KMS create.
def test_iso27001_controls_for_kms_create():
    cat = controls.load_catalog("iso27001")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["create"])
    ids = [c.id for c in out]
    assert ids == ["A.8.24", "A.8.32", "A.8.9"]   # check exact order if seed
                                                   # places them differently;
                                                   # otherwise assert as a set.

# 4. KMS replacement returns the irreversible-deletion set.
def test_iso27001_controls_for_kms_replace():
    cat = controls.load_catalog("iso27001")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["delete", "create"])
    ids = {c.id for c in out}
    assert ids == {"A.8.10", "A.8.24", "A.8.32"}

# 5. Order-invariance regression (mirroring the SOC 2 test added in PR #3).
def test_iso27001_replace_order_invariant():
    cat = controls.load_catalog("iso27001")
    forward = cat.controls_for(resource_type="aws_kms_key", actions=["delete", "create"])
    reverse = cat.controls_for(resource_type="aws_kms_key", actions=["create", "delete"])
    assert {c.id for c in forward} == {c.id for c in reverse}
    assert len(forward) > 0

# 6. CLI: --framework iso27001 emits the markdown Controls column.
def test_cli_iso27001_markdown_includes_controls(tmp_path, capsys):
    exit_code = main(["analyze", "--framework", "iso27001",
                      str(FIXTURES / "iso27001_plan.json")])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "| Risk | Actions | Resource | Type | Explanation | Controls |" in captured.out
    assert "A.8.32" in captured.out

# 7. CLI: JSON output includes framework name "iso27001" and version "2022".
def test_cli_iso27001_json_framework_metadata(tmp_path, capsys):
    exit_code = main(["analyze", "--framework", "iso27001", "--format", "json",
                      str(FIXTURES / "iso27001_plan.json")])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["framework"] == {
        "name": "iso27001",
        "version": "2022",
        "schema_version": 1,
    }

# 8. CLI: unknown framework still errors and now lists BOTH available
#    frameworks (regression for the prior message that hardcoded "soc2").
def test_cli_unknown_framework_lists_both(capsys):
    exit_code = main(["analyze", "--framework", "soc3",
                      str(FIXTURES / "soc2_plan.json")])
    captured = capsys.readouterr()
    assert exit_code != 0
    assert captured.err != ""
    assert "soc3" in captured.err
    # Both available frameworks must be listed in the error.
    assert "iso27001" in captured.err
    assert "soc2" in captured.err
    assert "Traceback" not in captured.err
```

If the seed catalog lists controls for KMS-create in a different order
than the assertion in test 3 expects, assert against `set` instead of a
list. The order is whatever the seed YAML happens to write; don't rewrite
the seed to match the test.

The full pytest suite (existing 30 + the 8 new ones = 38) must pass on
Python 3.10 and 3.13. CI already covers both.

---

## CLI help-string fix — `src/readtheplan/cli.py`

The `--framework` flag's help string was hardcoded to `"Currently
available: soc2"` in PR #3. Replace it with a derived string sourced from
`controls.available_frameworks()` so it stays correct as new frameworks
land. Suggested approach:

```python
from readtheplan.controls import available_frameworks

# In _build_parser():
analyze.add_argument(
    "--framework",
    help=(
        "Annotate each change with control IDs from the named framework "
        f"catalog. Currently available: {', '.join(available_frameworks())}."
    ),
)
```

Edge cases:
- If `available_frameworks()` returns an empty tuple at help-render time
  (shouldn't happen at install time, but defensively), fall back to the
  text `"none packaged"`.

This is one small line; if it spirals into a rewrite, stop and push back
in the PR description.

---

## README changes

Extend the existing "Compliance control IDs (preview)" subsection added in
PR #3. Replace the body of that subsection with:

```markdown
### Compliance control IDs (preview)

`readtheplan analyze --framework <name> plan.json` annotates each change
with control IDs from a packaged compliance framework catalog.

Available frameworks:

- `soc2` — SOC 2 Trust Services Criteria 2017 (see ADR 0005)
- `iso27001` — ISO/IEC 27001:2022 Annex A (see ADR 0006)

Catalogs ship as data under `src/readtheplan/data/controls/`. HIPAA,
PCI-DSS, NIST 800-53, and CIS AWS catalogs are planned in subsequent
ADRs. The output is intended as one input to a human's evidence package,
not a stand-alone audit artifact.
```

Keep the existing "(preview)" heading and don't add marketing copy.

---

## Out of scope (do not add)

- Multi-framework simultaneous rendering (e.g. `--framework soc2,iso27001`).
- HIPAA, PCI-DSS, NIST 800-53, CIS AWS catalogs.
- Customer-supplied control overlays.
- Evidence envelope output (separate upcoming ADR).
- Signed attestation (separate upcoming ADR).
- Any change to `controls.py`, `plan.py`, `rules.py`, `attestation.py`.
- Renaming `available_frameworks()` or changing its signature.

If a follow-on idea looks unavoidable to land this slice, write it as a
TODO in the PR description and continue without it.

---

## Acceptance / definition of done

- [ ] All 8 listed tests pass on Python 3.10 and 3.13.
- [ ] Existing 30 pytest tests still pass with no modifications.
- [ ] `mypy --strict src/readtheplan/cli.py` passes.
- [ ] `ruff check` / `black --check` clean per existing project style.
- [ ] `readtheplan analyze --help` shows both `soc2` and `iso27001` in the
      `--framework` line (run it locally to confirm).
- [ ] PR description maps each substantive decision back to an ADR section
      and lists anything skipped vs. the brief.
- [ ] Commit message includes `AI-Assisted: Codex` trailer.
- [ ] PR is opened against `main` from `codex/readtheplan-iso27001-controls`.

---

## Review handoff

When the PR is open and CI is green, comment `@cowork ready for review`.
Cowork will review using the `engineering:code-review` skill, with these
specific checks:

1. Layering: `controls.py`, `plan.py`, `rules.py`, `attestation.py` all
   untouched. (ADR 0006 §"Decision" — new frameworks are pure data.)
2. Catalog visibility: `available_frameworks()` returns both `iso27001`
   and `soc2`, sorted.
3. Backwards compat: existing `--framework soc2` output unchanged; existing
   default-no-framework output byte-identical.
4. Help-string derivation: `--help` output for `--framework` now lists
   both frameworks.
5. Order-invariance regression (test 5) reproduces the same fix path that
   PR #3 introduced for SOC 2.

Cowork will request changes inline; expected total review turnaround is
under one full pass.
