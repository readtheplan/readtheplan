# Codex task — ADR 0009 HIPAA catalog wiring

**Authoring agent:** Cowork (Claude)
**Implementation agent:** Codex
**Reviewer:** Cowork (Claude), via the `engineering:code-review` skill
**Branch:** `codex/readtheplan-hipaa-controls`
**Commit trailer:** `AI-Assisted: Codex`
**Reference ADR:** [`docs/adr/0009-hipaa-control-catalog.md`](../adr/0009-hipaa-control-catalog.md)
**Seed catalog:** [`src/readtheplan/data/controls/hipaa.yaml`](../../src/readtheplan/data/controls/hipaa.yaml)

---

## Goal

Wire the HIPAA Security Rule catalog (already on main) into the test
suite, README, and CLI help. Same pattern as task 0003 (ISO 27001) —
data is already on main, no loader / CLI / format changes required;
this PR adds the test fixture, eight named tests, and a small README
update.

ADR 0009 is the source of truth. If anything in this brief contradicts
the ADR, the ADR wins; stop and write up the issue.

---

## Inputs already on main (read-only)

- `docs/adr/0009-hipaa-control-catalog.md` — the ADR.
- `src/readtheplan/data/controls/hipaa.yaml` — the seed catalog
  covering KMS, RDS, S3, IAM, security groups, Route 53, EKS,
  CloudTrail under ten Security Rule citations (`164.308(a)(1)`,
  `164.308(a)(4)`, `164.308(a)(7)`, `164.310(d)`, `164.312(a)(1)`,
  `164.312(a)(2)(iv)`, `164.312(b)`, `164.312(c)(1)`, `164.312(d)`,
  `164.312(e)(1)`).

  Treat as versioned API surface. Read-only unless a real bug —
  in which case, call it out in the PR.

- The existing `controls.py` loader, `--framework` CLI flag, and
  evidence envelope all already work with any framework name. No
  module changes for this PR.

---

## Files you will write

```
tests/fixtures/hipaa_plan.json                        (new)
tests/test_controls.py                                (modify — add HIPAA tests)
README.md                                             (modify — extend the preview subsection)
```

No other files. Do NOT modify `controls.py`, `evidence.py`,
`signing.py`, `attestation.py`, `plan.py`, `rules.py`, or the
`cli.py`'s `--framework` help string (it already derives from
`available_frameworks()` per PR #5 — adding `hipaa` happens
automatically).

---

## Test fixture — `tests/fixtures/hipaa_plan.json`

Same shape as `tests/fixtures/iso27001_plan.json`. Six cases:

| address                                  | type                                | actions                | expected control IDs (set)                                  |
|------------------------------------------|-------------------------------------|------------------------|-------------------------------------------------------------|
| `aws_kms_key.customer_data`              | `aws_kms_key`                       | `["delete", "create"]` | 164.308(a)(1), 164.308(a)(7), 164.310(d), 164.312(a)(2)(iv) |
| `aws_kms_key.new_key`                    | `aws_kms_key`                       | `["create"]`           | 164.308(a)(1), 164.312(a)(2)(iv)                            |
| `aws_s3_bucket_policy.assets`            | `aws_s3_bucket_policy`              | `["update"]`           | 164.308(a)(1), 164.312(a)(1), 164.312(d)                    |
| `aws_security_group_rule.web_ingress`    | `aws_security_group_rule`           | `["create"]`           | 164.308(a)(1), 164.312(a)(1), 164.312(e)(1)                 |
| `aws_cloudtrail.org`                     | `aws_cloudtrail`                    | `["delete"]`           | 164.308(a)(1), 164.312(b), 164.312(c)(1)                    |
| `aws_lambda_function.handler`            | `aws_lambda_function`               | `["update"]`           | (empty — not in the seed catalog)                           |

Match the existing fixture style in `tests/fixtures/iso27001_plan.json`.

---

## Tests — additions to `tests/test_controls.py`

Required test cases. Names and intent are fixed; style is yours.

```python
# 1. Catalog loads cleanly with the right framework / version.
def test_load_hipaa_catalog_smoke():
    cat = controls.load_catalog("hipaa")
    assert cat.framework == "hipaa"
    assert cat.framework_version == "2013-omnibus"
    assert cat.schema_version == 1

# 2. available_frameworks() now reports all three frameworks, sorted.
def test_available_frameworks_includes_hipaa():
    frameworks = controls.available_frameworks()
    assert "hipaa" in frameworks
    assert "iso27001" in frameworks
    assert "soc2" in frameworks
    assert list(frameworks) == sorted(frameworks)

# 3. Match semantics — KMS create returns the encryption + management pair.
def test_hipaa_controls_for_kms_create():
    cat = controls.load_catalog("hipaa")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["create"])
    ids = [c.id for c in out]
    # Match exact order from the seed YAML; if order differs, assert
    # against a set instead of a list.
    assert ids == ["164.312(a)(2)(iv)", "164.308(a)(1)"]

# 4. KMS replacement returns the irreversible-deletion set.
def test_hipaa_controls_for_kms_replace():
    cat = controls.load_catalog("hipaa")
    out = cat.controls_for(resource_type="aws_kms_key", actions=["delete", "create"])
    ids = {c.id for c in out}
    assert ids == {
        "164.312(a)(2)(iv)",
        "164.310(d)",
        "164.308(a)(7)",
        "164.308(a)(1)",
    }

# 5. Order-invariance regression for HIPAA.
def test_hipaa_replace_order_invariant():
    cat = controls.load_catalog("hipaa")
    forward = cat.controls_for(resource_type="aws_kms_key", actions=["delete", "create"])
    reverse = cat.controls_for(resource_type="aws_kms_key", actions=["create", "delete"])
    assert {c.id for c in forward} == {c.id for c in reverse}
    assert len(forward) > 0

# 6. CLI: --framework hipaa emits the markdown Controls column.
def test_cli_hipaa_markdown_includes_controls(tmp_path, capsys):
    exit_code = main(["analyze", "--framework", "hipaa",
                      str(FIXTURES / "hipaa_plan.json")])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "| Risk | Actions | Resource | Type | Explanation | Controls |" in captured.out
    assert "164.308(a)(1)" in captured.out

# 7. CLI: JSON output reports framework name "hipaa" and version "2013-omnibus".
def test_cli_hipaa_json_framework_metadata(tmp_path, capsys):
    exit_code = main(["analyze", "--framework", "hipaa", "--format", "json",
                      str(FIXTURES / "hipaa_plan.json")])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["framework"] == {
        "name": "hipaa",
        "version": "2013-omnibus",
        "schema_version": 1,
    }

# 8. CLI: unknown framework error now lists all THREE available frameworks.
def test_cli_unknown_framework_lists_all_three(capsys):
    exit_code = main(["analyze", "--framework", "soc3",
                      str(FIXTURES / "soc2_plan.json")])
    captured = capsys.readouterr()
    assert exit_code != 0
    assert captured.err != ""
    assert "soc3" in captured.err
    assert "hipaa" in captured.err
    assert "iso27001" in captured.err
    assert "soc2" in captured.err
    assert "Traceback" not in captured.err
```

If the seed catalog lists controls for KMS-create in a different order
than the test 3 assertion expects, assert against `set` instead of a
list. Order is whatever the seed YAML happens to write; don't rewrite
the seed to match the test.

The full pytest suite (existing 76 + 8 new = 84) must pass on Python
3.10 and 3.13. CI now runs both via the new pytest workflow.

---

## README changes

Extend the existing "Compliance control IDs (preview)" subsection
added in PR #3 / PR #5. Replace its body with:

```markdown
### Compliance control IDs (preview)

`readtheplan analyze --framework <name> plan.json` annotates each change
with control IDs from a packaged compliance framework catalog.

Available frameworks:

- `soc2` — SOC 2 Trust Services Criteria 2017 (see ADR 0005)
- `iso27001` — ISO/IEC 27001:2022 Annex A (see ADR 0006)
- `hipaa` — HIPAA Security Rule, 45 CFR Part 164 Subpart C (see ADR 0009)

Catalogs ship as data under `src/readtheplan/data/controls/`. PCI-DSS,
NIST 800-53, and CIS AWS catalogs are planned in subsequent ADRs. The
output is intended as one input to a human's evidence package, not a
stand-alone audit artifact.
```

Keep the (preview) heading. No marketing copy.

---

## Out of scope (do not bundle)

- HIPAA Privacy Rule or Breach Notification Rule (separate ADRs if
  ever scoped).
- HITRUST CSF / 42 CFR Part 2 / state-specific privacy rules.
- PCI-DSS, NIST 800-53, CIS AWS catalogs.
- Multi-framework simultaneous rendering.
- Customer-supplied control overlays.
- Any change to `controls.py`, `evidence.py`, `signing.py`,
  `attestation.py`, `plan.py`, `rules.py`, or the CLI's flag plumbing.

If a follow-on idea looks unavoidable to land this slice, write it as
a TODO in the PR description and continue without it.

---

## Acceptance / definition of done

- [ ] All 8 listed tests pass on Python 3.10 and 3.13.
- [ ] Existing 76 pytest tests still pass with no modifications.
- [ ] `ruff check` / `black --check` clean per existing project style.
- [ ] `readtheplan analyze --help` shows `hipaa`, `iso27001`, `soc2`
      in the `--framework` line (no code change should be needed —
      `available_frameworks()` derives the list).
- [ ] PR description maps each substantive decision back to ADR 0009
      and lists anything skipped vs. the brief.
- [ ] Commit message includes `AI-Assisted: Codex` trailer.
- [ ] PR is opened against `main` from `codex/readtheplan-hipaa-controls`.

---

## Review handoff

When the PR is open and CI is green (`test-action`, `pytest (3.10)`,
`pytest (3.13)` all passing), comment `@cowork ready for review`.
Cowork will review using the `engineering:code-review` skill, with
these specific checks:

1. **Layering**: `controls.py`, `evidence.py`, `signing.py`,
   `attestation.py`, `plan.py`, `rules.py` all untouched.
2. **Catalog visibility**: `available_frameworks()` returns
   `("hipaa", "iso27001", "soc2")`, sorted.
3. **Backwards compat**: existing `--framework soc2` and
   `--framework iso27001` outputs unchanged.
4. **Help-string derivation**: `--help` output for `--framework` lists
   all three frameworks.
5. **Order-invariance regression** (test 5) reproduces the canonical
   action-order fix path.
