# Agent Gate Integration Guide

**Contract:** `rtp-agent-gate-v1`
**Source:** [src/readtheplan/agent_gate.py](https://github.com/readtheplan/readtheplan/blob/main/src/readtheplan/agent_gate.py)
**JSON Schema:** [/schemas/rtp-agent-gate-v1.json](/schemas/rtp-agent-gate-v1.json)

The readtheplan agent-gate contract is a **deterministic, locally computable JSON document** that tells a coding agent what to do with an infrastructure plan. It is designed to be consumed by **Claude Code**, **OpenAI Codex CLI**, **Cline**, and any other agentic coding tool that can run shell commands and read JSON.

---

## Invocation

All three tools call the same CLI:

```bash
readtheplan agent-gate path/to/plan.json
```

Optional flag:

```bash
readtheplan agent-gate --framework soc2 path/to/plan.json
```

The `--framework` flag adds framework-specific control check IDs to `required_checks`.

Output is written to **stdout** as pretty-printed JSON. Exit codes are meaningful (see below). Errors and warnings go to **stderr**.

---

## Decision Model

| Decision  | Exit Code | Meaning |
|-----------|-----------|---------|
| `proceed` | `0`       | All changes are safe-tier; agent may continue and apply. |
| `warn`    | `1`       | At least one change is review-tier; peer review and change evidence required. |
| `block`   | `2`       | At least one change is dangerous or irreversible; human approval + security review + evidence required. |

> **⚠️ Stability guarantee:** `decision` is the **only field you may branch on**. All other fields (`risk`, `required_checks`, `reason`, etc.) may gain values or change wording between schema versions. The `decision` enum (`proceed` / `warn` / `block`) will not change.

---

## Integration Examples

### Claude Code

Claude Code supports shell commands natively via `/` commands or `!` directives.

**Basic usage inside a Claude Code session:**

````
# Run the gate, capture both the JSON and the exit code
!readtheplan agent-gate plan.json > /tmp/agent-gate.json; echo "EXIT=$?"
````

**Scripted Claude Code workflow (`agent-gate.claude.md`):**

````markdown
# Agent Gate — Claude Code workflow

Run this at the start of any Terraform PR review:

```bash
readtheplan agent-gate plan.json > /tmp/agent-gate.json
exit_code=$?
```

Read the gate output:

```bash
cat /tmp/agent-gate.json | jq '.decision, .reason, .pr_comment, .risk, .risk_counts'
```

Then branch on exit code:

```bash
if [ "$exit_code" -eq 2 ]; then
  echo "BLOCKED — requesting human review"
  # Post the PR comment, tag a reviewer
  jq -r '.pr_comment' /tmp/agent-gate.json | gh pr comment $PR_NUMBER --body-file -
elif [ "$exit_code" -eq 1 ]; then
  echo "WARN — requesting peer review"
  jq -r '.pr_comment' /tmp/agent-gate.json | gh pr comment $PR_NUMBER --body-file -
else
  echo "PROCEED — changes are safe"
fi
```

For compliance, log the evidence checklist:

```bash
echo "## Compliance evidence"
jq -r '.evidence_checklist[] | "- [ ] \(.)"' /tmp/agent-gate.json
echo ""
echo "Auditor summary: $(jq -r '.auditor_summary' /tmp/agent-gate.json)"
```
````

---

### Codex (OpenAI Codex CLI)

Codex CLI runs in a sandboxed environment. Use the `@terminal` directive to invoke the gate.

**Basic usage:**

````
@terminal readtheplan agent-gate plan.json > /tmp/agent-gate.json; echo "EXIT=$?"
````

**Python wrapper for structured consumption (recommended for Codex):**

```python
import json
import subprocess
import sys

def agent_gate(plan_path: str, framework: str | None = None) -> dict:
    """Run readtheplan agent-gate and return the parsed contract."""
    cmd = ["readtheplan", "agent-gate", plan_path]
    if framework:
        cmd.extend(["--framework", framework])

    result = subprocess.run(cmd, capture_output=True, text=True)
    gate = json.loads(result.stdout)

    # Schema verification — MUST check this before reading any field
    assert gate["schema"] == "rtp-agent-gate-v1", (
        f"Unknown schema: {gate.get('schema')}"
    )

    return {
        "decision": gate["decision"],
        "risk": gate["risk"],
        "reason": gate["reason"],
        "payload": gate,
        "exit_code": result.returncode,  # 0=proceed, 1=warn, 2=block
    }

def post_pr_comment(gate: dict, pr_number: str) -> None:
    """Post the pre-formatted PR comment via GitHub CLI."""
    comment = gate["pr_comment"]
    subprocess.run(
        ["gh", "pr", "comment", pr_number, "--body", comment],
        check=True,
    )

def compliance_log(gate: dict) -> list[str]:
    """Return the evidence checklist as a list of incomplete items."""
    return gate["evidence_checklist"]

# ---- Example usage ----
gate = agent_gate("plan.json", framework="soc2")
print(f"Decision: {gate['decision']} (exit {gate['exit_code']})")
print(f"Reason: {gate['reason']}")

if gate["exit_code"] == 2:
    post_pr_comment(gate["payload"], "42")
    print("PR comment posted, escalation initiated.")
elif gate["exit_code"] == 1:
    print(f"Required checks: {gate['payload']['required_checks']}")

# Log evidence items for compliance
for item in compliance_log(gate["payload"]):
    print(f"  ☐ {item}")
```

---

### Cline

Cline supports `@cli` and `@terminal` directives. The recommended pattern uses a shell helper with `jq`.

**Basic usage via @cli:**

````
@cli readtheplan agent-gate plan.json > /tmp/agent-gate.json
@cli echo "Exit code: $?"
````

**Cline `.clinerules` snippet for agent-gate integration:**

```yaml
# .clinerules — agent-gate guard
always_run:
  - description: "Run readtheplan agent-gate before any apply or merge"
    command: |
      readtheplan agent-gate plan.json > /tmp/agent-gate.json
      echo "AGENT_GATE_EXIT=$?"
    post_process: |
      DECISION=$(jq -r '.decision' /tmp/agent-gate.json)
      if [ "$DECISION" = "block" ]; then
        echo "❌ BLOCKED — dangerous or irreversible changes detected."
        echo "Required actions:"
        jq -r '.allowed_next_actions[] | "  → \(.)"' /tmp/agent-gate.json
        echo ""
        echo "Prohibited actions (DO NOT ATTEMPT):"
        jq -r '.prohibited_next_actions[] | "  ✗ \(.)"' /tmp/agent-gate.json
      elif [ "$DECISION" = "warn" ]; then
        echo "⚠️  WARN — review-tier changes detected."
        echo "Required checks:"
        jq -r '.required_checks[] | "  ☐ \(.)"' /tmp/agent-gate.json
      else
        echo "✅ PROCEED — all changes safe-tier."
      fi
```

**Cline task prompt for PR review:**

````
You are reviewing a Terraform PR. Follow these steps:

1. Run the agent gate:
   @cli readtheplan agent-gate plan.json > /tmp/agent-gate.json

2. Parse the decision:
   @cli jq -r '.decision' /tmp/agent-gate.json

3. If blocked:
   - Post the PR comment: @cli jq -r '.pr_comment' /tmp/agent-gate.json | gh pr comment $PR_NUMBER --body-file -
   - Do NOT merge or apply (prohibited actions include: merge, apply, auto_approve)
   - Tag a human reviewer

4. If warned:
   - Post the PR comment
   - Verify required checks are completed before approving merge
   - Collect change evidence

5. If proceed:
   - Continue with normal review
   - Post a brief summary comment with the auditor_summary
````

---

## Consuming the Output Fields

```jsonc
{
  // ALWAYS verify this first
  "schema": "rtp-agent-gate-v1",

  // Branch on this field only (stability guarantee)
  "decision": "warn",

  // Highest risk tier — informational only, do NOT branch on this
  "risk": "review",

  // Checks to complete before merge
  "required_checks": ["rtp.check.peer_review", "rtp.check.change_evidence"],

  // Actions you ARE allowed to take
  "allowed_next_actions": ["request_review", "post_pr_comment", "collect_evidence", "open_change_record"],

  // Actions you MUST NOT take
  "prohibited_next_actions": ["merge_without_review", "apply_without_review", "auto_approve"],

  // Human-readable explanation
  "reason": "Warn because the highest risk tier is review; reviewer approval and change evidence are required before merge or apply.",

  // Ready-to-post PR comment (Markdown)
  "pr_comment": "**readtheplan agent gate:** WARN\n\nWarn because...",

  // Compliance evidence items to satisfy
  "evidence_checklist": [
    "Record the local Terraform plan JSON path or CI artifact reference.",
    "Attach the readtheplan JSON summary or PR comment to the change record.",
    "Record reviewer identity, timestamp, and approval decision.",
    "Document mitigation or rollback notes for review-tier changes."
  ],

  // One-line audit log summary
  "auditor_summary": "readtheplan evaluated 3 Terraform resource change(s). The agent gate decision is warn with maximum risk review. Risk counts: safe=2, review=1, dangerous=0, irreversible=0.",

  // Per-tier change counts
  "risk_counts": { "safe": 2, "review": 1, "dangerous": 0, "irreversible": 0 }
}
```

---

## Schema Validation

Always verify the `schema` field before consuming the rest of the payload:

```bash
SCHEMA=$(jq -r '.schema' /tmp/agent-gate.json)
if [ "$SCHEMA" != "rtp-agent-gate-v1" ]; then
  echo "ERROR: Unknown schema $SCHEMA — aborting" >&2
  exit 1
fi
```

The JSON Schema document is available at `site/data/agent-gate-schema.json` in the repository and published at `https://readtheplan.dev/schemas/rtp-agent-gate-v1.json`.

---

## Posting PR Comments

The `pr_comment` field contains a pre-formatted Markdown string ready for posting. Example with GitHub CLI:

```bash
jq -r '.pr_comment' /tmp/agent-gate.json | gh pr comment $PR_NUMBER --body-file -
```

For other platforms (GitLab, Bitbucket), use their respective API or CLI tools. The Markdown is plain GitHub-Flavored Markdown and should render correctly on any platform.

---

## Compliance Workflow

The `evidence_checklist` is **decision-aware**:

| Decision | Checklist Items |
|----------|----------------|
| `proceed` | Record plan path, attach summary to change record |
| `warn`    | All of the above + reviewer identity + mitigation notes |
| `block`   | All of the above + explicit human approval + recovery evidence |

For framework-specific controls (when `--framework` is passed), an additional item is appended:

> "Map touched controls from the {framework} catalog into the evidence package."

---

## Versioning & Stability

| Aspect | Guarantee |
|--------|-----------|
| `schema` value | Changes only on major version bumps (e.g., `rtp-agent-gate-v2`) |
| `decision` enum | `proceed` / `warn` / `block` — will not change |
| All other fields | May gain values, keys, or change wording within the same schema version |
| Exit codes | 0 = proceed, 1 = warn, 2 = block — stable |

> **Rule for agent authors:** Only branch on `decision`. Treat all other fields as advisory/human-facing content that may change in minor releases.
