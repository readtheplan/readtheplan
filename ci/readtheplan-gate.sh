#!/usr/bin/env bash
# readtheplan-gate.sh — portable CI gate for the agent-gate contract.
# Maps agent-gate decisions to process exit codes for CI systems.
#   exit 0 = proceed, exit 1 = block (or hard error), exit 2 = warn
# Usage: readtheplan-gate.sh <plan.json> [framework] [--warn-ok]
#   framework: any framework identifier supported by the installed release (optional)
#   --warn-ok: treat warn as success (exit 0) for non-prod pipelines
# Outputs: gate.json (full contract), gate-comment.md (ready-to-post PR comment)
set -euo pipefail

PLAN_FILE="${1:?usage: readtheplan-gate.sh <plan.json> [framework] [--warn-ok]}"
FRAMEWORK="${2:-}"
WARN_OK="false"
for a in "$@"; do [ "$a" = "--warn-ok" ] && WARN_OK="true"; done
[ "$FRAMEWORK" = "--warn-ok" ] && FRAMEWORK=""

if [ ! -f "$PLAN_FILE" ]; then echo "gate: plan file not found: $PLAN_FILE" >&2; exit 1; fi
# Fail early when a binary Terraform plan is supplied instead of exported JSON.
if ! head -c 1 "$PLAN_FILE" | grep -q '{'; then
  echo "gate: $PLAN_FILE does not look like plan JSON." >&2
  echo "gate: generate it with: terraform plan -out=tfplan && terraform show -json tfplan > plan.json" >&2
  exit 1
fi

ARGS=("$PLAN_FILE"); [ -n "$FRAMEWORK" ] && ARGS=(--framework "$FRAMEWORK" "$PLAN_FILE")
if ! readtheplan agent-gate "${ARGS[@]}" > gate.json 2> gate.err; then
  echo "gate: readtheplan failed:" >&2; cat gate.err >&2; exit 1
fi

DECISION=$(python3 -c "import json;print(json.load(open('gate.json'))['decision'])")
python3 -c "import json;print(json.load(open('gate.json'))['pr_comment'])" > gate-comment.md
python3 -c "
import json; g=json.load(open('gate.json'))
print(f\"gate: decision={g['decision']} risk={g['risk']} counts={g['risk_counts']}\")
print('gate: ' + g['reason'])"

case "$DECISION" in
  proceed) exit 0 ;;
  warn)    [ "$WARN_OK" = "true" ] && exit 0 || exit 2 ;;
  block)   exit 1 ;;
  *)       echo "gate: unknown decision '$DECISION' — failing closed" >&2; exit 1 ;;
esac
