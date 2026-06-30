#!/usr/bin/env bash
# readtheplan-gate.sh — portable CI gate for readtheplan v0.3.x
# Works around the CLI's lack of --fail-on by mapping agent-gate decisions to exit codes.
#   exit 0 = proceed, exit 1 = block (or hard error), exit 2 = warn
# Usage: readtheplan-gate.sh <plan.json> [framework] [--warn-ok]
#   framework: soc2 | iso27001 | hipaa (optional)
#   --warn-ok: treat warn as success (exit 0) for non-prod pipelines
# Outputs: gate.json (full contract), gate-comment.md (ready-to-post PR comment)
set -euo pipefail

PLAN_FILE="${1:?usage: readtheplan-gate.sh <plan.json> [framework] [--warn-ok]}"
FRAMEWORK="${2:-}"
WARN_OK="false"
for a in "$@"; do [ "$a" = "--warn-ok" ] && WARN_OK="true"; done
[ "$FRAMEWORK" = "--warn-ok" ] && FRAMEWORK=""

if [ ! -f "$PLAN_FILE" ]; then echo "gate: plan file not found: $PLAN_FILE" >&2; exit 1; fi
# Guard against the binary-plan footgun (v0.3.0 stack-traces on non-UTF-8 input)
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
