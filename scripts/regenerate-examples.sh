#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python}"

export PYTHONPATH="${ROOT_DIR}/src${PYTHONPATH:+:${PYTHONPATH}}"
cd "${ROOT_DIR}"

for example in \
  examples/01-small-create \
  examples/02-dangerous-replacement \
  examples/03-multi-resource
do
  "${PYTHON_BIN}" -m readtheplan.cli analyze "${example}/plan.json" > "${example}/analysis.md"
  "${PYTHON_BIN}" -m readtheplan.cli analyze --format json --framework soc2 "${example}/plan.json" > "${example}/analysis.json"
done

"${PYTHON_BIN}" - <<'PY'
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from readtheplan.controls import load_catalog
from readtheplan.evidence import build_evidence
from readtheplan.plan import analyze_plan_file
from readtheplan.signing import _canonical_payload

plan_path = Path("examples/02-dangerous-replacement/plan.json")
output_path = Path("examples/02-dangerous-replacement/evidence.json")
generated_at = datetime(2026, 5, 3, 15, 33, 49, tzinfo=timezone.utc)

envelope = build_evidence(
    plan_summary=analyze_plan_file(plan_path),
    plan_json=plan_path.read_bytes(),
    catalog=load_catalog("soc2"),
    agent_id="readtheplan-examples-fixture",
    run_id="examples/02-dangerous-replacement",
    generated_at=generated_at,
)
payload = envelope.to_dict()
canonical = _canonical_payload(payload)
signature = base64.b64encode(
    hashlib.sha256(canonical + b"|readtheplan-examples-fixture").digest()
).decode("ascii")
bundle = {
    "readtheplan_examples_fixture_v1": {
        "identity": "examples-fixture@readtheplan.dev",
        "oidc_issuer": "https://issuer.example.test",
        "rekor_uuid": "examples-fixture-rekor-0001",
        "signature": signature,
    }
}
payload["agent_attestation"]["signature"] = signature
payload["agent_attestation"]["cert"] = json.dumps(
    bundle,
    sort_keys=True,
    separators=(",", ":"),
)
output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

for generated in Path("examples").glob("*/analysis.md"):
    lines = generated.read_text(encoding="utf-8").splitlines()
    if lines:
        lines[0] = lines[0].replace("\\", "/")
    generated.write_text("\n".join(lines) + "\n", encoding="utf-8")

for generated in Path("examples").glob("*/analysis.json"):
    payload = json.loads(generated.read_text(encoding="utf-8"))
    payload["path"] = str(payload["path"]).replace("\\", "/")
    generated.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
