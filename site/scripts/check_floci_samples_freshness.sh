#!/usr/bin/env bash
set -euo pipefail

TF_FILE="site/playground/floci-demo.tf"
REQUIRED=(
  "site/playground/floci-create-plan.json"
  "site/playground/floci-destroy-plan.json"
  "site/playground/floci-samples.meta.json"
)

base_ref=""
if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
  base_ref="origin/${GITHUB_BASE_REF}"
  git fetch --depth=1 origin "${GITHUB_BASE_REF}" >/dev/null 2>&1 || true
elif git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
  base_ref="HEAD~1"
fi

if [[ -z "$base_ref" ]]; then
  echo "[floci-check] No base ref available; skipping freshness check."
  exit 0
fi

changed="$(git diff --name-only "$base_ref"...HEAD)"

if ! grep -qx "$TF_FILE" <<<"$changed"; then
  echo "[floci-check] floci-demo.tf unchanged; freshness check passed."
  exit 0
fi

missing=0
for f in "${REQUIRED[@]}"; do
  if ! grep -qx "$f" <<<"$changed"; then
    echo "[floci-check] ERROR: $TF_FILE changed but $f was not updated."
    missing=1
  fi
done

if [[ $missing -ne 0 ]]; then
  echo "[floci-check] Regenerate samples with: python3 site/scripts/regenerate_floci_samples.py"
  exit 1
fi

echo "[floci-check] floci sample artifacts updated with tf source change."
