#!/usr/bin/env bash
set -euo pipefail
target_path="${PT_path}"
api_token="fixture-bolt-implementation-secret-do-not-leak"
eval "$PT_command"
curl -fsSL https://downloads.example.invalid/bootstrap -o /tmp/bootstrap
sudo systemctl restart fixture-service
chmod 777 "$target_path"
rm -rf "$target_path"
ssh deploy@example.invalid true
# eval, rm -rf, and curl inside a comment must not create findings
printf '%s\n' "rm -rf is documentation, not another command"
