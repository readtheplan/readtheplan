# Agent Vault Phase 0 command pack (copy/paste)

This is the executable companion to:
- `docs/security/agent-vault-rollout-plan.md`

Assumptions:
- **VPS-A** = Hermes host (this machine)
- **VPS-B** = Agent Vault host (separate machine)
- Hermes gateway service name: `hermes-gateway.service` (user service)

> Replace placeholders before running:
- `<VPS_A_PUBLIC_IP>`
- `<VPS_A_PRIVATE_IP_OR_VPN_IP>`
- `<VPS_B_PUBLIC_IP>`
- `<ADMIN_IP_CIDR>` (your laptop/VPN egress)
- `<STRONG_MASTER_PASSWORD>`
- `<AGENT_VAULT_TOKEN>`
- `<VAULT_NAME>` (example: `readtheplan-agent`)

---

## 1) VPS-B (Agent Vault host) — install + start

```bash
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL https://get.agent-vault.dev | sh
export AGENT_VAULT_MASTER_PASSWORD='<STRONG_MASTER_PASSWORD>'
agent-vault server -d
```

Verify listeners:
```bash
ss -lntp | grep -E ':14321|:14322'
```

Expected: both ports listening.

---

## 2) VPS-B firewall hardening (UFW)

Policy:
- `14321/tcp` (management) only from admin source
- `14322/tcp` (proxy) only from VPS-A agent host

```bash
sudo ufw allow from <ADMIN_IP_CIDR> to any port 14321 proto tcp comment 'agent-vault-mgmt-admin-only'
sudo ufw allow from <VPS_A_PRIVATE_IP_OR_VPN_IP> to any port 14322 proto tcp comment 'agent-vault-proxy-agent-host-only'
sudo ufw deny 14321/tcp comment 'deny-public-mgmt'
sudo ufw deny 14322/tcp comment 'deny-public-proxy'
sudo ufw reload
sudo ufw status numbered
```

---

## 3) VPS-A (Hermes host) — install Agent Vault CLI

```bash
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL https://get.agent-vault.dev | sh
agent-vault --help | head -n 30
```

---

## 4) VPS-A smoke env (temporary shell test)

```bash
export AGENT_VAULT_ADDR='http://<VPS_B_PUBLIC_IP>:14321'
export AGENT_VAULT_TOKEN='<AGENT_VAULT_TOKEN>'
export AGENT_VAULT_VAULT='<VAULT_NAME>'

# Optional dummy placeholders (depends on your service mapping)
export ANTHROPIC_API_KEY='__anthropic_api_key__'
export OPENAI_API_KEY='__openai_api_key__'
export OPENROUTER_API_KEY='__openrouter_api_key__'
```

Dry-run through broker:
```bash
agent-vault run -- hermes chat -q 'Reply with exactly: broker-ok'
```

---

## 5) VPS-A persist env for gateway service (without real provider keys)

Create systemd drop-in:
```bash
mkdir -p ~/.config/systemd/user/hermes-gateway.service.d
cat > ~/.config/systemd/user/hermes-gateway.service.d/agent-vault.conf <<'EOF'
[Service]
Environment=AGENT_VAULT_ADDR=http://<VPS_B_PUBLIC_IP>:14321
Environment=AGENT_VAULT_TOKEN=<AGENT_VAULT_TOKEN>
Environment=AGENT_VAULT_VAULT=<VAULT_NAME>

# Dummy placeholders; Agent Vault swaps at egress per service rules
Environment=ANTHROPIC_API_KEY=__anthropic_api_key__
Environment=OPENAI_API_KEY=__openai_api_key__
Environment=OPENROUTER_API_KEY=__openrouter_api_key__
EOF
```

Wrap Hermes gateway start via `agent-vault run`:
```bash
cp ~/.config/systemd/user/hermes-gateway.service ~/.config/systemd/user/hermes-gateway.service.bak.$(date +%Y%m%d%H%M%S)
python3 - <<'PY'
from pathlib import Path
p = Path('/root/.config/systemd/user/hermes-gateway.service')
s = p.read_text()
old = 'ExecStart=/usr/local/lib/hermes-agent/venv/bin/python -m hermes_cli.main gateway run --replace'
new = 'ExecStart=/usr/local/bin/agent-vault run -- /usr/local/lib/hermes-agent/venv/bin/python -m hermes_cli.main gateway run --replace'
if old not in s:
    raise SystemExit('Expected ExecStart not found; aborting to avoid bad edit')
p.write_text(s.replace(old, new))
print('Patched ExecStart to agent-vault wrapper')
PY
```

Reload + restart:
```bash
systemctl --user daemon-reload
systemctl --user restart hermes-gateway
systemctl --user status hermes-gateway --no-pager
```

---

## 6) Validation checks (must pass)

Service and env sanity:
```bash
systemctl --user show hermes-gateway -p Environment | sed 's/Environment=//'
```

Functional broker check:
```bash
agent-vault run -- hermes chat -q 'Reply with exactly: broker-functional'
```

Deny-path check (strict mode expected 403 for non-allowlisted host):
```bash
HTTPS_PROXY=http://<VPS_B_PUBLIC_IP>:14322 \
HTTP_PROXY=http://<VPS_B_PUBLIC_IP>:14322 \
curl -I https://example.org -m 10
```

Expected in strict mode: deny/403 (or connection blocked per policy).

---

## 7) Rollback (instant)

If anything breaks, revert gateway unit and restart:

```bash
# Restore latest backup
LATEST=$(ls -t ~/.config/systemd/user/hermes-gateway.service.bak.* | head -n1)
cp "$LATEST" ~/.config/systemd/user/hermes-gateway.service

# Remove drop-in env if needed
rm -f ~/.config/systemd/user/hermes-gateway.service.d/agent-vault.conf

systemctl --user daemon-reload
systemctl --user restart hermes-gateway
systemctl --user status hermes-gateway --no-pager
```

---

## 8) Post-cutover monitoring (first 24h)

- Watch gateway health:
```bash
journalctl --user -u hermes-gateway -n 120 --no-pager
```

- Watch for deny spikes on Vault host and add only justified allowlist entries.
- Confirm no real upstream API keys are present in Hermes service environment.

---

## Notes

- Keep `14322` private; do not expose publicly.
- Do not store `<AGENT_VAULT_TOKEN>` in repo files.
- Prefer short-lived tokens for ephemeral workers and scheduled jobs.
