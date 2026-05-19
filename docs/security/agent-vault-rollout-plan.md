# Agent Vault rollout plan for readtheplan SaaS (Hermes + VPS)

## Objective
Adopt secretless agent execution so Hermes never receives real API credentials in prompt/runtime context, while preserving current CI/security posture and enabling fast rollback.

## Scope
- In scope: Hermes agent runtime on VPS, outbound API credential brokering, egress policy, observability, rollback.
- Out of scope: app-user auth changes, Terraform module redesign, non-agent production traffic.

## Target architecture
- **VPS-A (Agent Host):** Hermes gateway + agent workloads.
- **VPS-B (Vault Host):** Agent Vault server (management API/UI :14321, proxy :14322).
- Hermes runs with `agent-vault run -- hermes` and proxy env injected.
- Agent-facing env uses placeholders (dummy tokens) where supported; real credentials live only in Agent Vault.

## Security requirements (hard gates)
1. `unmatched_host_policy=deny` (no blind pass-through).
2. Proxy port `14322` private to agent network only.
3. Management `14321` locked to admin IP/VPN/reverse proxy auth.
4. Short-lived scoped agent tokens for ephemeral jobs; rotated long-lived token for persistent gateway.
5. Outbound host allowlist enforced at both Agent Vault service rules and host firewall layer.
6. Full request audit logs enabled and retained.

---

## Phase 0 — Dry run in staging (no production cutover)

### 0.1 Provision + isolate
- Deploy Agent Vault on VPS-B.
- Do **not** expose `14322` publicly.
- Restrict `14321` to admin source(s).

### 0.2 Baseline config
- Create vault: `readtheplan-agent`.
- Add first service mappings for only required domains (start minimal):
  - `api.github.com`
  - model provider endpoints currently used by Hermes
  - any mandatory SaaS API endpoints
- Set strict unmatched policy to deny.

### 0.3 Test token and session
- Create dedicated Hermes agent identity + token.
- Export on VPS-A:
  - `AGENT_VAULT_ADDR=http://<vault-host>:14321`
  - `AGENT_VAULT_TOKEN=<agent token>`
  - `AGENT_VAULT_VAULT=readtheplan-agent`
- Launch test:
  - `agent-vault run -- hermes chat -q "health check: echo reachable services only"`

### 0.4 Validation checklist
- Allowed endpoint succeeds via broker.
- Non-allowlisted endpoint returns deny/403.
- Request logs show brokered traffic.
- No real secret appears in Hermes output/session logs.

Rollback: stop using wrapper and run normal Hermes process.

---

## Phase 1 — Partial production (low-risk credentials first)

### 1.1 Move only selected secrets behind broker
Start with keys that are high-value but low blast radius if requests fail:
- LLM provider key(s) used by agent runs.
- GitHub token for read-only/review operations.

Keep critical deploy credentials outside scope for this phase.

### 1.2 Systemd integration (Hermes on VPS-A)
- Update Hermes gateway service to run through Agent Vault wrapper.
- Inject only Agent Vault env in service unit/env file (never raw provider keys).
- Keep prior unit as backup file for instant revert.

### 1.3 Production checks
- Existing task flows still pass (web search, repo reads, CI checks).
- Security scans still green.
- Latency impact acceptable.
- Deny logs reviewed for missing allowlist entries.

Rollback: restore previous systemd ExecStart and restart gateway.

---

## Phase 2 — Full brokered mode

### 2.1 Expand coverage
Add remaining agent-used credentials/service mappings:
- write-capable GitHub automation token (if used)
- external APIs used by cron or workers
- any MCP/connector credentials used by agent runtime

### 2.2 Token lifecycle hardening
- Long-lived token for always-on gateway: rotate on schedule (e.g., every 14–30 days).
- Short-lived scoped tokens for ephemeral workers/cron sandboxes.
- Immediate revoke process documented.

### 2.3 Defense-in-depth
- Host firewall egress allowlist on VPS-A to known destinations.
- Alerting on denied requests spikes.
- Alerting on service mapping changes.

Rollback: per-service fallback by disabling affected mapping and temporarily restoring direct key path for that single dependency.

---

## Operational runbook

## A) Daily checks
- Agent Vault health endpoint/UI reachable from admin network.
- Denied request count trend normal.
- Token expiry/rotation window not breached.

## B) Incident playbook (suspected prompt injection)
1. Pause agent jobs.
2. Revoke active Agent Vault token.
3. Review request logs for unusual destinations.
4. Rotate mapped upstream secrets.
5. Reissue new scoped token.
6. Resume with tightened allowlist.

## C) Change control
Any new outbound integration must include:
- explicit host/path mapping
- owner
- risk level
- rollback step
- test evidence

---

## Acceptance criteria for completion
- Hermes production runtime no longer stores/uses raw upstream credentials in its runtime env for brokered services.
- Unknown outbound hosts are denied by default.
- Token rotation and revoke tested successfully.
- Security + CI behavior unchanged or improved.
- Runbook documented and verified in one tabletop exercise.

## Suggested first implementation batch for your stack
1. LLM provider endpoint(s)
2. GitHub API
3. Any webhook target used by scheduled automations

This gives immediate exfiltration-risk reduction with minimal service disruption risk.
