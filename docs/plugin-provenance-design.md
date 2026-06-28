# Plugin Provenance Design

## Status

Draft

## Summary

This document specifies the `RuleResult.provenance` field, the attestation-tracking pipeline for rule provenance, and the security model governing plugin-supplied rules in readtheplan. Together these three additions close the gap between "a rule fired" and "we know exactly *who* authored the rule, *where* it came from, and *whether* we trust it."

## Motivation

readtheplan's rules engine today produces a `RuleResult(risk, explanation)` for each resource change. The engine evaluates three rule sources — built-in provider modules (`rules/aws.py`, etc.), cross-cutting functions, and customer-supplied YAML overlays — but the output is a flat `risk + explanation` pair with no record of which source produced the winning result.

This creates three problems:

1. **Audit trail gap.** An auditor examining an `rtp-evidence-v1` envelope can see the final risk tier and explanation, but cannot determine whether the result came from readtheplan's built-in library, a customer overlay, or a third-party plugin. Compliance frameworks increasingly expect attribution of automated controls to their source policy.

2. **Plugin trust ambiguity.** The `@register_rule` decorator in `rules/_shared.py` accepts any callable. A plugin installed via `pip install readtheplan-acme-rules` registers functions into the same `_RULE_REGISTRY` as built-in rules, with no mechanism to distinguish trusted built-in rules from externally-supplied ones. There is no capability boundary, no integrity check, and no way to audit which plugins contributed to a gate decision.

3. **Debugging opacity.** When a rule escalates risk unexpectedly, operators have no structured way to identify which rule function produced the escalation — they must grep source code and mentally replay `_rule_candidates`. A provenance field on `RuleResult` makes this inspectable.

## Existing architecture (as-is)

### RuleResult

Defined in `src/readtheplan/rules/_shared.py`:

```python
@dataclass(frozen=True)
class RuleResult:
    risk: str
    explanation: str
```

Created by built-in rule functions (e.g., `aws._kms_candidates`), cross-cutting functions, and the action-baseline logic in `plan.py`. The highest-risk `RuleResult` wins via `_max_result()`, which uses `>=` comparison — on a tie, the later candidate replaces the current result.

### Rule registry

`_RULE_REGISTRY` maps exact resource types to lists of callables. `_CROSS_CUTTING` holds callables that run for every resource type. Both are populated at module-import time by `@register_rule` and `@register_cross_cutting` decorators. Plugin authors can import these decorators and register functions from any Python package.

### Overlays (ADR 0010)

YAML files with schema `rtp-overlay-v1` are loaded by `overlays.py` and applied *after* the rules engine. Overlays can escalate risk and append controls but never downgrade. They operate on `ResourceChange` objects, not `RuleResult` objects, and are applied in CLI-specified order.

### Evidence envelope (ADR 0007)

The `rtp-evidence-v1` JSON document wraps plan hash, framework controls, agent attestation, reviewer identity, and the change list. Each entry in `changes[]` carries `risk` and `explanation` but no provenance metadata.

### Signed attestation (ADR 0008)

Sigstore keyless signing covers the evidence envelope as a whole — it attests that a specific agent identity produced the envelope against a specific plan SHA at a specific time. It does *not* attest individual rule results or their sources.

## Design

### 1. RuleResult provenance field

Add an optional `provenance` field to `RuleResult`:

```python
@dataclass(frozen=True)
class RuleProvenance:
    source: str           # "builtin" | "plugin" | "overlay" | "baseline"
    rule_id: str          # stable identifier, e.g. "aws.kms_replace"
    package: str | None   # Python distribution name, e.g. "readtheplan-acme-rules"
    version: str | None   # package version, e.g. "1.2.0"
    sha256: str | None    # SHA-256 of the rule source file (for plugins)


@dataclass(frozen=True)
class RuleResult:
    risk: str
    explanation: str
    provenance: RuleProvenance | None = None
```

#### Source taxonomy

| `source` value | Origin | Example `rule_id` |
|---|---|---|
| `"baseline"` | Action-based baseline in `plan.py` | `"baseline.delete"` |
| `"builtin"` | Built-in `@register_rule` functions shipped in `readtheplan` | `"aws.kms_replace"` |
| `"plugin"` | External Python package using `@register_rule` | `"acme.lambda_ephi_check"` |
| `"overlay"` | Customer-supplied `rtp-overlay-v1` YAML | `"overlay.acme-prod.risk_overrides[0]"` |

#### Rule ID conventions

Rule IDs are dotted strings. Built-in rules use `<provider>.<short_name>` (e.g., `aws.kms_replace`, `gcp.sql_delete`, `k8s.secret_update`). Plugin rules use `<plugin_namespace>.<short_name>`. Overlay rules use `overlay.<overlay_name>.<path>`.

Rule IDs are stable across versions within a major release. Renaming a rule ID is a breaking change and requires a changelog entry.

#### Backwards compatibility

`provenance` defaults to `None`. Existing code that constructs `RuleResult(risk, explanation)` continues to work. The field is additive — `_max_result()` ignores it when comparing candidates, and only the winning result's provenance propagates to the output.

### 2. Provenance in the evidence pipeline

#### ResourceChange serialization

`ResourceChange.to_dict()` gains an optional `provenance` key:

```python
def to_dict(self) -> dict[str, Any]:
    d = {
        "address": self.address,
        "type": self.resource_type,
        "actions": list(self.actions),
        "risk": self.risk,
        "explanation": self.explanation,
    }
    if self.provenance is not None:
        d["provenance"] = {
            "source": self.provenance.source,
            "rule_id": self.provenance.rule_id,
            "package": self.provenance.package,
            "version": self.provenance.version,
        }
    return d
```

Note: the `sha256` field of `RuleProvenance` is intentionally excluded from the serialized evidence envelope. It is available at runtime for gate-level integrity checks (see section 3) but is not persisted in the evidence artifact. This keeps the envelope stable regardless of rule-file edits that don't change behavior.

#### Evidence envelope changes

The `changes[]` array in `rtp-evidence-v1` already allows additional keys without a schema version bump (per ADR 0007: "New optional fields can be added to v1 without bumping. Downstream consumers should ignore unknown fields."). Adding `provenance` to each change entry is a non-breaking addition.

The envelope's top-level `summary` object gains a new optional field:

```json
{
  "summary": {
    "rule_sources": {
      "builtin": 5,
      "plugin": 2,
      "overlay": 1,
      "baseline": 3
    }
  }
}
```

This gives auditors a quick breakdown of how many rule results came from each source without walking the full change list.

#### Attestation coverage

The existing sigstore signature covers the entire evidence envelope (ADR 0008). Because provenance metadata is now embedded in the envelope's `changes[]` entries, the signature implicitly attests the provenance chain. No changes are needed to `signing.py` or the signing payload canonicalization.

However, the signed envelope only attests that the agent *claims* a rule came from a given source. It does not independently verify that claim. Independent verification is the responsibility of the plugin security model (section 3).

### 3. Security model for plugin-supplied rules

#### Threat model

Plugin-supplied rules are Python code that runs in the same process as readtheplan. The threats are:

1. **Risk downgrade.** A malicious plugin registers a rule that returns `safe` for a resource type that the built-in library classifies as `dangerous`, effectively silencing the warning.
2. **Explanation injection.** A plugin returns an `explanation` string that misleads the reviewer (e.g., "This change is pre-approved by security team").
3. **Side-channel exfiltration.** A plugin's rule function reads environment variables, plan data, or filesystem contents and exfiltrates them.
4. **Supply-chain compromise.** A legitimate plugin package is compromised at the registry (PyPI) or dependency level.
5. **Provenance spoofing.** A plugin sets `source: "builtin"` on its `RuleProvenance` to masquerade as a built-in rule.

#### Design principles

**Composition, not replacement.** The existing invariant that overlays and rules can only escalate risk, never downgrade, is the primary defense against threat 1. This invariant is already enforced by `_max_result()` in the rules engine and `apply_overlay_to_change()` in the overlay engine. Plugin rules participate in the same max-risk composition — they can raise the ceiling but never lower the floor.

**Attribution, not sandboxing.** Full process-level sandboxing of plugin code is out of scope for v1. The security model focuses on *attribution*: making it visible and auditable which rules came from which source, so that operators and compliance reviewers can make informed trust decisions. This is consistent with the Terraform provider model, where providers run in-process and trust is established at the supply-chain level.

**Verify, then trust.** Plugin integrity is checked at load time, not at rule-evaluation time. This avoids per-invocation overhead and keeps the hot path fast.

#### Plugin manifest

Each plugin package must include a `readtheplan-plugin.toml` manifest at the package root:

```toml
[plugin]
name = "acme-infra-rules"
namespace = "acme"
version = "1.2.0"
min_readtheplan = "0.6.0"

[plugin.author]
name = "Acme Corp Platform Team"
email = "platform@acme.com"

[plugin.rules]
# Declares which resource types this plugin registers rules for.
# Used for documentation and conflict detection — not enforcement.
resource_types = [
    "aws_lambda_function",
    "aws_efs_file_system",
]

[plugin.permissions]
# Declarative capability flags. All default to false.
network = false           # rule functions may make network calls
filesystem_read = false   # rule functions may read files outside the plan
env_access = false        # rule functions may read environment variables
```

The manifest is informational and documentary for v1. Runtime enforcement of permissions requires process-level isolation, which is out of scope. The manifest's value in v1 is that it makes the plugin's declared capabilities visible to operators and CI policy checks.

#### Plugin discovery and loading

Plugins are discovered via Python `importlib.metadata` entry points under the group `readtheplan.plugins`:

```toml
# In the plugin's pyproject.toml
[project.entry-points."readtheplan.plugins"]
acme = "readtheplan_acme_rules:register"
```

The entry point function receives a `PluginContext` and must return a `PluginRegistration`:

```python
@dataclass(frozen=True)
class PluginContext:
    readtheplan_version: str
    registry: RuleRegistry          # typed wrapper around _RULE_REGISTRY

@dataclass(frozen=True)
class PluginRegistration:
    namespace: str
    version: str
    rule_count: int
```

Built-in rules are loaded first, at module-import time (as today). Plugins are loaded second, during CLI initialization. Overlays are loaded third, at analysis time. This ordering guarantees that built-in rules always contribute to the baseline before plugins or overlays can escalate.

#### Provenance injection

When a plugin registers a rule via the `PluginContext.registry`, the registry wrapper automatically attaches `RuleProvenance(source="plugin", ...)` to every `RuleResult` the function returns. The plugin author does not construct `RuleProvenance` manually — the framework injects it. This prevents threat 5 (provenance spoofing).

```python
# Internal implementation in rules/_shared.py

def _wrap_plugin_rule(
    func: Callable,
    *,
    namespace: str,
    package: str,
    version: str,
    source_sha256: str | None,
) -> Callable:
    """Wrap a plugin rule function to inject provenance on every RuleResult."""
    @functools.wraps(func)
    def wrapper(resource_type, action_set, change):
        results = func(resource_type, action_set, change)
        return [
            RuleResult(
                risk=r.risk,
                explanation=r.explanation,
                provenance=RuleProvenance(
                    source="plugin",
                    rule_id=f"{namespace}.{func.__name__}",
                    package=package,
                    version=version,
                    sha256=source_sha256,
                ),
            )
            for r in results
        ]
    return wrapper
```

Similarly, built-in rules are wrapped at registration time with `source="builtin"`, and baseline results in `plan.py` are constructed with `source="baseline"`. Overlay results in `overlays.py` are constructed with `source="overlay"`.

#### Integrity checking

At plugin load time, the loader computes the SHA-256 of the plugin's rule source file(s) and records it in the `RuleProvenance.sha256` field. This hash is available at runtime for optional policy checks:

```bash
# CI policy: only allow plugins whose rule source matches a pinned hash
readtheplan analyze --plugin-policy pin:acme=sha256:abc123... plan.json
```

The `--plugin-policy` flag accepts:

| Policy | Behavior |
|---|---|
| `allow:*` | Load all discovered plugins (default) |
| `allow:acme,internal` | Only load plugins with these namespaces |
| `deny:acme` | Load all plugins except these namespaces |
| `pin:<ns>=sha256:<hash>` | Load plugin only if source hash matches |
| `none` | Disable all plugins; only built-in rules and overlays |

#### Conflict detection

When a plugin registers a rule for a resource type that already has a built-in rule, the loader emits a warning:

```
WARNING: plugin 'acme' registers rule for 'aws_kms_key' which already has built-in rules.
Both will run; the highest-risk result wins.
```

This is informational, not blocking. The max-risk composition model means both rules contribute; the more conservative result wins. Operators who want to disable the built-in rule for a resource type can use an overlay to set the explanation without changing risk.

#### Agent gate integration

The agent gate contract (`rtp-agent-gate-v1`) gains a new optional field:

```json
{
  "plugin_rules_loaded": [
    {
      "namespace": "acme",
      "package": "readtheplan-acme-rules",
      "version": "1.2.0",
      "rule_count": 3,
      "source_sha256": "abc123..."
    }
  ]
}
```

This allows CI gates to enforce plugin allow/deny lists at the gate level, not just at the CLI level. A CI pipeline can inspect the gate output and fail if an unapproved plugin contributed to the decision.

## Migration path

### Phase 1 (non-breaking)

Add `RuleProvenance` and the `provenance` field to `RuleResult` with a default of `None`. Attach provenance to built-in rules and baseline results. No plugin loading infrastructure yet. Ship provenance in the evidence envelope `changes[]` array.

This phase requires changes to:

- `src/readtheplan/rules/_shared.py` — add `RuleProvenance`, update `RuleResult`, update `@register_rule` to inject `source="builtin"` provenance
- `src/readtheplan/plan.py` — attach `source="baseline"` provenance to baseline results, propagate `provenance` through `ResourceChange`
- `src/readtheplan/overlays.py` — attach `source="overlay"` provenance to overlay results
- `src/readtheplan/evidence.py` — serialize provenance in `_change_to_dict`, add `rule_sources` to summary

### Phase 2 (plugin loading)

Add `PluginContext`, `PluginRegistration`, entry-point discovery, provenance wrapping, and `--plugin-policy` CLI flag. Ship `readtheplan-plugin.toml` spec.

This phase requires:

- New module `src/readtheplan/plugins.py` — discovery, loading, manifest parsing, policy enforcement
- Updates to `src/readtheplan/cli.py` — `--plugin-policy` flag, plugin loading during init
- Updates to `src/readtheplan/agent_gate.py` — `plugin_rules_loaded` field
- New test fixtures and integration tests

### Phase 3 (future, out of scope)

Process-level isolation for plugin rule functions (e.g., subprocess or WASM sandbox). Runtime enforcement of declared permissions. Plugin signing with sigstore (extending ADR 0008 to plugin packages, not just evidence envelopes).

## Alternatives considered

**Embedding provenance in the explanation string.** Appending `[source: acme/1.2.0]` to the explanation text. Rejected because it's unstructured, hard to parse programmatically, and pollutes the human-readable explanation.

**Separate provenance sidecar file.** Writing provenance to a separate JSON file alongside the evidence envelope. Rejected because it breaks the "one artifact per analysis" contract established by ADR 0007 and creates a file-pairing problem for CI pipelines.

**DSSE predicates for per-rule attestation.** Wrapping each rule result in a DSSE predicate with its own signature. Rejected as over-engineered for v1 — the envelope-level signature from ADR 0008 is sufficient when combined with the provenance metadata inside the envelope.

**Denying plugin rules that overlap built-in types.** Refusing to load a plugin that registers for `aws_kms_key` when a built-in rule already covers it. Rejected because it would prevent legitimate use cases like organization-specific hardening of built-in resource types. The max-risk composition model already handles this safely.

## Open questions

1. **Should overlays gain `rule_id` fields?** Currently overlay risk overrides are matched by position (`risk_overrides[0]`). Adding an explicit `id` field to the overlay schema would make provenance more stable across file edits. This would be a non-breaking addition to `rtp-overlay-v1`.

2. **Should the MCP server expose plugin metadata?** The `analyze_plan` and `agent_gate` MCP tools could return plugin provenance in their responses, making it visible to AI agents. This is low-risk but adds surface area.

3. **Per-rule telemetry.** Should the CLI emit structured logs or OpenTelemetry spans per rule evaluation? This would help with debugging but adds a dependency and performance overhead.

## References

- [ADR 0004: Resource-Aware Rule Library](adr/0004-resource-aware-rule-library.md)
- [ADR 0007: Evidence Envelope](adr/0007-evidence-envelope.md)
- [ADR 0008: Signed Attestation](adr/0008-signed-attestation.md)
- [ADR 0010: Customer-Supplied Rule Overrides](adr/0010-customer-supplied-rule-overrides.md)
- [Authoring rules guide](authoring-rules.md)
- [Sigstore Python package](https://sigstore.github.io/sigstore-python/)
- [Python entry points specification](https://packaging.python.org/en/latest/specifications/entry-points/)
