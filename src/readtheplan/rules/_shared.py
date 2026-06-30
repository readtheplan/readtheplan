from __future__ import annotations

import json
import re
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from importlib.metadata import entry_points
from typing import Any

# ── Rule registry ──────────────────────────────────────────────────────
# Plugin authors can import `register_rule` from `readtheplan.rules` and
# register their own candidate functions.  Each function must have the
# signature: ``(resource_type: str, action_set: set[str], change: dict)
# -> list[RuleResult]``.

_RULE_REGISTRY: dict[str, list[Callable[..., list[RuleResult]]]] = {}
"""Exact resource-type → list of rule functions.  All registered functions
accumulate (no short-circuit).  See also ``_CROSS_CUTTING``."""

_CROSS_CUTTING: list[Callable[..., list[RuleResult]]] = []
"""Functions that run **for every resource type**.  They self-filter
internally by checking the ``resource_type`` prefix.  Currently holds the
AWS platform/network/observability candidate functions."""


# ── Plugin provenance ──────────────────────────────────────────────────
# Tracks the "current" provenance source while a plugin's entry point is being
# loaded, so any rules it registers are attributed to that plugin rather than to
# the default "builtin".  Builtin rules register at import time, when the source
# is still the default, so they remain "builtin".
RULES_ENTRY_POINT_GROUP = "readtheplan.rules"

_current_source: str = "builtin"


@contextmanager
def _source_context(source: str):
    """Temporarily set the provenance source applied to rules registered inside
    the ``with`` block (used by entry-point discovery)."""
    global _current_source
    previous = _current_source
    _current_source = source
    try:
        yield
    finally:
        _current_source = previous


def register_rule(*resource_types: str, source: str | None = None) -> Callable:
    """Decorator that registers a candidate function for exact resource types.

    Example::

        @register_rule("aws_kms_key")
        def _kms_candidates(
            resource_type: str, action_set: set[str], change: dict,
        ) -> list[RuleResult]:
            ...

    The registered function **must** accept ``(resource_type, action_set,
    change)`` and return ``list[RuleResult]``.  If the underlying
    implementation doesn't need the ``resource_type`` or ``change``
    parameters, accept them and ignore them — the caller always passes
    all three.
    """
    src = source if source is not None else _current_source

    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__rtp_source__"):
            func.__rtp_source__ = src
        for rt in resource_types:
            bucket = _RULE_REGISTRY.setdefault(rt, [])
            if func not in bucket:  # idempotent: re-discovery must not duplicate
                bucket.append(func)
        return func
    return decorator


def register_cross_cutting(func: Callable, *, source: str | None = None) -> Callable:
    """Register a function that runs for every resource type.

    The function self-filters by inspecting ``resource_type`` internally
    (e.g. checking ``resource_type.startswith(\"aws_\")``).
    """
    if not hasattr(func, "__rtp_source__"):
        func.__rtp_source__ = source if source is not None else _current_source
    if func not in _CROSS_CUTTING:  # idempotent: re-discovery must not duplicate
        _CROSS_CUTTING.append(func)
    return func


# ── Risk classification primitives ─────────────────────────────────────

RISK_ORDER = {
    "safe": 0,
    "review": 1,
    "dangerous": 2,
    "irreversible": 3,
}


@dataclass(frozen=True)
class RuleResult:
    risk: str
    explanation: str
    #: Provenance — "builtin" for core rules, else the plugin (entry point) name
    #: that registered the rule that produced this result.
    source: str = "builtin"




def action_explanation(actions: tuple[str, ...], *, tool_name: str = "Terraform") -> str:
    if not actions:
        return f"{tool_name} action metadata is missing or unknown; human review is required."
    action_set = set(actions)
    if "delete" in action_set and "create" in action_set:
        return (
            f"{tool_name} will replace this resource. Review downtime, identity "
            "changes, and any state that must be migrated or restored."
        )
    if "delete" in action_set:
        return (
            f"{tool_name} will delete this resource. Verify recovery, backups, and "
            "external dependencies before applying."
        )
    if "update" in action_set:
        return (
            f"{tool_name} will update this resource in place. Review the changed "
            "attributes and rollout timing before applying."
        )
    if action_set <= {"no-op", "read"}:
        return f"{tool_name} is only reading or refreshing this resource."
    if "create" in action_set and action_set <= {"create", "no-op", "read", "update"}:
        return f"{tool_name} will create a new resource without changing existing state."
    return f"{tool_name} action metadata is missing or unknown; human review is required."




def apply_resource_rules(
    *,
    resource_type: str,
    actions: tuple[str, ...],
    change: dict[str, Any],
    baseline: RuleResult,
    tool_name: str = "Terraform",
) -> RuleResult:
    result = baseline
    for candidate in _rule_candidates(resource_type, actions, change):
        result = _max_result(result, candidate)
    # Post-process: replace __TOOL__ sentinel with the actual tool name.
    # This avoids blind string-replace of "Terraform" which could
    # mangle compound names like "Terraform Cloud".
    if result is not baseline:
        result = RuleResult(
            risk=result.risk,
            explanation=result.explanation.replace("__TOOL__", tool_name),
            source=result.source,
        )
    return result




def _rule_candidates(
    resource_type: str,
    actions: tuple[str, ...],
    change: dict[str, Any],
) -> list[RuleResult]:
    """Look up registered rule functions from the decorator-based registry."""
    action_set = set(actions)
    candidates: list[RuleResult] = []

    # Exact resource-type rules
    for func in _RULE_REGISTRY.get(resource_type, []):
        candidates.extend(_stamp_source(func, func(resource_type, action_set, change)))

    # Cross-cutting rules (run for every type, self-filter internally)
    for func in _CROSS_CUTTING:
        candidates.extend(_stamp_source(func, func(resource_type, action_set, change)))

    return candidates


def _stamp_source(func: Callable, results: list[RuleResult]) -> list[RuleResult]:
    """Tag each result with the registering function's provenance source unless
    the result already declares a non-builtin source of its own."""
    src = getattr(func, "__rtp_source__", "builtin")
    if src == "builtin":
        return results
    return [r if r.source != "builtin" else replace(r, source=src) for r in results]





def _policy_resource_candidates(
    action_set: set[str],
    change: dict[str, Any],
    label: str,
    protected_subject: str,
) -> list[RuleResult]:
    candidates: list[RuleResult] = []
    if "delete" in action_set:
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    f"__TOOL__ will delete a {label}. Access for {protected_subject} "
                    "may become too broad or too restrictive depending on defaults."
                ),
            )
        )
    elif "update" in action_set or "create" in action_set:
        candidates.append(
            RuleResult(
                "review",
                (
                    f"__TOOL__ will change a {label}. Review principals, actions, "
                    "and cross-account access before applying."
                ),
            )
        )

    policy = _policy_document(_after_value(change, "policy"))
    if policy is not None and _policy_allows_public(policy):
        candidates.append(
            RuleResult(
                "dangerous",
                (
                    f"This {label} appears to allow public access. Public or "
                    "anonymous access requires security review."
                ),
            )
        )
    return candidates




def _max_result(current: RuleResult, candidate: RuleResult) -> RuleResult:
    current_rank = RISK_ORDER.get(current.risk, RISK_ORDER["review"])
    candidate_rank = RISK_ORDER.get(candidate.risk, RISK_ORDER["review"])
    if candidate_rank >= current_rank:
        return candidate
    return current




def _before_value(change: dict[str, Any], key: str) -> Any:
    before = change.get("before")
    if isinstance(before, dict):
        return before.get(key)
    return None




def _after_value(change: dict[str, Any], key: str) -> Any:
    after = change.get("after")
    if isinstance(after, dict):
        return after.get(key)
    return None




def _attribute_changed(change: dict[str, Any], key: str) -> bool:
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    return before.get(key) != after.get(key)




def _major_version_changed(change: dict[str, Any], key: str) -> bool:
    if not _attribute_changed(change, key):
        return False
    before_major = _major_version(_before_value(change, key))
    after_major = _major_version(_after_value(change, key))
    return before_major is not None and after_major is not None and after_major != before_major




def _major_version(value: Any) -> int | None:
    if value is None:
        return None
    match = re.match(r"^\s*(\d+)", str(value))
    if match is None:
        return None
    return int(match.group(1))




def _health_check_changed(change: dict[str, Any]) -> bool:
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    before_hc = before.get("health_check")
    after_hc = after.get("health_check")
    return before_hc != after_hc and before_hc is not None and after_hc is not None




def _runtime_major_changed(change: dict[str, Any]) -> bool:
    if not _attribute_changed(change, "runtime"):
        return False
    before_rt = _before_value(change, "runtime")
    after_rt = _after_value(change, "runtime")
    if not isinstance(before_rt, str) or not isinstance(after_rt, str):
        return False
    before_major = _extract_runtime_major(before_rt)
    after_major = _extract_runtime_major(after_rt)
    return (
        before_major is not None
        and after_major is not None
        and before_major != after_major
    )




def _extract_runtime_major(runtime: str) -> str | None:
    match = re.match(r"^([a-zA-Z]+)(\d+)", runtime)
    if match is None:
        return None
    return f"{match.group(1)}{match.group(2)}"


# AWS Lambda runtimes deprecated as of 2026-05.
# See https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
_DEPRECATED_RUNTIMES: set[str] = {
    "nodejs12.x",
    "nodejs14.x",
    "nodejs16.x",
    "nodejs18.x",
    "python3.6",
    "python3.7",
    "python3.8",
    "python3.9",
    "dotnetcore3.1",
    "dotnet5.0",
    "dotnet6",
    "ruby2.5",
    "ruby2.7",
    "java8",
    "java8.al2",
    "go1.x",
    "provided",
}




def _runtime_deprecated(change: dict[str, Any]) -> bool:
    """Check if the runtime is deprecated (in after value) or changing to deprecated."""
    after = _after_value(change, "runtime")
    if isinstance(after, str) and after in _DEPRECATED_RUNTIMES:
        return True
    before = _before_value(change, "runtime")
    if isinstance(before, str) and before in _DEPRECATED_RUNTIMES:
        return True
    return False




def _route_opens_internet_path(change: dict[str, Any]) -> bool:
    destination = _after_value(change, "destination_cidr_block")
    ipv6_destination = _after_value(change, "destination_ipv6_cidr_block")
    gateway_id = _after_value(change, "gateway_id")
    return (
        (destination == "0.0.0.0/0" or ipv6_destination == "::/0")
        and isinstance(gateway_id, str)
        and (gateway_id.startswith("igw-") or "internet_gateway" in gateway_id)
    )




def _retention_decreased(change: dict[str, Any], key: str) -> bool:
    if not _attribute_changed(change, key):
        return False
    before = _before_value(change, key)
    after = _after_value(change, key)
    if not isinstance(before, int) or not isinstance(after, int):
        return False
    return after < before




def _s3_public_exposure(resource_type: str, change: dict[str, Any]) -> bool:
    acl = _after_value(change, "acl")
    if isinstance(acl, str) and acl.lower() in {"public-read", "public-read-write"}:
        return True

    if resource_type == "aws_s3_bucket_policy" or _after_value(change, "policy"):
        policy = _policy_document(_after_value(change, "policy"))
        return policy is not None and _policy_allows_public(policy)
    return False




def _security_group_opens_to_internet(resource_type: str, change: dict[str, Any]) -> bool:
    if resource_type == "aws_security_group":
        ingress = _after_value(change, "ingress")
        if isinstance(ingress, list):
            return any(_rule_block_opens_to_internet(rule) for rule in ingress)
        return _rule_block_opens_to_internet(ingress)

    return _rule_block_opens_to_internet(change.get("after"))




def _rule_block_opens_to_internet(value: Any) -> bool:
    if isinstance(value, dict):
        cidrs = value.get("cidr_blocks")
        if isinstance(cidrs, list) and any(cidr == "0.0.0.0/0" for cidr in cidrs):
            return True
        ipv6_cidrs = value.get("ipv6_cidr_blocks")
        if isinstance(ipv6_cidrs, list) and any(cidr == "::/0" for cidr in ipv6_cidrs):
            return True

        if value.get("cidr_ipv4") == "0.0.0.0/0" or value.get("cidr_ipv6") == "::/0":
            return True

        nested_ingress = value.get("ingress")
        if isinstance(nested_ingress, list) and any(
            _rule_block_opens_to_internet(rule) for rule in nested_ingress
        ):
            return True

    return False




def _policy_document(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return None
        if isinstance(decoded, dict):
            return decoded
    return None




def _policy_allows_public(policy: dict[str, Any]) -> bool:
    return any(
        _statement_effect(statement) == "allow" and _principal_is_public(statement)
        for statement in _statements(policy)
    )




def _has_deny_statement(policy: dict[str, Any]) -> bool:
    return any(_statement_effect(statement) == "deny" for statement in _statements(policy))




def _statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [statement for statement in statements if isinstance(statement, dict)]




def _statement_effect(statement: dict[str, Any]) -> str:
    return str(statement.get("Effect", "")).lower()




def _principal_is_public(statement: dict[str, Any]) -> bool:
    principal = statement.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any(_contains_public_principal(value) for value in principal.values())
    return False




def _contains_public_principal(value: Any) -> bool:
    if value == "*":
        return True
    if isinstance(value, list):
        return any(item == "*" for item in value)
    return False

# ── Import provider modules to trigger @register_rule decorators ──────
# Placed at the end so ALL symbols (RuleResult, _after_value, etc.) are
# defined before provider modules try to import them.
from readtheplan.rules import aws, azure, gcp, k8s  # noqa: E402, F401


# Dynamically load auto-generated rules
try:
    from pathlib import Path
    import importlib
    import pkgutil

    def _load_auto_rules() -> None:
        auto_dir = Path(__file__).parent / "auto"
        if not auto_dir.exists():
            auto_dir.mkdir(parents=True, exist_ok=True)
        init_file = auto_dir / "__init__.py"
        if not init_file.exists():
            init_file.write_text('"""Auto-generated rules package."""\n', encoding="utf-8")
        
        package_name = "readtheplan.rules.auto"
        try:
            auto_pkg = importlib.import_module(package_name)
            for _, module_name, _ in pkgutil.iter_modules(auto_pkg.__path__):
                importlib.import_module(f"{package_name}.{module_name}")
        except Exception:
            pass

    _load_auto_rules()
except Exception:
    pass



def load_entry_point_rules() -> list[str]:
    """Discover and register rules contributed by external packages via the
    ``readtheplan.rules`` entry point group.

    Each entry point is loaded with its provenance source set to the entry point
    name, so any rules it registers are attributed to that plugin (see
    :class:`RuleResult.source`). The entry point may be either a module (whose
    ``@register_rule`` decorators fire on import) or a zero-arg callable hook.

    Best-effort and idempotent: a failure in any single plugin is isolated and
    never breaks import of the core package, and re-running never duplicates
    registrations. Returns the list of discovered entry point names.
    """
    discovered: list[str] = []
    try:
        eps = entry_points(group=RULES_ENTRY_POINT_GROUP)
    except Exception:
        return discovered
    for ep in eps:
        try:
            with _source_context(ep.name):
                obj = ep.load()
                if callable(obj):
                    obj()
            discovered.append(ep.name)
        except Exception:
            continue
    return discovered


# Discover external rule plugins (best-effort; idempotent). Builtins above are
# already registered as "builtin"; entry points for them resolve to cached
# modules and re-register nothing.
load_entry_point_rules()
