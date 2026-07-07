"""Resource risk rules — public API.

The rules engine is split into per-provider modules under this package.
``apply_resource_rules`` dispatches to the appropriate provider module
based on resource type, then merges results with the baseline.

Public API (re-exported):
    - ``RISK_ORDER``: severity ranking
    - ``RuleResult``: risk + explanation dataclass
    - ``action_explanation``: human-readable action summary
    - ``apply_resource_rules``: main entry point
    - ``register_rule``: decorator to register a rule for resource type(s)
    - ``register_cross_cutting``: decorator for prefix-matching rules
    - ``_DEPRECATED_RUNTIMES``: snapshot used by freshness tests

Internal layout:
    - ``_shared``: constants, shared helpers, dispatcher, rule registry
    - ``aws``: AWS resource rules
    - ``gcp``: Google Cloud resource rules
    - ``azure``: Azure resource rules
    - ``k8s``: Kubernetes resource rules
"""
from __future__ import annotations

from readtheplan.rules._shared import (
    _DEPRECATED_RUNTIMES,
    RISK_ORDER,
    RULES_ENTRY_POINT_GROUP,
    RuleResult,
    action_explanation,
    apply_resource_rules,
    load_entry_point_rules,
    register_cross_cutting,
    register_rule,
)

__all__ = [
    "RISK_ORDER",
    "_DEPRECATED_RUNTIMES",
    "RULES_ENTRY_POINT_GROUP",
    "RuleResult",
    "action_explanation",
    "apply_resource_rules",
    "load_entry_point_rules",
    "register_cross_cutting",
    "register_rule",
]
