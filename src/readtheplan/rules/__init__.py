"""Resource risk rules — public API.

The rules engine is split into per-provider modules under this package.
``apply_resource_rules`` dispatches to the appropriate provider module
based on resource type, then merges results with the baseline.

Public API (re-exported):
    - ``RISK_ORDER``: severity ranking
    - ``RuleResult``: risk + explanation dataclass
    - ``action_explanation``: human-readable action summary
    - ``apply_resource_rules``: main entry point
    - ``_DEPRECATED_RUNTIMES``: snapshot used by freshness tests

Internal layout:
    - ``_shared``: constants, shared helpers, dispatcher
    - ``aws``: AWS resource rules
    - ``gcp``: Google Cloud resource rules
    - ``azure``: Azure resource rules
    - ``k8s``: Kubernetes resource rules
"""
from __future__ import annotations

from readtheplan.rules._shared import (
    RISK_ORDER,
    RuleResult,
    _DEPRECATED_RUNTIMES,
    action_explanation,
    apply_resource_rules,
)

__all__ = [
    "RISK_ORDER",
    "RuleResult",
    "action_explanation",
    "apply_resource_rules",
]
