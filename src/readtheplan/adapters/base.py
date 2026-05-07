from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from readtheplan.plan import ResourceChange
from readtheplan.rules import RuleResult, apply_resource_rules


@dataclass(frozen=True)
class GateDecision:
    """Deterministic local agent gate contract for a plan analysis."""
    decision: str
    risk: str
    reason: str
    required_checks: list[str]


class BaseAdapter(ABC):
    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """The unique name of this adapter (e.g., 'cloudformation')."""
        pass

    @abstractmethod
    def can_handle(self, input_data: dict[str, Any]) -> bool:
        """Returns True if the input data matches this adapter's format."""
        pass

    @abstractmethod
    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extracts a flat list of per-resource change dicts (adapter-normalized)."""
        pass

    @abstractmethod
    def normalize_change(self, raw_change: dict[str, Any]) -> ResourceChange:
        """Maps one adapter change dict to a ResourceChange dataclass instance."""
        pass

    def analyze(self, input_data: dict[str, Any], *, use_rules: bool = True) -> list[ResourceChange]:
        """Template method: extract -> normalize -> apply rules."""
        changes = []
        for raw in self.extract_changes(input_data):
            rc = self.normalize_change(raw)
            if use_rules:
                rc = self._apply_resource_rules(rc, raw)
            changes.append(rc)
        return changes

    def _apply_resource_rules(self, rc: ResourceChange, raw: dict[str, Any]) -> ResourceChange:
        """Hooks into the shared rules engine for resource-specific risk escalation."""
        # Baseline result from the adapter's normalization
        baseline = RuleResult(risk=rc.risk, explanation=rc.explanation)
        
        # CFN adapters might store extra metadata in 'raw' to help rules.
        # For now, we pass an empty or minimal 'change' dict to rules.
        # Rules.py expects 'before' and 'after' keys for some deep checks.
        change_metadata = raw.get("_metadata", {})
        
        result = apply_resource_rules(
            resource_type=rc.resource_type,
            actions=rc.actions,
            change=change_metadata,
            baseline=baseline,
        )
        
        return ResourceChange(
            address=rc.address,
            resource_type=rc.resource_type,
            actions=rc.actions,
            risk=result.risk,
            explanation=result.explanation,
        )
