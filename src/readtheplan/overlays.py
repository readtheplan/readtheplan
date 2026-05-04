from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, cast

import yaml

from readtheplan.controls import ControlCatalog, ControlEntry
from readtheplan.plan import ResourceChange
from readtheplan.rules import RISK_ORDER

OVERLAY_SCHEMA = "rtp-overlay-v1"
_MATCH_KEYS = frozenset({"resource_type", "address_prefix", "address", "account_id"})


@dataclass(frozen=True)
class RiskOverride:
    match: Mapping[str, Any]
    risk: str
    explanation: str


@dataclass(frozen=True)
class Overlay:
    schema: str
    name: str
    description: str
    risk_overrides: tuple[RiskOverride, ...]
    control_additions: Mapping[str, Any] | None


class OverlayError(ValueError):
    """Raised when an overlay file is invalid."""


@dataclass(frozen=True)
class _OverlayControlMapping:
    actions: tuple[str, ...]
    controls: tuple[ControlEntry, ...]


def load_overlay(path: str | Path) -> Overlay:
    """Load and validate an overlay YAML file."""

    overlay_path = Path(path)
    try:
        data = yaml.safe_load(overlay_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise OverlayError(f"{overlay_path}: invalid YAML: {exc}") from exc
    except OSError as exc:
        raise OverlayError(f"{overlay_path}: cannot read overlay: {exc}") from exc

    raw = _expect_mapping(data, overlay_path, "$")
    schema = _required_str(raw, "schema", overlay_path, "$")
    if schema != OVERLAY_SCHEMA:
        raise OverlayError(
            f'{overlay_path}: expected $.schema "{OVERLAY_SCHEMA}", got "{schema}"'
        )

    return Overlay(
        schema=schema,
        name=_required_str(raw, "name", overlay_path, "$"),
        description=_required_str(raw, "description", overlay_path, "$"),
        risk_overrides=_risk_overrides(raw, overlay_path),
        control_additions=_control_additions(raw, overlay_path),
    )


def apply_overlay_to_change(
    change: ResourceChange,
    overlay: Overlay,
    *,
    plan_account_id: str | None = None,
) -> ResourceChange:
    """Apply overlay risk overrides to a single change."""

    out = change
    for override in overlay.risk_overrides:
        if not _override_matches(out, override, plan_account_id=plan_account_id):
            continue

        current_rank = RISK_ORDER.get(out.risk, RISK_ORDER["review"])
        override_rank = RISK_ORDER.get(override.risk, RISK_ORDER["review"])
        if override_rank < current_rank:
            continue

        out = replace(
            out,
            risk=override.risk,
            explanation=_append_explanation(out.explanation, override.explanation),
        )
    return out


def apply_overlay_to_catalog(
    catalog: ControlCatalog,
    overlay: Overlay,
) -> ControlCatalog:
    """Apply overlay control_additions to a framework catalog."""

    additions = overlay.control_additions
    if additions is None or additions["framework"] != catalog.framework:
        return catalog

    mappings: dict[str, list[Any]] = defaultdict(list)
    for resource_type, existing in catalog._mappings.items():
        mappings[resource_type].extend(existing)

    for raw_mapping in cast("list[Mapping[str, Any]]", additions["mappings"]):
        controls = tuple(
            ControlEntry(
                id=control["id"],
                title=control["title"],
                rationale=control["rationale"],
            )
            for control in cast("list[Mapping[str, str]]", raw_mapping["controls"])
        )
        mappings[raw_mapping["resource_type"]].append(
            _OverlayControlMapping(
                actions=tuple(cast("list[str]", raw_mapping["actions"])),
                controls=controls,
            )
        )

    return ControlCatalog(
        framework=catalog.framework,
        framework_version=catalog.framework_version,
        schema_version=catalog.schema_version,
        _mappings={key: tuple(value) for key, value in mappings.items()},
    )


def _risk_overrides(
    raw: Mapping[str, Any],
    path: Path,
) -> tuple[RiskOverride, ...]:
    items = _optional_list(raw, "risk_overrides", path, "$")
    out: list[RiskOverride] = []
    for index, item in enumerate(items):
        key_path = f"$.risk_overrides[{index}]"
        mapping = _expect_mapping(item, path, key_path)
        match = _required_mapping(mapping, "match", path, key_path)
        if not match:
            raise OverlayError(
                f"{path}: expected non-empty mapping at {key_path}.match"
            )
        _validate_match(match, path, f"{key_path}.match")

        risk = _required_str(mapping, "risk", path, key_path)
        if risk not in RISK_ORDER:
            raise OverlayError(f"{path}: unknown risk at {key_path}.risk: {risk}")
        out.append(
            RiskOverride(
                match=match,
                risk=risk,
                explanation=_required_str(mapping, "explanation", path, key_path),
            )
        )
    return tuple(out)


def _validate_match(match: Mapping[str, Any], path: Path, key_path: str) -> None:
    for key, value in match.items():
        if key not in _MATCH_KEYS:
            raise OverlayError(f"{path}: unknown match key {key_path}.{key}")
        if not isinstance(value, str):
            raise OverlayError(f"{path}: expected string at {key_path}.{key}")


def _control_additions(
    raw: Mapping[str, Any],
    path: Path,
) -> Mapping[str, Any] | None:
    if "control_additions" not in raw or raw["control_additions"] is None:
        return None

    key_path = "$.control_additions"
    additions = _expect_mapping(raw["control_additions"], path, key_path)
    framework = _required_str(additions, "framework", path, key_path)
    mappings = _required_list(additions, "mappings", path, key_path)

    parsed_mappings: list[Mapping[str, Any]] = []
    for index, raw_mapping in enumerate(mappings):
        mapping_path = f"{key_path}.mappings[{index}]"
        mapping = _expect_mapping(raw_mapping, path, mapping_path)
        parsed_mappings.append(
            {
                "resource_type": _required_str(
                    mapping, "resource_type", path, mapping_path
                ),
                "actions": tuple(
                    _expect_str(action, path, f"{mapping_path}.actions[{action_index}]")
                    for action_index, action in enumerate(
                        _required_list(mapping, "actions", path, mapping_path)
                    )
                ),
                "controls": tuple(
                    _control_entry(
                        control,
                        path,
                        f"{mapping_path}.controls[{control_index}]",
                    )
                    for control_index, control in enumerate(
                        _required_list(mapping, "controls", path, mapping_path)
                    )
                ),
            }
        )

    return {"framework": framework, "mappings": tuple(parsed_mappings)}


def _control_entry(raw: Any, path: Path, key_path: str) -> Mapping[str, str]:
    control = _expect_mapping(raw, path, key_path)
    return {
        "id": _required_str(control, "id", path, key_path),
        "title": _required_str(control, "title", path, key_path),
        "rationale": _required_str(control, "rationale", path, key_path),
    }


def _override_matches(
    change: ResourceChange,
    override: RiskOverride,
    *,
    plan_account_id: str | None,
) -> bool:
    for key, expected in override.match.items():
        if key == "resource_type" and change.resource_type != str(expected):
            return False
        if key == "address_prefix" and not change.address.startswith(str(expected)):
            return False
        if key == "address" and change.address != str(expected):
            return False
        if key == "account_id" and plan_account_id != str(expected):
            return False
    return True


def _append_explanation(existing: str, addition: str) -> str:
    if addition in existing:
        return existing
    return f"{existing} Overlay: {addition}"


def _required_str(
    data: Mapping[str, Any],
    key: str,
    path: Path,
    key_path: str,
) -> str:
    if key not in data:
        raise OverlayError(f"{path}: missing required key {key_path}.{key}")
    return _expect_str(data[key], path, f"{key_path}.{key}")


def _required_mapping(
    data: Mapping[str, Any],
    key: str,
    path: Path,
    key_path: str,
) -> Mapping[str, Any]:
    if key not in data:
        raise OverlayError(f"{path}: missing required key {key_path}.{key}")
    return _expect_mapping(data[key], path, f"{key_path}.{key}")


def _required_list(
    data: Mapping[str, Any],
    key: str,
    path: Path,
    key_path: str,
) -> list[Any]:
    if key not in data:
        raise OverlayError(f"{path}: missing required key {key_path}.{key}")
    value = data[key]
    if not isinstance(value, list):
        raise OverlayError(f"{path}: expected list at {key_path}.{key}")
    return value


def _optional_list(
    data: Mapping[str, Any],
    key: str,
    path: Path,
    key_path: str,
) -> list[Any]:
    if key not in data or data[key] is None:
        return []
    value = data[key]
    if not isinstance(value, list):
        raise OverlayError(f"{path}: expected list at {key_path}.{key}")
    return value


def _expect_mapping(value: Any, path: Path, key_path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise OverlayError(f"{path}: expected mapping at {key_path}")
    return value


def _expect_str(value: Any, path: Path, key_path: str) -> str:
    if not isinstance(value, str):
        raise OverlayError(f"{path}: expected string at {key_path}")
    return value
