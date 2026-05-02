from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Mapping, Sequence

import yaml


class FrameworkNotFoundError(ValueError):
    """Raised when a requested compliance framework catalog is unavailable."""


class CatalogSchemaError(ValueError):
    """Raised when a compliance framework catalog fails schema validation."""


@dataclass(frozen=True)
class ControlEntry:
    id: str
    title: str
    rationale: str


@dataclass(frozen=True)
class _ControlMapping:
    actions: tuple[str, ...]
    controls: tuple[ControlEntry, ...]


@dataclass(frozen=True)
class ControlCatalog:
    framework: str
    framework_version: str
    schema_version: int
    _mappings: Mapping[str, tuple[_ControlMapping, ...]] = field(
        repr=False,
        compare=False,
    )

    def controls_for(
        self, *, resource_type: str, actions: Sequence[str]
    ) -> tuple[ControlEntry, ...]:
        action = _canonical_action(actions)
        seen: set[str] = set()
        out: list[ControlEntry] = []
        for mapping in self._mappings.get(resource_type, ()):
            if action not in mapping.actions:
                continue
            for control in mapping.controls:
                if control.id in seen:
                    continue
                seen.add(control.id)
                out.append(control)
        return tuple(out)


def _canonical_action(actions: Sequence[str]) -> str:
    action_set = set(actions)
    if not action_set:
        return "unknown"
    if "delete" in action_set and "create" in action_set:
        return "delete/create"
    if len(action_set) == 1:
        return next(iter(action_set))
    return "/".join(sorted(action_set))


def available_frameworks() -> tuple[str, ...]:
    """Sorted list of YAML basenames in the data dir."""

    data_dir = resources.files("readtheplan.data.controls")
    return tuple(
        sorted(
            item.name[:-5] for item in data_dir.iterdir() if item.name.endswith(".yaml")
        )
    )


def load_catalog(framework: str) -> ControlCatalog:
    """Load by short name, e.g. 'soc2'. Raises FrameworkNotFoundError."""

    available = available_frameworks()
    if framework not in available:
        listing = ", ".join(available) if available else "(none)"
        raise FrameworkNotFoundError(
            f'unknown framework "{framework}"; available: {listing}'
        )
    return _load_from_path(
        resources.files("readtheplan.data.controls") / f"{framework}.yaml"
    )


def _load_from_path(path: Any) -> ControlCatalog:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CatalogSchemaError(f"{path}: invalid YAML: {exc}") from exc
    except OSError as exc:
        raise CatalogSchemaError(f"{path}: cannot read catalog: {exc}") from exc

    catalog = _expect_mapping(data, path, "$")
    framework = _required_str(catalog, "framework", path, "$")
    framework_version = _required_str(catalog, "framework_version", path, "$")
    schema_version = _required_int(catalog, "schema_version", path, "$")
    mapping_items = _required_list(catalog, "mappings", path, "$")

    mappings: dict[str, list[_ControlMapping]] = defaultdict(list)
    for index, raw_mapping in enumerate(mapping_items):
        mapping_path = f"$.mappings[{index}]"
        mapping = _expect_mapping(raw_mapping, path, mapping_path)
        resource_type = _required_str(mapping, "resource_type", path, mapping_path)
        actions = tuple(
            _expect_str(action, path, f"{mapping_path}.actions[{action_index}]")
            for action_index, action in enumerate(
                _required_list(mapping, "actions", path, mapping_path)
            )
        )
        controls = tuple(
            _control_entry(
                raw_control, path, f"{mapping_path}.controls[{control_index}]"
            )
            for control_index, raw_control in enumerate(
                _required_list(mapping, "controls", path, mapping_path)
            )
        )
        mappings[resource_type].append(
            _ControlMapping(actions=actions, controls=controls)
        )

    return ControlCatalog(
        framework=framework,
        framework_version=framework_version,
        schema_version=schema_version,
        _mappings={key: tuple(value) for key, value in mappings.items()},
    )


def _control_entry(raw: Any, path: Any, key_path: str) -> ControlEntry:
    control = _expect_mapping(raw, path, key_path)
    return ControlEntry(
        id=_required_str(control, "id", path, key_path),
        title=_required_str(control, "title", path, key_path),
        rationale=_required_str(control, "rationale", path, key_path),
    )


def _required_str(
    data: Mapping[str, Any],
    key: str,
    path: Any,
    key_path: str,
) -> str:
    if key not in data:
        raise CatalogSchemaError(f"{path}: missing required key {key_path}.{key}")
    return _expect_str(data[key], path, f"{key_path}.{key}")


def _required_int(
    data: Mapping[str, Any],
    key: str,
    path: Any,
    key_path: str,
) -> int:
    if key not in data:
        raise CatalogSchemaError(f"{path}: missing required key {key_path}.{key}")
    value = data[key]
    if not isinstance(value, int):
        raise CatalogSchemaError(f"{path}: expected integer at {key_path}.{key}")
    return value


def _required_list(
    data: Mapping[str, Any],
    key: str,
    path: Any,
    key_path: str,
) -> list[Any]:
    if key not in data:
        raise CatalogSchemaError(f"{path}: missing required key {key_path}.{key}")
    value = data[key]
    if not isinstance(value, list):
        raise CatalogSchemaError(f"{path}: expected list at {key_path}.{key}")
    return value


def _expect_mapping(
    value: Any,
    path: Any,
    key_path: str,
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise CatalogSchemaError(f"{path}: expected mapping at {key_path}")
    return value


def _expect_str(value: Any, path: Any, key_path: str) -> str:
    if not isinstance(value, str):
        raise CatalogSchemaError(f"{path}: expected string at {key_path}")
    return value
