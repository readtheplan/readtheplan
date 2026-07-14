#!/usr/bin/env python3
"""Merge required production bindings into a downloaded Pages configuration."""

from __future__ import annotations

import argparse
import copy
import json
from collections.abc import Mapping
from datetime import date, datetime, time
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib

PROJECT_NAME = "readtheplan"
PAGES_BUILD_OUTPUT_DIR = "dist"
REQUEST_SIGNAL_FLAG = "enable_request_signal"
RATE_LIMITER_BINDING = {
    "name": "CHAT_RATE_LIMITER",
    "class_name": "ChatRateLimiter",
    "script_name": "readtheplan-chat-rate-limiter",
}


class ConfigurationError(ValueError):
    """Raised when the downloaded configuration cannot be merged safely."""


def _string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"{field} must be a list of strings")
    return list(value)


def _merge_request_signal_flag(scope: dict[str, Any], field: str) -> None:
    flags = _string_list(scope.get("compatibility_flags", []), field)
    if REQUEST_SIGNAL_FLAG not in flags:
        flags.append(REQUEST_SIGNAL_FLAG)
    scope["compatibility_flags"] = flags


def _merge_rate_limiter_binding(scope: dict[str, Any], field: str) -> None:
    durable_objects = scope.get("durable_objects", {})
    if not isinstance(durable_objects, Mapping):
        raise ConfigurationError(f"{field}durable_objects must be a table")
    durable_objects = copy.deepcopy(dict(durable_objects))

    bindings = durable_objects.get("bindings", [])
    if not isinstance(bindings, list) or not all(isinstance(item, Mapping) for item in bindings):
        raise ConfigurationError(f"{field}durable_objects.bindings must be a list of tables")

    updated_bindings: list[dict[str, Any]] = []
    target_added = False
    for raw_binding in bindings:
        binding = copy.deepcopy(dict(raw_binding))
        if binding.get("name") != RATE_LIMITER_BINDING["name"]:
            updated_bindings.append(binding)
            continue

        if target_added:
            continue
        updated_bindings.append(dict(RATE_LIMITER_BINDING))
        target_added = True

    if not target_added:
        updated_bindings.append(dict(RATE_LIMITER_BINDING))

    durable_objects["bindings"] = updated_bindings
    scope["durable_objects"] = durable_objects


def merge_pages_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of *config* with the required production settings merged in."""
    if config.get("name") != PROJECT_NAME:
        raise ConfigurationError(
            f"expected Pages project {PROJECT_NAME!r}, got {config.get('name')!r}"
        )

    merged = copy.deepcopy(dict(config))
    # Wrangler ignores a Pages configuration file without this field. Keep it
    # authoritative even when `pages download config` omits the value.
    merged["pages_build_output_dir"] = PAGES_BUILD_OUTPUT_DIR
    _merge_request_signal_flag(merged, "compatibility_flags")
    _merge_rate_limiter_binding(merged, "")

    environments = merged.get("env")
    if environments is not None:
        if not isinstance(environments, Mapping):
            raise ConfigurationError("env must be a table")
        environments = copy.deepcopy(dict(environments))
        for environment_name, raw_environment in environments.items():
            if not isinstance(raw_environment, Mapping):
                raise ConfigurationError(f"env.{environment_name} must be a table")
            environment = copy.deepcopy(dict(raw_environment))
            # Pages accepts this field only at the root; discard stale overrides.
            environment.pop("pages_build_output_dir", None)
            field = f"env.{environment_name}."
            if "compatibility_flags" in environment:
                _merge_request_signal_flag(environment, f"{field}compatibility_flags")
            _merge_rate_limiter_binding(environment, field)
            environments[environment_name] = environment
        merged["env"] = environments

    return merged


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"could not read {path}: {exc}") from exc
    return dict(config)


def _json_default(value: Any) -> str:
    if isinstance(value, (date, datetime, time)):
        return value.isoformat()
    raise TypeError(f"cannot serialize {type(value).__name__} to JSON")


def write_json_atomic(path: Path, config: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    payload = json.dumps(config, default=_json_default, indent=2, sort_keys=True) + "\n"
    try:
        temporary.write_text(payload, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Wrangler TOML downloaded from Cloudflare")
    parser.add_argument("output", type=Path, help="Generated Wrangler JSON for this deployment")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.input.resolve() == args.output.resolve():
        raise ConfigurationError("input and output paths must be different")
    write_json_atomic(args.output, merge_pages_config(load_toml(args.input)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
