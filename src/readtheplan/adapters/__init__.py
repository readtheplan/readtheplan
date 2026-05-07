from __future__ import annotations

from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.adapters.cloudformation import CloudFormationAdapter

_registry: dict[str, BaseAdapter] = {}

def register_adapter(adapter: BaseAdapter) -> None:
    _registry[adapter.adapter_name] = adapter

def get_adapter(name: str) -> BaseAdapter:
    return _registry[name]

def detect_adapter(input_data: dict[str, Any]) -> BaseAdapter | None:
    for adapter in _registry.values():
        if adapter.can_handle(input_data):
            return adapter
    return None

# Auto-register CloudFormationAdapter
register_adapter(CloudFormationAdapter())

__all__ = [
    "BaseAdapter",
    "CloudFormationAdapter",
    "register_adapter",
    "get_adapter",
    "detect_adapter",
]
