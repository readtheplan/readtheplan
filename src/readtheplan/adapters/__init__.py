from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from readtheplan.adapters.ansible import AnsibleAdapter
from readtheplan.adapters.base import BaseAdapter
from readtheplan.adapters.chef import ChefAdapter
from readtheplan.adapters.cloudformation import CloudFormationAdapter
from readtheplan.adapters.jenkins import JenkinsAdapter
from readtheplan.adapters.kubernetes import KubernetesAdapter
from readtheplan.adapters.pulumi import PulumiAdapter
from readtheplan.adapters.puppet import PuppetAdapter

#: Entry point group external packages use to contribute adapters.
ADAPTER_ENTRY_POINT_GROUP = "readtheplan.adapters"

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

def load_entry_point_adapters() -> list[str]:
    """Discover and register adapters contributed by external packages via the
    ``readtheplan.adapters`` entry point group.

    Each entry point may resolve to a :class:`BaseAdapter` subclass, an adapter
    instance, or a zero-arg factory returning one. Best-effort and idempotent
    (registration is keyed by ``adapter_name``); a failure in any single plugin
    is isolated and never breaks import of the core package. Returns the list of
    discovered entry point names.
    """
    discovered: list[str] = []
    try:
        eps = entry_points(group=ADAPTER_ENTRY_POINT_GROUP)
    except Exception:
        return discovered
    for ep in eps:
        try:
            obj = ep.load()
            adapter = obj() if isinstance(obj, type) else obj
            if not isinstance(adapter, BaseAdapter) and callable(adapter):
                adapter = adapter()
            if isinstance(adapter, BaseAdapter):
                register_adapter(adapter)
                discovered.append(ep.name)
        except Exception:
            continue
    return discovered

# Auto-register builtin adapters, then discover external plugins (best-effort).
register_adapter(CloudFormationAdapter())
register_adapter(KubernetesAdapter())
register_adapter(AnsibleAdapter())
register_adapter(JenkinsAdapter())
register_adapter(ChefAdapter())
register_adapter(PuppetAdapter())
register_adapter(PulumiAdapter())
load_entry_point_adapters()

__all__ = [
    "ADAPTER_ENTRY_POINT_GROUP",
    "AnsibleAdapter",
    "BaseAdapter",
    "ChefAdapter",
    "CloudFormationAdapter",
    "JenkinsAdapter",
    "KubernetesAdapter",
    "PulumiAdapter",
    "PuppetAdapter",
    "register_adapter",
    "get_adapter",
    "detect_adapter",
    "load_entry_point_adapters",
]
