from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from readtheplan.adapters.ansible import AnsibleAdapter
from readtheplan.adapters.ansible_project import AnsibleProjectAdapter
from readtheplan.adapters.atlantis import AtlantisAdapter
from readtheplan.adapters.azure import AzureWhatIfAdapter
from readtheplan.adapters.base import BaseAdapter
from readtheplan.adapters.bicep import BicepAdapter
from readtheplan.adapters.caddy import CaddyAdapter
from readtheplan.adapters.cdk import CdkAdapter
from readtheplan.adapters.chef import ChefAdapter
from readtheplan.adapters.chef_project import ChefProjectAdapter
from readtheplan.adapters.cloud_init import CloudInitAdapter
from readtheplan.adapters.cloudformation import CloudFormationAdapter
from readtheplan.adapters.crossplane import CrossplaneAdapter
from readtheplan.adapters.dockerfile import DockerfileAdapter
from readtheplan.adapters.envoy import EnvoyAdapter
from readtheplan.adapters.grafana import GrafanaAdapter
from readtheplan.adapters.hashicorp import ConsulAdapter, VaultAdapter
from readtheplan.adapters.helm import HelmAdapter
from readtheplan.adapters.jenkins import JenkinsAdapter
from readtheplan.adapters.jenkins_jcasc import JenkinsJCasCAdapter
from readtheplan.adapters.kubernetes import KubernetesAdapter
from readtheplan.adapters.kustomize import KustomizeAdapter
from readtheplan.adapters.loki import LokiAdapter
from readtheplan.adapters.monitoring import AlertmanagerAdapter, PrometheusAdapter
from readtheplan.adapters.otel_collector import OTelCollectorAdapter
from readtheplan.adapters.packer import PackerInspectAdapter
from readtheplan.adapters.pipelines import (
    AzurePipelinesAdapter,
    BitbucketPipelinesAdapter,
    BuildkiteAdapter,
    CircleCIAdapter,
    GitHubActionsAdapter,
    GitLabCIAdapter,
)
from readtheplan.adapters.proxy_configs import HAProxyAdapter, NginxAdapter
from readtheplan.adapters.pulumi import PulumiAdapter
from readtheplan.adapters.puppet import PuppetAdapter
from readtheplan.adapters.puppet_project import PuppetProjectAdapter
from readtheplan.adapters.salt import SaltAdapter
from readtheplan.adapters.serverless import SamTemplateAdapter, ServerlessFrameworkAdapter
from readtheplan.adapters.systemd import SystemdUnitAdapter
from readtheplan.adapters.terraform_config import TerraformConfigAdapter, TerragruntAdapter
from readtheplan.adapters.traefik import TraefikAdapter
from readtheplan.adapters.vagrant import VagrantAdapter
from readtheplan.adapters.workloads import DockerComposeAdapter, NomadPlanAdapter

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
register_adapter(CrossplaneAdapter())
register_adapter(CaddyAdapter())
register_adapter(CdkAdapter())
register_adapter(AtlantisAdapter())
register_adapter(CloudInitAdapter())
register_adapter(DockerfileAdapter())
register_adapter(EnvoyAdapter())
register_adapter(GrafanaAdapter())
register_adapter(VaultAdapter())
register_adapter(ConsulAdapter())
register_adapter(KubernetesAdapter())
register_adapter(HelmAdapter())
register_adapter(KustomizeAdapter())
register_adapter(LokiAdapter())
register_adapter(PrometheusAdapter())
register_adapter(AlertmanagerAdapter())
register_adapter(OTelCollectorAdapter())
register_adapter(AnsibleAdapter())
register_adapter(AnsibleProjectAdapter())
register_adapter(JenkinsAdapter())
register_adapter(JenkinsJCasCAdapter())
register_adapter(ChefAdapter())
register_adapter(ChefProjectAdapter())
register_adapter(PuppetAdapter())
register_adapter(PuppetProjectAdapter())
register_adapter(PulumiAdapter())
register_adapter(NginxAdapter())
register_adapter(HAProxyAdapter())
register_adapter(AzureWhatIfAdapter())
register_adapter(BicepAdapter())
register_adapter(GitHubActionsAdapter())
register_adapter(AzurePipelinesAdapter())
register_adapter(BitbucketPipelinesAdapter())
register_adapter(BuildkiteAdapter())
register_adapter(GitLabCIAdapter())
register_adapter(CircleCIAdapter())
register_adapter(DockerComposeAdapter())
register_adapter(NomadPlanAdapter())
register_adapter(PackerInspectAdapter())
register_adapter(SaltAdapter())
register_adapter(ServerlessFrameworkAdapter())
register_adapter(SamTemplateAdapter())
register_adapter(SystemdUnitAdapter())
register_adapter(TerraformConfigAdapter())
register_adapter(TerragruntAdapter())
register_adapter(TraefikAdapter())
register_adapter(VagrantAdapter())
load_entry_point_adapters()

__all__ = [
    "ADAPTER_ENTRY_POINT_GROUP",
    "AnsibleAdapter",
    "AnsibleProjectAdapter",
    "AtlantisAdapter",
    "BaseAdapter",
    "AzureWhatIfAdapter",
    "AzurePipelinesAdapter",
    "BicepAdapter",
    "BitbucketPipelinesAdapter",
    "BuildkiteAdapter",
    "CaddyAdapter",
    "CdkAdapter",
    "ChefAdapter",
    "ChefProjectAdapter",
    "CircleCIAdapter",
    "CloudFormationAdapter",
    "CrossplaneAdapter",
    "CloudInitAdapter",
    "DockerComposeAdapter",
    "DockerfileAdapter",
    "EnvoyAdapter",
    "GrafanaAdapter",
    "HelmAdapter",
    "VaultAdapter",
    "ConsulAdapter",
    "JenkinsAdapter",
    "JenkinsJCasCAdapter",
    "GitHubActionsAdapter",
    "GitLabCIAdapter",
    "KubernetesAdapter",
    "KustomizeAdapter",
    "LokiAdapter",
    "PrometheusAdapter",
    "AlertmanagerAdapter",
    "OTelCollectorAdapter",
    "NomadPlanAdapter",
    "NginxAdapter",
    "HAProxyAdapter",
    "PackerInspectAdapter",
    "PulumiAdapter",
    "PuppetAdapter",
    "PuppetProjectAdapter",
    "SaltAdapter",
    "SamTemplateAdapter",
    "ServerlessFrameworkAdapter",
    "SystemdUnitAdapter",
    "TerraformConfigAdapter",
    "TerragruntAdapter",
    "TraefikAdapter",
    "VagrantAdapter",
    "register_adapter",
    "get_adapter",
    "detect_adapter",
    "load_entry_point_adapters",
]
