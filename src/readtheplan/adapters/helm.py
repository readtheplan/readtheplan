from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class HelmInputError(ValueError):
    """Raised when Helm chart metadata, values, or template source is invalid."""


_SECRET_KEY = re.compile(
    r"(?:^|_)(?:api_key|client_secret|credential|credentials|password|private_key|"
    r"secret|secret_key|token)(?:$|_)",
    re.IGNORECASE,
)
_SECRET_REFERENCE_KEYS = {
    "existingsecret",
    "existingsecretname",
    "secretkeyref",
    "secretname",
    "secretref",
}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _disabled(value: Any) -> bool:
    return value is False or str(value).strip().lower() in {"0", "false", "no", "off"}


def parse_helm_source(source: str) -> dict[str, Any]:
    """Parse one explicit Helm Chart.yaml, values YAML, or Go-template source file."""
    if not source.strip():
        raise HelmInputError("input is empty")
    if "{{" in source or "}}" in source:
        if source.count("{{") != source.count("}}"):
            raise HelmInputError("template has unbalanced action delimiters")
        return {"helm_source": {"artifact_type": "template", "document": {"source": source}}}
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise HelmInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise HelmInputError("Helm metadata or values must be a YAML object")
    artifact_type = "chart" if {"apiVersion", "name", "version"} <= set(document) else "values"
    return {"helm_source": {"artifact_type": artifact_type, "document": document}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


class HelmAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "helm"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("helm_source")
        return (
            isinstance(source, dict)
            and source.get("artifact_type") in {"chart", "template", "values"}
            and isinstance(source.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        source = input_data["helm_source"]
        artifact_type = source["artifact_type"]
        document = source["document"]
        if artifact_type == "chart":
            changes = self._chart(document)
        elif artifact_type == "template":
            changes = self._template(str(document["source"]))
        else:
            changes = self._values(document)
        changes.append(
            _change(
                "helm.effective_configuration",
                "effective_configuration",
                "review",
                "Effective Helm output depends on all chart files, dependency archives and "
                "locks, merged values and --set arguments, capabilities, release metadata, "
                "cluster lookups, installed plugins, and Helm version.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"helm_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )

    def _chart(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes = [
            _change(
                "Chart.yaml",
                "chart_metadata",
                "review",
                "Helm chart metadata controls package identity, compatibility, and dependencies.",
            )
        ]
        if str(document.get("apiVersion", "")).lower() == "v1":
            changes.append(
                _change(
                    "Chart.yaml.apiVersion",
                    "legacy_chart_api",
                    "review",
                    "Helm chart uses the legacy v1 chart API and requirements format.",
                )
            )
        if not document.get("kubeVersion"):
            changes.append(
                _change(
                    "Chart.yaml.kubeVersion",
                    "unconstrained_kubernetes",
                    "review",
                    "Chart does not constrain compatible Kubernetes versions.",
                )
            )
        if _enabled(document.get("deprecated")):
            changes.append(
                _change(
                    "Chart.yaml.deprecated",
                    "deprecated_chart",
                    "dangerous",
                    "Chart is explicitly marked deprecated.",
                )
            )
        if str(document.get("type", "application")).lower() == "library":
            changes.append(
                _change(
                    "Chart.yaml.type",
                    "library_chart",
                    "review",
                    "Library chart contributes template functions instead of installable objects.",
                )
            )
        for index, dependency in enumerate(_items(document.get("dependencies"))):
            if not isinstance(dependency, dict):
                changes.append(
                    _change(
                        f"Chart.yaml.dependencies[{index}]",
                        "unresolved_dependency",
                        "review",
                        "Chart dependency is not a structured object.",
                    )
                )
                continue
            address = f"Chart.yaml.dependencies[{index}]"
            changes.append(
                _change(
                    address,
                    "chart_dependency",
                    "dangerous",
                    "Helm downloads and renders another chart into the same release.",
                )
            )
            if not str(dependency.get("version", "")).strip():
                changes.append(
                    _change(
                        f"{address}.version",
                        "unpinned_dependency",
                        "dangerous",
                        "Helm chart dependency has no version constraint.",
                    )
                )
            repository = str(dependency.get("repository", ""))
            if repository.lower().startswith("http://"):
                changes.append(
                    _change(
                        f"{address}.repository",
                        "plaintext_repository",
                        "dangerous",
                        "Helm downloads chart packages and metadata over plaintext HTTP.",
                    )
                )
            if dependency.get("condition") is not None or dependency.get("tags") is not None:
                changes.append(
                    _change(
                        f"{address}.activation",
                        "conditional_dependency",
                        "review",
                        "Values and tags conditionally include this dependency in the release.",
                    )
                )
            if dependency.get("import-values") is not None:
                changes.append(
                    _change(
                        f"{address}.import-values",
                        "imported_values",
                        "review",
                        "Helm imports values from the child chart into the parent values tree.",
                    )
                )
        return changes

    def _template(self, source: str) -> list[dict[str, Any]]:
        changes = [
            _change(
                "template",
                "template_execution",
                "review",
                "Helm evaluates Go templates and Sprig functions to generate Kubernetes objects.",
            )
        ]
        probes = (
            (
                r"\blookup\s+",
                "cluster_lookup",
                "dangerous",
                "Helm template queries resources from the live Kubernetes cluster.",
            ),
            (
                r"\btpl\s+",
                "dynamic_template",
                "dangerous",
                "Helm evaluates a value or file as a second-stage template.",
            ),
            (
                r"\.Files\.(?:Get|Glob|Lines|AsConfig|AsSecrets)\b",
                "chart_file_access",
                "review",
                "Helm template embeds or enumerates another file from the chart package.",
            ),
            (
                r"\b(?:include|template)\s+",
                "named_template",
                "review",
                "Helm executes a named template defined elsewhere in the chart or a dependency.",
            ),
            (
                r"\b(?:randAlpha|randAlphaNum|randAscii|randNumeric|uuidv4)\b",
                "nondeterministic_template",
                "review",
                "Helm template generates a nondeterministic value, causing render drift.",
            ),
            (
                r"\b(?:genCA|genPrivateKey|genSelfSignedCert|genSignedCert|derivePassword|decryptAES)\b",
                "generated_secret",
                "dangerous",
                "Helm template generates or decrypts cryptographic or credential material.",
            ),
            (
                r"\bgetHostByName\b",
                "dns_lookup",
                "dangerous",
                "Helm template performs a DNS lookup during rendering.",
            ),
        )
        for pattern, kind, risk, explanation in probes:
            if re.search(pattern, source):
                changes.append(_change(f"template.{kind}", kind, risk, explanation))
        if re.search(r"helm\.sh/hook\s*:", source, re.IGNORECASE):
            changes.append(
                _change(
                    "template.helm_hook",
                    "release_hook",
                    "dangerous",
                    "Helm hook creates resources before or after install, upgrade, rollback, "
                    "delete, or test lifecycle phases.",
                )
            )
        if re.search(r"helm\.sh/hook-delete-policy\s*:", source, re.IGNORECASE):
            changes.append(
                _change(
                    "template.hook_delete_policy",
                    "hook_deletion",
                    "dangerous",
                    "Helm hook policy deletes prior or completed hook resources.",
                )
            )
        if ".Values" in source:
            changes.append(
                _change(
                    "template.values",
                    "unresolved_values",
                    "review",
                    "Rendered Kubernetes behavior depends on values supplied outside this file.",
                )
            )
        if ".Capabilities" in source:
            changes.append(
                _change(
                    "template.capabilities",
                    "cluster_capabilities",
                    "review",
                    "Template output changes according to Kubernetes API capabilities.",
                )
            )
        return changes

    def _values(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes = [
            _change(
                "values",
                "values",
                "review",
                "Helm values override chart defaults and control the generated Kubernetes objects.",
            )
        ]
        changes.extend(self._scan_values(document, "values"))
        return changes

    def _scan_values(self, value: Any, address: str) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if isinstance(value, dict):
            lowered = {str(key).lower(): child for key, child in value.items()}
            if "repository" in lowered and ("tag" in lowered or "digest" in lowered):
                tag = str(lowered.get("tag", "")).lower()
                digest = str(lowered.get("digest", ""))
                changes.append(
                    _change(
                        f"{address}.image",
                        "container_image",
                        "dangerous" if not digest and tag in {"", "latest"} else "review",
                        "Helm values select a mutable or unpinned container image."
                        if not digest and tag in {"", "latest"}
                        else "Helm values select a container image repository and version.",
                    )
                )
            service_type = str(lowered.get("type", ""))
            if service_type.lower() in {"loadbalancer", "nodeport", "externalname"}:
                changes.append(
                    _change(
                        f"{address}.type",
                        "service_exposure",
                        "dangerous",
                        f"Helm values configure Kubernetes Service type {service_type}.",
                    )
                )
            for key, child in value.items():
                key_text = str(key)
                lowered_key = key_text.lower()
                child_address = f"{address}.{key_text}"
                if (
                    _SECRET_KEY.search(key_text)
                    and lowered_key not in _SECRET_REFERENCE_KEYS
                    and child is not None
                    and child != ""
                ):
                    changes.append(
                        _change(
                            child_address,
                            "secret_material",
                            "dangerous",
                            "Helm values contain or reference inline credential material.",
                        )
                    )
                if lowered_key in {
                    "allowprivilegeescalation",
                    "hostipc",
                    "hostnetwork",
                    "hostpid",
                    "privileged",
                } and _enabled(child):
                    changes.append(
                        _change(
                            child_address,
                            "privileged_workload",
                            "dangerous",
                            "Helm values enable privileged or host-level container access.",
                        )
                    )
                if lowered_key in {"runasnonroot", "readonlyrootfilesystem"} and _disabled(child):
                    changes.append(
                        _change(
                            child_address,
                            "disabled_hardening",
                            "dangerous",
                            "Helm values explicitly disable a container hardening control.",
                        )
                    )
                if lowered_key in {"automountserviceaccounttoken"} and _enabled(child):
                    changes.append(
                        _change(
                            child_address,
                            "service_account_token",
                            "dangerous",
                            "Helm values automount a Kubernetes API credential into workloads.",
                        )
                    )
                if isinstance(child, str) and child.lower().startswith("http://"):
                    changes.append(
                        _change(
                            child_address,
                            "plaintext_endpoint",
                            "dangerous",
                            "Helm values configure plaintext HTTP for an external endpoint.",
                        )
                    )
                if ("cidr" in lowered_key or "sourcerange" in lowered_key) and any(
                    cidr in str(child) for cidr in ("0.0.0.0/0", "::/0")
                ):
                    changes.append(
                        _change(
                            child_address,
                            "public_exposure",
                            "dangerous",
                            "Helm values allow network access from every IPv4 or IPv6 address.",
                        )
                    )
                changes.extend(self._scan_values(child, child_address))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._scan_values(child, f"{address}[{index}]"))
        return changes


def analyze_helm(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    adapter = HelmAdapter()
    changes = adapter.analyze(data, tool_name="helm")
    summary = PlanSummary(
        path=Path("helm://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="helm")
    gate["adapter"] = "helm"
    gate["total_changes"] = len(changes)
    return gate
