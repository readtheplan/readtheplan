from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.adapters.kubernetes import KubernetesInputError, parse_kubernetes_input
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class CrossplaneInputError(ValueError):
    """Raised when input contains no recognizable Crossplane resources."""


_CONTROL_PLANE_GROUPS = {
    "apiextensions.crossplane.io",
    "meta.pkg.crossplane.io",
    "pkg.crossplane.io",
    "protection.crossplane.io",
    "secrets.crossplane.io",
}
_PACKAGE_KINDS = {"Configuration", "Function", "Provider"}
_SECRET_KEY = re.compile(
    r"(?:^|[_.-])(?:api[_-]?key|client[_-]?secret|credential|password|private[_-]?key|"
    r"secret|token)(?:$|[_.-])",
    re.IGNORECASE,
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _group(resource: dict[str, Any]) -> str:
    return str(resource.get("apiVersion", "")).split("/", 1)[0]


def _is_crossplane_resource(resource: dict[str, Any]) -> bool:
    group = _group(resource)
    kind = str(resource.get("kind", ""))
    spec = _mapping(resource.get("spec"))
    if group in _CONTROL_PLANE_GROUPS:
        return True
    if kind in {"ClusterProviderConfig", "ProviderConfig"} and "credentials" in spec:
        return True
    managed_fields = {
        "deletionPolicy",
        "forProvider",
        "managementPolicies",
        "providerConfigRef",
        "publishConnectionDetailsTo",
        "writeConnectionSecretToRef",
    }
    if managed_fields & set(spec):
        return True
    crossplane = _mapping(spec.get("crossplane"))
    legacy_composite_fields = {
        "compositionRef",
        "compositionRevisionRef",
        "compositionSelector",
        "compositionUpdatePolicy",
        "resourceRefs",
    }
    return bool(crossplane or legacy_composite_fields & set(spec))


def parse_crossplane_input(source: str) -> dict[str, Any]:
    """Parse Crossplane Kubernetes YAML/JSON without contacting a cluster."""
    try:
        parsed = parse_kubernetes_input(source)
    except KubernetesInputError as exc:
        raise CrossplaneInputError(str(exc)) from exc
    resources = parsed.get("resources")
    if not isinstance(resources, list):
        raise CrossplaneInputError("Crossplane source must contain Kubernetes resources")
    if not any(_is_crossplane_resource(resource) for resource in resources):
        raise CrossplaneInputError("no recognizable Crossplane resources were found")
    return {"crossplane": {"resources": resources}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _image_pinned(image: str) -> bool:
    if "@sha256:" in image.lower():
        return True
    tail = image.rsplit("/", 1)[-1]
    return ":" in tail and not tail.lower().endswith(":latest")


class CrossplaneAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "crossplane"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("crossplane")
        return isinstance(source, dict) and isinstance(source.get("resources"), list)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        source = _mapping(input_data.get("crossplane"))
        changes: list[dict[str, Any]] = []
        for index, resource in enumerate(_items(source.get("resources"))):
            if not isinstance(resource, dict):
                continue
            metadata = _mapping(resource.get("metadata"))
            name = str(metadata.get("name") or f"resource-{index}")
            namespace = metadata.get("namespace")
            address = f"{namespace}/{name}" if namespace else name
            group = _group(resource)
            kind = str(resource.get("kind", "Unknown"))
            spec = _mapping(resource.get("spec"))
            annotations = _mapping(metadata.get("annotations"))

            if not _is_crossplane_resource(resource):
                from readtheplan.adapters.kubernetes import KubernetesAdapter

                embedded = KubernetesAdapter().analyze(
                    {"resources": [resource]}, tool_name="crossplane"
                )
                for change in embedded:
                    changes.append(
                        _change(
                            address,
                            f"embedded_{change.resource_type}",
                            change.risk,
                            "Crossplane source also contains a Kubernetes resource: "
                            f"{change.explanation}",
                        )
                    )
            elif group == "pkg.crossplane.io":
                changes.extend(self._package(address, kind, spec))
            elif group == "meta.pkg.crossplane.io":
                changes.extend(self._package_metadata(address, kind, spec))
            elif group in {
                "apiextensions.crossplane.io",
                "protection.crossplane.io",
                "secrets.crossplane.io",
            }:
                changes.extend(self._extension(address, kind, spec))
            elif kind in {"ClusterProviderConfig", "ProviderConfig"}:
                changes.extend(self._provider_config(address, kind, spec))
            elif self._managed(spec):
                changes.extend(self._managed_resource(address, spec, annotations))
            else:
                changes.extend(self._composite_resource(address, spec))
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw.get("Address", "crossplane")),
            resource_type=f"crossplane_{raw.get('Kind', 'resource')}",
            actions=("update",),
            risk=str(raw.get("Risk", "review")),
            explanation=str(raw.get("Explanation", "Crossplane configuration requires review.")),
        )

    def _package(self, address: str, kind: str, spec: dict[str, Any]) -> list[dict[str, str]]:
        if kind == "DeploymentRuntimeConfig":
            return self._runtime_config(address, spec)
        if kind == "ImageConfig":
            return self._image_config(address, spec)
        if kind not in _PACKAGE_KINDS:
            return [
                _change(
                    address,
                    "package_control",
                    "review",
                    f"Crossplane package control {kind} changes package lifecycle state.",
                )
            ]

        changes = [
            _change(
                address,
                "package_install",
                "dangerous",
                f"Crossplane installs {kind} package code or control-plane definitions.",
            )
        ]
        package = str(spec.get("package", ""))
        if not package or not _image_pinned(package):
            changes.append(
                _change(
                    f"{address}.package",
                    "unpinned_package",
                    "dangerous",
                    "Crossplane package does not use an explicit version tag or image digest.",
                )
            )
        else:
            changes.append(
                _change(
                    f"{address}.package",
                    "package_source",
                    "review",
                    "Crossplane pulls and installs a versioned package from an OCI registry.",
                )
            )
        if str(spec.get("packagePullPolicy", "")).lower() == "always":
            changes.append(
                _change(
                    f"{address}.packagePullPolicy",
                    "mutable_package_pull",
                    "dangerous",
                    "Crossplane always pulls this package, so a mutable tag can change "
                    "deployed code.",
                )
            )
        if str(spec.get("revisionActivationPolicy", "Automatic")).lower() == "automatic":
            changes.append(
                _change(
                    f"{address}.revisionActivationPolicy",
                    "automatic_revision",
                    "review",
                    "Crossplane automatically activates new package revisions.",
                )
            )
        for field, explanation in (
            (
                "skipDependencyResolution",
                "Crossplane skips dependency resolution, so required packages may be absent "
                "or incompatible.",
            ),
            (
                "ignoreCrossplaneConstraints",
                "Crossplane ignores package compatibility constraints for its own version.",
            ),
        ):
            if spec.get(field) is True:
                changes.append(_change(f"{address}.{field}", field, "dangerous", explanation))
        if spec.get("runtimeConfigRef") is not None:
            changes.append(
                _change(
                    f"{address}.runtimeConfigRef",
                    "runtime_config",
                    "dangerous",
                    "Crossplane applies custom pod and ServiceAccount runtime configuration "
                    "to package code.",
                )
            )
        if spec.get("packagePullSecrets"):
            changes.append(
                _change(
                    f"{address}.packagePullSecrets",
                    "registry_credentials",
                    "review",
                    "Crossplane gives its package manager registry credentials for this package.",
                )
            )
        return changes

    def _package_metadata(
        self, address: str, kind: str, spec: dict[str, Any]
    ) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "package_metadata",
                "review",
                f"Crossplane {kind} package metadata defines installable control-plane content.",
            )
        ]
        for index, dependency in enumerate(_items(spec.get("dependsOn"))):
            if not isinstance(dependency, dict):
                continue
            version = str(dependency.get("version", ""))
            changes.append(
                _change(
                    f"{address}.dependsOn[{index}]",
                    "package_dependency",
                    "review" if version else "dangerous",
                    "Crossplane package declares a versioned dependency."
                    if version
                    else "Crossplane package dependency has no version constraint.",
                )
            )
        return changes

    def _runtime_config(self, address: str, spec: dict[str, Any]) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "runtime_config",
                "dangerous",
                "Crossplane overrides the Deployment or ServiceAccount used by "
                "provider/function code.",
            )
        ]
        deployment = _mapping(spec.get("deploymentTemplate"))
        service_account = _mapping(spec.get("serviceAccountTemplate"))
        if deployment:
            changes.append(
                _change(
                    f"{address}.deploymentTemplate",
                    "runtime_deployment",
                    "dangerous",
                    "Crossplane package runtime supplies a custom controller pod template.",
                )
            )
            text = str(deployment).lower()
            if any(
                marker in text
                for marker in (
                    "allowprivilegeescalation': true",
                    "hostnetwork': true",
                    "hostpid': true",
                    "privileged': true",
                )
            ):
                changes.append(
                    _change(
                        f"{address}.deploymentTemplate.securityContext",
                        "privileged_runtime",
                        "dangerous",
                        "Crossplane package runtime enables host or privileged container access.",
                    )
                )
        if service_account:
            changes.append(
                _change(
                    f"{address}.serviceAccountTemplate",
                    "runtime_identity",
                    "dangerous",
                    "Crossplane package code receives a customized Kubernetes "
                    "ServiceAccount identity.",
                )
            )
        return changes

    def _image_config(self, address: str, spec: dict[str, Any]) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "image_policy",
                "review",
                "Crossplane globally changes how matching package images are resolved or trusted.",
            )
        ]
        matches = _items(spec.get("matchImages"))
        for index, match in enumerate(matches):
            prefix = str(_mapping(match).get("prefix", ""))
            if prefix in {"", "*", "xpkg.crossplane.io"}:
                changes.append(
                    _change(
                        f"{address}.matchImages[{index}]",
                        "broad_image_policy",
                        "dangerous",
                        "Crossplane image policy matches a broad package registry scope.",
                    )
                )
        if spec.get("rewriteImage") is not None:
            changes.append(
                _change(
                    f"{address}.rewriteImage",
                    "image_rewrite",
                    "dangerous",
                    "Crossplane rewrites package image locations before pulling them.",
                )
            )
        registry = _mapping(spec.get("registry"))
        if _mapping(registry.get("authentication")).get("pullSecretRef") is not None:
            changes.append(
                _change(
                    f"{address}.registry.authentication",
                    "registry_credentials",
                    "review",
                    "Crossplane injects registry credentials into package image operations.",
                )
            )
        if spec.get("verification") is not None:
            changes.append(
                _change(
                    f"{address}.verification",
                    "signature_policy",
                    "review",
                    "Crossplane applies Cosign identities, keys, or attestations to package "
                    "verification.",
                )
            )
        if spec.get("runtime") is not None:
            changes.append(
                _change(
                    f"{address}.runtime",
                    "runtime_config",
                    "dangerous",
                    "Crossplane applies a runtime configuration to every matching package.",
                )
            )
        return changes

    def _extension(self, address: str, kind: str, spec: dict[str, Any]) -> list[dict[str, str]]:
        if kind == "CompositeResourceDefinition":
            return self._xrd(address, spec)
        if kind in {"Composition", "CompositionRevision"}:
            return self._composition(address, kind, spec)
        if kind == "ManagedResourceDefinition":
            risk = "irreversible" if str(spec.get("state", "Inactive")) == "Active" else "review"
            return [
                _change(
                    address,
                    "managed_resource_definition",
                    risk,
                    "Crossplane activates a provider API and its controller; activation is one-way."
                    if risk == "irreversible"
                    else "Crossplane defines an inactive provider API schema.",
                )
            ]
        if kind == "EnvironmentConfig":
            changes = [
                _change(
                    address,
                    "environment_config",
                    "review",
                    "Crossplane makes environment data available to Composition functions.",
                )
            ]
            if self._contains_secret(spec.get("data")):
                changes.append(
                    _change(
                        f"{address}.data",
                        "secret_material",
                        "dangerous",
                        "Crossplane EnvironmentConfig appears to contain inline secret material.",
                    )
                )
            return changes
        if kind == "Usage":
            return [
                _change(
                    address,
                    "deletion_dependency",
                    "dangerous",
                    "Crossplane Usage changes deletion ordering and can block or cascade "
                    "resource removal.",
                )
            ]
        return [
            _change(
                address,
                "control_plane_extension",
                "review",
                f"Crossplane control-plane resource {kind} changes reconciliation behavior.",
            )
        ]

    def _xrd(self, address: str, spec: dict[str, Any]) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "composite_api_definition",
                "dangerous",
                "Crossplane adds or changes a cluster API and schema for composite resources.",
            )
        ]
        if spec.get("claimNames") is not None:
            changes.append(
                _change(
                    f"{address}.claimNames",
                    "claim_api",
                    "review",
                    "Crossplane exposes an additional namespaced claim API.",
                )
            )
        if spec.get("conversion") is not None:
            changes.append(
                _change(
                    f"{address}.conversion",
                    "conversion_webhook",
                    "dangerous",
                    "Crossplane custom API uses conversion behavior across served versions.",
                )
            )
        if spec.get("defaultCompositionRef") is not None:
            changes.append(
                _change(
                    f"{address}.defaultCompositionRef",
                    "default_composition",
                    "review",
                    "Crossplane selects a default implementation for composite instances.",
                )
            )
        if spec.get("enforcedCompositionRef") is not None:
            changes.append(
                _change(
                    f"{address}.enforcedCompositionRef",
                    "enforced_composition",
                    "dangerous",
                    "Crossplane forces all composite instances to use one Composition.",
                )
            )
        if str(spec.get("defaultCompositionUpdatePolicy", "Automatic")) == "Automatic":
            changes.append(
                _change(
                    f"{address}.defaultCompositionUpdatePolicy",
                    "automatic_composition_update",
                    "dangerous",
                    "Crossplane composite instances automatically adopt new Composition "
                    "revisions by default.",
                )
            )
        return changes

    def _composition(self, address: str, kind: str, spec: dict[str, Any]) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "composition",
                "dangerous",
                f"Crossplane {kind} determines which external and Kubernetes resources an "
                "API creates.",
            )
        ]
        mode = str(spec.get("mode", "Pipeline"))
        if mode != "Pipeline":
            changes.append(
                _change(
                    f"{address}.mode",
                    "legacy_composition_mode",
                    "review",
                    "Crossplane Composition uses a non-pipeline or legacy resource mode.",
                )
            )
        for index, step in enumerate(_items(spec.get("pipeline"))):
            if not isinstance(step, dict):
                continue
            step_address = f"{address}.pipeline[{index}]"
            function_name = str(_mapping(step.get("functionRef")).get("name", ""))
            changes.append(
                _change(
                    step_address,
                    "composition_function",
                    "dangerous",
                    "Crossplane executes Composition function "
                    f"{function_name or '<dynamic>'} to generate resources.",
                )
            )
            if step.get("input") is not None:
                changes.append(
                    _change(
                        f"{step_address}.input",
                        "function_input",
                        "review",
                        "Crossplane passes arbitrary structured input to a Composition function.",
                    )
                )
            if step.get("credentials") is not None:
                changes.append(
                    _change(
                        f"{step_address}.credentials",
                        "function_credentials",
                        "dangerous",
                        "Crossplane exposes referenced credentials to a Composition function.",
                    )
                )
        if spec.get("writeConnectionSecretsToNamespace") is not None:
            changes.append(
                _change(
                    f"{address}.writeConnectionSecretsToNamespace",
                    "connection_secret_destination",
                    "dangerous",
                    "Crossplane writes composed-resource connection credentials into a "
                    "selected namespace.",
                )
            )
        return changes

    def _provider_config(
        self, address: str, kind: str, spec: dict[str, Any]
    ) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "provider_credentials",
                "dangerous",
                f"Crossplane {kind} defines credentials and identity used to manage "
                "external infrastructure.",
            )
        ]
        credentials = _mapping(spec.get("credentials"))
        source = str(credentials.get("source", ""))
        if credentials.get("secretRef") is not None:
            changes.append(
                _change(
                    f"{address}.credentials.secretRef",
                    "credential_secret_ref",
                    "review",
                    "Crossplane provider loads external API credentials from a Kubernetes Secret.",
                )
            )
        elif source:
            changes.append(
                _change(
                    f"{address}.credentials.source",
                    "ambient_credentials",
                    "dangerous",
                    f"Crossplane provider loads credentials from {source} rather than an "
                    "explicit Secret reference.",
                )
            )
        if kind == "ClusterProviderConfig":
            changes.append(
                _change(
                    address,
                    "cluster_wide_credentials",
                    "dangerous",
                    "Crossplane makes this provider identity selectable across namespaces.",
                )
            )
        if self._contains_secret(spec, ignore_references=True):
            changes.append(
                _change(
                    f"{address}.spec",
                    "inline_credentials",
                    "dangerous",
                    "Crossplane ProviderConfig appears to contain inline credential material.",
                )
            )
        return changes

    def _managed(self, spec: dict[str, Any]) -> bool:
        return bool(
            {
                "deletionPolicy",
                "forProvider",
                "managementPolicies",
                "providerConfigRef",
                "publishConnectionDetailsTo",
                "writeConnectionSecretToRef",
            }
            & set(spec)
        )

    def _managed_resource(
        self, address: str, spec: dict[str, Any], annotations: dict[str, Any]
    ) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "managed_resource",
                "review",
                "Crossplane reconciles this Kubernetes object against external infrastructure.",
            )
        ]
        policies = [str(policy) for policy in _items(spec.get("managementPolicies"))]
        if not policies and "managementPolicies" in spec:
            changes.append(
                _change(
                    f"{address}.managementPolicies",
                    "paused_management",
                    "review",
                    "Crossplane pauses reconciliation because managementPolicies is empty.",
                )
            )
        elif "*" in policies or "Delete" in policies:
            changes.append(
                _change(
                    f"{address}.managementPolicies",
                    "external_delete_permission",
                    "dangerous",
                    "Crossplane may delete the external resource under its management policies.",
                )
            )
        elif policies == ["Observe"]:
            changes.append(
                _change(
                    f"{address}.managementPolicies",
                    "observe_only",
                    "safe",
                    "Crossplane observes this external resource without changing or deleting it.",
                )
            )
        elif policies:
            changes.append(
                _change(
                    f"{address}.managementPolicies",
                    "external_mutation_policy",
                    "review",
                    "Crossplane receives selected create, update, observe, or "
                    "late-initialize permissions.",
                )
            )
        deletion_policy = str(spec.get("deletionPolicy", "Delete"))
        changes.append(
            _change(
                f"{address}.deletionPolicy",
                "external_deletion_policy",
                "dangerous" if deletion_policy.lower() == "delete" else "review",
                "Deleting the Kubernetes object also deletes external infrastructure."
                if deletion_policy.lower() == "delete"
                else (
                    "Crossplane orphans external infrastructure when the Kubernetes object "
                    "is deleted."
                ),
            )
        )
        if spec.get("providerConfigRef") is None:
            changes.append(
                _change(
                    f"{address}.providerConfigRef",
                    "implicit_provider_identity",
                    "dangerous",
                    "Crossplane implicitly selects the default ClusterProviderConfig identity.",
                )
            )
        else:
            changes.append(
                _change(
                    f"{address}.providerConfigRef",
                    "provider_identity",
                    "review",
                    "Crossplane selects an explicit provider identity for external API operations.",
                )
            )
        for field in ("publishConnectionDetailsTo", "writeConnectionSecretToRef"):
            if spec.get(field) is not None:
                changes.append(
                    _change(
                        f"{address}.{field}",
                        "connection_details",
                        "dangerous",
                        "Crossplane publishes external resource credentials or connection details.",
                    )
                )
        if spec.get("initProvider") is not None:
            changes.append(
                _change(
                    f"{address}.initProvider",
                    "create_only_fields",
                    "review",
                    "Crossplane sends initProvider settings only when creating the external "
                    "resource.",
                )
            )
        if self._has_reference(spec.get("forProvider")):
            changes.append(
                _change(
                    f"{address}.forProvider",
                    "resource_reference",
                    "review",
                    "Crossplane resolves references or selectors to other managed resources.",
                )
            )
        if "crossplane.io/external-name" in annotations:
            changes.append(
                _change(
                    f"{address}.metadata.annotations.external-name",
                    "external_resource_binding",
                    "review",
                    "Crossplane binds this object to a specifically named external resource.",
                )
            )
        if str(annotations.get("crossplane.io/paused", "")).lower() == "true":
            changes.append(
                _change(
                    f"{address}.metadata.annotations.paused",
                    "paused_reconciliation",
                    "review",
                    "Crossplane reconciliation is paused and desired state may drift.",
                )
            )
        return changes

    def _composite_resource(self, address: str, spec: dict[str, Any]) -> list[dict[str, str]]:
        crossplane = _mapping(spec.get("crossplane")) or spec
        changes = [
            _change(
                address,
                "composite_resource",
                "dangerous",
                "Crossplane composite resource can create or update multiple composed resources.",
            )
        ]
        if crossplane.get("compositionRef") is not None:
            changes.append(
                _change(
                    f"{address}.compositionRef",
                    "composition_selection",
                    "review",
                    "Crossplane selects a specific Composition implementation.",
                )
            )
        if crossplane.get("compositionSelector") is not None:
            changes.append(
                _change(
                    f"{address}.compositionSelector",
                    "dynamic_composition_selection",
                    "dangerous",
                    "Crossplane dynamically selects a Composition by labels.",
                )
            )
        if str(crossplane.get("compositionUpdatePolicy", "Automatic")) == "Automatic":
            changes.append(
                _change(
                    f"{address}.compositionUpdatePolicy",
                    "automatic_composition_update",
                    "dangerous",
                    "Crossplane automatically adopts newer Composition revisions.",
                )
            )
        if crossplane.get("compositionRevisionRef") is not None:
            changes.append(
                _change(
                    f"{address}.compositionRevisionRef",
                    "pinned_composition_revision",
                    "review",
                    "Crossplane pins this composite to a specific Composition revision.",
                )
            )
        return changes

    def _contains_secret(self, value: Any, *, ignore_references: bool = False) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                lowered = str(key).lower()
                if ignore_references and lowered.endswith(("ref", "reference")):
                    continue
                if (
                    _SECRET_KEY.search(str(key))
                    and not isinstance(child, (dict, list))
                    and child not in (None, "")
                ):
                    return True
                if self._contains_secret(child, ignore_references=ignore_references):
                    return True
        elif isinstance(value, list):
            return any(
                self._contains_secret(item, ignore_references=ignore_references) for item in value
            )
        return False

    def _has_reference(self, value: Any) -> bool:
        if isinstance(value, dict):
            for key, child in value.items():
                if str(key).lower().endswith(("ref", "selector")):
                    return True
                if self._has_reference(child):
                    return True
        elif isinstance(value, list):
            return any(self._has_reference(item) for item in value)
        return False


def analyze_crossplane(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    adapter = CrossplaneAdapter()
    changes = adapter.analyze(data, tool_name="crossplane")
    summary = PlanSummary(
        path=Path("crossplane://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="crossplane")
    gate["adapter"] = "crossplane"
    gate["total_changes"] = len(changes)
    return gate
