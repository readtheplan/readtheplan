from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class KustomizeInputError(ValueError):
    """Raised when a kustomization YAML file is invalid or unrecognizable."""


_RECOGNIZED = {
    "apiVersion",
    "bases",
    "components",
    "configMapGenerator",
    "generators",
    "helmCharts",
    "images",
    "kind",
    "patches",
    "patchesJson6902",
    "patchesStrategicMerge",
    "replacements",
    "resources",
    "secretGenerator",
    "transformers",
}
_SECRET_KEY = re.compile(
    r"(?:^|[_.-])(?:api[_-]?key|client[_-]?secret|credential|password|private[_-]?key|"
    r"secret|token)(?:$|[_.-])",
    re.IGNORECASE,
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def parse_kustomization(source: str) -> dict[str, Any]:
    """Parse one kustomization YAML without loading referenced resources or plugins."""
    if not source.strip():
        raise KustomizeInputError("input is empty")
    try:
        document = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise KustomizeInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise KustomizeInputError("kustomization must be a YAML object")
    if str(document.get("kind", "")) == "Kustomization":
        pass
    elif not (_RECOGNIZED - {"apiVersion", "kind"}) & set(document):
        raise KustomizeInputError("input is not recognizable as a kustomization")
    return {"kustomization": {"document": document}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


class KustomizeAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "kustomize"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        config = input_data.get("kustomization")
        return isinstance(config, dict) and isinstance(config.get("document"), dict)

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        document = input_data["kustomization"]["document"]
        changes: list[dict[str, Any]] = []
        for key in ("resources", "bases", "components", "crds", "configurations"):
            for index, resource in enumerate(_items(document.get(key))):
                address = f"{key}[{index}]"
                value = str(resource)
                remote = self._remote(value)
                changes.append(
                    _change(
                        address,
                        "remote_resource" if remote else "resource_reference",
                        "dangerous" if remote else "review",
                        "Kustomize downloads and composes a remote resource or base."
                        if remote
                        else "Kustomize loads another local resource, base, component, or schema.",
                    )
                )
                if remote and not self._pinned(value):
                    changes.append(
                        _change(
                            f"{address}.version",
                            "unpinned_remote",
                            "dangerous",
                            "Remote Kustomize source lacks a visible immutable revision.",
                        )
                    )
        for key in ("patches", "patchesStrategicMerge", "patchesJson6902"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        key,
                        "patch",
                        "dangerous",
                        "Kustomize patches mutate selected Kubernetes object fields in order.",
                    )
                )
        if document.get("replacements") is not None:
            changes.append(
                _change(
                    "replacements",
                    "replacement",
                    "review",
                    "Kustomize copies field values from source objects into selected targets.",
                )
            )
        changes.extend(self._generators(document))
        changes.extend(self._images(document))
        changes.extend(self._helm_charts(document))
        for key, kind, risk, explanation in (
            (
                "generators",
                "generator_plugin",
                "dangerous",
                "Kustomize invokes configured generators, which may be external plugins.",
            ),
            (
                "transformers",
                "transformer_plugin",
                "dangerous",
                "Kustomize invokes configured transformers, which may be external plugins.",
            ),
            (
                "openapi",
                "openapi_schema",
                "review",
                "Kustomize loads a custom OpenAPI schema that changes merge behavior.",
            ),
            (
                "vars",
                "deprecated_vars",
                "review",
                "Kustomize uses deprecated variable substitution from object fields.",
            ),
        ):
            if document.get(key) is not None:
                changes.append(_change(key, kind, risk, explanation))
        if document.get("replicas") is not None:
            changes.append(
                _change(
                    "replicas",
                    "replica_override",
                    "review",
                    "Kustomize overrides workload replica counts after loading resources.",
                )
            )
        for key in ("namespace", "namePrefix", "nameSuffix", "labels", "commonLabels"):
            if document.get(key) is not None:
                changes.append(
                    _change(
                        key,
                        "cross_cutting_transform",
                        "review",
                        "Kustomize applies a cross-cutting name, namespace, label, or selector "
                        "transformation to multiple objects.",
                    )
                )
        changes.append(
            _change(
                "kustomize.effective_configuration",
                "effective_configuration",
                "review",
                "Effective output depends on every referenced resource, patch, schema, chart, "
                "generator input, plugin, build flag, load restriction, and Kustomize version.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"kustomize_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )

    def _generators(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for kind, risk in (("configMapGenerator", "review"), ("secretGenerator", "dangerous")):
            for index, generator in enumerate(_items(document.get(kind))):
                address = f"{kind}[{index}]"
                changes.append(
                    _change(
                        address,
                        "secret_generator" if kind == "secretGenerator" else "config_generator",
                        risk,
                        "Kustomize generates a Secret from files, environment files, or literals."
                        if kind == "secretGenerator"
                        else "Kustomize generates a ConfigMap from files, environment files, "
                        "or literals.",
                    )
                )
                if isinstance(generator, dict):
                    for literal_index, literal in enumerate(_items(generator.get("literals"))):
                        name = str(literal).split("=", 1)[0]
                        if kind == "secretGenerator" or _SECRET_KEY.search(name):
                            changes.append(
                                _change(
                                    f"{address}.literals[{literal_index}]",
                                    "secret_material",
                                    "dangerous",
                                    "Kustomize generator contains an inline credential-like "
                                    "literal.",
                                )
                            )
                    if generator.get("files") is not None or generator.get("envs") is not None:
                        changes.append(
                            _change(
                                f"{address}.files",
                                "external_generator_input",
                                "review",
                                "Generator loads values from files outside this artifact.",
                            )
                        )
        options = _mapping(document.get("generatorOptions"))
        if _enabled(options.get("disableNameSuffixHash")):
            changes.append(
                _change(
                    "generatorOptions.disableNameSuffixHash",
                    "stable_generated_name",
                    "dangerous",
                    "Generated ConfigMap and Secret names do not change with content, so "
                    "workloads may not roll out updated data.",
                )
            )
        return changes

    def _images(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, image in enumerate(_items(document.get("images"))):
            address = f"images[{index}]"
            if isinstance(image, str):
                unpinned = "@sha256:" not in image and (
                    ":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")
                )
            elif isinstance(image, dict):
                tag = str(image.get("newTag", ""))
                digest = str(image.get("digest", ""))
                unpinned = not digest and tag in {"", "latest"}
            else:
                changes.append(
                    _change(
                        address, "unresolved_image", "review", "Image override is not structured."
                    )
                )
                continue
            changes.append(
                _change(
                    address,
                    "image_override",
                    "dangerous" if unpinned else "review",
                    "Kustomize selects a mutable or unpinned container image."
                    if unpinned
                    else "Kustomize rewrites a container image name, tag, or digest.",
                )
            )
        return changes

    def _helm_charts(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        for index, chart in enumerate(_items(document.get("helmCharts"))):
            address = f"helmCharts[{index}]"
            changes.append(
                _change(
                    address,
                    "helm_inflation",
                    "dangerous",
                    "Kustomize downloads and renders a Helm chart into the object set.",
                )
            )
            if not isinstance(chart, dict):
                continue
            if not str(chart.get("version", "")).strip():
                changes.append(
                    _change(
                        f"{address}.version",
                        "unpinned_chart",
                        "dangerous",
                        "Kustomize Helm chart has no version constraint.",
                    )
                )
            repo = str(chart.get("repo", ""))
            if repo.lower().startswith("http://"):
                changes.append(
                    _change(
                        f"{address}.repo",
                        "plaintext_repository",
                        "dangerous",
                        "Kustomize downloads Helm chart metadata and packages over plaintext HTTP.",
                    )
                )
            if (
                chart.get("valuesInline") is not None
                or chart.get("additionalValuesFiles") is not None
            ):
                changes.append(
                    _change(
                        f"{address}.values",
                        "helm_values",
                        "review",
                        "Kustomize merges inline or external values into Helm chart rendering.",
                    )
                )
        return changes

    def _remote(self, value: str) -> bool:
        lowered = value.lower()
        return (
            lowered.startswith(("git::", "http://", "https://", "github.com/")) or ".git" in lowered
        )

    def _pinned(self, value: str) -> bool:
        lowered = value.lower()
        if "?ref=" in lowered:
            ref = lowered.split("?ref=", 1)[1].split("&", 1)[0]
            return ref not in {"", "head", "latest", "main", "master"}
        return "@sha256:" in lowered


def analyze_kustomize(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    adapter = KustomizeAdapter()
    changes = adapter.analyze(data, tool_name="kustomize")
    summary = PlanSummary(
        path=Path("kustomize://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="kustomize")
    gate["adapter"] = "kustomize"
    gate["total_changes"] = len(changes)
    return gate
