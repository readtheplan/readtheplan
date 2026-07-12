from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class CdkInputError(ValueError):
    """Raised when input is not a valid supported AWS CDK synthesized manifest."""


_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|client.?secret|api.?key|credential)",
    re.IGNORECASE,
)
_HASH = re.compile(r"[0-9a-f]{32,128}$", re.IGNORECASE)
_KNOWN_ARTIFACT_TYPES = {
    "aws:cloudformation:stack",
    "cdk:asset-manifest",
    "cdk:cloud-assembly",
    "cdk:feature-flag-report",
    "cdk:tree",
    "none",
}
_STACK_ROLE_FIELDS = {
    "assumeRoleArn",
    "cloudFormationExecutionRoleArn",
    "lookupRoleArn",
}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CdkInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _expect_mapping(value: Any, address: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CdkInputError(f"{address} must be a JSON object")
    return value


def _validate_assembly(document: dict[str, Any]) -> None:
    if not isinstance(document.get("version"), str) or not document["version"].strip():
        raise CdkInputError("Cloud Assembly version must be a non-empty string")
    artifacts = _expect_mapping(document.get("artifacts", {}), "artifacts")
    for artifact_id, artifact in artifacts.items():
        artifact = _expect_mapping(artifact, f"artifact {artifact_id!r}")
        if not isinstance(artifact.get("type"), str) or not artifact["type"]:
            raise CdkInputError(f"artifact {artifact_id!r} must have a type")
        if "properties" in artifact:
            _expect_mapping(artifact["properties"], f"artifact {artifact_id!r} properties")
        if "dependencies" in artifact and not isinstance(artifact["dependencies"], list):
            raise CdkInputError(f"artifact {artifact_id!r} dependencies must be a list")
        if "dependencies" in artifact and not all(
            isinstance(dependency, str) for dependency in artifact["dependencies"]
        ):
            raise CdkInputError(f"artifact {artifact_id!r} dependencies must contain only strings")
        if "metadata" in artifact:
            metadata = _expect_mapping(artifact["metadata"], f"artifact {artifact_id!r} metadata")
            for path, entries in metadata.items():
                if not isinstance(entries, list) or not all(
                    isinstance(entry, dict) for entry in entries
                ):
                    raise CdkInputError(
                        f"artifact {artifact_id!r} metadata {path!r} must be a list of objects"
                    )
    if "missing" in document and not isinstance(document["missing"], list):
        raise CdkInputError("Cloud Assembly missing context must be a list")
    if "missing" in document and not all(isinstance(query, dict) for query in document["missing"]):
        raise CdkInputError("Cloud Assembly missing context must contain only objects")
    if "runtime" in document:
        runtime = _expect_mapping(document["runtime"], "runtime")
        if "libraries" in runtime:
            _expect_mapping(runtime["libraries"], "runtime libraries")


def _validate_assets(document: dict[str, Any]) -> None:
    if not isinstance(document.get("version"), str) or not document["version"].strip():
        raise CdkInputError("asset manifest version must be a non-empty string")
    for collection_name in ("files", "dockerImages"):
        collection = _expect_mapping(document.get(collection_name, {}), collection_name)
        for asset_id, asset in collection.items():
            asset = _expect_mapping(asset, f"{collection_name} asset {asset_id!r}")
            if "source" in asset:
                source = _expect_mapping(
                    asset["source"], f"{collection_name} asset {asset_id!r} source"
                )
            else:
                source = asset
            if "executable" in source and (
                not isinstance(source["executable"], list)
                or not all(isinstance(part, str) for part in source["executable"])
            ):
                raise CdkInputError(
                    f"{collection_name} asset {asset_id!r} executable must be a list of strings"
                )
            if collection_name == "dockerImages":
                for key in ("dockerBuildArgs", "dockerBuildContexts", "dockerBuildSecrets"):
                    if key in source:
                        _expect_mapping(
                            source[key],
                            f"{collection_name} asset {asset_id!r} {key}",
                        )
            destinations = _expect_mapping(
                asset.get("destinations", {}),
                f"{collection_name} asset {asset_id!r} destinations",
            )
            for destination_id, destination in destinations.items():
                _expect_mapping(
                    destination,
                    f"{collection_name} asset {asset_id!r} destination {destination_id!r}",
                )


def parse_cdk_manifest(source: str) -> dict[str, Any]:
    """Parse a Cloud Assembly or asset manifest without executing the CDK app."""
    if not source.strip():
        raise CdkInputError("input is empty")
    try:
        document = json.loads(source, object_pairs_hook=_unique_object)
    except CdkInputError:
        raise
    except json.JSONDecodeError as exc:
        raise CdkInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise CdkInputError("CDK manifest must be a JSON object")
    if "artifacts" in document:
        _validate_assembly(document)
        artifact_type = "assembly"
    elif "files" in document or "dockerImages" in document:
        _validate_assets(document)
        artifact_type = "assets"
    else:
        raise CdkInputError("JSON is not a recognized Cloud Assembly or asset manifest")
    return {"cdk_manifest": {"artifact_type": artifact_type, "document": document}}


def _path_escapes(value: str) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        path.is_absolute()
        or ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:/", normalized))
        or bool(urlsplit(normalized).scheme)
    )


def _secret_paths(value: Any, prefix: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if _SECRET.search(path) and isinstance(child, (str, int, float, bool)):
                paths.append(path)
            paths.extend(_secret_paths(child, path))
    elif isinstance(value, list):
        for child in value:
            paths.extend(_secret_paths(child, prefix))
    return paths


def _dependency_problems(artifacts: dict[str, Any]) -> tuple[list[str], list[list[str]]]:
    missing: list[str] = []
    graph: dict[str, list[str]] = {}
    for artifact_id, artifact in artifacts.items():
        dependencies = [str(item) for item in artifact.get("dependencies", [])]
        graph[artifact_id] = dependencies
        missing.extend(
            f"{artifact_id}->{dependency}"
            for dependency in dependencies
            if dependency not in artifacts
        )
    cycles: list[list[str]] = []
    visited: set[str] = set()
    active: list[str] = []

    def visit(node: str) -> None:
        if node in active:
            cycles.append([*active[active.index(node) :], node])
            return
        if node in visited:
            return
        active.append(node)
        for dependency in graph.get(node, []):
            if dependency in graph:
                visit(dependency)
        active.pop()
        visited.add(node)

    for artifact_id in graph:
        visit(artifact_id)
    return missing, cycles


def _metadata_changes(artifact_id: str, metadata: dict[str, Any]) -> list[dict[str, str]]:
    errors: list[str] = []
    warnings: list[str] = []
    asset_entries = 0
    for path, entries in metadata.items():
        for entry in entries:
            entry_type = str(entry.get("type", "unknown"))
            if entry_type == "aws:cdk:error":
                errors.append(str(path))
            elif entry_type == "aws:cdk:warning":
                warnings.append(str(path))
            elif "asset" in entry_type.lower():
                asset_entries += 1
    changes: list[dict[str, str]] = []
    if errors:
        changes.append(
            _change(
                f"assembly.artifact.{artifact_id}.metadata",
                "synthesis_error",
                "dangerous",
                f"CDK stack metadata contains {len(errors)} synthesis error entry/entries; "
                "do not deploy an assembly with unresolved synthesis errors.",
            )
        )
    if warnings:
        changes.append(
            _change(
                f"assembly.artifact.{artifact_id}.metadata",
                "synthesis_warning",
                "review",
                f"CDK stack metadata contains {len(warnings)} synthesis warning entry/entries.",
            )
        )
    if asset_entries:
        changes.append(
            _change(
                f"assembly.artifact.{artifact_id}.metadata",
                "stack_asset_reference",
                "review",
                f"CDK stack metadata references {asset_entries} synthesized asset(s); verify "
                "their companion asset manifest and published content.",
            )
        )
    return changes


def _stack_changes(artifact_id: str, artifact: dict[str, Any]) -> list[dict[str, str]]:
    properties = artifact.get("properties", {})
    environment = str(artifact.get("environment", "<environment-agnostic>"))
    template_file = str(properties.get("templateFile", "<missing>"))
    risk = "review"
    reasons = [
        f"CDK synthesizes CloudFormation stack {artifact_id!r} for {environment!r} using template "
        f"file {template_file!r}."
    ]
    if template_file == "<missing>":
        risk = "dangerous"
        reasons.append("The stack artifact has no templateFile.")
    elif _path_escapes(template_file):
        risk = "dangerous"
        reasons.append("The template path escapes the Cloud Assembly directory.")
    if environment.startswith("aws://"):
        target = environment.removeprefix("aws://").split("/", 1)
        if len(target) != 2 or any(
            item in {"", "*", "unknown-account", "unknown-region"} for item in target
        ):
            risk = "dangerous"
            reasons.append("The deployment account or region is wildcard, unknown, or malformed.")
    role_fields = [key for key in _STACK_ROLE_FIELDS if properties.get(key)]
    if role_fields:
        reasons.append(
            "Deployment/lookup assumes privileged role field(s): "
            + ", ".join(sorted(role_fields))
            + "."
        )
    changes = [
        _change(
            f"assembly.artifact.{artifact_id}",
            "cloudformation_stack",
            risk,
            " ".join(reasons),
        )
    ]
    if properties.get("validateOnSynth") is False:
        changes.append(
            _change(
                f"assembly.artifact.{artifact_id}.validateOnSynth",
                "disabled_template_validation",
                "dangerous",
                "CDK disables CloudFormation template validation during synthesis for this stack.",
            )
        )
    if properties.get("terminationProtection") is False:
        changes.append(
            _change(
                f"assembly.artifact.{artifact_id}.terminationProtection",
                "termination_protection",
                "review",
                "CDK explicitly disables stack termination protection; verify recovery and "
                "deletion controls for the target environment.",
            )
        )
    secrets = _secret_paths(properties.get("parameters", {}))
    if secrets:
        changes.append(
            _change(
                f"assembly.artifact.{artifact_id}.parameters",
                "literal_stack_parameter_secret",
                "dangerous",
                "CDK stack parameters contain literal secret-like field(s): "
                + ", ".join(secrets[:3]),
            )
        )
    changes.extend(_metadata_changes(artifact_id, artifact.get("metadata", {})))
    return changes


def _assembly_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    artifacts = document.get("artifacts", {})
    changes = [
        _change(
            "assembly.version",
            "schema_version",
            "review",
            f"CDK Cloud Assembly uses schema version {document['version']!r}; verify the deploy "
            "CLI satisfies minimum version "
            f"{document.get('minimumCliVersion', '<unspecified>')!r}.",
        )
    ]
    missing_context = document.get("missing", [])
    if missing_context:
        changes.append(
            _change(
                "assembly.missing_context",
                "missing_context",
                "dangerous",
                f"Cloud Assembly contains {len(missing_context)} unresolved context lookup(s); "
                "AWS documents that an assembly with missing context is incomplete and should "
                "not be deployed.",
            )
        )
    libraries = document.get("runtime", {}).get("libraries", {})
    if libraries:
        changes.append(
            _change(
                "assembly.runtime.libraries",
                "runtime_supply_chain",
                "review",
                f"CDK synthesis records {len(libraries)} runtime library/libraries; verify "
                "lockfile "
                "provenance and reproduce synthesis in a trusted build.",
            )
        )
    for artifact_id, artifact in artifacts.items():
        artifact_type = artifact["type"]
        properties = artifact.get("properties", {})
        if artifact_type == "aws:cloudformation:stack":
            changes.extend(_stack_changes(artifact_id, artifact))
        elif artifact_type == "cdk:asset-manifest":
            manifest_file = str(properties.get("file", "<missing>"))
            risk = "review"
            reason = (
                f"CDK delegates file/image publishing to asset manifest {manifest_file!r}; analyze "
                "that companion manifest before deployment."
            )
            if manifest_file == "<missing>" or _path_escapes(manifest_file):
                risk = "dangerous"
                reason += " The asset manifest path is missing or escapes the assembly directory."
            changes.append(
                _change(
                    f"assembly.artifact.{artifact_id}",
                    "asset_manifest_reference",
                    risk,
                    reason,
                )
            )
        elif artifact_type == "cdk:cloud-assembly":
            directory = str(properties.get("directoryName", "<missing>"))
            changes.append(
                _change(
                    f"assembly.artifact.{artifact_id}",
                    "nested_assembly",
                    "dangerous"
                    if directory == "<missing>" or _path_escapes(directory)
                    else "review",
                    f"CDK delegates deployment instructions to nested assembly directory "
                    f"{directory!r}; inspect its manifest recursively.",
                )
            )
        else:
            known = artifact_type in _KNOWN_ARTIFACT_TYPES
            changes.append(
                _change(
                    f"assembly.artifact.{artifact_id}",
                    "assembly_artifact",
                    "review" if known else "dangerous",
                    f"Cloud Assembly includes artifact type {artifact_type!r}; "
                    + (
                        "its schema is known but its referenced content remains external."
                        if known
                        else "this consumer does not recognize the deployment instruction, so "
                        "the assembly must not be deployed through this gate."
                    ),
                )
            )
    missing_dependencies, cycles = _dependency_problems(artifacts)
    if missing_dependencies:
        changes.append(
            _change(
                "assembly.dependencies",
                "missing_artifact_dependency",
                "dangerous",
                "Cloud Assembly artifact dependencies reference missing artifact(s): "
                + ", ".join(missing_dependencies[:5]),
            )
        )
    if cycles:
        changes.append(
            _change(
                "assembly.dependencies",
                "cyclic_artifact_dependency",
                "dangerous",
                "Cloud Assembly artifact dependency graph contains cycle(s): "
                + "; ".join(" -> ".join(cycle) for cycle in cycles[:3]),
            )
        )
    return changes


def _source_path_risk(value: str) -> tuple[str, str]:
    if not value:
        return "dangerous", "The asset source path is missing."
    if _path_escapes(value):
        return "dangerous", "The asset source path escapes the Cloud Assembly directory."
    return "review", "The asset source is relative to the Cloud Assembly directory."


def _file_asset_change(asset_id: str, asset: dict[str, Any]) -> dict[str, str]:
    source = asset.get("source", {})
    path = str(source.get("path", ""))
    risk, reason = _source_path_risk(path)
    executable = source.get("executable")
    if executable:
        risk = "dangerous"
        reason += " CDK executes an external command to produce the packaged file asset."
    destinations = asset.get("destinations", {})
    roles = sum(bool(destination.get("assumeRoleArn")) for destination in destinations.values())
    return _change(
        f"assets.file.{asset_id}",
        "file_asset",
        risk,
        f"CDK packages file asset {asset_id!r} using {source.get('packaging', '<unspecified>')!r} "
        f"and publishes it to {len(destinations)} destination(s). {reason} "
        f"{roles} destination(s) assume a publishing role.",
    )


def _docker_asset_change(asset_id: str, asset: dict[str, Any]) -> dict[str, str]:
    source = asset.get("source", asset)
    directory = str(source.get("directory", source.get("directoryName", "")))
    risk, reason = _source_path_risk(directory)
    if source.get("executable"):
        risk = "dangerous"
        reason += " CDK executes an external command to produce the Docker image asset."
    if source.get("dockerBuildSsh"):
        risk = "dangerous"
        reason += " Docker build forwards SSH credentials or agent access."
    build_secrets = source.get("dockerBuildSecrets", {})
    if build_secrets:
        risk = "dangerous"
        reason += f" Docker build receives {len(build_secrets)} secret mount(s)."
    secret_args = _secret_paths(source.get("dockerBuildArgs", {}))
    if secret_args:
        risk = "dangerous"
        reason += " Docker build arguments contain literal secret-like field(s): " + ", ".join(
            secret_args[:3]
        )
    if str(source.get("networkMode", "")).lower() == "host":
        risk = "dangerous"
        reason += " Docker build uses the host network namespace."
    contexts = source.get("dockerBuildContexts", {})
    if isinstance(contexts, dict) and any(
        str(value).lower().startswith(("http://", "git://"))
        or str(value).lower().endswith(":latest")
        for value in contexts.values()
    ):
        risk = "dangerous"
        reason += " A build context uses plaintext transport or a mutable latest image tag."
    destinations = asset.get("destinations", {})
    if any(
        not _HASH.fullmatch(str(destination.get("imageTag", "")))
        for destination in destinations.values()
    ):
        risk = "dangerous"
        reason += " A destination image tag is missing or not content-addressed."
    return _change(
        f"assets.docker.{asset_id}",
        "docker_image_asset",
        risk,
        f"CDK builds Docker image asset {asset_id!r} and publishes it to "
        f"{len(destinations)} destination(s). {reason}",
    )


def _asset_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes = [
        _change(
            "assets.version",
            "schema_version",
            "review",
            f"CDK asset manifest uses schema version {document['version']!r}.",
        )
    ]
    for asset_id, asset in document.get("files", {}).items():
        changes.append(_file_asset_change(asset_id, asset))
    for asset_id, asset in document.get("dockerImages", {}).items():
        changes.append(_docker_asset_change(asset_id, asset))
    return changes


class CdkAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "cdk"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        manifest = input_data.get("cdk_manifest")
        return (
            isinstance(manifest, dict)
            and manifest.get("artifact_type") in {"assembly", "assets"}
            and isinstance(manifest.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        manifest = input_data["cdk_manifest"]
        changes = (
            _assembly_changes(manifest["document"])
            if manifest["artifact_type"] == "assembly"
            else _asset_changes(manifest["document"])
        )
        changes.append(
            _change(
                "cdk.effective_deployment",
                "deployment_boundary",
                "review",
                "The synthesized manifest does not contain the live deployment delta. Review "
                "referenced CloudFormation templates and asset manifests, then run cdk diff or "
                "create a CloudFormation Change Set in the target account before deployment.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"cdk_{raw['Kind']}",
            actions=("synthesize",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_cdk(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = CdkAdapter().analyze(data, tool_name="AWS CDK")
    summary = PlanSummary(
        path=Path("cdk://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="AWS CDK")
    gate["adapter"] = "cdk"
    gate["artifact_type"] = data["cdk_manifest"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
