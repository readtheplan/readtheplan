# User-facing explanations remain complete sentences.
# ruff: noqa: E501

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class CarvelInputError(ValueError):
    """Raised when input is not a recognizable Carvel artifact."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise CarvelInputError("Carvel YAML mapping keys must be scalar") from exc
        if duplicate:
            raise CarvelInputError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)

_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$", re.I)
_COMMIT = re.compile(r"^[0-9a-f]{40,64}$", re.I)
_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_YTT_LOAD = re.compile(r'(?m)^\s*#@\s*load\(\s*["\'](?P<path>[^"\']+)["\']')


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _outside(value: str, *, root_relative: bool = False) -> bool:
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    return (
        ".." in path.parts
        or bool(re.match(r"^[A-Za-z]:/", normalized))
        or path.is_absolute()
        and not root_relative
    )


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _family(document: dict[str, Any]) -> str | None:
    api = str(document.get("apiVersion") or "")
    api_group, separator, _version = api.partition("/")
    kind = str(document.get("kind") or "")
    if separator and api_group == "vendir.k14s.io" and kind in {"Config", "LockConfig"}:
        return "vendir-lock" if kind == "LockConfig" else "vendir"
    if (
        separator
        and api_group == "kbld.k14s.io"
        and kind
        in {
            "Config",
            "ImageDestinations",
            "ImageKeys",
            "ImageOverrides",
            "Sources",
        }
    ):
        return "kbld"
    if (
        separator
        and api_group == "imgpkg.carvel.dev"
        and kind
        in {
            "BundleLock",
            "ImagesLock",
        }
    ):
        return "imgpkg-lock"
    if separator and api_group == "kapp.k14s.io" and kind == "Config":
        return "kapp"
    if _contains_kapp_annotations(document):
        return "kapp"
    return None


def _contains_kapp_annotations(value: Any) -> bool:
    if isinstance(value, dict):
        return any(str(key).partition("/")[:2] == ("kapp.k14s.io", "/") for key in value) or any(
            _contains_kapp_annotations(child) for child in value.values()
        )
    if isinstance(value, list):
        return any(_contains_kapp_annotations(child) for child in value)
    return False


def parse_carvel(source: str, filename: str = "config.yml") -> dict[str, Any]:
    """Parse a Carvel artifact without evaluation, fetching, building, or deployment."""
    if not source.strip():
        raise CarvelInputError("input is empty")
    if "#@" in source:
        if source.count("#@") and re.search(
            r"(?m)^\s*#@\s*(?:load|data/|overlay/|def\b|if\b|for\b)", source
        ):
            return {
                "carvel": {
                    "artifact_type": "ytt",
                    "filename": Path(filename).name,
                    "source": source,
                    "documents": [],
                }
            }
    try:
        loaded = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except CarvelInputError:
        raise
    except yaml.YAMLError as exc:
        raise CarvelInputError(f"invalid Carvel YAML: {exc}") from exc
    documents = [document for document in loaded if document is not None]
    if not documents or not all(isinstance(document, dict) for document in documents):
        raise CarvelInputError("Carvel input must contain YAML objects")
    families = {_family(document) for document in documents}
    families.discard(None)
    if len(families) != 1:
        raise CarvelInputError("input must contain one recognizable Carvel artifact family")
    artifact_type = next(iter(families))
    return {
        "carvel": {
            "artifact_type": artifact_type,
            "filename": Path(filename).name,
            "source": source,
            "documents": documents,
        }
    }


def _secret_changes(value: Any, address: str, tool: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_address = f"{address}.{key}"
            if _SECRET.search(str(key)) and child not in (None, "", False, [], {}):
                reference = str(key).lower().endswith("ref") or isinstance(child, dict)
                changes.append(
                    _change(
                        child_address,
                        "secret_reference" if reference else "literal_secret",
                        "review" if reference else "dangerous",
                        f"{tool} references externally supplied credential or secret data."
                        if reference
                        else f"{tool} embeds credential-like material; the value is omitted from analysis output.",
                    )
                )
            changes.extend(_secret_changes(child, child_address, tool))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_secret_changes(child, f"{address}[{index}]", tool))
    return changes


def _ytt_changes(source: str) -> list[dict[str, str]]:
    changes = [
        _change(
            "ytt",
            "template_evaluation",
            "review",
            "ytt evaluates sandboxed Starlark annotations, schemas, data values, overlays, modules, and libraries to produce effective YAML configuration.",
        )
    ]
    for index, match in enumerate(_YTT_LOAD.finditer(source)):
        path = match.group("path")
        builtin = path.startswith("@ytt:")
        library = path.startswith("@") and not builtin
        changes.append(
            _change(
                f"ytt.load[{index}]",
                "library_load" if library else "module_load",
                "dangerous" if _outside(path.removeprefix("@")) else "review",
                "ytt loads a built-in, local module, or supplied library; review file-set confinement, _ytt_lib provenance, private transitive libraries, exported symbols, and evaluation behavior.",
            )
        )
    probes = (
        (
            r"#@\s*data/values-schema\b",
            "data_values_schema",
            "review",
            "ytt schema declares external data-value types, defaults, nullability, validations, and effective input contract.",
        ),
        (
            r"#@\s*data/values\b",
            "data_values",
            "review",
            "ytt data values participate in layered merge precedence and can inject CLI, file, URL, stdin, environment, or secret-derived inputs.",
        ),
        (
            r"#@\s*overlay/(?:remove|replace|insert|append|match)",
            "overlay_mutation",
            "dangerous",
            "ytt overlay mutates, removes, replaces, inserts, or matches generated YAML nodes; review selectors, cardinality, missing_ok behavior, and final resources.",
        ),
        (
            r"\blibrary\.(?:get|instance)\b|\.eval\(\)|\.with_data_values\(",
            "library_evaluation",
            "review",
            "ytt explicitly configures and evaluates a library with an isolated data-values and overlay pipeline.",
        ),
        (
            r"#@\s*(?:def|lambda|if|for)\b",
            "generated_configuration",
            "review",
            "ytt functions, conditions, or loops generate effective YAML only during evaluation.",
        ),
        (
            r"#@\s*(?:assert|@ytt:assert)\b|assert\.",
            "template_assertion",
            "review",
            "ytt assertions or validation functions can stop rendering based on dynamic inputs.",
        ),
        (
            r"\bdata\.values\b",
            "external_data_input",
            "review",
            "ytt output depends on merged external data values supplied by files, flags, environment variables, URLs, stdin, or libraries.",
        ),
    )
    for pattern, kind, risk, explanation in probes:
        if re.search(pattern, source):
            changes.append(_change(f"ytt.{kind}", kind, risk, explanation))
    for match in re.finditer(
        r"(?mi)^\s*(?:#@[^\n]*\n\s*)?(?P<key>[\w.-]*(?:password|token|secret|credential|api.?key)[\w.-]*)\s*:",
        source,
    ):
        changes.append(
            _change(
                f"ytt.line[{source.count(chr(10), 0, match.start()) + 1}]",
                "credential_data",
                "dangerous",
                "ytt source declares credential-like data or a reference; the value is omitted from analysis output.",
            )
        )
    changes.append(
        _change(
            "ytt.effective_output",
            "evaluation_boundary",
            "review",
            "Static analysis does not evaluate Starlark, resolve load paths or supplied file sets, merge data values, apply overlays, validate schemas, evaluate libraries, read CLI/file/URL/stdin/environment inputs, or inspect final YAML. ytt itself intentionally does not shell out or fetch secrets, but wrappers may inject them before evaluation.",
        )
    )
    return changes


def _vendir_source_changes(content: dict[str, Any], address: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for source_type in (
        "directory",
        "git",
        "githubRelease",
        "helmChart",
        "hg",
        "http",
        "image",
        "imgpkgBundle",
        "inline",
        "manual",
    ):
        config = content.get(source_type)
        if not isinstance(config, dict):
            continue
        risk = "review"
        explanation = "vendir materializes content into a managed directory; review source provenance, resolved lock, path selection, permissions, credentials, and overwrite scope."
        if source_type in {"git", "hg"}:
            ref = str(config.get("ref") or "")
            url = str(config.get("url") or "")
            verified = bool(_mapping(config.get("verification")).get("publicKeysSecretRef"))
            risk = "review" if _COMMIT.fullmatch(ref) and verified else "dangerous"
            if url.startswith("http://") or _embedded_credential(url):
                risk = "dangerous"
        elif source_type == "http":
            url = str(config.get("url") or "")
            risk = "review" if _SHA256.fullmatch(str(config.get("sha256") or "")) else "dangerous"
            if (
                url.startswith("http://")
                or _enabled(config.get("disableAutoChecksumValidation"))
                or _embedded_credential(url)
            ):
                risk = "dangerous"
        elif source_type in {"image", "imgpkgBundle"}:
            url = str(config.get("url") or "")
            risk = "review" if "@sha256:" in url else "dangerous"
        elif source_type == "githubRelease":
            tag = str(config.get("tag") or "")
            risk = (
                "review"
                if _SEMVER.fullmatch(tag)
                and not _enabled(config.get("disableAutoChecksumValidation"))
                else "dangerous"
            )
        elif source_type == "helmChart":
            version = str(config.get("version") or "")
            repository = _mapping(config.get("repository"))
            risk = "review" if _SEMVER.fullmatch(version) else "dangerous"
            if str(repository.get("url") or "").startswith("http://"):
                risk = "dangerous"
        elif source_type == "directory":
            risk = "dangerous" if _outside(str(config.get("path") or "")) else "review"
        elif source_type == "inline" and config.get("pathsFrom"):
            risk = "dangerous"
            explanation = "vendir writes secret/config-map content into managed paths; review key selection, permissions, path confinement, disclosure, and overwrite scope."
        changes.append(
            _change(f"{address}.{source_type}", f"{source_type}_source", risk, explanation)
        )
        changes.extend(_secret_changes(config, f"{address}.{source_type}", "vendir"))
    if content.get("includePaths") or content.get("excludePaths") or content.get("newRootPath"):
        changes.append(
            _change(
                f"{address}.path_selection",
                "source_path_selection",
                "review",
                "vendir filters or re-roots fetched content; verify globs, required legal/security files, symlinks, collisions, and effective destination tree.",
            )
        )
    permissions = content.get("permissions")
    if permissions is not None and str(permissions) not in {"448", "0700", "0o700"}:
        changes.append(
            _change(
                f"{address}.permissions",
                "broad_content_permissions",
                "dangerous",
                "vendir configures non-default permissions for fetched content; verify secret exposure and executability.",
            )
        )
    return changes


def _vendir_changes(documents: list[dict[str, Any]], locked: bool) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for document in documents:
        for directory_index, directory in enumerate(_items(document.get("directories"))):
            if not isinstance(directory, dict):
                continue
            address = f"directories[{directory_index}]"
            path = str(directory.get("path") or "")
            changes.append(
                _change(
                    address,
                    "managed_directory",
                    "dangerous" if not path or _outside(path) else "review",
                    "vendir owns and synchronizes a directory tree, potentially replacing or deleting unmanaged content; review destination confinement, manual paths, permissions, and rollback.",
                )
            )
            for content_index, content in enumerate(_items(directory.get("contents"))):
                if not isinstance(content, dict):
                    continue
                content_address = f"{address}.contents[{content_index}]"
                if locked:
                    serialized = str(content)
                    pinned = bool(
                        re.search(
                            r"(?:sha|digest)['\"]?\s*:\s*['\"]?(?:sha256:)?[0-9a-f]{40,64}",
                            serialized,
                            re.I,
                        )
                    )
                    changes.append(
                        _change(
                            content_address,
                            "locked_content",
                            "review" if pinned else "dangerous",
                            "vendir lock records resolved source identity; verify immutable commit/digest/checksum, source correspondence, and checked-in lock freshness.",
                        )
                    )
                else:
                    changes.extend(_vendir_source_changes(content, content_address))
    changes.append(
        _change(
            "vendir.effective_tree",
            "resolution_boundary",
            "review",
            "Static analysis does not authenticate, fetch Git/Hg/HTTP/GitHub/Helm/OCI content, verify signatures/checksums, unpack archives, follow submodules/symlinks, apply include/exclude/legal paths, compare the lock, or mutate managed directories.",
        )
    )
    return changes


def _kbld_changes(documents: list[dict[str, Any]]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for document in documents:
        if document.get("searchRules"):
            changes.append(
                _change(
                    "kbld.searchRules",
                    "image_search_rules",
                    "review",
                    "kbld custom search rules identify and recursively rewrite image references in YAML or JSON strings; review match breadth, precedence, exclusions, and nested parsing.",
                )
            )
        for index, override in enumerate(_items(document.get("overrides"))):
            if not isinstance(override, dict):
                continue
            new_image = str(override.get("newImage") or "")
            pinned = "@sha256:" in new_image
            dangerous = (
                _enabled(override.get("preresolved"))
                and not pinned
                or bool(override.get("tagSelection"))
            )
            changes.append(
                _change(
                    f"kbld.overrides[{index}]",
                    "image_override",
                    "dangerous" if dangerous or not pinned else "review",
                    "kbld rewrites an image reference before resolution; verify destination registry, immutable digest, preresolved trust bypass, tag/platform selection, and original-to-new mapping.",
                )
            )
        for index, source in enumerate(_items(document.get("sources"))):
            if not isinstance(source, dict):
                continue
            path = str(source.get("path") or "")
            builders = set(source) & {"bazel", "docker", "ko", "kubectlBuildkit", "maven", "pack"}
            changes.append(
                _change(
                    f"kbld.sources[{index}]",
                    "image_build",
                    "dangerous",
                    "kbld invokes an external image builder against source context; review builder/toolchain provenance, Dockerfile/buildpacks/targets, raw options, credentials, network access, cache, cluster use, generated image, and source confinement.",
                )
            )
            if re.search(r"(?:password|token|secret|credential|api.?key)\s*=", str(source), re.I):
                changes.append(
                    _change(
                        f"kbld.sources[{index}].rawOptions",
                        "literal_secret",
                        "dangerous",
                        "kbld builder options embed credential-like material; the value is omitted from analysis output.",
                    )
                )
            if not path or _outside(path):
                changes.append(
                    _change(
                        f"kbld.sources[{index}].path",
                        "external_build_context",
                        "dangerous",
                        "kbld image build context is missing or escapes the project boundary.",
                    )
                )
            if not builders:
                changes.append(
                    _change(
                        f"kbld.sources[{index}].builder",
                        "implicit_builder",
                        "review",
                        "kbld image source relies on the default Docker builder and host PATH/tooling.",
                    )
                )
        for index, destination in enumerate(_items(document.get("destinations"))):
            if isinstance(destination, dict):
                new_image = str(destination.get("newImage") or "")
                changes.append(
                    _change(
                        f"kbld.destinations[{index}]",
                        "image_publish",
                        "dangerous",
                        "kbld publishes a built image to a registry; verify target ownership, authentication scope, mutable tags, overwrite policy, provenance/signing, and disclosure.",
                    )
                )
                if not new_image or "@sha256:" not in new_image:
                    changes.append(
                        _change(
                            f"kbld.destinations[{index}].newImage",
                            "mutable_image_destination",
                            "review",
                            "kbld destination uses a tag/repository rather than an immutable digest; the produced digest must be captured in a lock.",
                        )
                    )
        changes.extend(_secret_changes(document, "kbld", "kbld"))
    changes.append(
        _change(
            "kbld.effective_images",
            "execution_boundary",
            "review",
            "Static analysis does not scan effective YAML/JSON, resolve registry tags/platforms, authenticate to registries or clusters, invoke Docker/Buildpacks/BuildKit/ko/Bazel/Maven, build/push images, generate image locks, or rewrite manifests.",
        )
    )
    return changes


def _imgpkg_changes(documents: list[dict[str, Any]]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for document in documents:
        kind = str(document.get("kind") or "")
        if kind == "BundleLock":
            image = str(_mapping(document.get("bundle")).get("image") or "")
            changes.append(
                _change(
                    "imgpkg.bundle",
                    "bundle_lock",
                    "review" if "@sha256:" in image else "dangerous",
                    "imgpkg BundleLock should identify the OCI bundle by immutable digest; verify registry ownership, signature/provenance, relocation, and intended tag-to-digest correspondence.",
                )
            )
        else:
            for index, item in enumerate(_items(document.get("images"))):
                image = str(_mapping(item).get("image") or "")
                changes.append(
                    _change(
                        f"imgpkg.images[{index}]",
                        "image_lock",
                        "review" if "@sha256:" in image else "dangerous",
                        "imgpkg ImagesLock should identify a dependent OCI image by immutable digest; verify source/destination mapping, registry ownership, provenance, and platform coverage.",
                    )
                )
    changes.append(
        _change(
            "imgpkg.lock_boundary",
            "registry_boundary",
            "review",
            "Static analysis does not authenticate to OCI registries, pull/push/copy bundles or images, inspect bundle contents, verify signatures/attestations, relocate references, process tarballs, or recalculate digests.",
        )
    )
    return changes


def _kapp_annotation_changes(value: Any, address: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_address = f"{address}.{key}"
            key_text = str(key)
            group, separator, suffix = key_text.partition("/")
            if separator and group == "kapp.k14s.io":
                dangerous = any(
                    token in suffix
                    for token in ("owned-for-deletion", "update-strategy", "rebase-rule")
                )
                changes.append(
                    _change(
                        child_address,
                        "resource_lifecycle_annotation",
                        "dangerous" if dangerous else "review",
                        "kapp annotation controls resource ownership, deletion, update/recreate strategy, ordering, grouping, nonce, or rebase behavior; review live-state consequences and rollback.",
                    )
                )
            changes.extend(_kapp_annotation_changes(child, child_address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_kapp_annotation_changes(child, f"{address}[{index}]"))
    return changes


def _kapp_changes(documents: list[dict[str, Any]]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for index, document in enumerate(documents):
        address = f"kapp.documents[{index}]"
        api_group, separator, _version = str(document.get("apiVersion") or "").partition("/")
        if separator and api_group == "kapp.k14s.io":
            changes.append(
                _change(
                    address,
                    "deploy_configuration",
                    "dangerous",
                    "kapp configuration changes live-resource merge, ownership, ordering, waiting, and preflight behavior; verify matchers, field paths, sources, ytt rules, and built-in rule overrides.",
                )
            )
            for rule_index, rule in enumerate(_items(document.get("rebaseRules"))):
                if isinstance(rule, dict):
                    rule_type = str(rule.get("type") or "")
                    sources = [str(item) for item in _items(rule.get("sources"))]
                    dangerous = rule_type == "ytt" or sources == ["new"] or not sources
                    changes.append(
                        _change(
                            f"{address}.rebaseRules[{rule_index}]",
                            "rebase_rule",
                            "dangerous" if dangerous else "review",
                            "kapp rebase rule selects existing/new/current field sources or evaluates ytt against live and desired resources; review matchers, paths, merge precedence, secret fields, immutable fields, and drift masking.",
                        )
                    )
            if document.get("ownershipLabelRules"):
                changes.append(
                    _change(
                        f"{address}.ownershipLabelRules",
                        "ownership_rules",
                        "dangerous",
                        "kapp ownership-label rules determine which live resources become associated with and deleted by an application; review match scope and shared resources.",
                    )
                )
            if document.get("changeGroupBindings") or document.get("changeRuleBindings"):
                changes.append(
                    _change(
                        f"{address}.changeRules",
                        "change_ordering",
                        "review",
                        "kapp change rules alter apply/delete ordering and dependencies across resources; review cycles, convergence, and reverse deletion behavior.",
                    )
                )
        changes.extend(_kapp_annotation_changes(document, address))
        changes.extend(_secret_changes(document, address, "kapp"))
    changes.append(
        _change(
            "kapp.live_application",
            "cluster_boundary",
            "review",
            "Static analysis does not load kubeconfig, discover kapp application state/ownership, diff live resources, apply rebase/change/wait rules, run preflights, take ownership, deploy/update/recreate/delete resources, or validate dangerous CLI flags such as allowing an empty resource set.",
        )
    )
    return changes


class CarvelAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "carvel"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("carvel")
        return isinstance(payload, dict) and payload.get("artifact_type") in {
            "imgpkg-lock",
            "kapp",
            "kbld",
            "vendir",
            "vendir-lock",
            "ytt",
        }

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["carvel"]
        artifact = payload["artifact_type"]
        if artifact == "ytt":
            return _ytt_changes(payload["source"])
        if artifact.startswith("vendir"):
            return _vendir_changes(payload["documents"], artifact == "vendir-lock")
        if artifact == "kbld":
            return _kbld_changes(payload["documents"])
        if artifact == "imgpkg-lock":
            return _imgpkg_changes(payload["documents"])
        return _kapp_changes(payload["documents"])

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"carvel_{raw['Kind']}",
            actions=("execute",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_carvel(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = CarvelAdapter().analyze(data, tool_name="Carvel")
    summary = PlanSummary(
        path=Path("carvel://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Carvel")
    gate["adapter"] = "carvel"
    gate["artifact_type"] = data["carvel"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
