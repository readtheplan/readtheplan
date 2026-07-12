from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.adapters.pulumi import PulumiAdapter, _normalize_properties
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class PulumiProjectInputError(ValueError):
    """Raised when input is not a strict Pulumi project, stack, or policy file."""


_PROJECT_KEYS = {
    "author",
    "backend",
    "config",
    "description",
    "license",
    "main",
    "name",
    "options",
    "outputs",
    "packages",
    "plugins",
    "requiredPulumiVersion",
    "resources",
    "runtime",
    "stackConfigDir",
    "template",
    "variables",
    "website",
}
_STACK_KEYS = {"config", "encryptedkey", "encryptionsalt", "environment", "secretsprovider"}
_POLICY_KEYS = {
    "author",
    "description",
    "license",
    "main",
    "runtime",
    "version",
    "website",
}
_RUNTIME_NAMES = {"dotnet", "go", "java", "nodejs", "python", "yaml"}
_POLICY_RUNTIMES = {"nodejs", "opa", "python"}
_SECRET_KEY = re.compile(
    r"(?:^|[-_.:])(?:api[-_.]?key|auth|credential|password|passwd|private[-_.]?key|"
    r"secret|token|passphrase)(?:$|[-_.:])",
    re.IGNORECASE,
)
_EXACT_VERSION = re.compile(
    r"v?(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_IMMUTABLE_COMMIT = re.compile(r"[0-9a-f]{40,64}$", re.IGNORECASE)
_MUTABLE_VERSION = {"", "*", "dev", "head", "latest", "main", "master", "trunk"}


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    keys: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            raise PulumiProjectInputError("YAML merge keys are not supported")
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in keys
        except TypeError as exc:
            raise PulumiProjectInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise PulumiProjectInputError(f"duplicate YAML key: {key}")
        keys.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _change(
    address: str,
    kind: str,
    risk: str,
    explanation: str,
    *,
    resource_type: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    change: dict[str, Any] = {
        "Address": address,
        "Kind": kind,
        "Risk": risk,
        "Explanation": explanation,
    }
    if resource_type:
        change["ResourceType"] = resource_type
    if metadata is not None:
        change["_metadata"] = metadata
    return change


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(item, (*path, str(key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, (*path, str(index)))


def _runtime(document: dict[str, Any], *, policy: bool = False) -> tuple[str, dict[str, Any]]:
    value = document.get("runtime")
    if isinstance(value, str):
        name, options = value.strip().lower(), {}
    elif isinstance(value, dict):
        unknown = set(value) - {"name", "options"}
        if unknown:
            raise PulumiProjectInputError(
                "runtime contains unsupported attribute(s): " + ", ".join(sorted(unknown))
            )
        name = str(value.get("name", "")).strip().lower()
        options = value.get("options", {})
        if not isinstance(options, dict):
            raise PulumiProjectInputError("runtime options must be a mapping")
    else:
        raise PulumiProjectInputError("runtime must be a string or mapping")
    allowed = _POLICY_RUNTIMES if policy else _RUNTIME_NAMES
    if name not in allowed:
        label = "policy runtime" if policy else "runtime"
        raise PulumiProjectInputError(f"unsupported {label}: {name or '<empty>'}")
    return name, _mapping(options)


def _artifact_from_filename(filename: str | None) -> str | None:
    if not filename:
        return None
    name = Path(filename).name
    if name == "PulumiPolicy.yaml" or name == "PulumiPolicy.yml":
        return "policy"
    if re.fullmatch(r"Pulumi\.[^.]+\.ya?ml", name):
        return "stack"
    if name in {"Pulumi.yaml", "Pulumi.yml"}:
        return "project"
    return None


def _validate_project(document: dict[str, Any]) -> None:
    if not isinstance(document.get("name"), str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+", document["name"]
    ):
        raise PulumiProjectInputError(
            "project name must contain only letters, numbers, hyphens, underscores, or periods"
        )
    _runtime(document)
    for key in ("backend", "options", "packages", "plugins", "template", "config"):
        if key in document and not isinstance(document[key], dict):
            raise PulumiProjectInputError(f"project {key} must be a mapping")
    if "resources" in document and not isinstance(document["resources"], dict):
        raise PulumiProjectInputError("Pulumi YAML resources must be a mapping")


def _validate_stack(document: dict[str, Any]) -> None:
    unknown = set(document) - _STACK_KEYS
    if unknown:
        raise PulumiProjectInputError(
            "stack file contains unsupported attribute(s): " + ", ".join(sorted(unknown))
        )
    if not (_STACK_KEYS & set(document)):
        raise PulumiProjectInputError("stack file contains no recognized settings")
    if "config" in document and not isinstance(document["config"], dict):
        raise PulumiProjectInputError("stack config must be a mapping")
    environment = document.get("environment")
    if environment is not None and not isinstance(environment, (str, list, dict)):
        raise PulumiProjectInputError("stack environment must be a string, list, or mapping")
    if isinstance(environment, list) and not all(isinstance(item, str) for item in environment):
        raise PulumiProjectInputError("stack environment imports must be strings")


def _validate_policy(document: dict[str, Any]) -> None:
    unknown = set(document) - _POLICY_KEYS
    if unknown:
        raise PulumiProjectInputError(
            "policy file contains unsupported attribute(s): " + ", ".join(sorted(unknown))
        )
    _runtime(document, policy=True)
    if "version" in document and not isinstance(document["version"], (str, int, float)):
        raise PulumiProjectInputError("policy version must be a scalar value")


def parse_pulumi_project(source: str, *, filename: str | None = None) -> dict[str, Any]:
    """Parse a Pulumi project, stack settings, or policy project YAML document."""
    if not source.strip():
        raise PulumiProjectInputError("input is empty")
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except PulumiProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise PulumiProjectInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise PulumiProjectInputError("input must contain exactly one YAML mapping document")
    document = _mapping(documents[0])
    artifact = _artifact_from_filename(filename)
    if artifact is None:
        if "name" in document and "runtime" in document:
            artifact = "project"
        elif "runtime" in document and set(document) <= _POLICY_KEYS:
            artifact = "policy"
        elif set(document) <= _STACK_KEYS and (_STACK_KEYS & set(document)):
            artifact = "stack"
        else:
            raise PulumiProjectInputError(
                "input is not recognizable as Pulumi.yaml, Pulumi.<stack>.yaml, or "
                "PulumiPolicy.yaml"
            )
    if artifact == "project":
        _validate_project(document)
    elif artifact == "stack":
        _validate_stack(document)
    else:
        _validate_policy(document)
    return {"pulumi_project": {"artifact": artifact, "document": document}}


def _outside_project(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    raw = value.strip().replace("\\", "/")
    if PurePosixPath(raw).is_absolute() or PureWindowsPath(value).is_absolute():
        return True
    depth = 0
    for part in PurePosixPath(raw).parts:
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        elif part not in {"", "."}:
            depth += 1
    return False


def _url_risk(value: str) -> tuple[str | None, str | None]:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "dangerous", "The URL is malformed and cannot be safely validated."
    if parsed.username is not None or parsed.password is not None:
        return "dangerous", "The URL embeds credentials in project configuration."
    if parsed.scheme.lower() in {"http", "git", "ftp"}:
        return "dangerous", "The URL uses a plaintext transport."
    host = parsed.hostname
    if host:
        try:
            if ipaddress.ip_address(host).is_private:
                return "dangerous", "The URL targets a private or local network address."
        except ValueError:
            if host.lower() in {"localhost", "localhost.localdomain"} or host.endswith(
                (".internal", ".local")
            ):
                return "dangerous", "The URL targets a private or local network address."
    return None, None


def _runtime_changes(document: dict[str, Any], *, policy: bool = False) -> list[dict[str, Any]]:
    name, options = _runtime(document, policy=policy)
    prefix = "pulumi_policy" if policy else "pulumi_project"
    changes = [
        _change(
            f"{prefix}.runtime",
            "runtime_execution",
            "review",
            f"Pulumi will execute the {name!r} runtime and its language dependencies; verify "
            "the entry point, lockfiles, toolchain, and build provenance.",
        )
    ]
    executable_options = {"binary", "compiler", "nodeargs"}
    for key in sorted(options):
        value = options[key]
        if key in executable_options:
            risk = "dangerous" if str(value).strip() else "review"
            changes.append(
                _change(
                    f"{prefix}.runtime.options.{key}",
                    "runtime_command",
                    risk,
                    f"Runtime option {key!r} changes executable code or arguments run by "
                    "Pulumi; review command injection, path provenance, and CI trust boundaries.",
                )
            )
        elif key in {"buildTarget", "tsconfig", "virtualenv"} and _outside_project(value):
            changes.append(
                _change(
                    f"{prefix}.runtime.options.{key}",
                    "external_runtime_path",
                    "dangerous",
                    f"Runtime option {key!r} escapes the project directory or uses an absolute "
                    "path, making the analyzed repository an incomplete trust boundary.",
                )
            )
        elif key in {"packagemanager", "toolchain", "typechecker"}:
            changes.append(
                _change(
                    f"{prefix}.runtime.options.{key}",
                    "runtime_toolchain",
                    "review",
                    f"Runtime option {key!r} selects an executable dependency-management or "
                    "validation tool that can run installation hooks or repository code.",
                )
            )
    return changes


def _secretish(key: str) -> bool:
    return bool(_SECRET_KEY.search(key.replace("/", ":")))


def _secure_wrapper(value: Any) -> bool:
    return isinstance(value, dict) and "secure" in value


def _literal_secret_changes(value: Any, prefix: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for path, item in _walk(value):
        if not path or not _secretish(path[-1]) or item in (None, ""):
            continue
        if path[-1].lower() == "secret" and isinstance(item, bool):
            continue
        parent: Any = value
        for component in path[:-1]:
            if isinstance(parent, dict):
                parent = parent.get(component)
            elif isinstance(parent, list) and component.isdigit():
                parent = parent[int(component)]
            else:
                parent = None
                break
        if _secure_wrapper(parent) or path[-1] == "secure":
            continue
        if isinstance(item, (str, int, float, bool)):
            address = ".".join((prefix, *path))
            changes.append(
                _change(
                    address,
                    "plaintext_secret",
                    "dangerous",
                    "A secret-like setting contains a literal value. Store it with Pulumi "
                    "secret encryption or import it from a trusted ESC environment; the value "
                    "is intentionally omitted from this report.",
                )
            )
    return changes


def _project_config_changes(config: dict[str, Any]) -> list[dict[str, Any]]:
    changes = _literal_secret_changes(config, "pulumi_project.config")
    for key, value in config.items():
        declaration = _mapping(value)
        secret = declaration.get("secret") is True
        has_default = "default" in declaration or "value" in declaration
        if secret and has_default:
            changes.append(
                _change(
                    f"pulumi_project.config.{key}",
                    "secret_default",
                    "dangerous",
                    "A project config property marked secret also supplies a repository-stored "
                    "default or value; the literal is intentionally omitted from this report.",
                )
            )
        elif _secretish(key) and not secret:
            changes.append(
                _change(
                    f"pulumi_project.config.{key}",
                    "unmarked_secret_schema",
                    "dangerous",
                    "A secret-like project config property is not declared with secret: true.",
                )
            )
    return changes


def _package_changes(packages: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for name, declaration in packages.items():
        address = f"pulumi_project.packages.{name}"
        if isinstance(declaration, str):
            source = declaration
            source_part, separator, version = declaration.rpartition("@")
            if not separator:
                source_part, version = declaration, ""
        elif isinstance(declaration, dict):
            source = str(declaration.get("source", ""))
            source_part = source
            version = str(declaration.get("version", ""))
        else:
            changes.append(
                _change(
                    address,
                    "invalid_package",
                    "dangerous",
                    "Package declaration is not a string or mapping.",
                )
            )
            continue
        local = _outside_project(source_part) or source_part.startswith((".", "/", "file:"))
        git_source = ".git" in source_part or source_part.startswith(("git+", "github.com/"))
        risk = "dangerous" if local or not source_part.strip() else "review"
        explanation = (
            "Pulumi will install or generate SDK code from a local package source outside the "
            "analyzed project."
            if local
            else "Pulumi will install or generate SDK code from this package source; verify "
            "publisher ownership, generated code, and dependency provenance."
        )
        changes.append(_change(address, "package_dependency", risk, explanation))
        if not version or version.lower() in _MUTABLE_VERSION:
            changes.append(
                _change(
                    f"{address}.version",
                    "mutable_package_version",
                    "dangerous",
                    "The package source is not pinned to an immutable version or commit, so a "
                    "future install may execute or generate different code.",
                )
            )
        elif git_source and not (
            _EXACT_VERSION.fullmatch(version) or _IMMUTABLE_COMMIT.fullmatch(version)
        ):
            changes.append(
                _change(
                    f"{address}.version",
                    "unverified_git_revision",
                    "review",
                    "The Git-backed package revision is not an exact semantic version or full "
                    "commit identifier.",
                )
            )
        if isinstance(declaration, dict):
            checksums = declaration.get("checksums")
            if not isinstance(checksums, dict) or not checksums:
                changes.append(
                    _change(
                        f"{address}.checksums",
                        "missing_package_checksums",
                        "review",
                        "The structured package declaration has no platform checksums; verify how "
                        "the selected plugin artifact is authenticated and locked.",
                    )
                )
            download = declaration.get("pluginDownloadURL")
            if isinstance(download, str) and download:
                url_risk, reason = _url_risk(download)
                changes.append(
                    _change(
                        f"{address}.pluginDownloadURL",
                        "custom_plugin_origin",
                        url_risk or "review",
                        reason
                        or "Package downloads use a custom plugin origin; verify TLS, ownership, "
                        "authentication, and checksum coverage.",
                    )
                )
    return changes


def _plugin_changes(plugins: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for category in ("providers", "analyzers", "languages"):
        entries = plugins.get(category, [])
        if entries is None:
            continue
        if not isinstance(entries, list):
            changes.append(
                _change(
                    f"pulumi_project.plugins.{category}",
                    "invalid_plugin_set",
                    "dangerous",
                    "Plugin declarations must be a list.",
                )
            )
            continue
        for index, item in enumerate(entries):
            address = f"pulumi_project.plugins.{category}.{index}"
            plugin = _mapping(item)
            if not plugin.get("name") or not plugin.get("path"):
                changes.append(
                    _change(
                        address,
                        "invalid_local_plugin",
                        "dangerous",
                        "Local plugin declaration is missing its required name or path.",
                    )
                )
                continue
            changes.append(
                _change(
                    address,
                    "local_executable_plugin",
                    "dangerous",
                    f"Pulumi will load a local {category[:-1]} plugin executable; verify the "
                    "binary, source repository, build provenance, and path trust boundary.",
                )
            )
            if _outside_project(plugin.get("path")):
                changes.append(
                    _change(
                        f"{address}.path",
                        "external_plugin_path",
                        "dangerous",
                        "The local plugin path escapes the project directory or is absolute.",
                    )
                )
            if not plugin.get("version"):
                changes.append(
                    _change(
                        f"{address}.version",
                        "unversioned_local_plugin",
                        "review",
                        "The local plugin accepts any engine-requested version, weakening "
                        "reproducibility and compatibility review.",
                    )
                )
    return changes


def _template_changes(template: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    config = _mapping(template.get("config"))
    for key, value in config.items():
        declaration = _mapping(value)
        secret = declaration.get("secret") is True
        has_default = "default" in declaration
        if _secretish(key) and not secret:
            changes.append(
                _change(
                    f"pulumi_project.template.config.{key}",
                    "unmarked_template_secret",
                    "dangerous",
                    "A secret-like template input is not marked secret, so generated projects "
                    "may persist or display the supplied value as plaintext.",
                )
            )
        if secret and has_default:
            changes.append(
                _change(
                    f"pulumi_project.template.config.{key}.default",
                    "template_secret_default",
                    "dangerous",
                    "A template input marked secret includes a repository-stored default; the "
                    "literal is intentionally omitted from this report.",
                )
            )
    return changes


def _resource_changes(resources: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    normalizer = PulumiAdapter()
    for name, declaration in resources.items():
        resource = _mapping(declaration)
        pulumi_type = str(resource.get("type", ""))
        if not pulumi_type:
            changes.append(
                _change(
                    f"pulumi_project.resources.{name}",
                    "invalid_resource",
                    "dangerous",
                    "Pulumi YAML resource declaration is missing its required type.",
                )
            )
            continue
        properties = _mapping(resource.get("properties"))
        changes.append(
            _change(
                f"pulumi_project.resources.{name}",
                "resource_declaration",
                "review",
                "Pulumi YAML declares this infrastructure resource; source configuration does "
                "not prove the eventual preview operation or provider-computed values.",
                resource_type=normalizer._normalize_resource_type(pulumi_type),
                metadata={"before": {}, "after": _normalize_properties(properties)},
            )
        )
        changes.extend(
            _literal_secret_changes(
                properties,
                f"pulumi_project.resources.{name}.properties",
            )
        )
        options = _mapping(resource.get("options"))
        if options.get("protect") is False:
            changes.append(
                _change(
                    f"pulumi_project.resources.{name}.options.protect",
                    "unprotected_resource",
                    "review",
                    "Resource deletion protection is explicitly disabled; confirm recovery and "
                    "retention requirements for stateful infrastructure.",
                )
            )
        if options.get("deleteBeforeReplace") is True:
            changes.append(
                _change(
                    f"pulumi_project.resources.{name}.options.deleteBeforeReplace",
                    "delete_before_replace",
                    "dangerous",
                    "Replacement is configured to delete the old resource before creating the "
                    "new one, which can cause downtime or data loss.",
                )
            )
    return changes


def _project_changes(document: dict[str, Any]) -> list[dict[str, Any]]:
    changes = [
        _change(
            "pulumi_project.definition",
            "project_definition",
            "review",
            "Pulumi project metadata selects executable infrastructure code, dependency "
            "tooling, backend state, and configuration schema.",
        )
    ]
    changes.extend(_runtime_changes(document))
    for key in sorted(set(document) - _PROJECT_KEYS):
        changes.append(
            _change(
                f"pulumi_project.{key}",
                "unknown_project_attribute",
                "review",
                "This top-level Pulumi project attribute is outside the analyzer's current "
                "schema and requires manual review.",
            )
        )
    for key in ("main", "stackConfigDir"):
        if _outside_project(document.get(key)):
            changes.append(
                _change(
                    f"pulumi_project.{key}",
                    "external_project_path",
                    "dangerous",
                    f"Project attribute {key!r} escapes the project directory or uses an absolute "
                    "path, so the analyzed repository is not the complete trust boundary.",
                )
            )
    backend = _mapping(document.get("backend"))
    backend_url = backend.get("url")
    if isinstance(backend_url, str) and backend_url:
        url_risk, reason = _url_risk(backend_url)
        scheme = urlsplit(backend_url).scheme.lower()
        local = scheme == "file"
        diy = scheme in {"azblob", "gs", "s3"}
        changes.append(
            _change(
                "pulumi_project.backend.url",
                "state_backend",
                url_risk or ("dangerous" if local else "review"),
                reason
                or (
                    "Project uses a local state backend; verify encryption, locking, access "
                    "control, durability, backup, and team concurrency."
                    if local
                    else (
                        "Project uses a DIY object-storage state backend; verify encryption, "
                        "locking, access control, durability, backup, and team concurrency."
                        if diy
                        else "Project pins a backend URL; verify tenant, authentication, state "
                        "encryption, locking, and access control."
                    )
                ),
            )
        )
    options = _mapping(document.get("options"))
    if options.get("refresh") == "always":
        changes.append(
            _change(
                "pulumi_project.options.refresh",
                "automatic_refresh",
                "review",
                "Pulumi will refresh provider state before operations, which can import drift "
                "and change the effective update plan.",
            )
        )
    changes.extend(_project_config_changes(_mapping(document.get("config"))))
    changes.extend(_package_changes(_mapping(document.get("packages"))))
    changes.extend(_plugin_changes(_mapping(document.get("plugins"))))
    changes.extend(_resource_changes(_mapping(document.get("resources"))))
    changes.extend(_template_changes(_mapping(document.get("template"))))
    changes.append(
        _change(
            "pulumi_project.effective_execution",
            "project_boundary",
            "review",
            "Static project analysis does not execute the Pulumi program, install packages, "
            "load plugins, resolve language lockfiles, contact the backend, evaluate ESC, or "
            "replace a Pulumi preview and policy run.",
        )
    )
    return changes


def _stack_changes(document: dict[str, Any]) -> list[dict[str, Any]]:
    changes = [
        _change(
            "pulumi_stack.settings",
            "stack_settings",
            "review",
            "Pulumi stack settings select environment-specific provider configuration, secrets "
            "metadata, and ESC imports.",
        )
    ]
    config = _mapping(document.get("config"))
    changes.extend(_literal_secret_changes(config, "pulumi_stack.config"))
    for key, value in config.items():
        address = f"pulumi_stack.config.{key}"
        if _secure_wrapper(value):
            ciphertext = value.get("secure")
            risk = "review" if isinstance(ciphertext, str) and ciphertext.strip() else "dangerous"
            changes.append(
                _change(
                    address,
                    "encrypted_config",
                    risk,
                    "Stack config uses Pulumi's secure wrapper; ciphertext is intentionally "
                    "omitted, and decryption provider access remains outside static analysis."
                    if risk == "review"
                    else "Stack config has an empty or malformed secure wrapper.",
                )
            )
        elif isinstance(value, str):
            url_risk, reason = _url_risk(value) if "://" in value else (None, None)
            if url_risk:
                changes.append(_change(address, "unsafe_config_url", url_risk, str(reason)))
    provider = document.get("secretsprovider")
    if provider is None:
        changes.append(
            _change(
                "pulumi_stack.secretsprovider",
                "implicit_secrets_provider",
                "review",
                "The stack does not name a secrets provider; verify the selected backend's "
                "default provider and key custody before decrypting configuration or state.",
            )
        )
    elif isinstance(provider, str):
        url_risk, reason = _url_risk(provider) if "://" in provider else (None, None)
        passphrase = provider.lower().startswith("passphrase")
        changes.append(
            _change(
                "pulumi_stack.secretsprovider",
                "secrets_provider",
                url_risk or "review",
                reason
                or (
                    "Stack secrets use the passphrase provider; verify strong passphrase "
                    "generation, protected PULUMI_CONFIG_PASSPHRASE handling, and recovery."
                    if passphrase
                    else "Stack selects an external secrets provider; verify key identity, "
                    "access policy, rotation, availability, and disaster recovery."
                ),
            )
        )
    else:
        changes.append(
            _change(
                "pulumi_stack.secretsprovider",
                "invalid_secrets_provider",
                "dangerous",
                "The secrets provider must be a string.",
            )
        )
    for key in ("encryptionsalt", "encryptedkey"):
        if key in document:
            value = document[key]
            changes.append(
                _change(
                    f"pulumi_stack.{key}",
                    "encryption_metadata",
                    "review" if isinstance(value, str) and value.strip() else "dangerous",
                    "Stack encryption metadata is present and intentionally omitted; verify it "
                    "was generated by Pulumi and retained with the matching key or passphrase."
                    if isinstance(value, str) and value.strip()
                    else "Stack encryption metadata is empty or malformed.",
                )
            )
    environment = document.get("environment")
    imports: list[str] = []
    values: Any = None
    if isinstance(environment, str):
        imports = [environment]
    elif isinstance(environment, list):
        imports = environment
    elif isinstance(environment, dict):
        raw_imports = environment.get("imports", [])
        if isinstance(raw_imports, str):
            imports = [raw_imports]
        elif isinstance(raw_imports, list) and all(isinstance(item, str) for item in raw_imports):
            imports = raw_imports
        elif raw_imports:
            changes.append(
                _change(
                    "pulumi_stack.environment.imports",
                    "invalid_environment_imports",
                    "dangerous",
                    "ESC environment imports must be a string or list of strings.",
                )
            )
        values = environment.get("values")
        unknown = set(environment) - {"imports", "values"}
        for key in sorted(unknown):
            changes.append(
                _change(
                    f"pulumi_stack.environment.{key}",
                    "unknown_environment_attribute",
                    "review",
                    "This inline ESC attribute is outside the analyzer's current schema.",
                )
            )
    for index, reference in enumerate(imports):
        pinned = "@" in reference and not reference.endswith("@")
        changes.append(
            _change(
                f"pulumi_stack.environment.imports.{index}",
                "environment_import",
                "review" if pinned else "dangerous",
                "Stack imports a versioned ESC environment; verify environment access, "
                "projection, and secret rotation."
                if pinned
                else "Stack imports an ESC environment without an explicit revision; future "
                "operations can receive different configuration or secrets.",
            )
        )
    if values is not None:
        changes.extend(_literal_secret_changes(values, "pulumi_stack.environment.values"))
    changes.append(
        _change(
            "pulumi_stack.effective_configuration",
            "stack_boundary",
            "review",
            "Static stack analysis does not decrypt secure values, fetch ESC environments, "
            "resolve backend defaults, inspect provider environment variables, or determine "
            "which project program consumes each config key.",
        )
    )
    return changes


def _policy_changes(document: dict[str, Any]) -> list[dict[str, Any]]:
    changes = [
        _change(
            "pulumi_policy.definition",
            "policy_pack",
            "review",
            "Pulumi policy-pack code executes against resource inputs and decrypted secrets and "
            "may block or remediate infrastructure operations.",
        )
    ]
    changes.extend(_runtime_changes(document, policy=True))
    if _outside_project(document.get("main")):
        changes.append(
            _change(
                "pulumi_policy.main",
                "external_policy_path",
                "dangerous",
                "The policy entry point escapes the policy-pack directory or is absolute.",
            )
        )
    version = str(document.get("version", "")).strip()
    if not version:
        changes.append(
            _change(
                "pulumi_policy.version",
                "implicit_policy_version",
                "review",
                "No policy-pack version is declared here; Node.js may fall back to package.json, "
                "while Python and OPA publication requires explicit version review.",
            )
        )
    elif not _EXACT_VERSION.fullmatch(version):
        changes.append(
            _change(
                "pulumi_policy.version",
                "non_semver_policy_version",
                "review",
                "The policy-pack version is not an exact semantic version.",
            )
        )
    changes.append(
        _change(
            "pulumi_policy.effective_enforcement",
            "policy_boundary",
            "review",
            "Static metadata analysis does not execute policy code, inspect dependency lockfiles, "
            "verify published pack identity, read organization policy-group configuration, or "
            "prove advisory, mandatory, and remediation behavior.",
        )
    )
    return changes


class PulumiProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "pulumi-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        payload = input_data.get("pulumi_project")
        return (
            isinstance(payload, dict)
            and payload.get("artifact") in {"project", "stack", "policy"}
            and isinstance(payload.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        payload = input_data["pulumi_project"]
        artifact = payload["artifact"]
        document = _mapping(payload["document"])
        if artifact == "project":
            return _project_changes(document)
        if artifact == "stack":
            return _stack_changes(document)
        return _policy_changes(document)

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=str(
                raw.get("ResourceType") or f"pulumi_project_{raw['Kind']}"
            ),
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_pulumi_project(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    payload = data.get("pulumi_project", {})
    artifact = str(payload.get("artifact", "unknown"))
    changes = PulumiProjectAdapter().analyze(data, tool_name="Pulumi project")
    summary = PlanSummary(
        path=Path("pulumi-project://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Pulumi project")
    gate["adapter"] = "pulumi-project"
    gate["artifact"] = artifact
    gate["total_changes"] = len(changes)
    return gate
