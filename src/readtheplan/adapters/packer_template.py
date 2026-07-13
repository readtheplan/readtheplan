from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

import hcl2
from hcl2.utils import SerializationOptions


class PackerTemplateInputError(ValueError):
    """Raised when input is not a recognizable Packer HCL/JSON template."""


_SECRET = re.compile(
    r"(?:password|passwd|token|secret|private.?key|access.?key|credential|api.?key|auth)", re.I
)
_PUBLISHING = {
    "alicloud-import",
    "amazon-import",
    "artifactory",
    "docker-import",
    "docker-push",
    "googlecompute-export",
    "hcp-packer-registry",
    "vagrant-cloud",
    "vsphere",
}
_EXECUTING_PROVISIONERS = {
    "ansible",
    "ansible-local",
    "chef-client",
    "chef-solo",
    "converge",
    "inspec",
    "powershell",
    "puppet-masterless",
    "puppet-server",
    "salt-masterless",
    "shell",
    "shell-local",
    "windows-shell",
    "windows-update",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PackerTemplateInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strip_internal(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_internal(child) for key, child in value.items() if key != "__is_block__"
        }
    if isinstance(value, list):
        return [_strip_internal(child) for child in value]
    return value


def parse_packer_template(source: str) -> dict[str, Any]:
    """Parse native Packer HCL2/JSON or legacy JSON without evaluating expressions."""
    if not source.strip():
        raise PackerTemplateInputError("input is empty")
    representation = "json" if source.lstrip().startswith(("{", "[")) else "hcl"
    if representation == "json":
        try:
            document: Any = json.loads(source, object_pairs_hook=_unique_object)
        except PackerTemplateInputError:
            raise
        except json.JSONDecodeError as exc:
            raise PackerTemplateInputError(f"invalid Packer template JSON: {exc}") from exc
    else:
        try:
            document = hcl2.loads(
                source,
                serialization_options=SerializationOptions(
                    explicit_blocks=False,
                    strip_string_quotes=True,
                ),
            )
        except Exception as exc:
            raise PackerTemplateInputError(f"invalid Packer HCL template: {exc}") from exc
    document = _strip_internal(document)
    if not isinstance(document, dict):
        raise PackerTemplateInputError("Packer template must be an HCL or JSON object")
    recognized = {
        "packer",
        "source",
        "build",
        "variable",
        "variables",
        "local",
        "locals",
        "data",
        "builders",
        "provisioners",
        "post-processors",
    }
    if not recognized & set(document):
        raise PackerTemplateInputError("input is not recognized as a Packer template")
    return {
        "packer_template": {
            "representation": representation,
            "document": document,
            "source_text": source,
        }
    }


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _value(document: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in document:
            return document[name]
    return default


def _labeled_blocks(document: dict[str, Any], name: str) -> list[tuple[list[str], dict[str, Any]]]:
    raw = document.get(name, [])
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        raise PackerTemplateInputError(f"Packer {name} must contain blocks")
    result: list[tuple[list[str], dict[str, Any]]] = []

    def visit(value: Any, labels: list[str]) -> None:
        if not isinstance(value, dict):
            raise PackerTemplateInputError(f"Packer {name} block must be an object")
        nested = [(key, child) for key, child in value.items() if isinstance(child, dict)]
        attributes = {key: child for key, child in value.items() if not isinstance(child, dict)}
        if attributes or not nested:
            result.append((labels, value))
            return
        for label, child in nested:
            visit(child, [*labels, str(label)])

    for item in raw:
        visit(item, [])
    return result


def _blocks(document: dict[str, Any], name: str) -> list[tuple[list[str], dict[str, Any]]]:
    return _labeled_blocks(document, name) if name in document else []


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _literal_secret_changes(value: Any, prefix: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            address = f"{prefix}.{key}"
            if _SECRET.search(str(key)) and child not in (None, "", False, [], {}):
                text = str(child)
                reference = bool(re.search(r"\$\{|\bvar\.|\blocal\.|\benv\(", text))
                changes.append(
                    _change(
                        address,
                        "secret_reference" if reference else "literal_secret",
                        "review" if reference else "dangerous",
                        "Packer template references externally supplied credential-like data."
                        if reference
                        else "Packer template embeds credential-like material directly; the "
                        "value is omitted from analysis output.",
                    )
                )
            changes.extend(_literal_secret_changes(child, address))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            changes.extend(_literal_secret_changes(child, f"{prefix}[{index}]"))
    return changes


def _plugin_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    packer_blocks = _items(document.get("packer"))
    if not packer_blocks:
        changes.append(
            _change(
                "packer.required_version",
                "version_boundary",
                "review",
                "Packer template has no packer block declaring core or plugin requirements.",
            )
        )
        return changes
    for index, block in enumerate(packer_blocks):
        if not isinstance(block, dict):
            continue
        address = f"packer[{index}]"
        if not block.get("required_version"):
            changes.append(
                _change(
                    f"{address}.required_version",
                    "version_boundary",
                    "review",
                    "Packer core version is not constrained, so language and plugin behavior "
                    "may vary.",
                )
            )
        required = block.get("required_plugins", [])
        for plugin_container in _items(required):
            if not isinstance(plugin_container, dict):
                continue
            for name, plugin in plugin_container.items():
                if not isinstance(plugin, dict):
                    continue
                source = str(plugin.get("source") or "")
                version = str(plugin.get("version") or "")
                official = source.startswith("github.com/hashicorp/")
                exact = bool(re.fullmatch(r"=?\s*v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version))
                risk = "review" if official and exact else "dangerous"
                changes.append(
                    _change(
                        f"{address}.required_plugins.{name}",
                        "required_plugin",
                        risk,
                        "Packer can install this executable plugin during init; review source "
                        "ownership, exact version, release checksums/signatures, platform binary, "
                        "and plugin lockfile.",
                    )
                )
    return changes


def _variable_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for labels, block in _blocks(document, "variable"):
        name = labels[-1] if labels else "unknown"
        address = f"variable.{name}"
        sensitive_name = bool(_SECRET.search(name))
        sensitive = bool(block.get("sensitive"))
        default = block.get("default")
        if sensitive_name and not sensitive:
            changes.append(
                _change(
                    f"{address}.sensitive",
                    "unmasked_secret_variable",
                    "dangerous",
                    "Credential-like Packer variable is not marked sensitive and may appear in "
                    "logs or UI output.",
                )
            )
        if sensitive_name and default not in (None, "", False, [], {}):
            changes.append(
                _change(
                    f"{address}.default",
                    "literal_secret",
                    "dangerous",
                    "Credential-like Packer variable has a source default; the value is omitted "
                    "from analysis output.",
                )
            )
        if default is None:
            changes.append(
                _change(
                    address,
                    "runtime_variable",
                    "review",
                    "Packer variable must be supplied at runtime; its effective value and "
                    "provenance are unresolved.",
                )
            )
    legacy = document.get("variables", {})
    if isinstance(legacy, dict):
        changes.extend(_literal_secret_changes(legacy, "variables"))
    for labels, block in _blocks(document, "local"):
        name = labels[-1] if labels else "unknown"
        if _SECRET.search(name) and not block.get("sensitive"):
            changes.append(
                _change(
                    f"local.{name}",
                    "unmasked_secret_local",
                    "dangerous",
                    "Credential-like Packer local is not marked sensitive and may be exposed "
                    "in logs.",
                )
            )
    changes.extend(_literal_secret_changes(document.get("locals", {}), "locals"))
    return changes


def _source_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for labels, block in _blocks(document, "source"):
        source_type = labels[0] if labels else "unknown"
        name = labels[1] if len(labels) > 1 else "source"
        address = f"source.{source_type}.{name}"
        risk = "review" if source_type in {"file", "null"} else "dangerous"
        changes.append(
            _change(
                address,
                "builder",
                risk,
                f"Packer {source_type!r} builder can create infrastructure or image artifacts; "
                "review plugin, base image, credentials, network, temporary resources, cleanup, "
                "encryption, and destination ownership.",
            )
        )
        communicator = str(block.get("communicator") or "ssh").lower()
        if communicator in {"ssh", "winrm"}:
            changes.append(
                _change(
                    f"{address}.communicator",
                    "communicator",
                    "review",
                    f"Packer uses {communicator} to access the temporary build host; review "
                    "identity, host verification, bastion/proxy, certificates, and credential "
                    "lifetime.",
                )
            )
        for key in (
            "insecure_skip_tls_verify",
            "ssh_skip_request_pty",
            "ssh_clear_authorized_keys",
        ):
            if block.get(key) is True:
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "verification_bypass",
                        "dangerous",
                        f"Packer builder enables {key}, weakening transport or post-build "
                        "access controls.",
                    )
                )
        if block.get("most_recent") is True:
            changes.append(
                _change(
                    f"{address}.most_recent",
                    "mutable_base_image",
                    "dangerous",
                    "Packer dynamically selects the most recent base image, so identical source "
                    "can build different artifacts.",
                )
            )
        for key in ("iso_url", "url", "source_url"):
            value = str(block.get(key) or "")
            if value:
                checksum = block.get("iso_checksum") or block.get("checksum")
                dangerous = (
                    value.startswith(("http://", "git://"))
                    or _embedded_credential(value)
                    or not checksum
                )
                changes.append(
                    _change(
                        f"{address}.{key}",
                        "remote_source",
                        "dangerous" if dangerous else "review",
                        "Packer downloads builder input; review TLS, immutable origin, checksum "
                        "algorithm/value, redirect, extraction, and credential handling.",
                    )
                )
        changes.extend(_literal_secret_changes(block, address))
    legacy = document.get("builders", [])
    for index, builder in enumerate(_items(legacy)):
        if isinstance(builder, dict):
            source_type = str(builder.get("type") or "unknown")
            changes.append(
                _change(
                    f"builders[{index}]",
                    "builder",
                    "review" if source_type in {"file", "null"} else "dangerous",
                    f"Legacy JSON Packer {source_type!r} builder creates or transforms an image "
                    "artifact.",
                )
            )
            changes.extend(_literal_secret_changes(builder, f"builders[{index}]"))
    return changes


def _provisioner_change(kind: str, block: dict[str, Any], address: str) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    if kind in {"breakpoint", "sleep"}:
        risk = "safe"
    elif kind == "file":
        risk = "review"
    else:
        risk = "dangerous" if kind in _EXECUTING_PROVISIONERS or kind == "shell-local" else "review"
    boundary = (
        "on the Packer host" if kind == "shell-local" else "inside the temporary build machine"
    )
    changes.append(
        _change(
            address,
            "provisioner",
            risk,
            f"Packer {kind!r} provisioner executes or transfers build steps {boundary}; review "
            "commands, scripts, environment, privilege, error handling, and secrets.",
        )
    )
    if block.get("elevated_user") or block.get("execute_command") or block.get("use_sudo"):
        changes.append(
            _change(
                f"{address}.privilege",
                "elevated_provisioning",
                "dangerous",
                "Packer provisioner customizes elevated execution or explicitly requests "
                "privilege escalation.",
            )
        )
    changes.extend(_literal_secret_changes(block, address))
    return changes


def _processor_change(kind: str, block: dict[str, Any], address: str) -> list[dict[str, str]]:
    if kind in _PUBLISHING or kind == "shell-local":
        risk = "dangerous"
    elif kind in {"checksum", "manifest"}:
        risk = "safe"
    else:
        risk = "review"
    changes = [
        _change(
            address,
            "post_processor",
            risk,
            f"Packer {kind!r} post-processor transforms, executes against, or publishes the "
            "build artifact; review destination, credentials, overwrite/deletion, retention, "
            "checksum, signing, and provenance.",
        )
    ]
    if kind == "checksum":
        algorithms = " ".join(str(v) for v in _items(block.get("checksum_types")))
        if re.search(r"\b(?:md5|sha1)\b", algorithms, re.I):
            changes.append(
                _change(
                    f"{address}.checksum",
                    "weak_checksum",
                    "dangerous",
                    "Packer checksum post-processor includes MD5 or SHA-1, which is unsuitable "
                    "for artifact integrity assurance.",
                )
            )
    changes.extend(_literal_secret_changes(block, address))
    return changes


def _build_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    builds = _items(document.get("build"))
    if not builds and any(
        key in document for key in ("builders", "provisioners", "post-processors")
    ):
        builds = [
            {
                "name": "legacy",
                "provisioner": document.get("provisioners", []),
                "post-processor": document.get("post-processors", []),
            }
        ]
    for index, build in enumerate(builds):
        if not isinstance(build, dict):
            continue
        name = str(build.get("name") or f"build-{index}")
        address = f"build.{name}"
        sources = _items(build.get("sources")) + [
            labels[-1] for labels, _ in _blocks(build, "source") if labels
        ]
        if not sources and not document.get("builders"):
            changes.append(
                _change(
                    f"{address}.sources",
                    "missing_source",
                    "dangerous",
                    "Packer build has no recognized builder source.",
                )
            )
        for p_index, (labels, block) in enumerate(_blocks(build, "provisioner")):
            kind = labels[-1] if labels else "unknown"
            changes.extend(
                _provisioner_change(kind, block, f"{address}.provisioner[{p_index}].{kind}")
            )
        for p_index, provisioner in enumerate(_items(build.get("provisioners"))):
            if isinstance(provisioner, dict):
                kind = str(provisioner.get("type") or "unknown")
                changes.extend(
                    _provisioner_change(
                        kind, provisioner, f"{address}.provisioner[{p_index}].{kind}"
                    )
                )
        processors = _blocks(build, "post-processor")
        for p_index, (labels, block) in enumerate(processors):
            kind = labels[-1] if labels else "unknown"
            changes.extend(
                _processor_change(kind, block, f"{address}.post_processor[{p_index}].{kind}")
            )
        post_processor_items = _items(build.get("post-processors"))
        for sequence_index, container in enumerate(post_processor_items):
            if isinstance(container, dict) and "post-processor" in container:
                for processor_index, (labels, block) in enumerate(
                    _blocks(container, "post-processor")
                ):
                    kind = labels[-1] if labels else "unknown"
                    changes.extend(
                        _processor_change(
                            kind,
                            block,
                            f"{address}.post_processors[{sequence_index}]"
                            f"[{processor_index}].{kind}",
                        )
                    )
        for p_index, processor in enumerate(post_processor_items):
            if isinstance(processor, dict) and "post-processor" in processor:
                continue
            if isinstance(processor, str):
                changes.extend(
                    _processor_change(
                        processor, {}, f"{address}.post_processor[{p_index}].{processor}"
                    )
                )
            elif isinstance(processor, dict):
                kind = str(processor.get("type") or "unknown")
                changes.extend(
                    _processor_change(
                        kind, processor, f"{address}.post_processor[{p_index}].{kind}"
                    )
                )
        for sequence_index, sequence in enumerate(post_processor_items):
            if isinstance(sequence, list):
                for processor_index, processor in enumerate(sequence):
                    if isinstance(processor, dict):
                        kind = str(processor.get("type") or "unknown")
                        changes.extend(
                            _processor_change(
                                kind,
                                processor,
                                f"{address}.post_processors[{sequence_index}][{processor_index}].{kind}",
                            )
                        )
    return changes


def packer_template_changes(payload: dict[str, Any]) -> list[dict[str, str]]:
    document = payload["document"]
    changes = [*_plugin_changes(document), *_variable_changes(document)]
    for labels, block in _blocks(document, "data"):
        kind = labels[0] if labels else "unknown"
        name = labels[1] if len(labels) > 1 else "data"
        changes.append(
            _change(
                f"data.{kind}.{name}",
                "external_data",
                "review",
                f"Packer {kind!r} data source queries external state at build time; review "
                "credentials, filters, mutability, and returned sensitivity.",
            )
        )
        changes.extend(_literal_secret_changes(block, f"data.{kind}.{name}"))
    changes.extend(_source_changes(document))
    changes.extend(_build_changes(document))
    changes.extend(_literal_secret_changes(document, "packer.template"))
    source_text = str(payload.get("source_text") or "")
    if re.search(r"\b(?:env|file|fileset|templatefile|vault)\s*\(", source_text):
        changes.append(
            _change(
                "packer.expressions",
                "dynamic_evaluation",
                "review",
                "Packer template uses functions that read environment, files, templates, or "
                "external data; effective values were not evaluated.",
            )
        )
    changes.append(
        _change(
            "packer.effective_template",
            "source_boundary",
            "review",
            "Static analysis does not run packer init/validate/build, install or lock plugins, "
            "evaluate HCL functions/variables/data, connect to builders, execute provisioners, "
            "or publish artifacts.",
        )
    )
    return changes
