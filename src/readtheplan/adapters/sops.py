from __future__ import annotations

import configparser
import json
import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class SOPSInputError(ValueError):
    """Raised when SOPS policy or encrypted-document input is invalid."""


_ENC_VALUE = re.compile(r"^ENC\[[A-Za-z0-9_]+,.*\]$", re.DOTALL)
_SENSITIVE_NAME = re.compile(
    r"(?:^|[^A-Za-z0-9])(?:access[._-]?key|api[._-]?key|auth|credential|passwd|"
    r"password|private[._-]?key|secret|token)(?=$|[^A-Za-z0-9])",
    re.IGNORECASE,
)
_IDENTITY_KEYS = (
    "kms",
    "gcp_kms",
    "azure_keyvault",
    "azure_kv",
    "hc_vault_transit_uri",
    "hc_vault",
    "hckms",
    "age",
    "pgp",
)
_SELECTOR_KEYS = (
    "unencrypted_suffix",
    "encrypted_suffix",
    "unencrypted_regex",
    "encrypted_regex",
    "unencrypted_comment_regex",
    "encrypted_comment_regex",
)


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise SOPSInputError("SOPS YAML contains an unhashable mapping key") from exc
        if duplicate:
            raise SOPSInputError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _load_yaml(source: str) -> Any:
    try:
        return yaml.load(source, Loader=_UniqueKeyLoader)
    except SOPSInputError:
        raise
    except yaml.YAMLError as exc:
        raise SOPSInputError(str(exc)) from exc


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise SOPSInputError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _load_json(source: str) -> Any:
    try:
        return json.loads(source, object_pairs_hook=_unique_json_object)
    except SOPSInputError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SOPSInputError(str(exc)) from exc


def parse_sops(source: str, filename: str) -> dict[str, Any]:
    """Parse SOPS policy or encrypted data without decrypting or resolving keys."""
    if not source.strip():
        raise SOPSInputError("input is empty")
    name = Path(filename).name.casefold()
    suffix = Path(filename).suffix.casefold()
    if name == ".sops.yaml":
        return _parse_config(source)
    if suffix == ".env":
        return _parse_dotenv_document(source)
    if suffix == ".ini":
        return _parse_ini_document(source)
    document = _load_json(source) if suffix == ".json" else _load_yaml(source)
    if not isinstance(document, dict):
        raise SOPSInputError("SOPS input must be an object")
    if "sops" in document:
        file_format = "json" if suffix == ".json" else "yaml"
        return _structured_document(document, file_format)
    if any(key in document for key in ("creation_rules", "destination_rules", "stores")):
        return _config_wrapper(document)
    raise SOPSInputError("input is neither SOPS policy nor an encrypted SOPS document")


def _parse_config(source: str) -> dict[str, Any]:
    document = _load_yaml(source)
    if not isinstance(document, dict):
        raise SOPSInputError(".sops.yaml must be a YAML object")
    return _config_wrapper(document)


def _config_wrapper(document: dict[str, Any]) -> dict[str, Any]:
    if not any(key in document for key in ("creation_rules", "destination_rules", "stores")):
        raise SOPSInputError("SOPS policy has no creation_rules, destination_rules, or stores")
    return {"sops_artifact": {"kind": "config", "format": "yaml", "content": document}}


def _structured_document(document: dict[str, Any], file_format: str) -> dict[str, Any]:
    metadata = document.get("sops")
    if not isinstance(metadata, dict):
        raise SOPSInputError("encrypted document has malformed sops metadata")
    values: list[dict[str, Any]] = []
    for key, value in document.items():
        if key == "sops":
            continue
        _collect_values(value, str(key), str(key), values)
    return {
        "sops_artifact": {
            "kind": "document",
            "format": file_format,
            "metadata": metadata,
            "values": values,
        }
    }


def _parse_dotenv_document(source: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    values: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SOPSInputError(f"invalid dotenv assignment on line {line_number}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            raise SOPSInputError(f"empty dotenv key on line {line_number}")
        if key.startswith("sops_"):
            metadata[key.removeprefix("sops_")] = value.strip()
            continue
        values.append(_value_summary(key, key, value.strip()))
    if not metadata:
        raise SOPSInputError("dotenv input has no SOPS metadata")
    return {
        "sops_artifact": {
            "kind": "document",
            "format": "dotenv",
            "metadata": metadata,
            "values": values,
        }
    }


def _parse_ini_document(source: str) -> dict[str, Any]:
    parser = configparser.RawConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    try:
        parser.read_string(source)
    except configparser.Error as exc:
        raise SOPSInputError(str(exc)) from exc
    if not parser.has_section("sops"):
        raise SOPSInputError("INI input has no [sops] metadata section")
    metadata = {key: value for key, value in parser.items("sops")}
    values: list[dict[str, Any]] = []
    for section in parser.sections():
        if section == "sops":
            continue
        for key, value in parser.items(section):
            values.append(_value_summary(f"{section}.{key}", key, value.strip()))
    return {
        "sops_artifact": {
            "kind": "document",
            "format": "ini",
            "metadata": metadata,
            "values": values,
        }
    }


def _collect_values(value: Any, path: str, key: str, output: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        for child_key, child in value.items():
            child_name = str(child_key)
            _collect_values(child, f"{path}.{child_name}", child_name, output)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _collect_values(child, f"{path}[{index}]", key, output)
        return
    output.append(_value_summary(path, key, value))


def _value_summary(path: str, key: str, value: Any) -> dict[str, Any]:
    return {
        "path": path,
        "key": key,
        "encrypted": isinstance(value, str) and _ENC_VALUE.fullmatch(value.strip()) is not None,
        "sensitive_name": _SENSITIVE_NAME.search(key) is not None,
        "empty": value is None or value == "",
    }


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _items(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, str) and "," in value:
        return [item.strip() for item in value.split(",") if item.strip()]
    return value if isinstance(value, list) else [value]


def _identity_counts(
    value: dict[str, Any], seen: set[int] | None = None
) -> dict[str, int]:
    seen = set() if seen is None else seen
    identity = id(value)
    if identity in seen:
        return {}
    seen.add(identity)
    groups = value.get("key_groups")
    if isinstance(groups, list):
        counts = {key: 0 for key in _IDENTITY_KEYS}
        for group in groups:
            if not isinstance(group, dict):
                continue
            nested = _identity_counts(group, seen)
            for key, count in nested.items():
                counts[key] += count
    else:
        counts = {key: len(_items(value.get(key))) for key in _IDENTITY_KEYS}
        merged = value.get("merge")
        if isinstance(merged, list):
            for group in merged:
                if not isinstance(group, dict):
                    continue
                nested = _identity_counts(group, seen)
                for key, count in nested.items():
                    counts[key] += count
    seen.remove(identity)
    return {key: count for key, count in counts.items() if count}


def _flat_identity_counts(metadata: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, set[str]] = {}
    for raw_key in metadata:
        key = str(raw_key)
        for provider in _IDENTITY_KEYS:
            if key == provider or key.startswith(f"{provider}__"):
                match = re.search(r"__list_(\d+)", key)
                counts.setdefault(provider, set()).add(match.group(1) if match else "0")
    return {provider: len(indexes) for provider, indexes in counts.items()}


def _metadata_identity_counts(metadata: dict[str, Any]) -> dict[str, int]:
    structured = _identity_counts(metadata)
    flat = _flat_identity_counts(metadata)
    for provider, count in flat.items():
        structured[provider] = max(structured.get(provider, 0), count)
    return structured


def _metadata_value(metadata: dict[str, Any], key: str) -> Any:
    if key in metadata:
        return metadata[key]
    return metadata.get(key.replace("_", "-"))


class SOPSAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "sops"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        artifact = input_data.get("sops_artifact")
        return isinstance(artifact, dict) and artifact.get("kind") in {"config", "document"}

    def normalize_change(self, raw_change: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw_change["Address"]),
            resource_type=f"sops_{raw_change['Kind']}",
            actions=("review",),
            risk=str(raw_change["Risk"]),
            explanation=str(raw_change["Explanation"]),
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        artifact = input_data["sops_artifact"]
        if artifact["kind"] == "config":
            return self._config(artifact["content"])
        return self._document(artifact)

    def _config(self, document: dict[str, Any]) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        rules = document.get("creation_rules")
        if not isinstance(rules, list) or not rules:
            changes.append(
                _change(
                    "policy.creation_rules",
                    "missing_creation_rules",
                    "dangerous",
                    "SOPS policy has no creation rule that can assign encryption identities.",
                )
            )
        else:
            for index, rule in enumerate(rules):
                self._creation_rule(rule, index, changes)
            last = rules[-1]
            if isinstance(last, dict) and last.get("path_regex") is not None:
                changes.append(
                    _change(
                        "policy.creation_rules.default",
                        "missing_default_rule",
                        "review",
                        "Every SOPS creation rule is path-scoped; unmatched files require an "
                        "explicit key selection or a catch-all rule.",
                    )
                )
        if document.get("destination_rules") is not None:
            changes.append(
                _change(
                    "policy.destination_rules",
                    "secret_publication",
                    "dangerous",
                    "SOPS destination rules can publish secret material to external stores; "
                    "verify destination identity, encryption, and overwrite boundaries.",
                )
            )
        if document.get("stores") is not None:
            changes.append(
                _change(
                    "policy.stores",
                    "serialization",
                    "review",
                    "SOPS store settings change serialization of encrypted data and diffs.",
                )
            )
        changes.append(
            _change(
                "policy.effective_configuration",
                "effective_configuration",
                "review",
                "SOPS key selection also depends on the target filename, config search path, "
                "command-line flags, environment variables, and key-service settings.",
            )
        )
        return changes

    def _creation_rule(
        self, rule: Any, index: int, changes: list[dict[str, Any]]
    ) -> None:
        address = f"policy.creation_rules[{index}]"
        if not isinstance(rule, dict):
            changes.append(
                _change(address, "unresolved", "dangerous", "Creation rule is malformed.")
            )
            return
        if rule.get("path_regex") is not None:
            changes.append(
                _change(
                    f"{address}.path_regex",
                    "path_scope",
                    "review",
                    "SOPS selects this creation rule according to the target file path.",
                )
            )
            try:
                re.compile(str(rule["path_regex"]))
            except re.error:
                changes.append(
                    _change(
                        f"{address}.path_regex",
                        "invalid_regex",
                        "dangerous",
                        "Creation-rule path_regex is not a valid regular expression.",
                    )
                )
        counts = _identity_counts(rule)
        if not counts:
            changes.append(
                _change(
                    f"{address}.identities",
                    "missing_identity",
                    "dangerous",
                    "Creation rule has no KMS, Vault, age, PGP, or other encryption identity.",
                )
            )
        for provider, count in counts.items():
            changes.append(
                _change(
                    f"{address}.identities.{provider}",
                    "encryption_identity",
                    "review",
                    f"SOPS grants {count} {provider} recipient(s) access to the file data key.",
                )
            )
        groups = rule.get("key_groups")
        group_count = len(groups) if isinstance(groups, list) else 0
        threshold = rule.get("shamir_threshold", 0)
        if groups is not None:
            changes.append(
                _change(
                    f"{address}.key_groups",
                    "key_groups",
                    "review",
                    "SOPS key groups split recovery and access across identity sets.",
                )
            )
            if not isinstance(groups, list) or not groups:
                changes.append(
                    _change(
                        f"{address}.key_groups",
                        "invalid_key_groups",
                        "dangerous",
                        "SOPS key_groups must be a non-empty list of identity mappings.",
                    )
                )
            elif any(
                not isinstance(group, dict) or not _identity_counts(group) for group in groups
            ):
                changes.append(
                    _change(
                        f"{address}.key_groups",
                        "invalid_key_groups",
                        "dangerous",
                        "Every SOPS key group must contain at least one encryption identity.",
                    )
                )
            if any(rule.get(key) is not None for key in _IDENTITY_KEYS):
                changes.append(
                    _change(
                        f"{address}.identities",
                        "ignored_identity",
                        "review",
                        "SOPS ignores direct identity fields when key_groups are configured.",
                    )
                )
        if threshold not in {None, 0}:
            valid = isinstance(threshold, int) and threshold >= 2 and threshold <= group_count
            changes.append(
                _change(
                    f"{address}.shamir_threshold",
                    "shamir_threshold",
                    "review" if valid else "dangerous",
                    "SOPS Shamir threshold controls how many key groups are required to "
                    "recover the data key.",
                )
            )
        selectors = [key for key in _SELECTOR_KEYS if rule.get(key) is not None]
        if len(selectors) > 1:
            changes.append(
                _change(
                    f"{address}.encryption_selector",
                    "conflicting_selectors",
                    "dangerous",
                    "A SOPS creation rule may use at most one encryption selector.",
                )
            )
        for selector in selectors:
            selective = selector.startswith("encrypted_")
            changes.append(
                _change(
                    f"{address}.{selector}",
                    "selective_encryption",
                    "dangerous" if selective else "review",
                    "SOPS selector intentionally leaves part of the document in plaintext; "
                    "verify that no secret-bearing field can fall outside encryption scope.",
                )
            )
            if selector.endswith("regex"):
                try:
                    re.compile(str(rule[selector]))
                except re.error:
                    changes.append(
                        _change(
                            f"{address}.{selector}",
                            "invalid_regex",
                            "dangerous",
                            "SOPS encryption selector is not a valid regular expression.",
                        )
                    )
        if rule.get("mac_only_encrypted") is True:
            changes.append(
                _change(
                    f"{address}.mac_only_encrypted",
                    "partial_integrity",
                    "dangerous",
                    "SOPS excludes plaintext fields from the document MAC, reducing tamper "
                    "detection coverage.",
                )
            )
        if rule.get("aws_profile") is not None:
            changes.append(
                _change(
                    f"{address}.aws_profile",
                    "ambient_identity",
                    "review",
                    "SOPS selects an AWS profile whose credentials determine KMS access.",
                )
            )
        if self._contains_aws_role_or_context(rule):
            changes.append(
                _change(
                    f"{address}.kms_context",
                    "delegated_identity",
                    "dangerous",
                    "SOPS AWS KMS configuration assumes a role or binds encryption context; "
                    "verify trust policy and exact context constraints.",
                )
            )
        if self._contains_ssh_age_recipient(rule):
            changes.append(
                _change(
                    f"{address}.age_ssh",
                    "ssh_identity",
                    "review",
                    "SOPS age encryption uses SSH recipients and may discover corresponding "
                    "private keys from standard SSH locations during decryption.",
                )
            )

    def _document(self, artifact: dict[str, Any]) -> list[dict[str, Any]]:
        metadata = artifact["metadata"]
        values = artifact["values"]
        changes: list[dict[str, Any]] = []
        encrypted = [value for value in values if value["encrypted"]]
        plaintext = [value for value in values if not value["encrypted"] and not value["empty"]]
        if encrypted:
            changes.append(
                _change(
                    "document.encrypted_values",
                    "encrypted_payload",
                    "safe",
                    f"SOPS document contains {len(encrypted)} encrypted value(s).",
                )
            )
        else:
            changes.append(
                _change(
                    "document.encrypted_values",
                    "missing_encryption",
                    "dangerous",
                    "SOPS metadata is present but no encrypted payload values were found.",
                )
            )
        selectors = {
            key: _metadata_value(metadata, key)
            for key in _SELECTOR_KEYS
            if _metadata_value(metadata, key) not in {None, ""}
        }
        for value in plaintext:
            intended = self._plaintext_is_selected(str(value["key"]), selectors)
            sensitive = bool(value["sensitive_name"])
            risk = "dangerous" if sensitive or not intended else "review"
            changes.append(
                _change(
                    f"document.{value['path']}",
                    "plaintext_value",
                    risk,
                    "SOPS document contains a plaintext leaf value; verify that the encryption "
                    "selector intentionally permits it and that the field is not sensitive.",
                )
            )
        counts = _metadata_identity_counts(metadata)
        if not counts:
            changes.append(
                _change(
                    "document.sops.identities",
                    "missing_identity",
                    "dangerous",
                    "SOPS metadata has no recognizable identity capable of unwrapping the "
                    "data key.",
                )
            )
        for provider, count in counts.items():
            changes.append(
                _change(
                    f"document.sops.identities.{provider}",
                    "encryption_identity",
                    "review",
                    f"SOPS metadata grants {count} {provider} recipient(s) access to the data key.",
                )
            )
        mac = _metadata_value(metadata, "mac")
        if not isinstance(mac, str) or _ENC_VALUE.fullmatch(mac.strip()) is None:
            changes.append(
                _change(
                    "document.sops.mac",
                    "integrity",
                    "dangerous",
                    "SOPS document MAC is missing or is not encrypted metadata.",
                )
            )
        else:
            changes.append(
                _change(
                    "document.sops.mac",
                    "integrity",
                    "safe",
                    "SOPS document includes an encrypted integrity MAC.",
                )
            )
        if _metadata_value(metadata, "mac_only_encrypted") in {True, "true", "True", "1"}:
            changes.append(
                _change(
                    "document.sops.mac_only_encrypted",
                    "partial_integrity",
                    "dangerous",
                    "SOPS MAC excludes plaintext values from integrity protection.",
                )
            )
        if _metadata_value(metadata, "version") in {None, ""}:
            changes.append(
                _change(
                    "document.sops.version",
                    "missing_version",
                    "review",
                    "SOPS metadata does not record the writer version.",
                )
            )
        changes.append(
            _change(
                "document.effective_access",
                "effective_configuration",
                "review",
                "Decryption access depends on current KMS IAM, Vault policy, private-key "
                "custody, key-service transport, recipient rotation, and audit configuration.",
            )
        )
        return changes

    @staticmethod
    def _plaintext_is_selected(key: str, selectors: dict[str, Any]) -> bool:
        if not selectors:
            return False
        if "unencrypted_suffix" in selectors:
            return key.endswith(str(selectors["unencrypted_suffix"]))
        if "encrypted_suffix" in selectors:
            return not key.endswith(str(selectors["encrypted_suffix"]))
        for selector, invert in (("unencrypted_regex", False), ("encrypted_regex", True)):
            if selector not in selectors:
                continue
            try:
                matches = re.search(str(selectors[selector]), key) is not None
            except re.error:
                return False
            return not matches if invert else matches
        return False

    @staticmethod
    def _contains_aws_role_or_context(value: Any) -> bool:
        if isinstance(value, dict):
            return any(
                str(key) in {"role", "context"}
                or SOPSAdapter._contains_aws_role_or_context(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(SOPSAdapter._contains_aws_role_or_context(child) for child in value)
        return False

    @staticmethod
    def _contains_ssh_age_recipient(value: Any) -> bool:
        if isinstance(value, dict):
            return any(SOPSAdapter._contains_ssh_age_recipient(child) for child in value.values())
        if isinstance(value, list):
            return any(SOPSAdapter._contains_ssh_age_recipient(child) for child in value)
        return str(value).strip().startswith(("ssh-rsa ", "ssh-ed25519 "))


def analyze_sops(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    adapter = SOPSAdapter()
    changes = adapter.analyze(data, tool_name="SOPS")
    summary = PlanSummary(
        path=Path("sops://"), terraform_version=None, resource_changes=tuple(changes)
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="SOPS")
    gate["adapter"] = "sops"
    gate["total_changes"] = len(changes)
    return gate
