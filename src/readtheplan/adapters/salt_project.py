from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class SaltProjectInputError(ValueError):
    """Raised when input is not recognizable Salt project configuration."""


_MASTER_KEYS = {
    "auto_accept",
    "autosign_file",
    "beacons",
    "engines",
    "ext_pillar",
    "external_auth",
    "file_recv",
    "file_roots",
    "git_pillar",
    "gitfs_remotes",
    "master_roots",
    "nodegroups",
    "open_mode",
    "peer",
    "peer_run",
    "permissive_pki_access",
    "pillar_cache",
    "pillar_cache_backend",
    "pillar_opts",
    "pillar_roots",
    "publisher_acl",
    "publisher_acl_blacklist",
    "reactor",
    "reactor_worker_threads",
    "rest_cherrypy",
    "rest_tornado",
    "schedule",
    "token_expire_user_override",
}
_MINION_KEYS = {
    "beacons",
    "enable_legacy_startup_events",
    "file_roots",
    "grains",
    "id",
    "include",
    "master",
    "master_type",
    "mine_functions",
    "module_dirs",
    "pillar_roots",
    "schedule",
    "sls_list",
    "startup_states",
    "top_file",
    "user",
    "verify_master_pubkey_sign",
}
_CONFIG_MARKERS = (_MASTER_KEYS | _MINION_KEYS) - {
    "beacons",
    "file_roots",
    "include",
    "schedule",
    "user",
}
_ROSTER_KEYS = {
    "cmd_umask",
    "host",
    "minion_opts",
    "passwd",
    "port",
    "priv",
    "priv_passwd",
    "proxy_host",
    "proxy_passwd",
    "proxy_port",
    "proxy_user",
    "python2_bin",
    "python3_bin",
    "roster",
    "set_path",
    "ssh_options",
    "ssh_pre_flight",
    "sudo",
    "sudo_user",
    "thin_dir",
    "timeout",
    "tty",
    "user",
}
_ROSTER_MARKERS = {"host", "passwd", "priv", "proxy_host", "ssh_options", "sudo"}
_SECRET_KEY = re.compile(
    r"(?:password|passwd|passphrase|token|secret|api.?key|priv(?:ate)?_?key|credential)",
    re.IGNORECASE,
)
_COMMIT = re.compile(r"[0-9a-f]{40,64}$", re.IGNORECASE)
_DYNAMIC = ("{{", "{%", "{#")


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    explicit: set[Any] = set()
    for key_node, _ in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in explicit
        except TypeError as exc:
            raise SaltProjectInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise SaltProjectInputError(f"duplicate YAML key: {key}")
        explicit.add(key)
    loader.flatten_mapping(node)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _disabled(value: Any) -> bool:
    return value is False or str(value).strip().lower() in {"0", "false", "no", "off"}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _yaml_document(source: str) -> dict[str, Any]:
    if not source.strip():
        raise SaltProjectInputError("input is empty")
    if any(marker in source for marker in _DYNAMIC):
        raise SaltProjectInputError(
            "Salt project input must be rendered YAML; template expressions are not executed"
        )
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except SaltProjectInputError:
        raise
    except yaml.YAMLError as exc:
        raise SaltProjectInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise SaltProjectInputError("input must contain exactly one YAML mapping")
    document = documents[0]
    if not document or not all(isinstance(key, str) for key in document):
        raise SaltProjectInputError("top-level Salt keys must be non-empty strings")
    return document


def _looks_like_roster(document: dict[str, Any]) -> bool:
    if not document or not all(isinstance(value, dict) for value in document.values()):
        return False
    entries = list(document.values())
    return all(_ROSTER_KEYS & set(map(str, entry)) for entry in entries) and any(
        _ROSTER_MARKERS & set(map(str, entry)) for entry in entries
    )


def _validate_roster(document: dict[str, Any]) -> None:
    for target, entry in document.items():
        if not isinstance(entry, dict):
            raise SaltProjectInputError(f"roster target {target!r} must be a mapping")
        unknown = set(entry) - _ROSTER_KEYS
        if unknown:
            raise SaltProjectInputError(
                f"unsupported roster key(s) for {target!r}: " + ", ".join(sorted(map(str, unknown)))
            )
        if not (_ROSTER_KEYS & set(entry)):
            raise SaltProjectInputError(f"roster target {target!r} has no connection settings")
        for key in ("host", "user", "passwd", "priv", "proxy_host", "ssh_pre_flight"):
            if key in entry and not isinstance(entry[key], str):
                raise SaltProjectInputError(f"roster {target!r} {key} must be a string")


def _looks_like_top(document: dict[str, Any]) -> bool:
    if not document or not all(isinstance(value, dict) for value in document.values()):
        return False
    return any(
        isinstance(assignments, dict)
        and assignments
        and all(isinstance(target, str) for target in assignments)
        for assignments in document.values()
    )


def _validate_top(document: dict[str, Any]) -> None:
    for environment, assignments in document.items():
        if not isinstance(assignments, dict):
            raise SaltProjectInputError(f"top environment {environment!r} must be a mapping")
        for target, body in assignments.items():
            if not isinstance(target, str) or not target.strip():
                raise SaltProjectInputError("top targets must be non-empty strings")
            if not isinstance(body, (str, list, dict)):
                raise SaltProjectInputError(
                    f"top assignment {environment}.{target} must be a string, list, or mapping"
                )
            if isinstance(body, list) and not all(isinstance(item, (str, dict)) for item in body):
                raise SaltProjectInputError(
                    f"top assignment {environment}.{target} contains an invalid item"
                )


def parse_salt_project(source: str) -> dict[str, Any]:
    """Parse Salt master/minion config, a top file, or a salt-ssh roster."""
    document = _yaml_document(source)
    if _looks_like_roster(document):
        _validate_roster(document)
        artifact_type = "roster"
    elif set(document) & _CONFIG_MARKERS:
        artifact_type = "config"
    elif _looks_like_top(document):
        _validate_top(document)
        artifact_type = "top"
    else:
        raise SaltProjectInputError(
            "input is not recognized as Salt master/minion config, a top file, or a roster"
        )
    return {"salt_project": {"artifact_type": artifact_type, "document": document}}


def _embedded_credential(value: str) -> bool:
    try:
        parsed = urlsplit(value.removeprefix("git+"))
    except ValueError:
        return False
    return bool(parsed.password or (parsed.username and parsed.scheme in {"http", "https"}))


def _remote_entries(value: Any) -> Iterable[tuple[str, dict[str, Any]]]:
    entries = value if isinstance(value, list) else [value]
    for item in entries:
        if isinstance(item, str):
            yield item, {}
        elif isinstance(item, dict):
            for source, options in item.items():
                option_map: dict[str, Any] = {}
                if isinstance(options, dict):
                    option_map = options
                elif isinstance(options, list):
                    for option in options:
                        if isinstance(option, dict):
                            option_map.update(option)
                yield str(source), option_map


def _permission_is_broad(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).strip() in {"*", ".*"} or _permission_is_broad(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_permission_is_broad(item) for item in value)
    text = str(value).strip()
    return text in {"*", ".*", "@runner", "@wheel"} or text.endswith(".*")


def _literal_secrets(value: Any, address: str = "config") -> list[tuple[str, Any]]:
    found: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{address}.{key}"
            if _SECRET_KEY.search(str(key)) and item not in (None, "", False):
                found.append((child, item))
            found.extend(_literal_secrets(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(_literal_secrets(item, f"{address}[{index}]"))
    return found


def _is_credential_reference(address: str, value: Any) -> bool:
    text = str(value).strip()
    key = address.rsplit(".", 1)[-1].lower()
    return (
        key in {"priv", "gitfs_privkey", "git_pillar_privkey", "private_key"}
        and ("/" in text or "\\" in text)
        and "-----begin" not in text.lower()
    )


def _config_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for key, message in {
        "open_mode": (
            "Salt master open_mode disables normal PKI authentication and accepts all "
            "authentication."
        ),
        "auto_accept": "Salt master automatically accepts every incoming minion public key.",
        "permissive_pki_access": (
            "Salt permits group-writable PKI material, weakening master key integrity."
        ),
        "file_recv": "Salt allows minions to upload files to the master.",
        "token_expire_user_override": "External-auth users can choose their own token lifetime.",
        "pillar_opts": "Salt exposes master configuration values through Pillar data.",
    }.items():
        if _enabled(document.get(key)):
            changes.append(_change(f"config.{key}", key, "dangerous", message))
    if _disabled(document.get("gitfs_ssl_verify")):
        changes.append(
            _change(
                "config.gitfs_ssl_verify",
                "git_tls_verification",
                "dangerous",
                "Salt disables TLS certificate verification when fetching GitFS content.",
            )
        )
    if _enabled(document.get("gitfs_insecure_auth")):
        changes.append(
            _change(
                "config.gitfs_insecure_auth",
                "git_insecure_auth",
                "dangerous",
                "Salt allows authenticated GitFS access over plaintext HTTP.",
            )
        )
    if _disabled(document.get("verify_master_pubkey_sign")):
        changes.append(
            _change(
                "config.verify_master_pubkey_sign",
                "master_identity_verification",
                "dangerous",
                "Salt minion explicitly disables verification of signed master authentication "
                "replies.",
            )
        )
    if str(document.get("master_type", "")).lower() == "func":
        changes.append(
            _change(
                "config.master_type",
                "dynamic_master_selection",
                "dangerous",
                "Salt executes a module function to select the minion's master dynamically.",
            )
        )

    for key in ("publisher_acl", "external_auth", "peer", "peer_run"):
        if key in document:
            broad = _permission_is_broad(document[key])
            changes.append(
                _change(
                    f"config.{key}",
                    "broad_remote_authorization" if broad else "remote_authorization",
                    "dangerous" if broad else "review",
                    f"Salt {key} grants remote execution or runner capabilities"
                    + (
                        " using wildcard/module-wide permissions."
                        if broad
                        else "; review principals, targets, and allowed functions."
                    ),
                )
            )

    for key in ("file_roots", "pillar_roots", "master_roots", "module_dirs", "extension_modules"):
        if key in document:
            changes.append(
                _change(
                    f"config.{key}",
                    "executable_content_roots",
                    "review",
                    f"Salt {key} selects filesystem content that can provide states, Pillar "
                    "data, or executable extension modules.",
                )
            )

    for key in ("gitfs_remotes", "git_pillar"):
        if key not in document:
            continue
        for index, (source, options) in enumerate(_remote_entries(document[key]), start=1):
            ref = str(options.get("ref") or options.get("commit") or options.get("base") or "")
            dangerous = (
                source.lower().startswith(("http://", "git://"))
                or _embedded_credential(source)
                or not _COMMIT.fullmatch(ref)
            )
            reasons: list[str] = []
            if source.lower().startswith(("http://", "git://")):
                reasons.append("uses a plaintext or unauthenticated transport")
            if _embedded_credential(source):
                reasons.append("embeds credentials in the URL")
            if not _COMMIT.fullmatch(ref):
                reasons.append("is not pinned to a full commit")
            changes.append(
                _change(
                    f"config.{key}[{index}]",
                    "remote_state_source",
                    "dangerous" if dangerous else "review",
                    f"Salt loads executable state or Pillar content from {source!r}; "
                    + ", ".join(reasons or ["verify repository ownership and review provenance"])
                    + ".",
                )
            )

    if "ext_pillar" in document:
        changes.append(
            _change(
                "config.ext_pillar",
                "external_pillar",
                "dangerous",
                "Salt executes external Pillar backends and imports their data into minion "
                "compilation.",
            )
        )
    for key, kind, explanation in (
        (
            "reactor",
            "event_reactor",
            "Salt reactors automatically execute state, runner, or wheel actions in response "
            "to event tags.",
        ),
        (
            "schedule",
            "scheduled_execution",
            "Salt schedules execution functions or runners without an interactive operator action.",
        ),
        (
            "engines",
            "engine_execution",
            "Salt engines run long-lived executable integration code inside a daemon.",
        ),
        (
            "startup_states",
            "startup_state_execution",
            "Salt applies states automatically when the minion daemon starts.",
        ),
    ):
        value = document.get(key)
        if value not in (None, "", [], {}, False):
            changes.append(_change(f"config.{key}", kind, "dangerous", explanation))
    if document.get("mine_functions"):
        dangerous = (
            any(
                str(name).lower().startswith(("cmd.", "module.", "state."))
                for name in document["mine_functions"]
            )
            if isinstance(document["mine_functions"], dict)
            else False
        )
        changes.append(
            _change(
                "config.mine_functions",
                "mine_execution",
                "dangerous" if dangerous else "review",
                "Salt periodically executes configured Mine functions and publishes their "
                "return data.",
            )
        )
    if document.get("beacons"):
        changes.append(
            _change(
                "config.beacons",
                "event_beacons",
                "review",
                "Salt beacons monitor minion state and emit events that may trigger reactors.",
            )
        )
    if "master" in document:
        changes.append(
            _change(
                "config.master",
                "master_endpoint",
                "review",
                "Salt minion selects one or more master endpoints; verify identity, failover "
                "order, and network boundary.",
            )
        )
    if document.get("include"):
        changes.append(
            _change(
                "config.include",
                "included_configuration",
                "review",
                "Salt loads additional configuration files that can override this document.",
            )
        )
    if (
        _enabled(document.get("pillar_cache"))
        and str(document.get("pillar_cache_backend", "disk")).lower() == "disk"
    ):
        changes.append(
            _change(
                "config.pillar_cache",
                "pillar_disk_cache",
                "dangerous",
                "Salt caches decrypted Pillar data on disk; protect cache files and review "
                "retention.",
            )
        )

    seen: set[str] = set()
    for address, value in _literal_secrets(document):
        if address in seen:
            continue
        seen.add(address)
        reference = _is_credential_reference(address, value)
        changes.append(
            _change(
                address,
                "credential_reference" if reference else "literal_secret",
                "review" if reference else "dangerous",
                "Salt configuration references credential material from a file; verify "
                "permissions and keep it outside source control."
                if reference
                else (
                    "Salt configuration contains a credential-like literal that can leak "
                    "through source control, logs, or Pillar output."
                ),
            )
        )
    return changes


def _top_items(body: Any) -> tuple[str, list[str]]:
    matcher = "compound"
    states: list[str] = []
    items = body if isinstance(body, list) else [body]
    for item in items:
        if isinstance(item, str):
            states.append(item)
        elif isinstance(item, dict):
            if "match" in item:
                matcher = str(item["match"])
            else:
                states.extend(map(str, item))
    return matcher, states


def _broad_target(target: str, matcher: str) -> bool:
    text = target.strip().lower()
    if text in {"*", ".*", "all", "g@*", "l@*"}:
        return True
    return matcher.lower() in {"glob", "compound", "pcre"} and text in {"*", ".*", "^.*$"}


def _top_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for environment, assignments in document.items():
        for target, body in assignments.items():
            matcher, states = _top_items(body)
            broad = _broad_target(target, matcher)
            changes.append(
                _change(
                    f"top.{environment}.{target}",
                    "broad_fleet_target" if broad else "state_target",
                    "dangerous" if broad else "review",
                    f"Salt environment {environment!r} assigns {len(states)} state/Pillar "
                    f"reference(s) to target {target!r} using matcher {matcher!r}."
                    + (
                        " This target can select the entire minion fleet."
                        if broad
                        else " Review resolved membership and environment precedence."
                    ),
                )
            )
            for address, _ in _literal_secrets(body, f"top.{environment}.{target}"):
                changes.append(
                    _change(
                        address,
                        "literal_secret",
                        "dangerous",
                        "Salt top data contains a credential-like literal exposed to matched "
                        "minions.",
                    )
                )
    return changes


def _roster_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    for target, entry in document.items():
        host = str(entry.get("host") or target)
        changes.append(
            _change(
                f"roster.{target}.host",
                "ssh_target",
                "review",
                f"Salt SSH connects target {target!r} to host {host!r}; verify inventory "
                "identity and network scope.",
            )
        )
        user = str(entry.get("user", "root")).lower()
        if user in {"root", "administrator"} or _enabled(entry.get("sudo")):
            changes.append(
                _change(
                    f"roster.{target}.privilege",
                    "privileged_ssh",
                    "dangerous",
                    f"Salt SSH connects as {user!r} or enables sudo for target {target!r}.",
                )
            )
        for key in ("passwd", "priv_passwd", "proxy_passwd"):
            if entry.get(key):
                changes.append(
                    _change(
                        f"roster.{target}.{key}",
                        "literal_secret",
                        "dangerous",
                        f"Salt SSH roster stores {key} as a literal credential.",
                    )
                )
        if entry.get("priv"):
            inline = "-----begin" in str(entry["priv"]).lower()
            changes.append(
                _change(
                    f"roster.{target}.priv",
                    "inline_private_key" if inline else "private_key_file",
                    "dangerous" if inline else "review",
                    "Salt SSH roster embeds private key material."
                    if inline
                    else (
                        "Salt SSH roster references a private key file; verify permissions and "
                        "keep it outside source control."
                    ),
                )
            )
        ssh_options = (
            " ".join(map(str, entry.get("ssh_options", [])))
            if isinstance(entry.get("ssh_options"), list)
            else str(entry.get("ssh_options", ""))
        )
        lowered = ssh_options.lower().replace(" ", "")
        if "stricthostkeychecking=no" in lowered or "userknownhostsfile=/dev/null" in lowered:
            changes.append(
                _change(
                    f"roster.{target}.ssh_options",
                    "host_key_bypass",
                    "dangerous",
                    "Salt SSH options disable host-key verification or known-host persistence.",
                )
            )
        if entry.get("proxy_host"):
            changes.append(
                _change(
                    f"roster.{target}.proxy_host",
                    "ssh_proxy",
                    "review",
                    "Salt SSH routes the target connection through a proxy host; review both "
                    "trust boundaries.",
                )
            )
        if entry.get("ssh_pre_flight"):
            changes.append(
                _change(
                    f"roster.{target}.ssh_pre_flight",
                    "preflight_execution",
                    "dangerous",
                    "Salt SSH executes a pre-flight command before deploying the Salt thin "
                    "runtime.",
                )
            )
    return changes


class SaltProjectAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "salt-project"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        project = input_data.get("salt_project")
        return (
            isinstance(project, dict)
            and project.get("artifact_type") in {"config", "top", "roster"}
            and isinstance(project.get("document"), dict)
        )

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        project = input_data["salt_project"]
        changes = {
            "config": _config_changes,
            "top": _top_changes,
            "roster": _roster_changes,
        }[project["artifact_type"]](project["document"])
        changes.append(
            _change(
                "salt.effective_project",
                "project_boundary",
                "review",
                "Effective Salt behavior also depends on included configuration, accepted "
                "keys, custom modules/renderers, Pillar and grain data, fileserver environment "
                "precedence, roster plugins, and the rendered highstate.",
            )
        )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"salt_project_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_salt_project(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = SaltProjectAdapter().analyze(data, tool_name="Salt project")
    summary = PlanSummary(
        path=Path("salt-project://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Salt project")
    gate["adapter"] = "salt-project"
    gate["artifact_type"] = data["salt_project"]["artifact_type"]
    gate["total_changes"] = len(changes)
    return gate
