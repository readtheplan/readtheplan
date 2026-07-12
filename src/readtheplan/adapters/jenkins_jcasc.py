from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class JenkinsJCasCInputError(ValueError):
    """Raised when input is not recognizable Jenkins Configuration as Code YAML."""


_ROOT_KEYS = {"appearance", "credentials", "jenkins", "jobs", "security", "tool", "unclassified"}
_SECRET_KEY = re.compile(
    r"(?:password|passwd|secret|token|private.?key|passphrase|client.?secret|api.?key|"
    r"credential.?value)",
    re.IGNORECASE,
)
_SECRET_INTERPOLATION = re.compile(r"(?<!\^)\$\{(?P<name>[^}]+)\}")
_MUTABLE_VERSION = {"", "head", "latest", "main", "master", "trunk"}
_BROAD_PERMISSION = re.compile(
    r"(?:overall/administer|credentials/(?:create|delete|manage|update|view)|"
    r"agent/(?:build|configure|connect|create|delete)|job/(?:build|configure|create|delete)|"
    r"run/(?:delete|replay|update)|view/configure)",
    re.IGNORECASE,
)
_TLS_BYPASS_KEYS = {
    "disablesslverification",
    "skipcertificatecheck",
    "skipsslverification",
    "trustall",
    "trustallcertificates",
    "useinsecuretrustmanager",
}


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    explicit_keys: set[Any] = set()
    for key_node, value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in explicit_keys
        except TypeError as exc:
            raise JenkinsJCasCInputError("YAML mapping keys must be scalar values") from exc
        if duplicate:
            raise JenkinsJCasCInputError(f"duplicate YAML key: {key}")
        explicit_keys.add(key)
    loader.flatten_mapping(node)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _walk(item, (*path, str(key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, (*path, str(index)))


def _flatten_strings(value: Any) -> list[str]:
    return [str(item) for _, item in _walk(value) if isinstance(item, (str, int, float, bool))]


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _external_secret(value: str) -> bool:
    stripped = value.strip()
    return bool(
        re.fullmatch(r"\$\{[^}]+\}", stripped)
        or re.fullmatch(r"\{[A-Za-z0-9+/=:_-]{16,}\}", stripped)
    )


def parse_jenkins_jcasc(source: str) -> dict[str, Any]:
    """Parse one JCasC YAML document without resolving variables or plugin schemas."""
    if not source.strip():
        raise JenkinsJCasCInputError("input is empty")
    try:
        documents = list(yaml.load_all(source, Loader=_UniqueKeyLoader))  # noqa: S506
    except JenkinsJCasCInputError:
        raise
    except yaml.YAMLError as exc:
        raise JenkinsJCasCInputError(str(exc)) from exc
    documents = [document for document in documents if document is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise JenkinsJCasCInputError("input must contain exactly one YAML mapping document")
    document = documents[0]
    root_keys = {str(key) for key in document}
    if not (_ROOT_KEYS & root_keys):
        raise JenkinsJCasCInputError("input does not contain a recognized JCasC root element")
    return {"jenkins_jcasc": document}


def _security_realm_changes(jenkins: dict[str, Any]) -> list[dict[str, str]]:
    if "securityRealm" not in jenkins:
        return []
    realm = jenkins["securityRealm"]
    text = " ".join(_flatten_strings(realm)).lower()
    keys = {_normalized_key(path[-1]) for path, _ in _walk(realm) if path}
    risk = "review"
    reasons = ["JCasC changes the Jenkins security realm that authenticates controller users."]
    if str(realm).strip().lower() in {"none", "unsecured"} or keys & {"none", "unsecured"}:
        risk = "dangerous"
        reasons.append("The configured realm disables authentication.")
    if "local" in keys:
        local = _mapping(_mapping(realm).get("local"))
        if _enabled(local.get("allowsSignup")):
            risk = "dangerous"
            reasons.append("Local account self-signup is enabled.")
        literal_passwords = [
            value
            for path, value in _walk(local)
            if path
            and _SECRET_KEY.search(path[-1])
            and isinstance(value, str)
            and value.strip()
            and not _external_secret(value)
        ]
        if literal_passwords:
            risk = "dangerous"
            reasons.append("A local controller account has a literal credential in YAML.")
    if "ldap://" in text:
        risk = "dangerous"
        reasons.append("LDAP authentication uses a plaintext endpoint.")
    return [_change("jenkins.securityRealm", "security_realm", risk, " ".join(reasons))]


def _authorization_changes(jenkins: dict[str, Any]) -> list[dict[str, str]]:
    if "authorizationStrategy" not in jenkins:
        return []
    strategy = jenkins["authorizationStrategy"]
    strings = _flatten_strings(strategy)
    normalized = {_normalized_key(value) for value in strings}
    normalized.update(_normalized_key(path[-1]) for path, _ in _walk(strategy) if path)
    risk = "review"
    reasons = ["JCasC changes the Jenkins authorization strategy and effective permissions."]
    if normalized & {"none", "unsecured"}:
        risk = "dangerous"
        reasons.append("Anyone-can-do-anything authorization is configured.")
    if "loggedinuserscandoanything" in normalized:
        risk = "dangerous"
        reasons.append("Every authenticated user receives unrestricted controller access.")
    broad_permission = any(_BROAD_PERMISSION.search(value) for value in strings)
    broad_subject = any(
        value.strip().lower() in {"anonymous", "authenticated"} for value in strings
    )
    if broad_permission and broad_subject:
        risk = "dangerous"
        reasons.append("A broad subject receives administrative or mutation permissions.")
    for value in strings:
        lowered = value.lower()
        if ("anonymous" in lowered or "authenticated" in lowered) and _BROAD_PERMISSION.search(
            value
        ):
            risk = "dangerous"
            reasons.append("A broad subject receives administrative or mutation permissions.")
            break
    return [_change("jenkins.authorizationStrategy", "authorization", risk, " ".join(reasons))]


def _credential_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    credentials = document.get("credentials")
    if credentials is None:
        return []
    changes = [
        _change(
            "credentials",
            "credentials",
            "review",
            "JCasC provisions controller credentials; verify scope, consumers, rotation, and "
            "the external secret source.",
        )
    ]
    exposed: list[str] = []
    for path, value in _walk(credentials, ("credentials",)):
        if not path or not isinstance(value, str) or not value.strip():
            continue
        if _SECRET_KEY.search(path[-1]) and not _external_secret(value):
            exposed.append(".".join(path))
    if exposed:
        changes.append(
            _change(
                exposed[0],
                "plaintext_credential",
                "dangerous",
                f"JCasC contains {len(exposed)} literal credential value(s) instead of external "
                "secret-source interpolation.",
            )
        )
    return changes


def _interpolation_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    exposed: list[str] = []
    for path, value in _walk(document):
        if not path or not isinstance(value, str):
            continue
        if _SECRET_KEY.search(path[-1]):
            continue
        variables = [match.group("name") for match in _SECRET_INTERPOLATION.finditer(value)]
        if any(_SECRET_KEY.search(variable) for variable in variables):
            exposed.append(".".join(path))
    if not exposed:
        return []
    return [
        _change(
            exposed[0],
            "secret_interpolation",
            "dangerous",
            f"{len(exposed)} JCasC field(s) interpolate secret-like variables into unprotected "
            "controller configuration that may be displayed or logged.",
        )
    ]


def _controller_and_agent_changes(jenkins: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    executors = jenkins.get("numExecutors")
    try:
        controller_executors = int(executors) if executors is not None else 0
    except (TypeError, ValueError):
        controller_executors = 0
    if controller_executors > 0:
        changes.append(
            _change(
                "jenkins.numExecutors",
                "controller_execution",
                "dangerous",
                "The Jenkins controller runs build executors; pipeline code can reach controller "
                "files, credentials, and plugin processes.",
            )
        )
    port = jenkins.get("slaveAgentPort")
    if port not in {None, -1, "-1"}:
        changes.append(
            _change(
                "jenkins.slaveAgentPort",
                "inbound_agent_port",
                "review",
                f"Jenkins exposes a fixed inbound-agent port ({port}); verify network policy, "
                "agent authentication, and remoting protocols.",
            )
        )

    nodes = jenkins.get("nodes")
    clouds = jenkins.get("clouds")
    if nodes:
        changes.append(
            _change(
                "jenkins.nodes",
                "agents",
                "review",
                "JCasC configures permanent agents; verify launcher trust, host-key checking, "
                "labels, filesystem access, and credential scope.",
            )
        )
    if clouds:
        changes.append(
            _change(
                "jenkins.clouds",
                "cloud_agents",
                "review",
                "JCasC configures elastic cloud agents; verify cloud identity, pod/VM privilege, "
                "network reachability, and cleanup.",
            )
        )

    agent_config = {"nodes": nodes, "clouds": clouds}
    privilege_paths: list[str] = []
    mutable_images: list[str] = []
    for path, value in _walk(agent_config):
        if not path:
            continue
        key = _normalized_key(path[-1])
        if (
            key in {"privileged", "hostnetwork", "allowprivilegeescalation"} and _enabled(value)
        ) or (key == "runasuser" and str(value).strip() == "0"):
            privilege_paths.append(".".join(path))
        if key in {"hostpath", "hostkeyverificationstrategy"} and (
            key == "hostpath" or "nonverifying" in str(value).lower()
        ):
            privilege_paths.append(".".join(path))
        if key == "image" and isinstance(value, str):
            image = value.strip()
            if "@sha256:" not in image:
                mutable_images.append(image)
    if privilege_paths:
        changes.append(
            _change(
                privilege_paths[0],
                "privileged_agent",
                "dangerous",
                "JCasC grants a build agent root, host, privileged-container, or unverified SSH "
                "access.",
            )
        )
    if mutable_images:
        changes.append(
            _change(
                "jenkins.clouds.image",
                "mutable_agent_image",
                "dangerous",
                f"Jenkins cloud agent image {mutable_images[0]!r} is not pinned by digest.",
            )
        )
    return changes


def _library_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    library_roots = [
        value
        for path, value in _walk(document)
        if path and _normalized_key(path[-1]) in {"globallibraries", "libraries"}
    ]
    if not library_roots:
        return []
    strings = _flatten_strings(library_roots)
    versions: list[str] = []
    for root in library_roots:
        for path, value in _walk(root):
            if path and _normalized_key(path[-1]) == "defaultversion":
                versions.append(str(value).strip())
    mutable = [version for version in versions if version.lower() in _MUTABLE_VERSION]
    insecure = [value for value in strings if value.lower().startswith(("http://", "git://"))]
    risk = "dangerous" if mutable or insecure else "review"
    reasons = ["JCasC configures Pipeline shared libraries whose external code is not expanded."]
    if mutable:
        reasons.append("A library uses a mutable or implicit default version.")
    if insecure:
        reasons.append("A library source uses an unauthenticated plaintext transport.")
    return [_change("unclassified.globalLibraries", "global_libraries", risk, " ".join(reasons))]


def _global_configuration_changes(document: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []
    tls_bypass: list[str] = []
    insecure_endpoints: list[str] = []
    script_approval = False
    job_dsl = bool(document.get("jobs"))
    literal_env_secrets: list[str] = []
    csrf_disabled = False
    for path, value in _walk(document):
        if not path:
            continue
        key = _normalized_key(path[-1])
        if key in _TLS_BYPASS_KEYS and _enabled(value):
            tls_bypass.append(".".join(path))
        if key in {"url", "server", "endpoint", "jenkinsurl"} and isinstance(value, str):
            if value.lower().startswith(("http://", "ldap://", "git://")):
                insecure_endpoints.append(".".join(path))
        if key in {"scriptapproval", "approvedsignatures", "approvedscripthashes"} and value:
            script_approval = True
        if key == "usescriptsecurity" and value is False:
            job_dsl = True
        if key == "crumbissuer" and (
            str(value).strip().lower() in {"none", "unsecured"}
            or "none" in {_normalized_key(item) for item in _mapping(value)}
        ):
            csrf_disabled = True
        if isinstance(value, dict):
            env_key = value.get("key")
            env_value = value.get("value")
            if (
                isinstance(env_key, str)
                and _SECRET_KEY.search(env_key)
                and isinstance(env_value, str)
                and env_value.strip()
                and not _external_secret(env_value)
            ):
                literal_env_secrets.append(".".join(path))
    if tls_bypass:
        changes.append(
            _change(
                tls_bypass[0],
                "tls_verification",
                "dangerous",
                "JCasC disables certificate or host-key verification for a controller integration.",
            )
        )
    if insecure_endpoints:
        changes.append(
            _change(
                insecure_endpoints[0],
                "plaintext_endpoint",
                "dangerous",
                f"JCasC configures {len(insecure_endpoints)} plaintext controller endpoint(s).",
            )
        )
    if script_approval:
        changes.append(
            _change(
                "security.scriptApproval",
                "script_approval",
                "dangerous",
                "JCasC pre-approves Groovy signatures or script hashes that can expand controller "
                "code execution authority.",
            )
        )
    if csrf_disabled:
        changes.append(
            _change(
                "jenkins.crumbIssuer",
                "csrf_protection",
                "dangerous",
                "JCasC disables the Jenkins crumb issuer and removes controller CSRF protection.",
            )
        )
    if job_dsl:
        changes.append(
            _change(
                "jobs",
                "job_dsl",
                "dangerous",
                "JCasC loads Job DSL or disables Job DSL script security; generated jobs can "
                "execute controller-approved Groovy and pipeline code.",
            )
        )
    if literal_env_secrets:
        changes.append(
            _change(
                literal_env_secrets[0],
                "plaintext_environment_secret",
                "dangerous",
                "A secret-like global environment variable has a literal value in JCasC source.",
            )
        )
    if any(document.get(key) for key in ("appearance", "tool", "unclassified")):
        changes.append(
            _change(
                "jcasc.plugin_configuration",
                "plugin_configuration",
                "review",
                "JCasC configures tools or plugins whose effective schema and behavior depend on "
                "the installed controller plugin set.",
            )
        )
    return changes


class JenkinsJCasCAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "jenkins-jcasc"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        document = input_data.get("jenkins_jcasc")
        return isinstance(document, dict) and bool(_ROOT_KEYS & set(document))

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        document = _mapping(input_data.get("jenkins_jcasc"))
        jenkins = _mapping(document.get("jenkins"))
        changes = [
            _change(
                "jcasc.effective_configuration",
                "configuration_boundary",
                "review",
                "Effective Jenkins configuration also depends on supplementary JCasC files, "
                "environment/secret-source interpolation, installed plugins, init hooks, system "
                "properties, and controller state.",
            )
        ]
        changes.extend(_security_realm_changes(jenkins))
        changes.extend(_authorization_changes(jenkins))
        changes.extend(_credential_changes(document))
        changes.extend(_interpolation_changes(document))
        changes.extend(_controller_and_agent_changes(jenkins))
        changes.extend(_library_changes(document))
        changes.extend(_global_configuration_changes(document))
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw["Address"]),
            resource_type=f"jenkins_jcasc_{raw['Kind']}",
            actions=("configure",),
            risk=str(raw["Risk"]),
            explanation=str(raw["Explanation"]),
        )


def analyze_jenkins_jcasc(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = JenkinsJCasCAdapter().analyze(data, tool_name="Jenkins JCasC")
    summary = PlanSummary(
        path=Path("jenkins-jcasc://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Jenkins JCasC")
    gate["adapter"] = "jenkins-jcasc"
    gate["total_changes"] = len(changes)
    return gate
