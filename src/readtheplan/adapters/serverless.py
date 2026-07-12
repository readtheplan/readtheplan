from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange


class ServerlessInputError(ValueError):
    """Raised when Serverless Framework or AWS SAM source is invalid."""


class _TemplateLoader(yaml.SafeLoader):
    """Safe YAML loader that retains CloudFormation intrinsic tags and rejects duplicates."""


def _construct_mapping(loader: _TemplateLoader, node: yaml.MappingNode, deep: bool = False):
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


def _construct_unknown_tag(loader: _TemplateLoader, node: yaml.Node) -> Any:
    tag = node.tag.rsplit("!", 1)[-1]
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {tag: value}


_TemplateLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)
_TemplateLoader.add_multi_constructor(
    "!", lambda loader, _suffix, node: _construct_unknown_tag(loader, node)
)

_SECRET_KEY = re.compile(
    r"(?:^|[_.-])(?:api[_-]?key|auth|client[_-]?secret|credential|password|"
    r"private[_-]?key|secret|token)(?:$|[_.-])",
    re.IGNORECASE,
)
_VARIABLE = re.compile(r"\$\{([^}]+)\}")


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _enabled(value: Any) -> bool:
    return value is True or str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _disabled(value: Any) -> bool:
    return value is False or str(value).strip().lower() in {"0", "false", "no", "off", "disabled"}


def _load_document(source: str) -> dict[str, Any]:
    if not source.strip():
        raise ServerlessInputError("input is empty")
    try:
        document = yaml.load(source, Loader=_TemplateLoader)
    except yaml.YAMLError as exc:
        raise ServerlessInputError(str(exc)) from exc
    if not isinstance(document, dict):
        raise ServerlessInputError("configuration must be a YAML or JSON object")
    return document


def parse_serverless_source(source: str) -> dict[str, Any]:
    """Parse one Serverless Framework service configuration without resolving variables."""
    document = _load_document(source)
    if "service" not in document or not isinstance(document.get("functions"), dict):
        raise ServerlessInputError(
            "input is not recognizable as Serverless Framework configuration"
        )
    return {"serverless_framework": {"document": document}}


def parse_sam_template(source: str) -> dict[str, Any]:
    """Parse one AWS SAM template without invoking the SAM transform."""
    document = _load_document(source)
    transform = document.get("Transform")
    transforms = transform if isinstance(transform, list) else [transform]
    if not any(str(item).startswith("AWS::Serverless-") for item in transforms):
        raise ServerlessInputError("template does not declare an AWS::Serverless transform")
    if not isinstance(document.get("Resources"), dict):
        raise ServerlessInputError("SAM template must contain a Resources object")
    return {"aws_sam": {"document": document}}


def _change(address: str, kind: str, risk: str, explanation: str) -> dict[str, str]:
    return {"Address": address, "Kind": kind, "Risk": risk, "Explanation": explanation}


def _image_pinned(image: str) -> bool:
    if "@sha256:" in image.lower():
        return True
    tail = image.rsplit("/", 1)[-1]
    return ":" in tail and not tail.lower().endswith(":latest")


def _policy_statements(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [statement for item in value for statement in _policy_statements(item)]
    if isinstance(value, dict):
        if "Statement" in value or "statement" in value:
            return _policy_statements(value.get("Statement", value.get("statement")))
        return [value]
    return []


def _wildcard(value: Any) -> bool:
    if value == "*":
        return True
    return isinstance(value, list) and "*" in value


def _secret_key(value: Any) -> bool:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value))
    return _SECRET_KEY.search(normalized) is not None


class _SourceAdapter(BaseAdapter):
    ecosystem = "source"
    source_key = "source"

    @property
    def adapter_name(self) -> str:
        return self.ecosystem

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get(self.source_key)
        return isinstance(source, dict) and isinstance(source.get("document"), dict)

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        return ResourceChange(
            address=str(raw.get("Address", self.ecosystem)),
            resource_type=f"{self.ecosystem}_{raw.get('Kind', 'source')}",
            actions=("update",),
            risk=str(raw.get("Risk", "review")),
            explanation=str(raw.get("Explanation", "Serverless source requires review.")),
        )

    def _policy_changes(self, value: Any, address: str) -> list[dict[str, str]]:
        changes: list[dict[str, str]] = []
        for index, statement in enumerate(_policy_statements(value)):
            effect = str(statement.get("Effect", statement.get("effect", "Allow")))
            action = statement.get("Action", statement.get("action"))
            resource = statement.get("Resource", statement.get("resource"))
            risk = (
                "dangerous"
                if effect.lower() == "allow" and (_wildcard(action) or _wildcard(resource))
                else "review"
            )
            changes.append(
                _change(
                    f"{address}[{index}]",
                    "iam_statement",
                    risk,
                    "Serverless IAM statement grants wildcard actions or resources."
                    if risk == "dangerous"
                    else "Serverless IAM statement changes execution permissions.",
                )
            )
        return changes

    def _secret_changes(self, value: Any, address: str) -> list[dict[str, str]]:
        changes: list[dict[str, str]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_address = f"{address}.{key}"
                if (
                    _secret_key(key)
                    and not isinstance(child, (dict, list))
                    and child not in (None, "")
                ):
                    text = str(child)
                    risk = (
                        "review"
                        if "${" in text or any(tag in text for tag in ("Ref", "resolve:"))
                        else "dangerous"
                    )
                    changes.append(
                        _change(
                            child_address,
                            "secret_material",
                            risk,
                            "Serverless source resolves credential-like data at deployment time."
                            if risk == "review"
                            else "Serverless source appears to contain inline credential material.",
                        )
                    )
                changes.extend(self._secret_changes(child, child_address))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._secret_changes(child, f"{address}[{index}]"))
        return changes

    def _variable_changes(self, value: Any, address: str) -> list[dict[str, str]]:
        changes: list[dict[str, str]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                changes.extend(self._variable_changes(child, f"{address}.{key}"))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                changes.extend(self._variable_changes(child, f"{address}[{index}]"))
        elif isinstance(value, str):
            for index, match in enumerate(_VARIABLE.findall(value)):
                source = match.split(":", 1)[0].strip().lower()
                if source.startswith("file("):
                    kind, risk = "external_file", "dangerous"
                elif source in {"env", "ssm", "aws", "cf", "s3", "secretsmanager"}:
                    kind, risk = "external_variable", "review"
                else:
                    continue
                changes.append(
                    _change(
                        f"{address}.variable[{index}]",
                        kind,
                        risk,
                        "Serverless resolves another file that can replace configuration structure."
                        if kind == "external_file"
                        else f"Serverless resolves deployment data from the {source} provider.",
                    )
                )
        return changes

    def _named_values(self, value: Any, name: str, address: str) -> list[tuple[str, Any]]:
        found: list[tuple[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                child_address = f"{address}.{key}"
                if str(key).lower() == name.lower():
                    found.append((child_address, child))
                found.extend(self._named_values(child, name, child_address))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                found.extend(self._named_values(child, name, f"{address}[{index}]"))
        return found


class ServerlessFrameworkAdapter(_SourceAdapter):
    ecosystem = "serverless"
    source_key = "serverless_framework"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        document = _mapping(_mapping(input_data.get(self.source_key)).get("document"))
        service = document.get("service")
        service_name = str(_mapping(service).get("name") or service or "service")
        changes = [
            _change(
                service_name,
                "service",
                "review",
                "Serverless Framework synthesizes and deploys this service through CloudFormation.",
            )
        ]
        version = str(document.get("frameworkVersion", ""))
        if not version or version.lower() in {"*", "latest"}:
            changes.append(
                _change(
                    "frameworkVersion",
                    "unpinned_framework",
                    "dangerous",
                    "Serverless Framework version is not constrained, so synthesis behavior "
                    "can drift.",
                )
            )
        else:
            changes.append(
                _change(
                    "frameworkVersion",
                    "framework_version",
                    "review",
                    "Serverless Framework synthesis is constrained to an explicit version range.",
                )
            )
        if document.get("org") is not None or document.get("app") is not None:
            changes.append(
                _change(
                    "dashboard",
                    "dashboard_integration",
                    "review",
                    "Serverless Dashboard can receive deployment, telemetry, secret, or "
                    "provider context.",
                )
            )
        if str(document.get("configValidationMode", "error")).lower() != "error":
            changes.append(
                _change(
                    "configValidationMode",
                    "relaxed_validation",
                    "dangerous",
                    "Serverless configuration validation does not fail on schema errors.",
                )
            )
        changes.extend(self._provider(_mapping(document.get("provider"))))
        for name, function in _mapping(document.get("functions")).items():
            changes.extend(self._function(str(name), _mapping(function)))
        changes.extend(self._plugins(document.get("plugins")))
        changes.extend(self._package(_mapping(document.get("package")), "package"))
        for name, layer in _mapping(document.get("layers")).items():
            changes.append(
                _change(
                    f"layers.{name}",
                    "layer",
                    "review",
                    "Serverless packages and publishes code shared across functions.",
                )
            )
            changes.extend(self._package(_mapping(layer), f"layers.{name}"))
        changes.extend(self._resources(document.get("resources")))
        if document.get("constructs") is not None:
            changes.append(
                _change(
                    "constructs",
                    "plugin_constructs",
                    "dangerous",
                    "Serverless plugin constructs can synthesize arbitrary infrastructure.",
                )
            )
        changes.extend(self._secret_changes(document.get("params"), "params"))
        changes.extend(self._secret_changes(document.get("custom"), "custom"))
        changes.extend(self._secret_changes(document.get("stages"), "stages"))
        changes.extend(self._variable_changes(document, "serverless"))
        return changes

    def _provider(self, provider: dict[str, Any]) -> list[dict[str, str]]:
        changes = [
            _change(
                "provider",
                "provider",
                "review",
                f"Serverless deploys through provider {provider.get('name', 'aws')}.",
            )
        ]
        for field in ("stage", "region", "profile", "deploymentRole"):
            if provider.get(field) is not None:
                risk = "dangerous" if field in {"profile", "deploymentRole"} else "review"
                changes.append(
                    _change(
                        f"provider.{field}",
                        "deployment_identity" if risk == "dangerous" else "deployment_target",
                        risk,
                        f"Serverless selects deployment {field} {provider[field]!s}.",
                    )
                )
        if str(provider.get("deploymentMethod", "direct")).lower() == "direct":
            changes.append(
                _change(
                    "provider.deploymentMethod",
                    "direct_deployment",
                    "review",
                    "Serverless updates CloudFormation directly instead of explicitly using "
                    "a change set.",
                )
            )
        bucket = _mapping(provider.get("deploymentBucket"))
        if bucket:
            changes.append(
                _change(
                    "provider.deploymentBucket",
                    "deployment_artifacts",
                    "review",
                    "Serverless stores templates, function code, and rollback artifacts in a "
                    "custom bucket.",
                )
            )
            if not bucket.get("serverSideEncryption"):
                changes.append(
                    _change(
                        "provider.deploymentBucket.serverSideEncryption",
                        "unencrypted_artifacts",
                        "dangerous",
                        "Custom Serverless deployment bucket does not declare server-side "
                        "encryption.",
                    )
                )
            if bucket.get("blockPublicAccess") is False:
                changes.append(
                    _change(
                        "provider.deploymentBucket.blockPublicAccess",
                        "public_artifact_boundary",
                        "dangerous",
                        "Serverless deployment bucket explicitly disables additional "
                        "public-access blocking.",
                    )
                )
            if _enabled(bucket.get("skipPolicySetup")):
                changes.append(
                    _change(
                        "provider.deploymentBucket.skipPolicySetup",
                        "unmanaged_bucket_policy",
                        "dangerous",
                        "Serverless skips its default deployment-bucket policy setup.",
                    )
                )
        iam = _mapping(provider.get("iam"))
        role = iam.get("role")
        if isinstance(role, str):
            changes.append(
                _change(
                    "provider.iam.role",
                    "execution_role",
                    "dangerous",
                    "Every function can inherit an externally managed execution role.",
                )
            )
        else:
            role_config = _mapping(role)
            changes.extend(
                self._policy_changes(role_config.get("statements"), "provider.iam.role.statements")
            )
            if role_config.get("managedPolicies"):
                changes.append(
                    _change(
                        "provider.iam.role.managedPolicies",
                        "managed_policies",
                        "dangerous",
                        "Serverless attaches externally managed policies to the shared "
                        "function role.",
                    )
                )
        changes.extend(
            self._policy_changes(provider.get("iamRoleStatements"), "provider.iamRoleStatements")
        )
        changes.extend(self._secret_changes(provider.get("environment"), "provider.environment"))
        if provider.get("vpc") is not None:
            changes.append(
                _change(
                    "provider.vpc",
                    "network_attachment",
                    "review",
                    "Serverless attaches functions to selected VPC subnets and security groups.",
                )
            )
        logs = provider.get("logs")
        if logs is False or isinstance(logs, dict) and any(_disabled(v) for v in logs.values()):
            changes.append(
                _change(
                    "provider.logs",
                    "disabled_logging",
                    "dangerous",
                    "Serverless disables API or function logging for part of the service.",
                )
            )
        return changes

    def _function(self, name: str, function: dict[str, Any]) -> list[dict[str, str]]:
        address = f"functions.{name}"
        changes = [
            _change(
                address,
                "function",
                "review",
                "Serverless deploys function code and its execution/event configuration.",
            )
        ]
        image = function.get("image")
        image_name = str(_mapping(image).get("uri") or image or "")
        if image_name:
            changes.append(
                _change(
                    f"{address}.image",
                    "function_image",
                    "review" if _image_pinned(image_name) else "dangerous",
                    "Serverless function image uses an explicit version or digest."
                    if _image_pinned(image_name)
                    else "Serverless function image is not pinned to a version or digest.",
                )
            )
        if function.get("role") is not None:
            changes.append(
                _change(
                    f"{address}.role",
                    "execution_role",
                    "dangerous",
                    "Serverless function assumes an explicitly selected IAM execution role.",
                )
            )
        changes.extend(self._secret_changes(function.get("environment"), f"{address}.environment"))
        for field, kind, risk, explanation in (
            (
                "vpc",
                "network_attachment",
                "review",
                "Function joins selected VPC network boundaries.",
            ),
            (
                "fileSystemConfig",
                "filesystem_mount",
                "dangerous",
                "Function mounts a shared EFS filesystem.",
            ),
            (
                "layers",
                "layers",
                "review",
                "Function executes code from one or more Lambda layers.",
            ),
            (
                "destinations",
                "async_destination",
                "review",
                "Function forwards asynchronous results to another service.",
            ),
            (
                "deadLetter",
                "dead_letter",
                "review",
                "Function forwards failed events to a dead-letter destination.",
            ),
            (
                "provisionedConcurrency",
                "provisioned_capacity",
                "review",
                "Function reserves always-warm execution capacity.",
            ),
            (
                "reservedConcurrency",
                "reserved_capacity",
                "review",
                "Function caps or reserves account concurrency.",
            ),
        ):
            if function.get(field) is not None:
                changes.append(_change(f"{address}.{field}", kind, risk, explanation))
        for index, event in enumerate(_items(function.get("events"))):
            changes.extend(self._event(event, f"{address}.events[{index}]"))
        changes.extend(self._package(_mapping(function.get("package")), f"{address}.package"))
        return changes

    def _event(self, event: Any, address: str) -> list[dict[str, str]]:
        if isinstance(event, str):
            return [
                _change(
                    address, "event_source", "review", f"Function subscribes to {event} events."
                )
            ]
        event_map = _mapping(event)
        if not event_map:
            return []
        kind, config = next(iter(event_map.items()))
        lowered = str(kind).lower()
        config_map = _mapping(config)
        if lowered in {"http", "httpapi", "websocket", "alb", "iot", "url"}:
            authorizer = config_map.get("authorizer", config_map.get("auth"))
            public = authorizer in (None, "", "none", "NONE")
            return [
                _change(
                    address,
                    "public_event_ingress" if public else "authenticated_event_ingress",
                    "dangerous" if public else "review",
                    f"Serverless exposes {kind} event ingress without a visible authorizer."
                    if public
                    else f"Serverless exposes {kind} event ingress with configured authorization.",
                )
            ]
        risk = (
            "dangerous"
            if lowered in {"s3", "sns", "sqs", "stream", "kinesis", "dynamodb"}
            else "review"
        )
        return [
            _change(
                address,
                "event_source",
                risk,
                f"Serverless subscribes the function to {kind} events, which can trigger "
                "code execution.",
            )
        ]

    def _plugins(self, plugins: Any) -> list[dict[str, str]]:
        values = _mapping(plugins).get("localPath") or _mapping(plugins).get("modules") or plugins
        return [
            _change(
                f"plugins[{index}]",
                "plugin",
                "dangerous",
                f"Serverless loads plugin {plugin!s}, which executes in the "
                "packaging/deployment process.",
            )
            for index, plugin in enumerate(_items(values))
        ]

    def _package(self, package: dict[str, Any], address: str) -> list[dict[str, str]]:
        if not package:
            return []
        return [
            _change(
                address,
                "package_boundary",
                "review",
                "Serverless package patterns or artifact settings change code included in "
                "deployment.",
            )
        ]

    def _resources(self, resources: Any) -> list[dict[str, str]]:
        document = _mapping(resources)
        definitions = _mapping(document.get("Resources")) or document
        changes: list[dict[str, str]] = []
        for name, resource in definitions.items():
            if name in {"Description", "Extensions", "Outputs"}:
                continue
            config = _mapping(resource)
            if not config.get("Type"):
                continue
            resource_type = str(config.get("Type"))
            risk = (
                "dangerous"
                if any(
                    token in resource_type
                    for token in ("IAM::", "KMS::", "SecurityGroup", "Gateway")
                )
                else "review"
            )
            changes.append(
                _change(
                    f"resources.{name}",
                    "embedded_cloudformation",
                    risk,
                    f"Serverless passes raw CloudFormation resource {resource_type} into the "
                    "synthesized stack.",
                )
            )
            for policy_address, policy in self._named_values(
                config.get("Properties"), "PolicyDocument", f"resources.{name}.Properties"
            ):
                changes.extend(self._policy_changes(policy, policy_address))
        if document.get("extensions") is not None:
            changes.append(
                _change(
                    "resources.extensions",
                    "generated_resource_override",
                    "dangerous",
                    "Serverless extensions mutate generated CloudFormation resources by "
                    "logical ID.",
                )
            )
        return changes


class SamTemplateAdapter(_SourceAdapter):
    ecosystem = "sam"
    source_key = "aws_sam"

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        document = _mapping(_mapping(input_data.get(self.source_key)).get("document"))
        changes = [
            _change(
                "template",
                "template",
                "review",
                "AWS SAM transforms shorthand resources into a CloudFormation deployment.",
            )
        ]
        transform = document.get("Transform")
        for index, item in enumerate(transform if isinstance(transform, list) else [transform]):
            if not str(item).startswith("AWS::Serverless-"):
                changes.append(
                    _change(
                        f"Transform[{index}]",
                        "additional_macro",
                        "dangerous",
                        f"CloudFormation macro {item!s} can rewrite the SAM template during "
                        "deployment.",
                    )
                )
        if document.get("Globals") is not None:
            changes.append(
                _change(
                    "Globals",
                    "global_defaults",
                    "review",
                    "AWS SAM merges Globals into every resource of matching types.",
                )
            )
            changes.extend(self._secret_changes(document.get("Globals"), "Globals"))
        changes.extend(self._secret_changes(document.get("Parameters"), "Parameters"))
        for name, resource in _mapping(document.get("Resources")).items():
            changes.extend(self._resource(str(name), _mapping(resource)))
        changes.extend(self._variable_changes(document, "template"))
        return changes

    def _resource(self, name: str, resource: dict[str, Any]) -> list[dict[str, str]]:
        address = f"Resources.{name}"
        resource_type = str(resource.get("Type", "Unknown"))
        properties = _mapping(resource.get("Properties"))
        if resource_type == "AWS::Serverless::Function":
            changes = self._function(address, properties)
        elif resource_type in {
            "AWS::Serverless::Api",
            "AWS::Serverless::GraphQLApi",
            "AWS::Serverless::HttpApi",
            "AWS::Serverless::WebSocketApi",
        }:
            changes = self._api(address, resource_type, properties)
        elif resource_type == "AWS::Serverless::StateMachine":
            changes = self._state_machine(address, properties)
        elif resource_type == "AWS::Serverless::Application":
            changes = self._application(address, properties)
        elif resource_type == "AWS::Serverless::Connector":
            changes = [
                _change(
                    address,
                    "connector_permissions",
                    "dangerous",
                    "AWS SAM Connector synthesizes IAM permissions between source and "
                    "destination resources.",
                )
            ]
        elif resource_type in {
            "AWS::Serverless::CapacityProvider",
            "AWS::Serverless::MicrovmImage",
            "AWS::Serverless::NetworkConnector",
        }:
            changes = [
                _change(
                    address,
                    "compute_or_network_control",
                    "dangerous",
                    f"AWS SAM resource {resource_type} changes compute or network "
                    "control-plane configuration.",
                )
            ]
        elif resource_type in {"AWS::Serverless::LayerVersion", "AWS::Serverless::SimpleTable"}:
            changes = [
                _change(
                    address,
                    "serverless_resource",
                    "review",
                    f"AWS SAM synthesizes {resource_type} and related CloudFormation resources.",
                )
            ]
            if properties.get("ContentUri") is not None:
                changes.append(
                    _change(
                        f"{address}.ContentUri",
                        "code_artifact",
                        "review",
                        "AWS SAM packages layer content from a local or remote location.",
                    )
                )
        else:
            risk = (
                "dangerous"
                if any(
                    token in resource_type
                    for token in ("IAM::", "KMS::", "SecurityGroup", "Gateway")
                )
                else "review"
            )
            changes = [
                _change(
                    address,
                    "embedded_cloudformation",
                    risk,
                    f"AWS SAM template embeds CloudFormation resource {resource_type}.",
                )
            ]
            changes.extend(
                self._policy_changes(properties.get("PolicyDocument"), f"{address}.PolicyDocument")
            )
        for field in ("DeletionPolicy", "UpdateReplacePolicy"):
            if resource.get(field) is not None:
                value = str(resource[field])
                changes.append(
                    _change(
                        f"{address}.{field}",
                        "lifecycle_policy",
                        "dangerous" if value.lower() == "delete" else "review",
                        f"AWS SAM propagates {field}={value} to generated resources.",
                    )
                )
        metadata = _mapping(resource.get("Metadata"))
        if str(metadata.get("BuildMethod", "")).lower() in {"makefile", "custommakebuilder"}:
            changes.append(
                _change(
                    f"{address}.Metadata.BuildMethod",
                    "custom_build",
                    "dangerous",
                    "AWS SAM build invokes repository-defined make targets or a custom builder.",
                )
            )
        return changes

    def _function(self, address: str, properties: dict[str, Any]) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "function",
                "review",
                "AWS SAM synthesizes Lambda code, identity, event sources, and supporting "
                "resources.",
            )
        ]
        if properties.get("InlineCode") is not None:
            changes.append(
                _change(
                    f"{address}.InlineCode",
                    "inline_code",
                    "dangerous",
                    "AWS SAM deploys executable Lambda code embedded directly in the template.",
                )
            )
        if properties.get("CodeUri") is not None:
            code_uri = properties["CodeUri"]
            remote = isinstance(code_uri, dict) or str(code_uri).startswith(
                ("s3://", "http://", "https://")
            )
            changes.append(
                _change(
                    f"{address}.CodeUri",
                    "code_artifact",
                    "dangerous" if remote else "review",
                    "AWS SAM retrieves function code from an external artifact location."
                    if remote
                    else "AWS SAM packages function code from a local project path.",
                )
            )
        image = str(properties.get("ImageUri", ""))
        if image:
            changes.append(
                _change(
                    f"{address}.ImageUri",
                    "function_image",
                    "review" if _image_pinned(image) else "dangerous",
                    "AWS SAM function image uses an explicit version or digest."
                    if _image_pinned(image)
                    else "AWS SAM function image is not pinned to a version or digest.",
                )
            )
        if properties.get("Role") is not None:
            changes.append(
                _change(
                    f"{address}.Role",
                    "execution_role",
                    "dangerous",
                    "AWS SAM function assumes an explicitly selected IAM role.",
                )
            )
        policies = properties.get("Policies")
        if policies is not None:
            changes.append(
                _change(
                    f"{address}.Policies",
                    "function_policies",
                    "dangerous",
                    "AWS SAM expands policy templates, managed policies, or statements into "
                    "function IAM access.",
                )
            )
            changes.extend(self._policy_changes(policies, f"{address}.Policies"))
        environment = _mapping(properties.get("Environment")).get("Variables")
        changes.extend(self._secret_changes(environment, f"{address}.Environment.Variables"))
        for field, kind, risk, explanation in (
            (
                "VpcConfig",
                "network_attachment",
                "review",
                "Function joins selected VPC network boundaries.",
            ),
            (
                "FileSystemConfigs",
                "filesystem_mount",
                "dangerous",
                "Function mounts one or more EFS access points.",
            ),
            (
                "FunctionUrlConfig",
                "function_url",
                "dangerous",
                "Function exposes a directly invokable HTTPS endpoint.",
            ),
            (
                "DeploymentPreference",
                "traffic_shift",
                "review",
                "SAM deploys versions through CodeDeploy traffic shifting and hooks.",
            ),
            (
                "AutoPublishAlias",
                "version_publication",
                "review",
                "SAM automatically publishes and aliases Lambda versions.",
            ),
            (
                "ProvisionedConcurrencyConfig",
                "provisioned_capacity",
                "review",
                "Function reserves always-warm capacity.",
            ),
            (
                "ReservedConcurrentExecutions",
                "reserved_capacity",
                "review",
                "Function caps or reserves account concurrency.",
            ),
        ):
            if properties.get(field) is not None:
                changes.append(_change(f"{address}.{field}", kind, risk, explanation))
        function_url = _mapping(properties.get("FunctionUrlConfig"))
        if function_url and str(function_url.get("AuthType", "NONE")).upper() == "NONE":
            changes.append(
                _change(
                    f"{address}.FunctionUrlConfig.AuthType",
                    "public_function_url",
                    "dangerous",
                    "AWS SAM Function URL accepts requests without AWS IAM authorization.",
                )
            )
        for name, event in _mapping(properties.get("Events")).items():
            changes.extend(self._event(_mapping(event), f"{address}.Events.{name}"))
        return changes

    def _event(self, event: dict[str, Any], address: str) -> list[dict[str, str]]:
        kind = str(event.get("Type", "Unknown"))
        properties = _mapping(event.get("Properties"))
        if kind in {"Api", "HttpApi", "WebSocket"}:
            auth = properties.get("Auth", properties.get("Authorizer"))
            public = auth in (None, "", "NONE")
            return [
                _change(
                    address,
                    "public_event_ingress" if public else "authenticated_event_ingress",
                    "dangerous" if public else "review",
                    f"AWS SAM exposes {kind} event ingress without a visible authorizer."
                    if public
                    else f"AWS SAM exposes {kind} event ingress with configured authorization.",
                )
            ]
        risk = "dangerous" if kind in {"S3", "SNS", "SQS", "Kinesis", "DynamoDB"} else "review"
        return [
            _change(
                address,
                "event_source",
                risk,
                f"AWS SAM configures {kind} to trigger executable serverless code.",
            )
        ]

    def _api(
        self, address: str, resource_type: str, properties: dict[str, Any]
    ) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "api",
                "dangerous",
                "AWS SAM synthesizes public-facing or network-reachable API resource "
                f"{resource_type}.",
            )
        ]
        auth = properties.get("Auth")
        if not auth:
            changes.append(
                _change(
                    f"{address}.Auth",
                    "missing_api_auth",
                    "dangerous",
                    "AWS SAM API has no visible default authorizer or resource policy.",
                )
            )
        if properties.get("CorsConfiguration", properties.get("Cors")) is not None:
            changes.append(
                _change(
                    f"{address}.Cors",
                    "cors_policy",
                    "review",
                    "AWS SAM API enables browser cross-origin access.",
                )
            )
        if properties.get("DefinitionUri") is not None:
            changes.append(
                _change(
                    f"{address}.DefinitionUri",
                    "external_api_definition",
                    "dangerous",
                    "AWS SAM loads an API definition from a local or remote artifact outside "
                    "this template.",
                )
            )
        if properties.get("ResourcePolicy") is not None:
            changes.append(
                _change(
                    f"{address}.ResourcePolicy",
                    "api_resource_policy",
                    "dangerous",
                    "AWS SAM API resource policy changes who can invoke the endpoint.",
                )
            )
        return changes

    def _state_machine(self, address: str, properties: dict[str, Any]) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "state_machine",
                "dangerous",
                "AWS SAM state machine orchestrates service calls and executable tasks.",
            )
        ]
        if properties.get("DefinitionUri") is not None:
            changes.append(
                _change(
                    f"{address}.DefinitionUri",
                    "external_definition",
                    "dangerous",
                    "AWS SAM loads the state-machine definition from an external artifact.",
                )
            )
        if properties.get("Role") is not None or properties.get("Policies") is not None:
            changes.append(
                _change(
                    f"{address}.Identity",
                    "state_machine_identity",
                    "dangerous",
                    "AWS SAM state machine receives IAM permissions for orchestrated actions.",
                )
            )
        for name, event in _mapping(properties.get("Events")).items():
            changes.extend(self._event(_mapping(event), f"{address}.Events.{name}"))
        return changes

    def _application(self, address: str, properties: dict[str, Any]) -> list[dict[str, str]]:
        changes = [
            _change(
                address,
                "nested_application",
                "dangerous",
                "AWS SAM installs another application and all infrastructure it expands into.",
            )
        ]
        location = properties.get("Location")
        if isinstance(location, dict) and not location.get("SemanticVersion"):
            changes.append(
                _change(
                    f"{address}.Location.SemanticVersion",
                    "unpinned_application",
                    "dangerous",
                    "AWS SAM application repository reference has no semantic version.",
                )
            )
        changes.extend(self._secret_changes(properties.get("Parameters"), f"{address}.Parameters"))
        return changes


def _analyze(
    data: dict[str, Any], adapter: _SourceAdapter, tool_name: str, *, catalog=None
) -> dict[str, Any]:
    changes = adapter.analyze(data, tool_name=tool_name)
    summary = PlanSummary(
        path=Path(f"{adapter.adapter_name}://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name=tool_name)
    gate["adapter"] = adapter.adapter_name
    gate["total_changes"] = len(changes)
    return gate


def analyze_serverless(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return _analyze(data, ServerlessFrameworkAdapter(), "serverless", catalog=catalog)


def analyze_sam(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    return _analyze(data, SamTemplateAdapter(), "sam", catalog=catalog)
