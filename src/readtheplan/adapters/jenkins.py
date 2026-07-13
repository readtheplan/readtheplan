from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from readtheplan.adapters.base import BaseAdapter
from readtheplan.agent_gate import agent_gate_to_dict
from readtheplan.plan import PlanSummary, ResourceChange

_STEP_PATTERNS = (
    ("shared_library", re.compile(r"(?:@Library\s*\(|\blibrary\s*(?:\(|['\"]))")),
    ("load_groovy", re.compile(r"\bload\s*(?:\(|['\"])")),
    ("evaluate_groovy", re.compile(r"\bevaluate\s*\(")),
    ("script_block", re.compile(r"\bscript\s*\{")),
    ("with_credentials", re.compile(r"\bwithCredentials\s*\(")),
    ("ssh_agent", re.compile(r"\bsshagent\s*\(")),
    ("credentials", re.compile(r"\bcredentials\s*\(")),
    ("kubernetes_agent", re.compile(r"\b(?:kubernetes|podTemplate)\s*(?:\{|\()")),
    ("docker_agent", re.compile(r"\bagent\s*\{\s*docker(?:file)?\b")),
    ("container_image", re.compile(r"\bimage\s+['\"][^'\"]+['\"]")),
    ("agent_args", re.compile(r"\bargs\s+['\"][^'\"]+['\"]")),
    ("powershell", re.compile(r"\bpowershell\s*(?:\(|['\"])")),
    ("pwsh", re.compile(r"\bpwsh\s*(?:\(|['\"])")),
    ("shell", re.compile(r"\bsh\s*(?:\(|['\"])")),
    ("batch", re.compile(r"\bbat\s*(?:\(|['\"])")),
    ("delete_dir", re.compile(r"\bdeleteDir\s*\(")),
    ("clean_workspace", re.compile(r"\bcleanWs\s*\(")),
    ("write_file", re.compile(r"\bwriteFile\s*(?:\(|\s)")),
    ("http_request", re.compile(r"\bhttpRequest\s*(?:\(|\s)")),
    ("input", re.compile(r"\binput\s*(?:\(|message\s*:)")),
    ("downstream_build", re.compile(r"\bbuild\s+(?:job\s*:|\()")),
    ("checkout", re.compile(r"\b(?:checkout\s+(?:scm|\()|git\s*(?:\(|url\s*:))")),
    ("trigger", re.compile(r"\b(?:cron|pollSCM|upstream)\s*\(")),
    ("parallel", re.compile(r"\bparallel\s*(?:\(|\{)")),
    ("retry", re.compile(r"\bretry\s*\(")),
    ("timeout", re.compile(r"\btimeout\s*\(")),
    ("stash", re.compile(r"\b(?:stash|unstash)\s*(?:\(|\s)")),
    ("archive", re.compile(r"\barchiveArtifacts\s*(?:\(|artifacts\s*:)")),
    ("junit", re.compile(r"\bjunit\s*(?:\(|['\"])")),
    ("echo", re.compile(r"\becho\s+(?:\(|['\"])")),
)

_DANGEROUS_STEPS = {
    "agent_args",
    "batch",
    "clean_workspace",
    "credentials",
    "delete_dir",
    "evaluate_groovy",
    "kubernetes_agent",
    "load_groovy",
    "powershell",
    "pwsh",
    "script_block",
    "shell",
    "ssh_agent",
    "with_credentials",
}
_SAFE_STEPS = {"archive", "echo", "junit"}
_MUTABLE_IMAGE = re.compile(r"\bimage\s+['\"](?P<image>[^'\"]+)['\"]")
_SHARED_LIBRARY_REF = re.compile(r"@Library\s*\(\s*['\"](?P<ref>[^'\"]+)['\"]")
_CREDENTIAL_HELPER = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*credentials\s*\("
)
_CREDENTIAL_VARIABLE = re.compile(
    r"\b(?P<field>"
    r"variable|usernameVariable|passwordVariable|keyFileVariable|passphraseVariable|"
    r"keystoreVariable|keyStoreVariable|aliasVariable|secretVariable|tokenVariable|"
    r"accessKeyVariable|secretKeyVariable|fileVariable|contentVariable|privateKeyVariable|"
    r"clientSecretVariable|clientPasswordVariable|clientPrivateKeyVariable|"
    r"keychainPathVariable|keychainPasswordVariable"
    r")\s*:\s*(?P<quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)"
)
_GSTRING = re.compile(
    r'(?P<triple>"""(?P<triple_body>.*?)""")|'
    r'(?P<double>"(?P<double_body>(?:\\.|[^"\\])*)")',
    re.DOTALL,
)
_INTERPOLATION = re.compile(
    r"\$(?:\{\s*(?:env\.)?(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\b|"
    r"(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
_WITH_CREDENTIALS_CALL = re.compile(r"\bwithCredentials\s*\(")
_CREDENTIAL_SINK = re.compile(r"\b(?P<sink>sh|bat|powershell|pwsh|echo|writeFile)\b")
_SINK_CAPABILITY = {
    "sh": "command",
    "bat": "command",
    "powershell": "command",
    "pwsh": "command",
    "echo": "log",
    "writeFile": "file",
}
_SINK_PARAMETER = {
    "sh": "script",
    "bat": "script",
    "powershell": "script",
    "pwsh": "script",
    "echo": "message",
    "writeFile": "text",
}


def _groovy_views(source: str) -> tuple[str, str]:
    """Return same-length code-only and comment-free views of Groovy source."""
    code: list[str] = []
    uncommented: list[str] = []
    state = "code"
    delimiter = ""
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                code.append(char)
                uncommented.append(char)
                state = "code"
            else:
                code.append(" ")
                uncommented.append(" ")
            index += 1
            continue
        if state == "block_comment":
            if char == "*" and following == "/":
                code.extend((" ", " "))
                uncommented.extend((" ", " "))
                state = "code"
                index += 2
                continue
            if char == "\n":
                code.append(char)
                uncommented.append(char)
            else:
                code.append(" ")
                uncommented.append(" ")
            index += 1
            continue
        if state == "string":
            if source.startswith(delimiter, index):
                code.extend(delimiter)
                uncommented.extend(delimiter)
                index += len(delimiter)
                state = "code"
                delimiter = ""
                continue
            if char == "\\" and index + 1 < len(source):
                code.append(" ")
                uncommented.append(char)
                next_char = source[index + 1]
                code.append("\n" if next_char == "\n" else " ")
                uncommented.append(next_char)
                index += 2
                continue
            code.append("\n" if char == "\n" else " ")
            uncommented.append(char)
            index += 1
            continue
        if char == "/" and following == "*":
            code.extend((" ", " "))
            uncommented.extend((" ", " "))
            state = "block_comment"
            index += 2
            continue
        if char == "/" and following == "/":
            code.extend((" ", " "))
            uncommented.extend((" ", " "))
            state = "line_comment"
            index += 2
            continue
        triple = source[index : index + 3]
        if triple in {"'''", '"""'}:
            delimiter = triple
            code.extend(triple)
            uncommented.extend(triple)
            state = "string"
            index += 3
            continue
        if char in {"'", '"'}:
            delimiter = char
            code.append(char)
            uncommented.append(char)
            state = "string"
            index += 1
            continue
        code.append(char)
        uncommented.append(char)
        index += 1
    return "".join(code), "".join(uncommented)


def _matching_delimiter(code: str, start: int, opening: str, closing: str) -> int | None:
    depth = 0
    for index in range(start, len(code)):
        if code[index] == opening:
            depth += 1
        elif code[index] == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _with_credentials_ranges(code: str) -> list[tuple[int, int, int, int]]:
    ranges: list[tuple[int, int, int, int]] = []
    for call in _WITH_CREDENTIALS_CALL.finditer(code):
        arguments_start = code.find("(", call.start(), call.end())
        if arguments_start < 0:
            continue
        arguments_end = _matching_delimiter(code, arguments_start, "(", ")")
        if arguments_end is None:
            continue
        scope_start = arguments_end + 1
        while scope_start < len(code) and code[scope_start].isspace():
            scope_start += 1
        if scope_start < len(code) and code[scope_start] == "{":
            scope_end = _matching_delimiter(code, scope_start, "{", "}")
            if scope_end is None:
                scope_end = len(code)
        else:
            scope_end = len(code)
        ranges.append((arguments_start, arguments_end, scope_start, scope_end))
    return ranges


def _credential_variables(
    code: str, uncommented: str
) -> tuple[dict[str, list[tuple[int, int]]], int]:
    variables: dict[str, list[tuple[int, int]]] = {}
    binding_count = 0

    def add(name: str, scope: tuple[int, int]) -> None:
        variables.setdefault(name, []).append(scope)

    for match in _CREDENTIAL_HELPER.finditer(code):
        name = match.group("name")
        for variable in (name, f"{name}_USR", f"{name}_PSW"):
            add(variable, (0, len(code)))
        binding_count += 1
    credential_ranges = _with_credentials_ranges(code)
    for match in _CREDENTIAL_VARIABLE.finditer(uncommented):
        start, end = match.span("field")
        if code[start:end] != match.group("field"):
            continue
        for arguments_start, arguments_end, scope_start, scope_end in credential_ranges:
            if arguments_start <= start <= arguments_end:
                add(match.group("name"), (scope_start, scope_end))
                binding_count += 1
                break
    return variables, binding_count


def _is_escaped(source: str, index: int) -> bool:
    backslashes = 0
    index -= 1
    while index >= 0 and source[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def _sink_before_gstring(code: str, start: int) -> str | None:
    window = code[max(0, start - 1024) : start]
    matches = list(_CREDENTIAL_SINK.finditer(window))
    if not matches:
        return None
    match = matches[-1]
    sink = match.group("sink")
    tail = window[match.end() :]
    if ";" in tail or "}" in tail:
        return None
    if re.fullmatch(r"\s*\(?\s*", tail):
        return None if sink == "writeFile" else sink
    parameter = re.search(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*$", tail)
    if parameter and parameter.group("name") == _SINK_PARAMETER[sink]:
        return sink
    return None


def _secret_interpolations(
    source: str,
    code: str,
    uncommented: str,
    variables: dict[str, list[tuple[int, int]]],
) -> list[tuple[int, str]]:
    findings: list[tuple[int, str]] = []
    if not variables:
        return findings
    for gstring in _GSTRING.finditer(uncommented):
        delimiter = '"""' if gstring.group("triple") is not None else '"'
        if code[gstring.start() : gstring.start() + len(delimiter)] != delimiter:
            continue
        body = gstring.group("triple_body") or gstring.group("double_body") or ""
        uses_credential = False
        for interpolation in _INTERPOLATION.finditer(body):
            if _is_escaped(body, interpolation.start()):
                continue
            name = interpolation.group("braced") or interpolation.group("plain")
            scopes = variables.get(name, ())
            if any(
                scope_start <= gstring.start() <= scope_end
                for scope_start, scope_end in scopes
            ):
                uses_credential = True
                break
        if not uses_credential:
            continue
        sink = _sink_before_gstring(code, gstring.start())
        if sink is None:
            continue
        line = source.count("\n", 0, gstring.start()) + 1
        findings.append((line, _SINK_CAPABILITY[sink]))
    return findings


def _jenkins_metadata(source: str) -> dict[str, Any]:
    code, uncommented = _groovy_views(source)
    variables, binding_count = _credential_variables(code, uncommented)
    findings = _secret_interpolations(source, code, uncommented, variables)
    return {
        "code": code,
        "uncommented": uncommented,
        "credential_binding_count": binding_count,
        "secret_interpolations": findings,
        "credential_exposure_capabilities": sorted({capability for _, capability in findings}),
    }


class JenkinsAdapter(BaseAdapter):
    @property
    def adapter_name(self) -> str:
        return "jenkins"

    def can_handle(self, input_data: dict[str, Any]) -> bool:
        source = input_data.get("jenkinsfile")
        if not isinstance(source, str):
            return False
        code, _ = _groovy_views(source)
        return bool(re.search(r"\b(?:pipeline\s*\{|node\s*\(|stages\s*\{)", code))

    def extract_changes(self, input_data: dict[str, Any]) -> list[dict[str, Any]]:
        source = str(input_data.get("jenkinsfile", ""))
        metadata = _jenkins_metadata(source)
        code_source = str(metadata["code"])
        uncommented = str(metadata["uncommented"])
        changes: list[dict[str, Any]] = []
        raw_lines = uncommented.splitlines()
        for line_number, line in enumerate(code_source.splitlines(), start=1):
            code = line.strip()
            if not code:
                continue
            raw = raw_lines[line_number - 1].strip()
            for step, pattern in _STEP_PATTERNS:
                if pattern.search(code):
                    changes.append(
                        {"Step": step, "Address": f"Jenkinsfile:{line_number}", "Source": raw}
                    )
        for line_number, capability in metadata["secret_interpolations"]:
            changes.append(
                {
                    "Step": "credential_interpolation",
                    "Address": f"Jenkinsfile:{line_number}",
                    "Capability": capability,
                }
            )
        if code_source.strip() and not changes:
            changes.append(
                {
                    "Step": "unparsed_pipeline",
                    "Address": "Jenkinsfile",
                    "Source": "Pipeline contains no recognized built-in steps.",
                }
            )
        return changes

    def normalize_change(self, raw: dict[str, Any]) -> ResourceChange:
        step = str(raw.get("Step", "unknown"))
        source = str(raw.get("Source", ""))
        risk = "review"
        explanation = f"Jenkins step '{step}' affects pipeline execution and requires review."
        if step == "credential_interpolation":
            risk = "dangerous"
            capability = str(raw.get("Capability", "command"))
            exposure = {
                "command": "a build-agent command",
                "file": "a workspace file",
                "log": "the build log",
            }.get(capability, "a pipeline output")
            explanation = (
                "Jenkins Groovy interpolation expands a managed credential into "
                f"{exposure} before the step runs; use a non-interpolating string and let "
                "the receiving process expand the environment variable."
            )
        elif step in _DANGEROUS_STEPS:
            risk = "dangerous"
            if step in {
                "batch",
                "evaluate_groovy",
                "load_groovy",
                "powershell",
                "pwsh",
                "script_block",
                "shell",
            }:
                explanation = f"Jenkins step '{step}' can execute arbitrary build-agent code."
            elif step in {"credentials", "ssh_agent", "with_credentials"}:
                explanation = (
                    f"Jenkins step '{step}' exposes managed credentials to pipeline code or "
                    "agent processes."
                )
            elif step in {"clean_workspace", "delete_dir"}:
                explanation = f"Jenkins step '{step}' deletes workspace state and artifacts."
            else:
                explanation = (
                    f"Jenkins step '{step}' can give an ephemeral build agent host-level "
                    "or cluster-level access."
                )
        elif step in _SAFE_STEPS:
            risk = "safe"
            explanation = f"Jenkins step '{step}' records output without changing infrastructure."
        elif step == "unparsed_pipeline":
            explanation = (
                "Jenkins pipeline syntax was recognized, but no supported steps were found; "
                "manual review is required."
            )
        elif step == "container_image":
            match = _MUTABLE_IMAGE.search(source)
            image = match.group("image") if match else "<dynamic>"
            if "@sha256:" not in image:
                risk = "dangerous"
                explanation = (
                    "Jenkins agent image is not pinned by digest; mutable build "
                    "environments can change pipeline behavior."
                )
        elif step == "shared_library":
            explanation = (
                "Jenkins loads a shared Pipeline library whose external Groovy code is not "
                "expanded in this Jenkinsfile; review source trust and version pinning."
            )
            match = _SHARED_LIBRARY_REF.search(source)
            reference = match.group("ref") if match else ""
            version = reference.rsplit("@", 1)[-1] if "@" in reference else ""
            if not version or version.lower() in {"main", "master", "latest", "head"}:
                risk = "dangerous"
                explanation += " The selected library version is mutable or implicit."
        elif step == "trigger":
            explanation = (
                "Jenkins automatically triggers this pipeline from a schedule, SCM polling, "
                "or an upstream job; review deployment gates and concurrency."
            )
        elif step in {"checkout", "http_request", "stash", "write_file"}:
            explanation = (
                f"Jenkins step '{step}' moves code, data, or artifacts across a trust "
                "boundary; review destinations, credentials, integrity, and retention."
            )

        if step == "agent_args" and not any(
            token in source
            for token in ("--privileged", "/var/run/docker.sock", "--device", "--network=host")
        ):
            risk = "review"
            explanation = "Jenkins passes runtime arguments to a build agent; review host access."

        return ResourceChange(
            address=str(raw.get("Address", "Jenkinsfile")),
            resource_type=f"jenkins_{step}",
            actions=("execute",),
            risk=risk,
            explanation=explanation,
        )


def analyze_jenkins(data: dict[str, Any], *, catalog=None) -> dict[str, Any]:
    changes = JenkinsAdapter().analyze(data, tool_name="Jenkins")
    summary = PlanSummary(
        path=Path("jenkins://"),
        terraform_version=None,
        resource_changes=tuple(changes),
    )
    gate = agent_gate_to_dict(summary, catalog=catalog, tool_name="Jenkins")
    source = data.get("jenkinsfile")
    metadata = _jenkins_metadata(source if isinstance(source, str) else "")
    gate["adapter"] = "jenkins"
    gate["credential_binding_count"] = metadata["credential_binding_count"]
    gate["secret_interpolation_count"] = len(metadata["secret_interpolations"])
    gate["credential_exposure_capabilities"] = metadata[
        "credential_exposure_capabilities"
    ]
    return gate
