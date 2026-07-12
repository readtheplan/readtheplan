from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

from readtheplan.adapters.dockerfile import (
    DockerfileAdapter,
    DockerfileInputError,
    parse_dockerfile,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_dockerfile_classifies_build_and_runtime_boundaries() -> None:
    data = parse_dockerfile(
        (FIXTURES / "Dockerfile.risky").read_text(encoding="utf-8")
    )
    changes = DockerfileAdapter().analyze(data, tool_name="Dockerfile")
    by_type: dict[str, list[str]] = defaultdict(list)
    for change in changes:
        by_type[change.resource_type].append(change.risk)

    assert by_type["dockerfile_frontend"] == ["review"]
    assert by_type["dockerfile_arg"] == ["safe", "dangerous"]
    assert by_type["dockerfile_base_image"] == ["dangerous", "review"]
    assert by_type["dockerfile_run"] == ["dangerous"]
    assert "BuildKit mounts sensitive credentials" in next(
        change.explanation
        for change in changes
        if change.resource_type == "dockerfile_run"
    )
    assert by_type["dockerfile_copy"] == ["review", "review"]
    assert by_type["dockerfile_add"] == ["dangerous"]
    assert by_type["dockerfile_user"] == ["dangerous", "review"]
    assert by_type["dockerfile_env"] == ["dangerous"]
    assert by_type["dockerfile_healthcheck"] == ["dangerous"]
    assert by_type["dockerfile_entrypoint"] == ["review"]
    assert by_type["dockerfile_onbuild"] == ["dangerous"]
    assert by_type["dockerfile_stopsignal"] == ["dangerous"]
    assert by_type["dockerfile_runtime_user"] == ["review"]
    assert by_type["dockerfile_context_boundary"] == ["review"]


def test_scratch_and_internal_stages_are_not_mutable_external_images() -> None:
    data = parse_dockerfile(
        "FROM scratch AS empty\nFROM empty AS final\nCOPY app /app\nUSER 1000\n"
    )
    changes = DockerfileAdapter().analyze(data, tool_name="Dockerfile")
    base_risks = [
        change.risk
        for change in changes
        if change.resource_type == "dockerfile_base_image"
    ]
    assert base_risks == ["safe", "review"]


def test_shell_entrypoint_sensitive_copy_and_relative_workdir_block() -> None:
    data = parse_dockerfile(
        "FROM alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "COPY .ssh/id_rsa /root/.ssh/id_rsa\n"
        "WORKDIR app\n"
        "ENTRYPOINT app --serve\n"
    )
    changes = DockerfileAdapter().analyze(data, tool_name="Dockerfile")
    by_type = {change.resource_type: change for change in changes}
    assert by_type["dockerfile_copy"].risk == "dangerous"
    assert by_type["dockerfile_workdir"].risk == "dangerous"
    assert by_type["dockerfile_entrypoint"].risk == "dangerous"
    assert by_type["dockerfile_runtime_user"].risk == "dangerous"


def test_run_heredoc_is_one_dangerous_instruction() -> None:
    data = parse_dockerfile(
        "FROM alpine\nRUN <<EOF\napk add curl\necho ready\nEOF\nUSER 1000\n"
    )
    changes = DockerfileAdapter().analyze(data, tool_name="Dockerfile")
    runs = [change for change in changes if change.resource_type == "dockerfile_run"]
    assert len(runs) == 1
    assert runs[0].risk == "dangerous"


def test_backtick_escape_and_external_copy_source() -> None:
    data = parse_dockerfile(
        "# escape=`\n"
        "FROM mcr.microsoft.com/windows/nanoserver:ltsc2022\n"
        "RUN echo first `\n"
        "    && echo second\n"
        "COPY --from=nginx:latest /etc/nginx/nginx.conf C:/nginx.conf\n"
        "USER ContainerUser\n"
    )
    changes = DockerfileAdapter().analyze(data, tool_name="Dockerfile")
    runs = [change for change in changes if change.resource_type == "dockerfile_run"]
    copies = [change for change in changes if change.resource_type == "dockerfile_copy"]
    assert len(runs) == 1
    assert copies[0].risk == "dangerous"
    assert "not digest-pinned" in copies[0].explanation


def test_secret_label_blocks() -> None:
    changes = DockerfileAdapter().analyze(
        parse_dockerfile("FROM scratch\nLABEL api_token=fixture\nUSER 1000\n"),
        tool_name="Dockerfile",
    )
    label = next(
        change for change in changes if change.resource_type == "dockerfile_label"
    )
    assert label.risk == "dangerous"


def test_dockerfile_cli_and_framework_baseline(capsys) -> None:
    assert (
        main(
            [
                "dockerfile",
                "--framework",
                "soc2",
                str(FIXTURES / "Dockerfile.risky"),
            ]
        )
        == 2
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "dockerfile"
    assert payload["decision"] == "block"
    assert payload["total_changes"] == 20
    assert payload["risk_counts"] == {
        "dangerous": 9,
        "irreversible": 0,
        "review": 10,
        "safe": 1,
    }
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]


@pytest.mark.parametrize("source", ["", "RUN echo hi", "services:\n  api: {}\n"])
def test_dockerfile_rejects_missing_from(source: str) -> None:
    with pytest.raises(DockerfileInputError):
        parse_dockerfile(source)


def test_dockerfile_rejects_unterminated_heredoc() -> None:
    with pytest.raises(DockerfileInputError, match="unterminated heredoc"):
        parse_dockerfile("FROM alpine\nRUN <<EOF\necho no end\n")
