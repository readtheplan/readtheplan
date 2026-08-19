from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_builds_checkout_and_runs_as_non_root() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    base_images = re.findall(
        r"^FROM python:3\.10-slim@sha256:[0-9a-f]{64} AS (builder|runtime)$",
        dockerfile,
        re.MULTILINE,
    )
    assert base_images == ["builder", "runtime"]
    assert "COPY pyproject.toml README.md LICENSE /build/" in dockerfile
    assert "COPY src/ /build/src/" in dockerfile
    assert "python -m pip wheel --no-cache-dir --wheel-dir /wheels /build" in dockerfile
    assert "COPY --from=builder /wheels/ /wheels/" in dockerfile
    assert "--no-index" in dockerfile
    assert "--find-links=/wheels readtheplan" in dockerfile
    assert "pip install --no-cache-dir readtheplan" not in dockerfile
    assert "USER 10001:10001" in dockerfile

    dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert 'package-ecosystem: "docker"' in dependabot


def test_docker_build_context_is_an_allowlist() -> None:
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    patterns = [line for line in dockerignore if line and not line.startswith("#")]

    assert patterns == [
        "**",
        "!pyproject.toml",
        "!README.md",
        "!LICENSE",
        "!src/",
        "!src/**",
    ]


def test_container_ci_proves_provenance_and_runtime_boundaries() -> None:
    workflow = (ROOT / ".github" / "workflows" / "pytest.yml").read_text(
        encoding="utf-8"
    )

    assert "expected_package_sha=" in workflow
    assert "scripts/hash_package_tree.py" in workflow
    assert "{{.Config.User}}" in workflow
    assert "os.getuid()" in workflow
    assert "--network none" in workflow
    assert "--read-only" in workflow
    assert "--tmpfs /tmp:rw,noexec,nosuid,size=64m" in workflow
    assert "tests/fixtures/valid_plan.json" in workflow


def test_readme_uses_a_read_only_offline_container() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    docker_section = readme.split("### Docker", 1)[1].split("### Sample CLI output", 1)[0]

    assert "checked-out source" in docker_section
    assert "non-root user" in docker_section
    assert "--network none --read-only" in docker_section
    assert "--tmpfs /tmp:rw,noexec,nosuid,size=64m" in docker_section
    assert '$(pwd):/workspace:ro' in docker_section
