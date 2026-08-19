from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = "0.5.0"
RELEASE_DATE = "2026-08-06"
CURRENT_PIN = re.compile(
    r"(?:readtheplan/readtheplan@v|readtheplan==|readtheplan@)(0\.\d+\.\d+)"
)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def assert_current_pins(relative: str) -> None:
    versions = CURRENT_PIN.findall(read(relative))
    assert versions, f"expected at least one release pin in {relative}"
    assert set(versions) == {RELEASE_VERSION}, f"stale pins in {relative}: {versions}"


def test_release_metadata_converges_on_one_version() -> None:
    project_match = re.search(
        r'^version = "([^"]+)"$', read("pyproject.toml"), re.M
    )
    assert project_match and project_match.group(1) == RELEASE_VERSION

    init_match = re.search(r'^__version__ = "([^"]+)"$', read("src/readtheplan/__init__.py"), re.M)
    assert init_match and init_match.group(1) == RELEASE_VERSION

    assert json.loads(read("package.json"))["version"] == RELEASE_VERSION
    assert json.loads(read("site/package.json"))["version"] == RELEASE_VERSION

    lock = json.loads(read("site/package-lock.json"))
    assert lock["version"] == RELEASE_VERSION
    assert lock["packages"][""]["version"] == RELEASE_VERSION

    assert json.loads(read("site/data/index.json"))["version"] == RELEASE_VERSION
    assert f'version: "{RELEASE_VERSION}"' in read("site/functions/openapi.json.js")
    assert f'placeholder: "{RELEASE_VERSION}"' in read(".github/ISSUE_TEMPLATE/bug_report.yml")


def test_current_public_install_and_action_pins_match_release() -> None:
    for relative in [
        "README.md",
        "docs/ci-integrations.md",
        "site/functions/api/chat.js",
    ]:
        assert_current_pins(relative)

    pinned_ci_files = set()
    for path in sorted((ROOT / "ci").iterdir()):
        if not path.is_file():
            continue
        relative = str(path.relative_to(ROOT)).replace("\\", "/")
        versions = CURRENT_PIN.findall(read(relative))
        if not versions:
            continue
        pinned_ci_files.add(path.name)
        assert set(versions) == {RELEASE_VERSION}, f"stale pins in {relative}: {versions}"
    assert pinned_ci_files == {
        "Jenkinsfile.example",
        "README.md",
        "azure-pipelines.example.yml",
        "bitbucket-pipelines.example.yml",
        "buildkite.example.yml",
        "circleci.example.yml",
        "gitlab-ci.example.yml",
        "terraform-gate.example.yml",
    }

    cli = read("src/readtheplan/cli.py")
    assert f"@refs/tags/v{RELEASE_VERSION}" in cli

    readme = read("README.md")
    action_section = readme.split("### GitHub Action — gate your CI pipeline", 1)[1].split(
        "### Any CI/CD system", 1
    )[0]
    assert "input-file: plan.json" in action_section
    assert "plan-file: plan.json" not in action_section

    terraform_example = read("ci/terraform-gate.example.yml")
    assert "input-file: infra/plan.json" in terraform_example
    assert "plan-file:" not in terraform_example

    status_section = readme.split("## Status", 1)[1].split("## License", 1)[0]
    assert "**v0.5 —" in status_section
    assert "**v0.4 —" not in status_section
    assert "PCI-DSS and NIST" not in status_section


def test_release_notes_and_support_matrix_are_rolled_forward() -> None:
    changelog = read("CHANGELOG.md")
    expected_prefix = (
        "# Changelog\n\n"
        "## [Unreleased]\n\n"
        f"## [{RELEASE_VERSION}] — {RELEASE_DATE}\n"
    )
    assert changelog.startswith(expected_prefix)
    release_notes = changelog.split(f"## [{RELEASE_VERSION}]", 1)[1].split(
        "## [0.4.0]", 1
    )[0]
    assert "### Fixed" in release_notes
    assert "truthful coverage semantics" in release_notes
    assert "linear time" in release_notes
    assert "### Security" in release_notes
    assert "full commit SHAs" in release_notes
    assert "fail closed on malformed or ambiguous Kubernetes inputs" in release_notes
    assert "scan non-regression gate" in release_notes

    security = read("SECURITY.md")
    assert "| 0.5.x   | ✅ Active |" in security
    assert "| < 0.5   | ❌ No longer supported |" in security
    assert "| 0.4.x   | ✅ Active |" not in security

    releasing = read("RELEASING.md")
    assert "export VERSION=X.Y.Z" in releasing
    assert "## [X.Y.Z] — YYYY-MM-DD" in releasing
    assert 'git tag -a "v${VERSION}"' in releasing
    assert 'readtheplan==${VERSION}' in releasing
    for stale_instruction in [
        "## [0.4.0] — 2026-06-12",
        'bump version to 0.4.0',
        "readtheplan==0.4.0",
    ]:
        assert stale_instruction not in releasing


def test_historical_and_compatibility_literals_remain_unchanged() -> None:
    changelog = read("CHANGELOG.md")
    assert "## [0.4.0] — 2026-07-11" in changelog
    assert "## [0.3.0] — 2026-05-11" in changelog
    assert "readtheplan version: 0.3.0" in read("benchmarks/results.md")
    assert '"agent": "readtheplan@0.3.0"' in read("docs/adr/0007-evidence-envelope.md")
    assert 'help="Expected certificate identity (e.g.,' in read("src/readtheplan/cli.py")
