from __future__ import annotations

import json
from pathlib import Path

import pytest

from readtheplan.adapters.jenkins_jcasc import (
    JenkinsJCasCAdapter,
    JenkinsJCasCInputError,
    analyze_jenkins_jcasc,
    parse_jenkins_jcasc,
)
from readtheplan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def _changes(fixture: str):
    source = (FIXTURES / fixture).read_text(encoding="utf-8")
    return JenkinsJCasCAdapter().analyze(parse_jenkins_jcasc(source), tool_name="Jenkins JCasC")


def test_jcasc_surfaces_controller_identity_execution_agents_and_secrets() -> None:
    changes = _changes("jenkins_jcasc_risky.yml")
    by_type = {change.resource_type: change for change in changes}
    encoded = json.dumps(
        [{"address": change.address, "explanation": change.explanation} for change in changes]
    )

    assert by_type["jenkins_jcasc_security_realm"].risk == "dangerous"
    assert by_type["jenkins_jcasc_authorization"].risk == "dangerous"
    assert by_type["jenkins_jcasc_plaintext_credential"].risk == "dangerous"
    assert by_type["jenkins_jcasc_secret_interpolation"].risk == "dangerous"
    assert by_type["jenkins_jcasc_controller_execution"].risk == "dangerous"
    assert by_type["jenkins_jcasc_privileged_agent"].risk == "dangerous"
    assert by_type["jenkins_jcasc_mutable_agent_image"].risk == "dangerous"
    assert by_type["jenkins_jcasc_trusted_library"].risk == "dangerous"
    assert by_type["jenkins_jcasc_library_version_policy"].risk == "dangerous"
    assert by_type["jenkins_jcasc_implicit_library"].risk == "dangerous"
    assert by_type["jenkins_jcasc_library_changelog"].risk == "dangerous"
    assert by_type["jenkins_jcasc_library_cache"].risk == "dangerous"
    assert by_type["jenkins_jcasc_library_source"].risk == "dangerous"
    assert by_type["jenkins_jcasc_library_resolution_boundary"].risk == "review"
    assert by_type["jenkins_jcasc_tls_verification"].risk == "dangerous"
    assert by_type["jenkins_jcasc_plaintext_endpoint"].risk == "dangerous"
    assert by_type["jenkins_jcasc_script_approval"].risk == "dangerous"
    assert by_type["jenkins_jcasc_csrf_protection"].risk == "dangerous"
    assert by_type["jenkins_jcasc_job_dsl"].risk == "dangerous"
    assert by_type["jenkins_jcasc_plaintext_environment_secret"].risk == "dangerous"
    for sensitive in (
        "shared-deploy",
        "git.example.test",
        "fixture-library-credential-do-not-leak",
        "feature/",
        "gitHubTrustEveryone",
    ):
        assert sensitive not in encoded


def test_jcasc_external_secrets_pinned_agents_and_libraries_stay_review() -> None:
    changes = _changes("jenkins_jcasc_review.yml")
    kinds = {change.resource_type for change in changes}
    assert "jenkins_jcasc_plaintext_credential" not in kinds
    assert "jenkins_jcasc_secret_interpolation" not in kinds
    assert "jenkins_jcasc_privileged_agent" not in kinds
    assert "jenkins_jcasc_mutable_agent_image" not in kinds
    assert "jenkins_jcasc_untrusted_library" in kinds
    assert "jenkins_jcasc_trusted_library" not in kinds
    assert "jenkins_jcasc_library_version_policy" in kinds
    assert "jenkins_jcasc_library_source" in kinds
    assert {change.risk for change in changes} == {"review"}


def test_jcasc_pinned_trusted_library_retains_controller_execution_trust() -> None:
    data = parse_jenkins_jcasc(
        """unclassified:
  globalLibraries:
    libraries:
      - name: trusted
        defaultVersion: 0123456789abcdef0123456789abcdef01234567
        allowVersionOverride: false
        retriever:
          modernSCM:
            scm:
              git:
                remote: https://git.example.invalid/trusted.git
"""
    )
    changes = JenkinsJCasCAdapter().analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}

    assert by_type["jenkins_jcasc_trusted_library"].risk == "dangerous"
    assert by_type["jenkins_jcasc_library_version_policy"].risk == "review"
    assert by_type["jenkins_jcasc_library_source"].risk == "review"


def test_jcasc_untrusted_library_version_override_is_still_dangerous() -> None:
    data = parse_jenkins_jcasc(
        """unclassified:
  globalUntrustedLibraries:
    libraries:
      - name: sandboxed
        defaultVersion: 0123456789abcdef0123456789abcdef01234567
        retriever:
          modernSCM:
            scm:
              git:
                remote: https://git.example.invalid/sandboxed.git
"""
    )
    changes = JenkinsJCasCAdapter().analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}

    assert by_type["jenkins_jcasc_untrusted_library"].risk == "review"
    assert by_type["jenkins_jcasc_library_version_policy"].risk == "dangerous"


def test_jcasc_legacy_dynamic_library_source_is_dangerous_and_redacted() -> None:
    data = parse_jenkins_jcasc(
        """unclassified:
  globalLibraries:
    libraries:
      - name: legacy-secret-name
        defaultVersion: release
        retriever:
          legacySCM:
            scm:
              git:
                remote: https://fixture-user:fixture-password@example.invalid/${LIBRARY_REF}
"""
    )
    changes = JenkinsJCasCAdapter().analyze(data, use_rules=False)
    source = next(
        change for change in changes if change.resource_type == "jenkins_jcasc_library_source"
    )
    encoded = json.dumps(
        [{"address": change.address, "explanation": change.explanation} for change in changes]
    )

    assert source.risk == "dangerous"
    assert "Legacy SCM" in source.explanation
    for sensitive in (
        "legacy-secret-name",
        "fixture-user",
        "fixture-password",
        "example.invalid",
        "LIBRARY_REF",
    ):
        assert sensitive not in encoded


@pytest.mark.parametrize(
    "source,error",
    [
        ("", "empty"),
        ("services:\n  web: {}\n", "recognized JCasC"),
        ("jenkins:\n  numExecutors: 0\n  numExecutors: 2\n", "duplicate YAML key"),
        ("---\njenkins: {}\n---\ncredentials: {}\n", "exactly one YAML"),
    ],
)
def test_jcasc_parser_rejects_invalid_or_ambiguous_yaml(source: str, error: str) -> None:
    with pytest.raises(JenkinsJCasCInputError, match=error):
        parse_jenkins_jcasc(source)


def test_jcasc_parser_supports_documented_yaml_anchors() -> None:
    data = parse_jenkins_jcasc(
        """x-agent: &agent
  remoteFS: /home/jenkins
  launcher:
    inbound: {}
jenkins:
  nodes:
    - permanent:
        <<: *agent
        name: agent-one
    - permanent:
        <<: *agent
        name: agent-two
"""
    )
    assert len(data["jenkins_jcasc"]["jenkins"]["nodes"]) == 2


def test_jcasc_nonverifying_ssh_agent_fails_dangerous() -> None:
    data = parse_jenkins_jcasc(
        """jenkins:
  nodes:
    - permanent:
        name: unsafe
        launcher:
          ssh:
            hostKeyVerificationStrategy:
              nonVerifyingKeyVerificationStrategy: {}
"""
    )
    changes = JenkinsJCasCAdapter().analyze(data, use_rules=False)
    by_type = {change.resource_type: change for change in changes}
    assert by_type["jenkins_jcasc_privileged_agent"].risk == "dangerous"


def test_jcasc_role_authorization_catches_broad_subject_assignment() -> None:
    data = parse_jenkins_jcasc(
        """jenkins:
  authorizationStrategy:
    roleBased:
      roles:
        global:
          - name: administrators
            permissions:
              - Overall/Administer
            assignments:
              - authenticated
"""
    )
    changes = JenkinsJCasCAdapter().analyze(data, use_rules=False)
    authorization = next(
        change for change in changes if change.resource_type == "jenkins_jcasc_authorization"
    )
    assert authorization.risk == "dangerous"


def test_jcasc_secret_interpolation_in_credential_description_is_exposed() -> None:
    data = parse_jenkins_jcasc(
        """credentials:
  system:
    domainCredentials:
      - credentials:
          - usernamePassword:
              id: registry
              username: robot
              password: ${REGISTRY_PASSWORD}
              description: ${ADMIN_SECRET}
"""
    )
    changes = JenkinsJCasCAdapter().analyze(data, use_rules=False)
    kinds = {change.resource_type for change in changes}
    assert "jenkins_jcasc_plaintext_credential" not in kinds
    assert "jenkins_jcasc_secret_interpolation" in kinds


def test_jcasc_gate_uses_shared_contract() -> None:
    source = (FIXTURES / "jenkins_jcasc_risky.yml").read_text(encoding="utf-8")
    gate = analyze_jenkins_jcasc(parse_jenkins_jcasc(source))
    assert gate["adapter"] == "jenkins-jcasc"
    assert gate["decision"] == "block"
    assert gate["library_count"] == 1
    assert gate["trusted_library_count"] == 1
    assert gate["total_changes"] == 26
    assert gate["risk_counts"] == {
        "safe": 0,
        "review": 7,
        "dangerous": 19,
        "irreversible": 0,
    }
    assert gate["total_changes"] == sum(gate["risk_counts"].values())


def test_jcasc_cli_reads_yaml(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "jenkins.yaml"
    source.write_text(
        (FIXTURES / "jenkins_jcasc_risky.yml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assert main(["jenkins-jcasc", "--framework", "soc2", str(source)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["adapter"] == "jenkins-jcasc"
    assert payload["library_count"] == 1
    assert payload["trusted_library_count"] == 1
    assert payload["total_changes"] == 26
    assert "fixture-library-credential-do-not-leak" not in json.dumps(payload)
    assert "rtp.control.soc2.CC8.1" in payload["required_checks"]
