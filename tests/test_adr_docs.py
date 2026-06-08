from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_architecture_review_findings_references_real_files() -> None:
    """Codex peer review finding X1: doc references must point to real files."""
    findings = (ROOT / "docs" / "architecture-review-findings-2026-06-07.md").read_text(
        encoding="utf-8"
    )
    # Extract all file references (paths in backticks or parenthesized)
    import re

    refs = re.findall(r"(?:`([^`]+)`|\(([^)]+)\))", findings)
    for a, b in refs:
        path_str = (a or b).strip()
        # Skip URLs, markdown links, status labels, numbers
        if any(
            kw in path_str
            for kw in ["http://", "https://", "github.com", "#", "✅", "📌"]
        ):
            continue
        # Skip values that look like numbers, percentages, or inline data
        if re.match(r"^\d", path_str) or "%" in path_str or "—" in path_str:
            continue
        # Only check things that look like file paths
        # Must either: have a known file extension, or look like a Unix/Windows path
        has_file_ext = any(path_str.endswith(ext) for ext in [".md", ".py", ".yml", ".yaml", ".json", ".toml", ".sh", ".js", ".html", ".css"])
        # Unix path: starts with / or ./ or contains ../ or path/to/file pattern
        looks_like_unix_path = path_str.startswith("/") or path_str.startswith("./") or "../" in path_str
        # Windows path: contains \ or starts with drive letter like C:\
        looks_like_win_path = "\\" in path_str or re.match(r"^[A-Za-z]:\\\\", path_str)
        if not (has_file_ext or looks_like_unix_path or looks_like_win_path):
            continue
        resolved = ROOT / path_str
        assert resolved.exists(), (
            f"Architecture review doc references '{path_str}' "
            f"but file does not exist at {resolved}"
        )


def test_explainer_engine_adr_documents_rules_first_decision() -> None:
    adr = (ROOT / "docs" / "adr" / "0001-explainer-engine.md").read_text(
        encoding="utf-8"
    )

    assert "deterministic rules and templates" in adr
    assert "LLM-generated explanations are deferred" in adr
    assert "explicit opt-in" in adr


def test_plan_input_adr_documents_json_only_contract() -> None:
    adr = (ROOT / "docs" / "adr" / "0002-plan-input-format.md").read_text(
        encoding="utf-8"
    )

    assert "Accept Terraform plan JSON only" in adr
    assert "terraform show -json" in adr
    assert "text-only" in adr


def test_risk_taxonomy_adr_matches_current_json_contract() -> None:
    adr = (
        ROOT / "docs" / "adr" / "0003-risk-classification-taxonomy.md"
    ).read_text(encoding="utf-8")

    assert "changes[].risk" in adr
    assert "`risks`" in adr
    assert "`risk_level`" in adr
    assert "not part of the current contract" in adr
    assert "safe < review < dangerous < irreversible" in adr
    assert "missing, malformed, or unknown actions" in adr
    assert "changes[].explanation" in adr


def test_resource_rule_adr_documents_mvp2_shape() -> None:
    adr = (
        ROOT / "docs" / "adr" / "0004-resource-aware-rule-library.md"
    ).read_text(encoding="utf-8")

    assert "changes[].explanation" in adr
    assert "--no-rules" in adr
    assert "aws_db_instance" in adr
    assert "aws_s3_bucket" in adr
    assert "aws_kms_key" in adr
