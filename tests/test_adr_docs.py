from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


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
