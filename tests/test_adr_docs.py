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
