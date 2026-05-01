from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


def test_site_has_client_onboarding_surface() -> None:
    html = (SITE / "index.html").read_text(encoding="utf-8")
    app = (SITE / "app.js").read_text(encoding="utf-8")

    assert "readtheplan" in html
    assert "No plan upload" in html
    assert "id=\"onboardingForm\"" in html
    assert "id=\"actionOutput\"" in html
    assert "id=\"cliOutput\"" in html
    assert "readtheplan/readtheplan@v1" in app
    assert "terraform show -json tfplan > plan.json" in app
    assert "No raw Terraform plan is attached." in app


def test_site_build_contract_for_cloudflare_pages() -> None:
    package = (SITE / "package.json").read_text(encoding="utf-8")
    build_script = (SITE / "scripts" / "build.js").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "site.yml").read_text(
        encoding="utf-8"
    )

    assert '"build": "node scripts/build.js"' in package
    assert "site/dist" in (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "X-Content-Type-Options: nosniff" in build_script
    assert "npm --prefix site run build" in workflow
