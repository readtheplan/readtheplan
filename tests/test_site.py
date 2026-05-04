from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


def test_site_has_client_onboarding_surface() -> None:
    html = (SITE / "index.html").read_text(encoding="utf-8")
    app = (SITE / "app.js").read_text(encoding="utf-8")

    assert "readtheplan" in html
    assert "No plan upload" in html
    assert "SOC 2 / ISO 27001 / HIPAA" in html
    assert "id=\"onboardingForm\"" in html
    assert "id=\"actionOutput\"" in html
    assert "id=\"cliOutput\"" in html
    assert "id=\"recommendation\"" in html
    assert "id=\"planRows\"" in html
    assert "id=\"demo\"" in html
    assert "id=\"demoSafeCount\"" in html
    assert "id=\"demoReviewCount\"" in html
    assert "id=\"demoDangerousCount\"" in html
    assert "id=\"demoRows\"" in html
    assert "What an analysis looks like" in html
    assert "rel=\"canonical\"" in html
    assert "og:image" in html
    assert 'name="framework"' in html
    assert 'value="soc2"' in html
    assert 'value="iso27001"' in html
    assert 'value="hipaa"' in html
    assert 'name="signEvidence"' in html
    assert "readtheplan/readtheplan@v1" in app
    assert "terraform show -json tfplan > plan.json" in app
    assert "--framework" in app
    assert "--evidence evidence.json" in app
    assert "--sign" in app
    assert "id-token: write" in app
    assert "actions/upload-artifact@v4" in app
    assert "verify evidence.json" in app
    assert "No raw Terraform plan is attached." in app
    assert "teamProfiles" in app
    assert "renderRiskCounts(rows)" in app
    assert "loadDemoData" in app
    assert "./demo-evidence.json" in app
    assert "workflow_run:" in app
    assert "actions: read" in app
    assert "actions/download-artifact@v4" in app
    assert "Do not expose cloud credentials to forked pull_request jobs." in app
    assert "terraform init -input=false" not in app


def test_site_build_contract_for_cloudflare_pages() -> None:
    package = (SITE / "package.json").read_text(encoding="utf-8")
    build_script = (SITE / "scripts" / "build.js").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "site.yml").read_text(
        encoding="utf-8"
    )

    assert '"build": "node scripts/build.js"' in package
    assert "site/dist" in (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "X-Content-Type-Options: nosniff" in build_script
    assert "Content-Security-Policy" in build_script
    assert "Strict-Transport-Security" in build_script
    assert "Access-Control-Allow-Origin: https://readtheplan.dev" in build_script
    assert "examples" in build_script
    assert "02-dangerous-replacement" in build_script
    assert "demo-evidence.json" in build_script
    assert "browsing-topics=()" in build_script
    assert "Cross-Origin-Opener-Policy" in build_script
    assert "npm --prefix site run build" in workflow

    for asset in [
        "404.html",
        "_redirects",
        "favicon.svg",
        "og-image.png",
        "robots.txt",
        "sitemap.xml",
    ]:
        assert (SITE / asset).exists()
        assert asset in build_script
