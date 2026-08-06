from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"


def test_security_supported_version_matches_project_version() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"(?P<version>\d+\.\d+)\.\d+"', pyproject, re.MULTILINE)
    assert match is not None

    minor_line = match.group("version")
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert f"| {minor_line}.x" in security
    assert f"| < {minor_line}" in security


def test_site_has_client_onboarding_surface() -> None:
    html = (SITE / "index.html").read_text(encoding="utf-8")

    assert "readtheplan" in html
    assert "No plan upload" in html
    assert "SOC 2" in html
    assert "ISO 27001" in html
    assert "HIPAA" in html
    assert 'id="top"' in html
    assert 'class="hero-proof signal-console"' in html
    assert "static product preview · no uploaded data" in html
    assert 'class="risk-orbit"' in html
    assert 'class="resource-map"' in html
    assert 'id="how-it-works"' in html
    assert 'id="setup"' in html
    assert 'id="agent"' in html
    assert 'id="community"' in html
    assert 'id="resources"' in html
    assert 'id="compare"' in html
    assert 'id="gen-output"' in html
    assert "One free local risk gate for Terraform, Kubernetes, CI/CD" in html
    assert "Native GitHub Action + any CI" in html
    for ci_name in ["GitLab CI", "CircleCI", "Jenkins", "Azure DevOps", "Buildkite", "Bitbucket"]:
        assert ci_name in html
    assert (
        "Six built-in catalogs cover SOC 2, ISO 27001, HIPAA, PCI DSS, "
        "FedRAMP Moderate, and HITRUST"
    ) in html
    assert "/tools/terraform-risk-calculator/" in html
    assert "/tools/soc2-cloud-control-mapper/" in html
    assert "/mcp/" in html
    assert "/brief/" in html
    assert "/playground/" in html
    # Document chrome (canonical, social cards) is owned by the shared layout;
    # templates carry the canonical URL as front matter.
    assert html.startswith("---")
    assert 'canonical: "https://readtheplan.dev/"' in html
    layout = (SITE / "_includes" / "layouts" / "base.njk").read_text(encoding="utf-8")
    assert 'rel="canonical"' in layout
    assert "og:image" in layout
    assert "Upload a plan" not in html
    assert "gmail.com" not in html
    # Interactive behavior ships as a CSP-safe external module.
    home_js = (SITE / "js" / "home.js").read_text(encoding="utf-8")
    assert "function workflowText()" in home_js
    assert "fail-on-threshold" in home_js
    assert "<script>" not in html


def test_site_build_contract_for_cloudflare_pages() -> None:
    package = json.loads((SITE / "package.json").read_text(encoding="utf-8"))
    build_script = (SITE / "scripts" / "build.js").read_text(encoding="utf-8")
    eleventy_config = (SITE / "eleventy.config.cjs").read_text(encoding="utf-8")
    shared_chrome = "\n".join(
        [
            (SITE / "_includes" / "site-header.njk").read_text(encoding="utf-8"),
            (SITE / "_includes" / "site-footer.njk").read_text(encoding="utf-8"),
            eleventy_config,
        ]
    )
    workflow = (ROOT / ".github" / "workflows" / "site.yml").read_text(encoding="utf-8")

    assert package["scripts"]["build"] == (
        "node scripts/build.js && node analysis/build-contract.test.mjs "
        "&& node analysis/rendered-route-contract.test.mjs"
    )
    assert "analysis/interaction-contract.test.mjs" in package["scripts"]["test"]
    assert "analysis/design-system-contract.test.mjs" in package["scripts"]["test"]
    assert "site/dist" in (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "X-Content-Type-Options: nosniff" in build_script
    assert "Content-Security-Policy" in build_script
    assert "font-src 'self'" in build_script
    assert "img-src 'self' data:" in build_script
    assert "Strict-Transport-Security" in build_script
    assert "Access-Control-Allow-Origin: https://readtheplan.dev" in build_script
    assert "examples" in build_script
    assert "02-dangerous-replacement" in build_script
    assert "demo-evidence.json" in build_script
    assert "browsing-topics=()" in build_script
    assert "Cross-Origin-Opener-Policy" in build_script
    assert package["devDependencies"]["@11ty/eleventy"] == "3.1.6"
    assert "npx eleventy --config=eleventy.config.cjs" in build_script
    # Layout-owned chrome: templates declare front matter, layouts/base.njk
    # renders the shell; the legacy regex chrome rewriter is retired.
    base_layout = (SITE / "_includes" / "layouts" / "base.njk").read_text(encoding="utf-8")
    assert "projectVersion" in shared_chrome
    assert "site-header:start" in shared_chrome
    assert "site-footer:start" in shared_chrome
    assert "__READTHEPLAN_VERSION__" in shared_chrome
    assert 'addGlobalData("layout", "layouts/base.njk")' in eleventy_config
    assert "version-token" in eleventy_config
    assert "canonicalHeader" not in eleventy_config
    assert "canonical-site-shell" not in eleventy_config
    assert 'include "site-header.njk"' in base_layout
    assert 'include "site-footer.njk"' in base_layout
    assert '"fonts"' in eleventy_config
    assert '"img"' in eleventy_config
    assert '"data"' in eleventy_config
    # Cloudflare Pages compiles Functions from the source tree; a dist copy
    # would be inert, so the passthrough must stay retired.
    assert '"functions"' not in eleventy_config
    assert '"modern.css"' in eleventy_config
    assert '"site-motion.js"' in eleventy_config
    assert "script-src 'self' https://plausible.io" in build_script
    assert "'unsafe-inline'" not in build_script.split("script-src")[1].split(";")[0]
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


def test_static_seo_tools_preserve_local_first_privacy() -> None:
    routes = [
        "tools/terraform-risk-calculator/index.html",
        "tools/soc2-cloud-control-mapper/index.html",
        "resources/terraform-s3-bucket-risk/index.html",
        "resources/terraform-iam-policy-risk/index.html",
        "resources/terraform-security-group-0-0-0-0-risk/index.html",
        "resources/terraform-cloudwatch-log-retention-risk/index.html",
    ]
    pages = [(SITE / route).read_text(encoding="utf-8") for route in routes]
    combined = "\n".join(pages)
    sitemap = (SITE / "sitemap.xml").read_text(encoding="utf-8")
    tools_js = (SITE / "tools" / "tools.js").read_text(encoding="utf-8")

    for route in routes:
        assert (SITE / route).exists()
        url_path = "/" + route.removesuffix("index.html")
        assert url_path in sitemap

    assert "Terraform Risk Calculator" in combined
    assert "SOC 2 Cloud Control Mapper" in combined
    assert "raw Terraform plans stay local" in combined
    assert 'id="riskCalculator"' in combined
    assert 'type="number"' in combined
    assert "Calculate risk" in combined
    assert "SOC 2 control family map" in combined
    assert "Terraform S3 Bucket Risk" in combined
    assert "Terraform IAM Policy Risk" in combined
    assert "Terraform Security Group 0.0.0.0/0 Risk" in combined
    assert "Terraform CloudWatch Log Retention Risk" in combined
    assert "Get free setup help" in combined
    assert "info@readtheplan.dev" in combined
    assert 'itemscope itemtype="https://schema.org/FAQPage"' in combined
    assert "new FormData(calculator)" in tools_js

    assert "Upload a plan" not in combined
    assert 'type="file"' not in combined
    assert "<form" in combined
    assert "action=" not in combined
    for prohibited in [
        "hosted analyzer",
        "hosted plan analysis",
        "API endpoint",
        "store uploaded",
        "stored plan",
    ]:
        assert prohibited.lower() not in combined.lower()


def test_mcp_landing_page_productizes_local_preview_only() -> None:
    mcp = (SITE / "mcp" / "index.html").read_text(encoding="utf-8")
    sitemap = (SITE / "sitemap.xml").read_text(encoding="utf-8")

    assert (SITE / "mcp" / "index.html").exists()
    assert "/mcp/" in sitemap

    for expected in [
        "Local MCP infrastructure reviewer",
        "Give your AI coding agent deterministic Terraform, CloudFormation, Azure, Kubernetes",
        "Local-first",
        "No raw plan upload",
        "No hosted MCP service",
        "No hosted plan analysis",
        'pip install "readtheplan[mcp]"',
        "readtheplan mcp",
        "agent_gate_project",
        "MCP_ROOT",
        "isolated temporary snapshot",
        "analyze_plan",
        "agent_gate",
        "agent_gate_pulumi",
        "agent_gate_pulumi_project",
        "agent_gate_azure",
        "agent_gate_bicep",
        "agent_gate_cdk",
        "agent_gate_nix",
        "agent_gate_dsc",
        "agent_gate_cfengine",
        "agent_gate_terraform_lock",
        "agent_gate_terraform_state",
        "agent_gate_terraform_stack",
        "agent_gate_spacelift",
        "jenkins-jcasc",
        "jenkins-project",
        "TeamCity Kotlin DSL",
        "Concourse",
        "Bamboo Specs",
        "AWS CodeBuild",
        "Google Cloud Build",
        "AWS CodePipeline",
        "agent_gate_sops",
        "agent_gate_docker_bake",
        "SOPS policy and encrypted documents",
        "Docker Buildx Bake definitions",
        "ansible-project",
        "chef-project",
        "Chef recipes/projects/Berkshelf dependencies/client, Workstation, Solo, and Server "
        "runtime configuration",
        "puppet-project",
        "salt-project",
        "NixOS",
        "PowerShell DSC",
        "CFEngine",
        "provider locks",
        "proceed/warn/block",
        "PR reviewer",
        "SOC 2 evidence prep",
        "Dangerous change triage",
        "Auditor-friendly summary",
        "CloudFormation",
        "Kubernetes",
        "Pulumi",
        "Get free setup help",
        "info@readtheplan.dev",
        "auth design",
        "least privilege",
        "audit logs",
        "Community guidance",
    ]:
        assert expected in mcp

    for prohibited in [
        "Upload a plan",
        "hosted MCP endpoint",
        "hosted MCP platform",
        "hosted plan analyzer",
        "API endpoint",
        "submit your plan",
        "store uploaded",
        "stored plan",
    ]:
        assert prohibited.lower() not in mcp.lower()

    assert 'type="file"' not in mcp
    assert "<form" not in mcp


def test_weekly_brief_free_community_slice() -> None:
    brief_path = SITE / "brief" / "index.html"
    sample_path = SITE / "brief" / "sample-001" / "index.html"
    sitemap = (SITE / "sitemap.xml").read_text(encoding="utf-8")
    homepage = (SITE / "index.html").read_text(encoding="utf-8")
    assert brief_path.exists()
    assert sample_path.exists()
    assert "/brief/" in sitemap
    assert "/brief/sample-001/" in sitemap
    assert "/brief/" in homepage

    combined = brief_path.read_text(encoding="utf-8") + "\n" + sample_path.read_text(encoding="utf-8")  # noqa: E501

    for expected in [
        "Weekly Terraform/SOC 2 change intelligence for platform teams",
        "free community loop",
        "monitor, filter, analyze, package, publish",
        "Platform and SRE teams",
        "DevOps consultancies",
        "SOC 2 consultants",
        "Infra and devtool projects",
        "Top 5 infra/compliance changes",
        "Why they matter",
        "Terraform/SOC2 risk angle",
        "Action checklist",
        "readtheplan CTA",
        "Public sample",
        "Free weekly brief",
        "Community requests",
        "Local integrations",
        "Suggest a brief item",
        "Terraform/OpenTofu",
        "AWS logging",
        "AWS IAM",
        "Security group ingress",
        "GitHub Actions permission expansion",
        "SOC 2 evidence",
        "readtheplan progress",
        "Demo issue",
    ]:
        assert expected in combined

    for prohibited in [
        'type="file"',
        "Upload a plan",
        "submit your plan",
        "Start hosted analyzer",
        "hosted plan analyzer is available",
        "Create account",
        "Sign up",
        "Stripe",
        "Checkout",
        "Subscribe now",
        "storage bucket",
        "store uploaded",
        "stored plan",
        "cron job is enabled",
        "scheduled delivery is enabled",
        "automatic scheduled delivery is enabled",
    ]:
        assert prohibited.lower() not in combined.lower()

    assert "<form" not in combined


def test_docs_routes_are_sitemap_listed_and_layout_owned() -> None:
    sitemap = (SITE / "sitemap.xml").read_text(encoding="utf-8")
    docs_routes = [
        "docs/index.html",
        "docs/quickstart/index.html",
        "docs/cli/index.html",
        "docs/ci/index.html",
        "docs/github-action/index.html",
    ]

    for route in docs_routes:
        path = SITE / route
        html = path.read_text(encoding="utf-8")
        url_path = "/" + route.removesuffix("index.html")

        assert path.exists()
        assert url_path in sitemap
        # Layout-owned templates: front matter only, no per-page chrome,
        # no legacy stylesheets, no version literals.
        assert html.startswith("---")
        assert "matrix.css" not in html
        assert "topbar" not in html
        assert "<head>" not in html
        assert re.search(r"\bv\d+\.\d+\.\d+\b", html) is None
        assert "readtheplan" in html

    assert "/demo/" in sitemap
    assert "/playground/" in sitemap


def test_site_redesign_visual_contract() -> None:
    css = (SITE / "modern.css").read_text(encoding="utf-8")
    docs = (SITE / "docs" / "index.html").read_text(encoding="utf-8")

    # "Ledger" light-first editorial system: paper canvas, ink text, one
    # indigo accent, dark proof surfaces for code/terminal only.
    assert "--paper: #faf9f7;" in css
    assert "--ink: #191b20;" in css
    assert "--accent: #4438ca;" in css
    assert "--proof-bg: #12151b;" in css
    assert '"JetBrains Mono"' in css
    assert 'url("/fonts/JetBrainsMono-Regular.woff2")' in css
    assert ".site-nav" in css
    assert ".site-footer" in css
    assert ".skip-link" in css
    assert ":focus-visible" in css
    assert "@media (max-width: 720px)" in css
    assert "prefers-reduced-motion" in css
    assert "@media print" in css
    assert "matrix" not in css.lower()
    assert docs.startswith("---")

    for asset in [
        "fonts/JetBrainsMono-Regular.woff2",
        "fonts/LICENSE-JetBrainsMono.txt",
    ]:
        assert (SITE / asset).exists()

    for retired in [
        "styles.css",
        "matrix.css",
        "home.css",
        "matrix.js",
        "app.js",
        "_headers",
        "fonts/DepartureMono-Regular.woff2",
    ]:
        assert not (SITE / retired).exists(), f"retired asset returned: {retired}"
