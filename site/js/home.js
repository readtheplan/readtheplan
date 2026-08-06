/* Homepage behavior: setup wizard, sample-analysis console, motion.
 CSP-safe external module — no inline handlers. Declarations stay
 top-level so the interaction contract can exercise the wizard logic
 in a synthetic DOM. */
"use strict";

/* Single-sourced version: rendered into the nav badge from pyproject. */
var versionBadge = document.querySelector(".site-brand__version");
var VERSION = versionBadge ? versionBadge.textContent.replace(/^v/, "").trim() : "0.0.0";

/* ── Setup wizard ─────────────────────────────────────────── */

var fwMap = { "SOC 2": "soc2", "ISO 27001": "iso27001", "HIPAA": "hipaa", "PCI DSS": "pci_dss", "FedRAMP": "fedramp_moderate", "HITRUST": "hitrust", "None": "none" };
var thMap = { "Irreversible only": "irreversible", "Dangerous": "dangerous", "Review": "review", "Don't block": "none" };
var evMap = { "JSON envelope": "json-envelope", "Signed (OIDC)": "signed-oidc", "Checklist only": "checklist" };

function activeVal(group) {
  var el = document.querySelector('[data-group="' + group + '"].active');
  return el ? el.textContent.trim() : "";
}
function activeFramework() { return fwMap[activeVal("fw")] || "none"; }
function activeThreshold() { return thMap[activeVal("thresh")] || "dangerous"; }
function activeEvidence() { return evMap[activeVal("ev")] || "checklist"; }
function evidenceFile(ev) { return ev === "checklist" ? "readtheplan-checklist.json" : "readtheplan-evidence.json"; }
function installPackage(ev) { return ev === "signed-oidc" ? '"readtheplan[sign]"' : "readtheplan"; }

function cliCommand(forceJson, includeThreshold) {
  var fw = activeFramework();
  var ev = activeEvidence();
  var th = activeThreshold();
  var parts = ["readtheplan", "analyze"];
  if (fw !== "none") parts.push("--framework", fw);
  if (forceJson || ev !== "checklist") parts.push("--format", "json");
  if (ev !== "checklist") parts.push("--evidence", evidenceFile(ev));
  if (ev === "signed-oidc") parts.push("--sign");
  if (includeThreshold && th !== "none") parts.push("--fail-on", th);
  parts.push("plan.json");
  return parts.join(" ");
}

function workflowText() {
  var ci = activeVal("ci");
  var fw = activeFramework();
  var th = activeThreshold();
  var ev = activeEvidence();
  var install = "python -m pip install " + installPackage(ev);
  var gate = cliCommand(true, true);
  var evidence = cliCommand(true, false) + " > readtheplan-summary.json";

  if (ci === "Local only") {
    return [
      "terraform plan -out=tfplan",
      "terraform show -json tfplan > plan.json",
      install,
      gate
    ].join("\n");
  }

  if (ci === "GitLab CI") {
    var gitlabLines = [
      "# .gitlab-ci.yml",
      "image: python:3.13",
      "",
      "readtheplan:",
      "  stage: test",
      "  script:",
      "    - " + install,
      "    - " + gate
    ];
    if (ev !== "checklist") {
      gitlabLines.push("  artifacts:", "    when: always", "    paths:", "      - " + evidenceFile(ev));
    }
    return gitlabLines.join("\n");
  }

  if (ci === "CircleCI") {
    return [
      "version: 2.1",
      "jobs:",
      "  readtheplan:",
      "    docker:",
      "      - image: cimg/python:3.13",
      "    steps:",
      "      - checkout",
      "      - run: " + install,
      "      - run: " + gate,
      "workflows:",
      "  infrastructure-review:",
      "    jobs: [readtheplan]"
    ].join("\n");
  }

  if (ci === "Jenkins") {
    return [
      "stage('Infrastructure risk gate') {",
      "  steps {",
      "    sh '''",
      "      " + install,
      "      " + gate,
      "    '''",
      "  }",
      "}"
    ].join("\n");
  }

  if (ci === "Azure DevOps") {
    return [
      "# azure-pipelines.yml",
      "steps:",
      "  - script: |",
      "      " + install,
      "      " + gate,
      "    displayName: Gate infrastructure risk"
    ].join("\n");
  }

  if (ci === "Buildkite") {
    return [
      "# .buildkite/pipeline.yml",
      "steps:",
      '  - label: ":shield: Infrastructure risk gate"',
      "    commands:",
      "      - " + install,
      "      - " + gate
    ].join("\n");
  }

  if (ci === "Bitbucket") {
    return [
      "# bitbucket-pipelines.yml",
      "pipelines:",
      "  default:",
      "    - step:",
      "        name: Infrastructure risk gate",
      "        image: python:3.13-slim",
      "        script:",
      "          - " + install,
      "          - " + gate
    ].join("\n");
  }

  var lines = [
    "# .github/workflows/terraform-review.yml",
    "- name: Analyze Terraform plan",
    "  id: readtheplan",
    "  uses: readtheplan/readtheplan@v" + VERSION,
    "  with:",
    "    input-file: plan.json"
  ];
  if (th !== "none") lines.push("    fail-on-threshold: " + th);
  if (fw !== "none" || ev !== "checklist") {
    lines.push("", "- name: Generate evidence artifact", "  if: always()", "  run: |", "    " + install, "    " + evidence);
  }
  return lines.join("\n");
}

function flashButton(button, nextLabel) {
  if (!button) return;
  var original = button.textContent;
  button.textContent = nextLabel;
  window.setTimeout(function () { button.textContent = original; }, 1400);
}

function updateCLIPreview() {
  var el = document.getElementById("cli-preview-cmd");
  if (el) el.textContent = cliCommand(false, true);
}

function updateGen() {
  var ci = activeVal("ci");
  var labels = {
    "GitHub Actions": "Generated GitHub Actions workflow",
    "GitLab CI": "Generated GitLab CI job",
    "CircleCI": "Generated CircleCI config",
    "Jenkins": "Generated Jenkins stage",
    "Azure DevOps": "Generated Azure DevOps steps",
    "Buildkite": "Generated Buildkite step",
    "Bitbucket": "Generated Bitbucket Pipelines step",
    "Local only": "Generated local commands"
  };
  var label = document.getElementById("gen-label");
  if (label) label.textContent = labels[ci] || "Generated CI configuration";
  var out = document.getElementById("gen-output");
  if (out) out.textContent = workflowText();
}

document.querySelectorAll(".seg-btn[data-group]").forEach(function (btn) {
  btn.addEventListener("click", function () {
    var group = btn.getAttribute("data-group");
    document.querySelectorAll('[data-group="' + group + '"]').forEach(function (b) {
      b.classList.remove("active");
      b.setAttribute("aria-pressed", "false");
    });
    btn.classList.add("active");
    btn.setAttribute("aria-pressed", "true");
    updateGen();
    updateCLIPreview();
  });
});

var copyInstallBtn = document.getElementById("copy-install");
if (copyInstallBtn) {
  copyInstallBtn.addEventListener("click", function () {
    navigator.clipboard.writeText("pip install readtheplan").then(function () {
      if (typeof window.readtheplanTrack === "function") window.readtheplanTrack("copy_install");
      flashButton(copyInstallBtn, "Copied");
    }, function () {
      flashButton(copyInstallBtn, "Copy failed");
    });
  });
}
var copyWorkflowBtn = document.getElementById("copy-workflow");
if (copyWorkflowBtn) {
  copyWorkflowBtn.addEventListener("click", function () {
    navigator.clipboard.writeText(workflowText()).then(function () {
      if (typeof window.readtheplanTrack === "function") window.readtheplanTrack("generate_ci");
      flashButton(copyWorkflowBtn, "Copied");
    }, function () {
      flashButton(copyWorkflowBtn, "Copy failed");
    });
  });
}
var copyCliBtn = document.getElementById("copy-cli");
if (copyCliBtn) {
  copyCliBtn.addEventListener("click", function () {
    navigator.clipboard.writeText(cliCommand()).then(function () {
      flashButton(copyCliBtn, "Copied");
    }, function () {
      flashButton(copyCliBtn, "Copy failed");
    });
  });
}

/* ── Sample-analysis console ──────────────────────────────── */

function startInteractiveDemo() {
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".scan-tab"));
  if (!tabs.length) return;

  var scenarios = {
    repository: {
      counts: [34, 23, 7, 3, 1], decision: "BLOCK", note: "4 findings need review",
      nodes: ["aws_s3_bucket.logs", "aws_iam_role.app", "aws_kms_key.primary", "aws_cloudwatch_log_group.app"],
      findings: [
        ["tier-irrev", "KMS deletion scheduled", "CC6.1 · permanent impact"],
        ["tier-danger", "IAM policy replaced", "CC6.3 · privilege change"],
        ["tier-review", "Public ingress changed", "CC6.6 · network exposure"]
      ]
    },
    terraform: {
      counts: [18, 11, 4, 2, 1], decision: "BLOCK", note: "3 changes cross the threshold",
      nodes: ["aws_db_instance.primary", "aws_security_group.app", "aws_iam_role.deploy", "aws_kms_alias.data"],
      findings: [
        ["tier-irrev", "Database replacement planned", "A1.2 · data persistence"],
        ["tier-danger", "Security group opened", "CC6.6 · public exposure"],
        ["tier-review", "Deploy role expanded", "CC6.3 · permission scope"]
      ]
    },
    kubernetes: {
      counts: [27, 20, 5, 2, 0], decision: "BLOCK", note: "2 workload changes need review",
      nodes: ["deployment/api", "service/api", "networkpolicy/egress", "secret/database"],
      findings: [
        ["tier-danger", "Privileged container enabled", "K8S-PSP · host access"],
        ["tier-danger", "Network policy removed", "CC6.6 · unrestricted egress"],
        ["tier-review", "Service account changed", "CC6.3 · workload identity"]
      ]
    },
    pipeline: {
      counts: [12, 9, 3, 0, 0], decision: "WARN", note: "3 changes need a human look",
      nodes: ["workflow/release", "permissions/contents", "environment/production", "secrets/oidc"],
      findings: [
        ["tier-review", "Workflow permissions expanded", "CC6.3 · token scope"],
        ["tier-review", "Fork trigger changed", "CI-04 · credential boundary"],
        ["tier-review", "Protection rule updated", "CC8.1 · release control"]
      ]
    }
  };

  var order = tabs.map(function (tab) { return tab.getAttribute("data-demo"); });
  var currentIndex = Math.max(0, order.indexOf(tabs.find(function (tab) {
    return tab.classList.contains("active");
  }).getAttribute("data-demo")));
  var paused = false;
  var timer = null;

  function setText(id, value) {
    var element = document.getElementById(id);
    if (element) element.textContent = value;
  }

  function showScenario(key) {
    var scenario = scenarios[key];
    if (!scenario) return;
    currentIndex = order.indexOf(key);

    tabs.forEach(function (tab) {
      var active = tab.getAttribute("data-demo") === key;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-pressed", active ? "true" : "false");
    });

    ["demo-total", "demo-safe", "demo-review", "demo-danger", "demo-irrev"].forEach(function (id, index) {
      setText(id, scenario.counts[index]);
    });
    var orbit = document.querySelector(".risk-orbit");
    if (orbit) {
      var safeEnd = (scenario.counts[1] / scenario.counts[0]) * 100;
      var reviewEnd = safeEnd + (scenario.counts[2] / scenario.counts[0]) * 100;
      var dangerEnd = reviewEnd + (scenario.counts[3] / scenario.counts[0]) * 100;
      orbit.style.setProperty("--safe-end", safeEnd + "%");
      orbit.style.setProperty("--review-end", reviewEnd + "%");
      orbit.style.setProperty("--danger-end", dangerEnd + "%");
      orbit.setAttribute("aria-label", scenario.counts[0] + " sample changes");
    }
    setText("demo-decision", scenario.decision);
    setText("demo-gate-note", scenario.note);
    ["demo-node-core", "demo-node-one", "demo-node-two", "demo-node-three"].forEach(function (id, index) {
      setText(id, scenario.nodes[index]);
    });

    scenario.findings.forEach(function (finding, index) {
      var suffix = ["one", "two", "three"][index];
      var risk = document.getElementById("demo-risk-" + suffix);
      if (risk) risk.className = finding[0];
      setText("demo-finding-" + suffix, finding[1]);
      setText("demo-detail-" + suffix, finding[2]);
    });

    var gate = document.getElementById("demo-gate");
    if (gate) gate.setAttribute("data-decision", scenario.decision.toLowerCase());
    var consoleEl = document.querySelector(".signal-console");
    if (consoleEl) {
      consoleEl.classList.remove("demo-updated");
      window.requestAnimationFrame(function () { consoleEl.classList.add("demo-updated"); });
    }
  }

  function restartTimer() {
    if (timer) window.clearInterval(timer);
    if (paused) return;
    timer = window.setInterval(function () {
      showScenario(order[(currentIndex + 1) % order.length]);
    }, 4600);
  }

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      showScenario(tab.getAttribute("data-demo"));
      restartTimer();
    });
  });

  var pause = document.getElementById("demo-pause");
  if (pause) {
    pause.addEventListener("click", function () {
      paused = !paused;
      pause.textContent = paused ? "Play" : "Pause";
      pause.setAttribute("aria-pressed", paused ? "true" : "false");
      restartTimer();
    });
  }

  var map = document.querySelector(".resource-map");
  if (map) {
    map.addEventListener("pointermove", function (event) {
      var rect = map.getBoundingClientRect();
      map.style.setProperty("--probe-x", (event.clientX - rect.left) + "px");
      map.style.setProperty("--probe-y", (event.clientY - rect.top) + "px");
      map.classList.add("is-exploring");
    });
    map.addEventListener("pointerleave", function () { map.classList.remove("is-exploring"); });
  }

  var reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reducedMotion) restartTimer();
}

/* ── Homepage motion (site-motion.js defers to route-home) ── */

function startHomepageMotion() {
  var reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var revealTargets = document.querySelectorAll(".section-shell, .closing-cta");
  var staggerTargets = document.querySelectorAll(".tiers, .panel-grid, .tools-grid");

  revealTargets.forEach(function (target) { target.classList.add("reveal"); });
  staggerTargets.forEach(function (target) { target.classList.add("stagger"); });

  if (reducedMotion || !("IntersectionObserver" in window)) {
    revealTargets.forEach(function (target) { target.classList.add("is-visible"); });
    staggerTargets.forEach(function (target) { target.classList.add("is-visible"); });
    return;
  }

  document.documentElement.classList.add("motion-ready");
  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("is-visible");
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.12, rootMargin: "0px 0px -7% 0px" });

  revealTargets.forEach(function (target) { observer.observe(target); });
  staggerTargets.forEach(function (target) { observer.observe(target); });

  document.querySelectorAll(".tier, .card, .tool-link").forEach(function (card) {
    card.classList.add("interactive-card");
    card.addEventListener("pointermove", function (event) {
      var rect = card.getBoundingClientRect();
      card.style.setProperty("--spot-x", (event.clientX - rect.left) + "px");
      card.style.setProperty("--spot-y", (event.clientY - rect.top) + "px");
    });
  });
}

updateGen();
updateCLIPreview();
startInteractiveDemo();
startHomepageMotion();
