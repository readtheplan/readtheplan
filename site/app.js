const form = document.querySelector("#onboardingForm");
const actionOutput = document.querySelector("#actionOutput");
const cliOutput = document.querySelector("#cliOutput");
const checklist = document.querySelector("#checklist");
const actionTitle = document.querySelector("#actionTitle");
const statusPill = document.querySelector("#statusPill");
const recommendation = document.querySelector("#recommendation");
const safeCount = document.querySelector("#safeCount");
const reviewCount = document.querySelector("#reviewCount");
const dangerousCount = document.querySelector("#dangerousCount");
const planRows = document.querySelector("#planRows");
const demoSafeCount = document.querySelector("#demoSafeCount");
const demoReviewCount = document.querySelector("#demoReviewCount");
const demoDangerousCount = document.querySelector("#demoDangerousCount");
const demoRows = document.querySelector("#demoRows");
const demoEvidenceNote = document.querySelector("#demoEvidenceNote");

const ciLabels = {
  github: "GitHub Actions",
  gitlab: "GitLab CI",
  circle: "CircleCI",
  local: "local only",
};

const frameworkLabels = {
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  hipaa: "HIPAA",
  none: "no framework",
};

const frameworkFlags = {
  soc2: "soc2",
  iso27001: "iso27001",
  hipaa: "hipaa",
};

const thresholdLabels = {
  dangerous: "block dangerous and irreversible findings",
  review: "block review, dangerous, and irreversible findings",
  irreversible: "block irreversible findings only",
  off: "warn only; do not block the workflow",
};

const evidenceLabels = {
  unsigned: "JSON evidence envelope",
  signed: "signed evidence envelope",
  checklist: "checklist only",
};

function cleanToken(value, fallback) {
  const next = String(value || "").trim();
  return next || fallback;
}

function shouldWriteEvidence(state) {
  return state.framework !== "none" && state.evidence !== "checklist";
}

function getFormState() {
  const data = new FormData(form);
  return {
    ci: data.get("ci"),
    framework: data.get("framework"),
    artifactName: cleanToken(data.get("artifactName"), "terraform-plan-json"),
    planPath: cleanToken(data.get("planPath"), "plan.json"),
    threshold: data.get("threshold"),
    evidence: data.get("evidence"),
  };
}

function renderDemoRows(changes) {
  if (!demoRows) return;
  demoRows.replaceChildren(
    ...changes.map((change) => {
      const risk = document.createElement("span");
      risk.className = `risk-tag ${change.risk}`;
      risk.textContent = change.risk;

      const resource = document.createElement("span");
      resource.textContent = change.address || change.type;

      const explanation = document.createElement("span");
      explanation.textContent = change.explanation;

      const controls = document.createElement("span");
      controls.className = "control-list";
      controls.textContent =
        (change.controls || []).map((control) => control.id).join(", ") || "none";

      const item = document.createElement("div");
      item.setAttribute("role", "row");
      item.replaceChildren(risk, resource, explanation, controls);
      return item;
    }),
  );
}

function renderDemoSummary(summary) {
  const risks = summary.risks || {};
  if (demoSafeCount) demoSafeCount.textContent = String(risks.safe || 0);
  if (demoReviewCount) demoReviewCount.textContent = String(risks.review || 0);
  if (demoDangerousCount) demoDangerousCount.textContent = String(risks.dangerous || 0);
}

function renderDemoEvidence(payload) {
  if (!demoEvidenceNote) return;
  const attestation = payload.agent_attestation || {};
  const signed = Boolean(attestation.signature && attestation.cert);
  const framework = payload.framework?.name ? payload.framework.name.toUpperCase() : "SOC2";
  const controlCount = payload.summary?.controls_touched?.length || 0;
  const planSha = payload.plan?.sha256 || "unknown";
  demoEvidenceNote.textContent = signed
    ? `Signed evidence fixture: ${framework}, ${controlCount} controls touched, plan ${planSha.slice(0, 12)}...`
    : `Evidence fixture: ${framework}, ${controlCount} controls touched.`;
}

async function loadDemoData() {
  try {
    const response = await fetch("/demo-evidence.json");
    if (!response.ok) {
      throw new Error(`demo data returned ${response.status}`);
    }
    const payload = await response.json();
    renderDemoSummary(payload.summary);
    renderDemoRows(payload.changes || []);
    renderDemoEvidence(payload);
  } catch (error) {
    if (demoEvidenceNote) demoEvidenceNote.textContent =
      "Demo evidence could not be loaded. The setup generator still works.";
  }
}

function analyzeArgs(state, planFile = state.planPath) {
  const args = ["analyze", "--format", "json"];

  if (state.framework !== "none") {
    args.push("--framework", frameworkFlags[state.framework]);
  }

  if (shouldWriteEvidence(state)) {
    args.push("--evidence", "readtheplan-evidence.json");
  }

  if (state.evidence === "signed" && state.framework !== "none") {
    args.push("--sign");
  }

  args.push(planFile);
  return args;
}

function analyzeCommand(state, planFile = state.planPath) {
  return ["readtheplan", ...analyzeArgs(state, planFile)].join(" ");
}

function actionAnalyzeCommand(state) {
  const args = analyzeArgs(state);
  if (state.framework !== "none") {
    args.splice(
      args.length - 1,
      0,
      "--reviewer-id",
      "${{ github.actor }}",
      "--run-id",
      '"github-actions/${{ github.run_id }}"',
    );
  }
  return ["readtheplan", ...args].join(" ");
}

function gateScript(state) {
  if (state.threshold === "off") {
    return [
      "          echo 'readtheplan is configured to warn only for this setup.'",
    ];
  }

  return [
    "          python - <<'PY'",
    "          import json",
    "          from pathlib import Path",
    "",
    "          risks = json.loads(Path('readtheplan-summary.json').read_text())['risks']",
    `          threshold = '${state.threshold}'`,
    "          order = ['safe', 'review', 'dangerous', 'irreversible']",
    "          blocked = order[order.index(threshold):]",
    "          count = sum(int(risks.get(risk, 0)) for risk in blocked)",
    "          if count:",
    "              print(f'::error::readtheplan found {count} finding(s) at or above {threshold}')",
    "              raise SystemExit(1)",
    "          print(f'readtheplan gate passed for threshold: {threshold}')",
    "          PY",
  ];
}

function generateAction(state) {
  return [
    "name: Terraform plan risk",
    "",
    "# Analyze an already-created Terraform plan JSON artifact.",
    "# Keep Terraform init/plan in a separate trusted workflow.",
    "# Do not expose cloud credentials to forked pull_request jobs.",
    "",
    "on:",
    "  workflow_run:",
    "    workflows: ['Terraform plan']",
    "    types: [completed]",
    "",
    "permissions:",
    "  contents: read",
    "  actions: read",
    ...(state.evidence === "signed" && state.framework !== "none" ? ["  id-token: write"] : []),
    "",
    "jobs:",
    "  readtheplan:",
    "    if: ${{ github.event.workflow_run.conclusion == 'success' }}",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - name: Download plan JSON artifact",
    "        uses: actions/download-artifact@v4",
    "        with:",
    "          name: " + state.artifactName,
    "          run-id: ${{ github.event.workflow_run.id }}",
    "          github-token: ${{ secrets.GITHUB_TOKEN }}",
    "",
    "      - name: Set up Python",
    "        uses: actions/setup-python@v5",
    "        with:",
    "          python-version: '3.13'",
    "",
    "      - name: Install readtheplan",
    "        run: |",
    "          python -m pip install --upgrade pip",
    "          python -m pip install readtheplan",
    "",
    "      - name: Analyze Terraform plan",
    "        id: readtheplan",
    "        run: |",
    "          " + actionAnalyzeCommand(state) + " > readtheplan-summary.json",
    "",
    "      - name: Apply blocking threshold",
    "        run: |",
    ...gateScript(state),
    "",
    ...(shouldWriteEvidence(state)
      ? [
          "      - name: Upload readtheplan evidence",
          "        if: always() && hashFiles('readtheplan-evidence.json') != ''",
          "        uses: actions/upload-artifact@v4",
          "        with:",
          "          name: readtheplan-evidence",
          "          path: readtheplan-evidence.json",
        ]
      : []),
  ].join("\n");
}

function generateCli(state) {
  const lines = [
    "python -m pip install readtheplan",
    "terraform plan -out=tfplan -input=false",
    "terraform show -json tfplan > " + state.planPath,
    analyzeCommand(state) + " > readtheplan-summary.json",
  ];

  if (state.threshold !== "off") {
    lines.push(
      "python - <<'PY'",
      "import json",
      "from pathlib import Path",
      "",
      "risks = json.loads(Path('readtheplan-summary.json').read_text())['risks']",
      `threshold = '${state.threshold}'`,
      "order = ['safe', 'review', 'dangerous', 'irreversible']",
      "blocked = order[order.index(threshold):]",
      "count = sum(int(risks.get(risk, 0)) for risk in blocked)",
      "if count:",
      "    raise SystemExit(f'readtheplan blocked {count} finding(s) at or above {threshold}')",
      "print(f'readtheplan gate passed for threshold: {threshold}')",
      "PY",
    );
  }

  return lines.join("\n");
}

function generateChecklist(state) {
  const checks = [
    `Confirm ${ciLabels[state.ci]} already creates a Terraform JSON plan artifact named ${state.artifactName}.`,
    `Store the downloaded plan at ${state.planPath} inside the readtheplan job workspace.`,
    `Use ${thresholdLabels[state.threshold]} for the first blocking rule.`,
    "Keep raw Terraform plan JSON out of issue comments, public artifacts, support tickets, and email.",
    "Review the generated workflow locally before committing it to .github/workflows/readtheplan.yml.",
  ];

  if (state.framework !== "none") {
    checks.push(`Attach ${frameworkLabels[state.framework]} control evidence from the generated evidence envelope.`);
  }

  if (state.evidence === "signed" && state.framework !== "none") {
    checks.push("Enable GitHub OIDC id-token: write and verify signed evidence before audit handoff.");
  } else if (state.evidence === "unsigned" && state.framework !== "none") {
    checks.push("Upload the JSON evidence envelope as a private CI artifact for reviewer and auditor access.");
  } else if (state.evidence !== "checklist" && state.framework === "none") {
    checks.push("Select a framework before enabling JSON or signed evidence output.");
  } else {
    checks.push("Start with the checklist, then enable evidence output once the gate is trusted.");
  }

  checks.push("Run the gate on one repository first, then repeat the same reviewed configuration elsewhere.");
  checks.push("No raw plan submission is needed; readtheplan runs in your CI or on your workstation.");
  return checks;
}

function generateSummaryRows(state) {
  return [
    {
      area: "CI",
      selection: ciLabels[state.ci],
      behavior:
        state.ci === "github"
          ? "Copy the workflow directly into GitHub Actions."
          : "Use the GitHub Actions snippet as the reference gate and the CLI command in your CI job.",
    },
    {
      area: "Plan JSON",
      selection: `${state.artifactName} -> ${state.planPath}`,
      behavior: "Analyze an existing Terraform JSON plan artifact; do not upload plan data.",
    },
    {
      area: "Blocking",
      selection: thresholdLabels[state.threshold],
      behavior: "The generated action and CLI use the same threshold.",
    },
    {
      area: "Evidence",
      selection: evidenceLabels[state.evidence],
      behavior:
        state.framework === "none"
          ? "Framework mapping is disabled; evidence output requires a framework."
          : `${frameworkLabels[state.framework]} evidence is generated from local analysis output.`,
    },
  ];
}

function renderRows(rows) {
  planRows.replaceChildren(
    ...rows.map((row) => {
      const area = document.createElement("span");
      area.className = "risk-tag safe";
      area.textContent = row.area;

      const selection = document.createElement("span");
      selection.textContent = row.selection;

      const behavior = document.createElement("span");
      behavior.textContent = row.behavior;

      const item = document.createElement("div");
      item.setAttribute("role", "row");
      item.replaceChildren(area, selection, behavior);
      return item;
    }),
  );
}

function render() {
  // Guard: bail if landing-page DOM isn't present. app.js is shared across
  // every page and only the landing page carries the setup-generator elements.
  // Must cover every element render() and its callees dereference (counts,
  // output areas, links) — a partial DOM will crash on the missing ones.
  if (
    !form || !statusPill || !recommendation || !planRows ||
    !actionOutput || !cliOutput || !checklist ||
    !safeCount || !reviewCount || !dangerousCount || !actionTitle
  ) return;
  const state = getFormState();
  statusPill.textContent = state.evidence === "signed" ? "oidc signing" : "no upload";
  recommendation.textContent =
    "Generate setup outputs from local form state only. The browser never sends plan paths, snippets, or Terraform plan contents to readtheplan.dev.";
  safeCount.textContent = "5";
  reviewCount.textContent = state.framework === "none" ? "0" : "1";
  dangerousCount.textContent = "0";
  actionTitle.textContent = "GitHub Action";
  renderRows(generateSummaryRows(state));
  actionOutput.textContent = generateAction(state);
  cliOutput.textContent = generateCli(state);
  checklist.replaceChildren(
    ...generateChecklist(state).map((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      return li;
    }),
  );
}

async function copyFrom(targetId, button) {
  const target = document.getElementById(targetId);
  if (!target) {
    return;
  }
  await navigator.clipboard.writeText(target.textContent);
  const original = button.textContent;
  button.textContent = "Copied";
  window.setTimeout(() => {
    button.textContent = original;
  }, 1200);
}

async function copyText(text, button) {
  await navigator.clipboard.writeText(text);
  const original = button.textContent;
  button.textContent = "Copied";
  window.setTimeout(() => {
    button.textContent = original;
  }, 1200);
}

function enhanceCodeCopy() {
  document.querySelectorAll("pre, .code-output").forEach((block, index) => {
    if (block.closest(".copyable-code") || block.dataset.copyEnhanced === "true") {
      return;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "copyable-code";
    block.dataset.copyEnhanced = "true";
    block.parentNode.insertBefore(wrapper, block);
    wrapper.appendChild(block);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy-code";
    button.textContent = "Copy";
    button.setAttribute("aria-label", `Copy code block ${index + 1}`);
    button.addEventListener("click", () => {
      copyText(block.textContent.trim(), button).catch(() => {
        button.textContent = "Select";
      });
    });
    wrapper.appendChild(button);
  });
}

if (form) {
  form.addEventListener("change", render);
  form.addEventListener("input", render);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    render();
    const setupEl = document.querySelector("#setup");
    if (setupEl) setupEl.scrollIntoView({ behavior: "smooth", block: "start" });
  });
}

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", () => {
    copyFrom(button.dataset.copy, button).catch(() => {
      button.textContent = "Select text";
    });
  });
});

enhanceCodeCopy();

// ── Live terminal animation ──────────────────────────────────
(function initTerminal() {
  const body = document.getElementById("terminalBody");
  const typingLine = document.getElementById("typingLine");
  const typingCmd = document.getElementById("typingCmd");
  const cursor = document.getElementById("cursor");
  if (!body || !typingLine || !typingCmd || !cursor) return;

  const commands = [
    {
      cmd: "readtheplan analyze examples/02-dangerous-replacement/plan.json --framework soc2",
      output: "→ risk tiers: 4 safe · 1 review · 2 dangerous · 1 irreversible",
    },
    {
      cmd: "readtheplan analyze plan.json --framework iso27001 --evidence evidence.json",
      output: "→ evidence envelope written. 7 controls touched.",
    },
    {
      cmd: "cat readtheplan-summary.json | jq '.risks'",
      output: "→ {\"safe\": 12, \"review\": 3, \"dangerous\": 1, \"irreversible\": 0}",
    },
    {
      cmd: "readtheplan agent-gate plan.json",
      output: "→ {\"decision\":\"block\",\"risk\":\"dangerous\"}",
    },
  ];

  let cmdIdx = 0;
  let charIdx = 0;
  let phase = "typing"; // "typing" | "output" | "pause"

  function tick() {
    if (cmdIdx >= commands.length) {
      // Loop: reset after a long pause
      setTimeout(() => {
        while (body.children.length > 3) body.removeChild(body.lastChild);
        cmdIdx = 0;
        charIdx = 0;
        phase = "typing";
        typingCmd.textContent = "";
        tick();
      }, 4000);
      return;
    }

    const cmd = commands[cmdIdx];

    if (phase === "typing") {
      if (charIdx < cmd.cmd.length) {
        typingCmd.textContent = cmd.cmd.slice(0, charIdx + 1);
        charIdx++;
        setTimeout(tick, 40 + Math.random() * 30);
      } else {
        phase = "output";
        setTimeout(tick, 350);
      }
      return;
    }

    if (phase === "output") {
      // Create completed command line (no cursor)
      const cmdLine = document.createElement("div");
      cmdLine.className = "terminal-line";
      cmdLine.innerHTML = `<span style="color:var(--accent)">λ</span> <span style="color:var(--foreground)">${cmd.cmd}</span>`;
      body.insertBefore(cmdLine, typingLine);

      // Create output line
      const outLine = document.createElement("div");
      outLine.className = "terminal-line";
      outLine.style.color = "var(--muted)";
      outLine.style.paddingLeft = "1.2em";
      outLine.textContent = cmd.output;
      body.insertBefore(outLine, typingLine);

      // Reset typing line
      typingCmd.textContent = "";
      charIdx = 0;
      cmdIdx++;
      phase = "pause";
      setTimeout(tick, 1800);
      return;
    }

    if (phase === "pause") {
      phase = "typing";
      setTimeout(tick, 200);
    }
  }

  // Start after a short delay
  setTimeout(tick, 600);
})();

if (form) {
  render();
} else {
  console.log("readtheplan — setup generator not on this page");
}
// loadDemoData is safe to skip on pages without demo elements
// (e.g. brief/mcp/seo pages that share app.js for copy-button behavior).
if (demoRows) {
  loadDemoData();
}
