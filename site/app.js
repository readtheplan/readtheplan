const form = document.querySelector("#onboardingForm");
const actionOutput = document.querySelector("#actionOutput");
const cliOutput = document.querySelector("#cliOutput");
const checklist = document.querySelector("#checklist");
const pilotLink = document.querySelector("#pilotLink");
const actionTitle = document.querySelector("#actionTitle");
const statusPill = document.querySelector("#statusPill");
const recommendation = document.querySelector("#recommendation");
const safeCount = document.querySelector("#safeCount");
const reviewCount = document.querySelector("#reviewCount");
const dangerousCount = document.querySelector("#dangerousCount");
const planRows = document.querySelector("#planRows");

const teamLabels = {
  maintainer: "solo maintainer",
  platform: "platform team",
  regulated: "regulated team",
  consultant: "consulting team",
};

const ciLabels = {
  github: "GitHub Actions",
  other: "non-GitHub CI",
  local: "local review",
};

const terraformLabels = {
  local: "terraform plan artifact",
  cloud: "Terraform Cloud / remote run",
  mixed: "mixed Terraform repositories",
};

const frameworkLabels = {
  none: "no compliance framework",
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  hipaa: "HIPAA",
};

const frameworkAdrs = {
  soc2: "ADR 0005",
  iso27001: "ADR 0006",
  hipaa: "ADR 0009",
};

const evidenceCliFlags = "--evidence evidence.json";

const teamProfiles = {
  maintainer: {
    status: "maintainer",
    recommendation:
      "Keep the first pass light: summarize plan risk in PRs, then only gate when the team trusts the signal.",
    rulesFile: "",
    agentId: "",
    cliFlags: "",
    row: {
      risk: "safe",
      resource: "aws_cloudwatch_log_group.app",
      explanation: "New stateless observability resource.",
    },
  },
  platform: {
    status: "platform",
    recommendation:
      "Standardize the rule file across repos so every team sees the same network, IAM, and data-store gates.",
    rulesFile: ".readtheplan/rules.yml",
    agentId: "platform-ci",
    cliFlags: "--rules-file .readtheplan/rules.yml",
    row: {
      risk: "review",
      resource: "aws_security_group_rule.platform_ingress",
      explanation: "Shared ingress changes should be reviewed before they fan out.",
    },
  },
  regulated: {
    status: "audit",
    recommendation:
      "Emit JSON output and an agent-read attestation so the review trail can be attached to release evidence.",
    rulesFile: ".readtheplan/regulated.yml",
    agentId: "release-review",
    cliFlags: "--format json --rules-file .readtheplan/regulated.yml",
    row: {
      risk: "dangerous",
      resource: "aws_kms_key.customer_data",
      explanation: "Key policy and deletion-window changes need auditable approval.",
    },
  },
  consultant: {
    status: "client",
    recommendation:
      "Start with a client-specific override file, then leave them with a repeatable CI gate instead of a one-off report.",
    rulesFile: ".readtheplan/client.yml",
    agentId: "client-review",
    cliFlags: "--rules-file .readtheplan/client.yml",
    row: {
      risk: "review",
      resource: "aws_organizations_account.client",
      explanation: "Account-level ownership and billing changes need client signoff.",
    },
  },
};

const riskRows = {
  rds: {
    risk: "dangerous",
    resource: "aws_db_instance.primary",
    explanation: "Replacement can change endpoints and recovery path.",
  },
  s3: {
    risk: "review",
    resource: "aws_s3_bucket_policy.assets",
    explanation: "Bucket policies can expose artifacts or state-adjacent data.",
  },
  iam: {
    risk: "review",
    resource: "aws_iam_role.deploy",
    explanation: "Trust policy changes can widen deploy access.",
  },
  kms: {
    risk: "dangerous",
    resource: "aws_kms_key.root",
    explanation: "Key policy or deletion changes can break recovery guarantees.",
  },
  dns: {
    risk: "dangerous",
    resource: "aws_route53_record.api",
    explanation: "DNS cutovers can move production traffic immediately.",
  },
  eks: {
    risk: "review",
    resource: "aws_eks_cluster.main",
    explanation: "Cluster endpoint and control-plane changes affect every workload.",
  },
};

function getFormState() {
  const data = new FormData(form);
  return {
    team: data.get("team"),
    ci: data.get("ci"),
    terraform: data.get("terraform"),
    policy: data.get("policy"),
    framework: data.get("framework"),
    signEvidence: data.get("signEvidence") === "on",
    risks: data.getAll("risk"),
  };
}

function policyLabel(policy) {
  if (policy === "any") {
    return "true";
  }
  return "false";
}

function buildRows(state) {
  const rows = [teamProfiles[state.team].row];
  for (const risk of state.risks) {
    rows.push(riskRows[risk]);
  }

  if (state.terraform === "cloud") {
    rows.push({
      risk: "review",
      resource: "tfe_workspace.production",
      explanation: "Remote runs need workspace and variable review before apply.",
    });
  } else if (state.terraform === "mixed") {
    rows.push({
      risk: "review",
      resource: "module.shared_network",
      explanation: "Mixed repos need consistent rule overrides across ownership boundaries.",
    });
  }

  const seen = new Set();
  return rows.filter((row) => {
    if (!row || seen.has(row.resource)) {
      return false;
    }
    seen.add(row.resource);
    return true;
  });
}

function renderRows(rows) {
  planRows.replaceChildren(
    ...rows.map((row) => {
      const resource = document.createElement("span");
      resource.textContent = row.resource;

      const explanation = document.createElement("span");
      explanation.textContent = row.explanation;

      const risk = document.createElement("span");
      risk.className = `risk-tag ${row.risk}`;
      risk.textContent = row.risk;

      const item = document.createElement("div");
      item.setAttribute("role", "row");
      item.replaceChildren(risk, resource, explanation);
      return item;
    }),
  );
}

function renderRiskCounts(rows) {
  const counts = rows.reduce(
    (acc, row) => {
      acc[row.risk] += 1;
      return acc;
    },
    { safe: 0, review: 0, dangerous: 0 },
  );
  safeCount.textContent = String(counts.safe);
  reviewCount.textContent = String(counts.review);
  dangerousCount.textContent = String(counts.dangerous);
}

function riskOverrideSnippet(state) {
  const profile = teamProfiles[state.team];
  if (!profile.rulesFile) {
    return [];
  }
  return [
    `          rules-file: ${profile.rulesFile}`,
    `          agent-id: ${profile.agentId}`,
  ];
}

function dangerousGateSnippet(state) {
  if (state.policy !== "dangerous") {
    return [];
  }
  return [
    "",
    "      - name: Gate dangerous plans",
    "        if: ${{ steps.readtheplan.outputs.risk-level == 'dangerous' || steps.readtheplan.outputs.risk-level == 'irreversible' }}",
    "        run: exit 1",
  ];
}

function analyzeArgs(state) {
  const profile = teamProfiles[state.team];
  const args = [];
  if (profile.cliFlags) {
    args.push(...profile.cliFlags.split(" "));
  } else if (state.team === "regulated") {
    args.push("--format", "json");
  }

  if (state.framework !== "none") {
    args.push("--framework", state.framework, ...evidenceCliFlags.split(" "));
    if (state.signEvidence) {
      args.push("--sign");
    }
  }

  return args;
}

function actionAnalyzeArgs(state) {
  const args = analyzeArgs(state);
  if (state.framework !== "none") {
    args.push(
      "--reviewer-id",
      "${{ github.actor }}",
      "--run-id",
      '"github-actions/${{ github.run_id }}"',
    );
  }
  return args;
}

function analyzeCommand(state, args = analyzeArgs(state)) {
  return ["readtheplan", "analyze", ...args, "plan.json"].join(" ");
}

function evidenceActionSnippet(state) {
  if (state.framework === "none") {
    return [];
  }

  return [
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
    "        run: " + analyzeCommand(state, actionAnalyzeArgs(state)),
    "",
    "      - name: Upload evidence envelope",
    "        uses: actions/upload-artifact@v4",
    "        with:",
    "          name: readtheplan-evidence",
    "          path: evidence.json",
    ...dangerousGateSnippet(state),
  ];
}

function generateAction(state) {
  if (state.ci !== "github") {
    return [
      "# Export a Terraform plan JSON artifact in your CI system.",
      "# Then run the CLI command shown in the next panel.",
      "",
      "python -m pip install readtheplan",
      analyzeCommand(state),
    ].join("\n");
  }

  if (state.framework !== "none") {
    return [
      "name: Terraform plan risk",
      "",
      "# Analyze an already-created plan JSON artifact.",
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
      ...(state.signEvidence ? ["  id-token: write"] : []),
      "",
      "jobs:",
      "  readtheplan:",
      "    if: ${{ github.event.workflow_run.conclusion == 'success' }}",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - name: Download plan JSON artifact",
      "        uses: actions/download-artifact@v4",
      "        with:",
      "          name: terraform-plan-json",
      "          run-id: ${{ github.event.workflow_run.id }}",
      "          github-token: ${{ secrets.GITHUB_TOKEN }}",
      "",
      ...evidenceActionSnippet(state),
    ].join("\n");
  }

  return [
    "name: Terraform plan risk",
    "",
    "# Analyze an already-created plan JSON artifact.",
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
    "",
    "jobs:",
    "  readtheplan:",
    "    if: ${{ github.event.workflow_run.conclusion == 'success' }}",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - name: Download plan JSON artifact",
    "        uses: actions/download-artifact@v4",
    "        with:",
    "          name: terraform-plan-json",
    "          run-id: ${{ github.event.workflow_run.id }}",
    "          github-token: ${{ secrets.GITHUB_TOKEN }}",
    "",
    "      - name: Analyze Terraform plan",
    "        id: readtheplan",
    "        uses: readtheplan/readtheplan@v1",
    "        with:",
    "          plan-file: plan.json",
    `          fail-on-changes: "${policyLabel(state.policy)}"`,
    ...riskOverrideSnippet(state),
    ...dangerousGateSnippet(state),
  ].join("\n");
}

function generateCli(state) {
  return [
    "python -m pip install readtheplan",
    "terraform plan -out=tfplan -input=false",
    "terraform show -json tfplan > plan.json",
    analyzeCommand(state),
    "",
    "# Compare deterministic rules with the action-only baseline:",
    "readtheplan analyze --no-rules --format json plan.json",
  ].join("\n");
}

function generateChecklist(state) {
  const riskText = state.risks.length
    ? `Prioritize ${state.risks.map((item) => item.toUpperCase()).join(", ")} rule review.`
    : "Start with the default AWS Tier A rule set.";
  const policyText =
    state.policy === "dangerous"
      ? "Gate releases on dangerous and irreversible findings."
      : state.policy === "any"
        ? "Treat any plan change as a release-manager checkpoint."
        : "Warn in CI and keep merge authority with the reviewer.";

  return [
    `Profile: ${teamLabels[state.team]} using ${ciLabels[state.ci]}.`,
    `Plan source: ${terraformLabels[state.terraform]}.`,
    riskText,
    policyText,
    ...(state.framework !== "none"
      ? [
          `Map changes to ${frameworkLabels[state.framework]} controls using ${frameworkAdrs[state.framework]}.`,
        ]
      : []),
    ...(state.signEvidence && state.framework !== "none"
      ? [
          "Signed evidence is identity-bound with no long-lived signing keys; verify with `readtheplan verify evidence.json`.",
        ]
      : []),
    "Keep raw plan files out of public artifacts and issue comments.",
  ];
}

function updatePilotLink(state) {
  const subject = encodeURIComponent("readtheplan pilot setup");
  const body = encodeURIComponent(
    [
      "Team profile:",
      `- ${teamLabels[state.team]}`,
      `- CI: ${ciLabels[state.ci]}`,
      `- Terraform flow: ${terraformLabels[state.terraform]}`,
      `- Compliance framework: ${frameworkLabels[state.framework]}`,
      `- Priority resources: ${state.risks.join(", ") || "default Tier A"}`,
      "",
      "No raw Terraform plan is attached.",
    ].join("\n"),
  );
  pilotLink.href = `mailto:rogma07k@gmail.com?subject=${subject}&body=${body}`;
}

function render() {
  const state = getFormState();
  const rows = buildRows(state);
  const profile = teamProfiles[state.team];
  statusPill.textContent = profile.status;
  recommendation.textContent = profile.recommendation;
  actionTitle.textContent =
    state.ci === "github" ? "GitHub Action" : state.ci === "local" ? "Local command" : "CI command";
  renderRiskCounts(rows);
  renderRows(rows);
  actionOutput.textContent = generateAction(state);
  cliOutput.textContent = generateCli(state);
  checklist.replaceChildren(
    ...generateChecklist(state).map((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      return li;
    }),
  );
  updatePilotLink(state);
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

form.addEventListener("change", render);
document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", () => {
    copyFrom(button.dataset.copy, button).catch(() => {
      button.textContent = "Select text";
    });
  });
});

render();
