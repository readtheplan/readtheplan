const form = document.querySelector("#onboardingForm");
const actionOutput = document.querySelector("#actionOutput");
const cliOutput = document.querySelector("#cliOutput");
const checklist = document.querySelector("#checklist");
const pilotLink = document.querySelector("#pilotLink");

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

function getFormState() {
  const data = new FormData(form);
  return {
    team: data.get("team"),
    ci: data.get("ci"),
    terraform: data.get("terraform"),
    policy: data.get("policy"),
    risks: data.getAll("risk"),
  };
}

function policyLabel(policy) {
  if (policy === "any") {
    return "true";
  }
  return "false";
}

function generateAction(state) {
  if (state.ci !== "github") {
    return [
      "# Export a Terraform plan JSON artifact in your CI system.",
      "# Then run the CLI command shown in the next panel.",
      "",
      "python -m pip install readtheplan",
      "readtheplan analyze --format json plan.json",
    ].join("\n");
  }

  return [
    "name: Terraform plan risk",
    "",
    "on:",
    "  pull_request:",
    "    paths:",
    "      - '**/*.tf'",
    "      - '**/*.tfvars'",
    "",
    "jobs:",
    "  readtheplan:",
    "    runs-on: ubuntu-latest",
    "    steps:",
    "      - uses: actions/checkout@v4",
    "",
    "      - name: Create Terraform plan JSON",
    "        run: |",
    "          terraform init -input=false",
    "          terraform plan -out=tfplan -input=false",
    "          terraform show -json tfplan > plan.json",
    "",
    "      - name: Analyze Terraform plan",
    "        uses: readtheplan/readtheplan@v1",
    "        with:",
    "          plan-file: plan.json",
    `          fail-on-changes: "${policyLabel(state.policy)}"`,
  ].join("\n");
}

function generateCli(state) {
  const format = state.team === "regulated" ? "--format json" : "";
  return [
    "python -m pip install readtheplan",
    "terraform plan -out=tfplan -input=false",
    "terraform show -json tfplan > plan.json",
    `readtheplan analyze ${format} plan.json`.replace("  ", " "),
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
      `- Priority resources: ${state.risks.join(", ") || "default Tier A"}`,
      "",
      "No raw Terraform plan is attached.",
    ].join("\n"),
  );
  pilotLink.href = `mailto:rogma07k@gmail.com?subject=${subject}&body=${body}`;
}

function render() {
  const state = getFormState();
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
