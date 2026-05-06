const calculator = document.querySelector("#riskCalculator");
const scoreValue = document.querySelector("#riskScore");
const scoreLabel = document.querySelector("#riskLabel");
const scoreAdvice = document.querySelector("#riskAdvice");

const weights = {
  replacements: 12,
  deletes: 10,
  iam: 8,
  publicNetwork: 9,
  dataStores: 7,
  logging: 5,
  production: 10,
  regulated: 8,
};

function numberValue(data, name) {
  return Math.max(0, Number.parseInt(data.get(name) || "0", 10) || 0);
}

function contextValue(data, name) {
  return data.get(name) === "yes" ? 1 : 0;
}

function classify(score) {
  if (score >= 70) {
    return {
      label: "High review priority",
      advice:
        "Use a reviewer gate before apply. Focus first on replacements, delete actions, IAM changes, public ingress, and evidence for SOC 2 change management.",
    };
  }

  if (score >= 35) {
    return {
      label: "Review before apply",
      advice:
        "Walk the changed resources with the service owner, confirm rollback and evidence needs, then run readtheplan locally or in CI on the real Terraform JSON plan.",
    };
  }

  return {
    label: "Lower apparent risk",
    advice:
      "The manual estimate is low. Still check the real Terraform JSON plan locally because attribute-level changes can carry risk that counts miss.",
  };
}

function renderCalculator() {
  if (!calculator) {
    return;
  }

  const data = new FormData(calculator);
  const rawScore =
    numberValue(data, "replacements") * weights.replacements +
    numberValue(data, "deletes") * weights.deletes +
    numberValue(data, "iam") * weights.iam +
    numberValue(data, "publicNetwork") * weights.publicNetwork +
    numberValue(data, "dataStores") * weights.dataStores +
    numberValue(data, "logging") * weights.logging +
    contextValue(data, "production") * weights.production +
    contextValue(data, "regulated") * weights.regulated;
  const score = Math.min(100, rawScore);
  const result = classify(score);

  scoreValue.textContent = String(score);
  scoreLabel.textContent = result.label;
  scoreAdvice.textContent = result.advice;
}

if (calculator) {
  calculator.addEventListener("input", renderCalculator);
  calculator.addEventListener("change", renderCalculator);
  calculator.addEventListener("submit", (event) => {
    event.preventDefault();
    renderCalculator();
  });
  renderCalculator();
}
