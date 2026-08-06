/* In-browser playground: drag/drop plan analysis. CSP-safe external module.
   Depends on risk-floors.js + classifier.js (loaded first). Plans never
   leave the browser — analysis is fully client-side. */
(function () {
  "use strict";

  // ── State ──
  let planData = null;
  let complianceData = null;
  let currentChanges = null;
  let hasTrackedRun = false;

  // ── DOM refs ──
  const dropZone = document.getElementById("dropZone");
  const fileInput = document.getElementById("fileInput");
  const resultsSection = document.getElementById("resultsSection");
  const errorSection = document.getElementById("errorSection");
  const errorMsg = document.getElementById("errorMsg");
  const riskMeter = document.getElementById("riskMeter");
  const tableContainer = document.getElementById("tableContainer");
  const frameworkSelect = document.getElementById("framework");
  const reanalyzeBtn = document.getElementById("reanalyze");

  // ── Load compliance data ──
  async function loadCompliance() {
    try {
      const resp = await fetch("/playground/compliance.json");
      if (resp.ok) complianceData = await resp.json();
    } catch (e) {
      console.log("Compliance data not available (offline or build step skipped)");
    }
  }
  loadCompliance();

  // ── Drag and drop ──
  dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("dragover"); });
  dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
  dropZone.addEventListener("drop", e => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  });
  dropZone.addEventListener("click", () => fileInput.click());
  dropZone.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") { fileInput.click(); e.preventDefault(); } });
  fileInput.addEventListener("change", e => {
    const file = e.target.files[0];
    if (file) handleFile(file);
  });

  // ── Framework change ──
  frameworkSelect.addEventListener("change", () => analyze());
  reanalyzeBtn.addEventListener("click", () => analyze());

  // ── File handling ──
  function handleFile(file) {
    if (!file.name.toLowerCase().endsWith(".json")) {
      showError("Please drop a .json file (Terraform plan JSON).");
      return;
    }
    const reader = new FileReader();
    reader.onload = e => {
      try {
        planData = JSON.parse(e.target.result);
        if (!planData.resource_changes && !planData.planned_values) {
          showError("This doesn't look like a Terraform plan JSON. Expected 'resource_changes' or 'planned_values'.");
          return;
        }
        clearError();
        dropZone.classList.add("has-file");
        dropZone.querySelector(".drop-text").innerHTML = `<strong>${esc(file.name)}</strong> (${(file.size / 1024).toFixed(1)} KB)`;
        analyze();
      } catch (err) {
        showError("Invalid JSON: " + err.message);
      }
    };
    reader.readAsText(file);
  }

  // ── Analysis ──
  function analyze() {
    if (!planData) return;
    try {
      const framework = frameworkSelect.value || null;
      let changes = parsePlan(planData);
      if (framework && complianceData) {
        changes = matchCompliance(changes, framework, complianceData);
      }
      currentChanges = changes;
      render(changes);
      if (!hasTrackedRun) {
        hasTrackedRun = true;
        if (typeof window.readtheplanTrack === "function") {
          window.readtheplanTrack("playground_run");
        }
      }
    } catch (err) {
      showError("Analysis error: " + err.message);
    }
  }

  // ── Render ──
  function render(changes) {
    clearError();
    resultsSection.style.display = "block";

    // Risk meter
    const summary = summarize(changes);
    riskMeter.innerHTML = `
      <div class="risk-badge safe"><span class="count">${summary.counts.safe}</span><span class="label">Safe</span></div>
      <div class="risk-badge review"><span class="count">${summary.counts.review}</span><span class="label">Review</span></div>
      <div class="risk-badge dangerous"><span class="count">${summary.counts.dangerous}</span><span class="label">Dangerous</span></div>
      <div class="risk-badge irreversible"><span class="count">${summary.counts.irreversible}</span><span class="label">Irreversible</span></div>
    `;

    // Table
    if (changes.length === 0) {
      tableContainer.innerHTML = '<div class="empty-state"><h3>No resource changes found</h3><p>This plan doesn\'t contain any resource changes to analyze.</p></div>';
      return;
    }

    const hasControls = changes.some(change => (change.controls || []).length > 0);
    let html = `<table class="plan-table"><thead><tr>
      <th>Resource</th><th>Type</th><th>Actions</th><th>Risk</th><th>Explanation</th>
      ${hasControls ? '<th>Controls</th>' : ''}
    </tr></thead><tbody>`;

    for (const c of changes) {
      const actions = c.actions.map(a => `<span class="action-tag">${esc(a)}</span>`).join(" ");
      const controlBadges = (c.controls || []).map(ctrl => `<span title="${esc(ctrl.title)}">${esc(ctrl.id)}</span>`).join(" ");
      const controls = hasControls
        ? `<td><div class="controls-list">${controlBadges || '<span>—</span>'}</div></td>`
        : "";
      html += `<tr>
        <td><code>${esc(c.address)}</code></td>
        <td>${esc(c.type)}</td>
        <td>${actions}</td>
        <td><span class="risk-pill ${c.risk}">${c.risk}</span></td>
        <td class="plan-explanation">${esc(c.explanation)}</td>
        ${controls}
      </tr>`;
    }
    html += "</tbody></table>";
    tableContainer.innerHTML = html;
  }

  function showError(msg) {
    errorMsg.textContent = msg;
    errorSection.style.display = "block";
    resultsSection.style.display = "none";
  }

  function clearError() {
    errorSection.style.display = "none";
  }

  function esc(s) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }

  // ── Sample plan loading (Floci-generated) ──
  async function loadSamplePlan(url, label) {
    try {
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      planData = await resp.json();
      if (!planData.resource_changes && !planData.planned_values) {
        showError("This doesn't look like a Terraform plan JSON. Expected 'resource_changes' or 'planned_values'.");
        return;
      }
      clearError();
      dropZone.classList.add("has-file");
      dropZone.querySelector(".drop-text").innerHTML = `<strong>${esc(label)}</strong> (Floci emulated AWS)`;
      analyze();
    } catch (err) {
      showError("Failed to load sample plan: " + err.message);
    }
  }
  document.getElementById("loadCreate").addEventListener("click", () =>
    loadSamplePlan("floci-spike-create-plan.json", "Create plan - 7 resources (Floci)")
  );
  document.getElementById("loadDestroy").addEventListener("click", () =>
    loadSamplePlan("floci-spike-destroy-plan.json", "Destroy plan - 7 resources (Floci)")
  );

  // Surface sample freshness metadata when available.
  (async function renderSampleMeta() {
    const el = document.getElementById("sampleMeta");
    if (!el) return;
    try {
      const resp = await fetch("floci-samples.meta.json");
      if (!resp.ok) return;
      const meta = await resp.json();
      const stamp = meta.generated_at_utc ? new Date(meta.generated_at_utc).toLocaleString() : "unknown";
      el.textContent = `Sample source: Floci emulated AWS · generated: ${stamp} UTC`;
    } catch (_) {
      // keep default text
    }
  })();
})();
