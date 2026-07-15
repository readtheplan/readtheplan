/* Demo route behavior: replay terminal animation + render the bundled
   evidence fixture. CSP-safe external module (extracted from app.js). */
(function () {
  "use strict";

  const demoSafeCount = document.querySelector("#demoSafeCount");
  const demoReviewCount = document.querySelector("#demoReviewCount");
  const demoDangerousCount = document.querySelector("#demoDangerousCount");
  const demoRows = document.querySelector("#demoRows");
  const demoEvidenceNote = document.querySelector("#demoEvidenceNote");

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
    const risks = (summary && summary.risks) || {};
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
        "Demo evidence could not be loaded. You can still run the sample locally.";
    }
  }

  /* ── Replayed terminal session ─────────────────────────────── */
  function initTerminal() {
    const body = document.getElementById("terminalBody");
    const typingLine = document.getElementById("typingLine");
    const typingCmd = document.getElementById("typingCmd");
    const cursor = document.getElementById("cursor");
    if (!body || !typingLine || !typingCmd || !cursor) return;

    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      typingCmd.textContent = "readtheplan analyze examples/02-dangerous-replacement/plan.json --framework soc2";
      cursor.style.display = "none";
      return;
    }

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
    let phase = "typing";

    function tick() {
      if (cmdIdx >= commands.length) {
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
        const cmdLine = document.createElement("div");
        cmdLine.className = "terminal-line";
        const prompt = document.createElement("span");
        prompt.className = "t-prompt";
        prompt.textContent = "λ";
        const cmdText = document.createElement("span");
        cmdText.className = "t-cmd";
        cmdText.textContent = " " + cmd.cmd;
        cmdLine.append(prompt, cmdText);
        body.insertBefore(cmdLine, typingLine);

        const outLine = document.createElement("div");
        outLine.className = "terminal-line t-dim";
        outLine.style.paddingLeft = "1.2em";
        outLine.textContent = cmd.output;
        body.insertBefore(outLine, typingLine);

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

    setTimeout(tick, 600);
  }

  if (demoRows) loadDemoData();
  initTerminal();
})();
