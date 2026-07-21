/**
 * AegisLab - renderer.js
 * ========================
 * Drives the dashboard: backend communication, OpenAPI import, real-time
 * scan progress via WebSocket, and rendering the gauge / findings list.
 */

const MODULES = [
  { id: "auth_tests", label: "auth_tests" },
  { id: "authorization_tests", label: "authorization_tests" },
  { id: "injection_tests", label: "injection_tests" },
  { id: "rate_limit_tests", label: "rate_limit_tests" },
  { id: "data_exposure_tests", label: "data_exposure_tests" },
  { id: "transport_security_tests", label: "transport_security_tests" },
  { id: "mass_assignment_tests", label: "mass_assignment_tests" },
  { id: "ssrf_tests", label: "ssrf_tests" },
];

const SEV_COLOR = {
  CRITICAL: "var(--c-critical)",
  HIGH: "var(--c-high)",
  MEDIUM: "var(--c-medium)",
  LOW: "var(--c-low)",
  INFO: "var(--c-info)",
};
const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

let BACKEND_URL = "http://127.0.0.1:8765";
let state = {
  endpoints: [],
  currentScanId: null,
  currentResult: null,
  activeFilter: "ALL",
  scanType: "dynamic", // "dynamic" | "static" — determines which report endpoint export hits
};

// ---------- crash / error logging (Sprint 5 Day 7) ----------
// Catches JS errors that would otherwise just vanish into the DevTools
// console (which nobody's watching once this is a packaged app), logs them
// via the main process, and surfaces something visible instead of a dead,
// silently-broken UI.
window.addEventListener("error", (event) => {
  const message = event.error ? event.error.message : event.message;
  const stack = event.error ? event.error.stack : "";
  if (window.aegis && window.aegis.logError) window.aegis.logError(message, stack);
  setStatus(`Something went wrong in the UI: ${message}. Check the app's log file for details.`);
});
window.addEventListener("unhandledrejection", (event) => {
  const message = event.reason && event.reason.message ? event.reason.message : String(event.reason);
  const stack = event.reason && event.reason.stack ? event.reason.stack : "";
  if (window.aegis && window.aegis.logError) window.aegis.logError(message, stack);
  setStatus(`Something went wrong: ${message}. Check the app's log file for details.`);
});

// ---------- bootstrap ----------
window.addEventListener("DOMContentLoaded", async () => {
  if (window.aegis && window.aegis.getBackendUrl) {
    BACKEND_URL = await window.aegis.getBackendUrl();
  }
  if (window.aegisAuth) await window.aegisAuth.init(BACKEND_URL);
  renderModuleList();
  wireUpEvents();
  waitForBackend();
  initOnboarding();
});

async function waitForBackend(retries = 20) {
  for (let i = 0; i < retries; i++) {
    try {
      const r = await fetch(`${BACKEND_URL}/api/health`);
      if (r.ok) {
        setStatus("Security engine online. Configure a target to begin.");
        return;
      }
    } catch (e) { /* retry */ }
    await new Promise((res) => setTimeout(res, 500));
  }
  setStatus("Could not reach the security engine — try running scripts/start_app.sh (or .bat) from a terminal to see the exact error.");
}

function setStatus(msg) {
  document.getElementById("statusLine").textContent = msg;
}

// ---------- module toggle list ----------
function renderModuleList() {
  const container = document.getElementById("moduleList");
  container.innerHTML = "";
  MODULES.forEach((m) => {
    const row = document.createElement("div");
    row.className = "dial-row checked";
    row.innerHTML = `
      <span class="dial-name">${m.label}</span>
      <label class="switch">
        <input type="checkbox" data-module="${m.id}" checked />
        <span class="switch-track"></span>
      </label>`;
    container.appendChild(row);
  });
  container.querySelectorAll("input[type=checkbox]").forEach((cb) => {
    cb.addEventListener("change", () => {
      cb.closest(".dial-row").classList.toggle("checked", cb.checked);
    });
  });

  // mirror into the checklist on the right (scan progress)
  const checklist = document.getElementById("moduleChecklist");
  checklist.innerHTML = MODULES.map((m) => `
    <div class="checklist-row" data-checklist="${m.id}">
      <span class="checklist-icon">○</span><span>${m.label}</span>
    </div>`).join("");
}

function getEnabledModules() {
  return Array.from(document.querySelectorAll("#moduleList input[type=checkbox]"))
    .filter((cb) => cb.checked)
    .map((cb) => cb.dataset.module);
}

// ---------- wiring ----------
function wireUpEvents() {
  document.getElementById("dropzone").addEventListener("click", () => {
    document.getElementById("specFile").click();
  });
  document.getElementById("specFile").addEventListener("change", handleSpecFile);

  document.getElementById("staticDropzone").addEventListener("click", () => {
    document.getElementById("staticZipFile").click();
  });
  document.getElementById("staticZipFile").addEventListener("change", handleStaticZipUpload);

  document.getElementById("addManualEndpoint").addEventListener("click", () => {
    document.getElementById("modalBackdrop").classList.add("open");
    _updateManualBodyVisibility();
  });
  document.getElementById("manualCancel").addEventListener("click", () => {
    document.getElementById("modalBackdrop").classList.remove("open");
  });
  document.getElementById("manualAdd").addEventListener("click", addManualEndpoint);
  document.getElementById("manualMethod").addEventListener("change", _updateManualBodyVisibility);

  document.getElementById("feedbackLink").addEventListener("click", async (e) => {
    e.preventDefault();
    // REPLACE_WITH_YOUR_REPO once the repo is actually published — see docs/legal and README for the same placeholder pattern.
    const issueUrl = "https://github.com/REPLACE_WITH_YOUR_REPO/issues/new";
    if (window.aegis && window.aegis.openExternal) await window.aegis.openExternal(issueUrl);
  });

  document.getElementById("startScanBtn").addEventListener("click", startScan);

  document.getElementById("exportJsonBtn").addEventListener("click", () => exportReport("json"));
  document.getElementById("exportPdfBtn").addEventListener("click", () => exportReport("pdf"));

  document.getElementById("filterRow").addEventListener("click", (e) => {
    const chip = e.target.closest(".filter-chip");
    if (!chip) return;
    document.querySelectorAll(".filter-chip").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
    state.activeFilter = chip.dataset.filter;
    renderFindings();
  });

  document.getElementById("baseUrl").addEventListener("input", (e) => {
    document.getElementById("targetLabel").textContent = e.target.value || "No target configured";
  });
}

async function handleSpecFile(e) {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  try {
    const resp = await fetch(`${BACKEND_URL}/api/openapi/parse`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_text: text }),
    });
    if (!resp.ok) throw new Error((await resp.json()).detail || "Parse failed");
    const data = await resp.json();
    state.endpoints = state.endpoints.concat(data.endpoints);
    document.getElementById("dropzoneText").textContent = file.name;
    document.getElementById("endpointCount").textContent =
      `${state.endpoints.length} endpoint(s) loaded.`;
    setStatus(`Imported ${data.endpoint_count} endpoints from ${file.name}.`);
  } catch (err) {
    setStatus(`Spec import failed: ${err.message}`);
  }
}

async function handleStaticZipUpload(e) {
  const file = e.target.files[0];
  if (!file) return;

  document.getElementById("staticDropzoneText").textContent = file.name;
  document.getElementById("staticScanStatus").textContent = "Scanning source code…";
  setStatus(`Running static scan on ${file.name}...`);

  const formData = new FormData();
  formData.append("file", file);

  try {
    const resp = await fetch(`${BACKEND_URL}/api/static-scan/upload`, { method: "POST", body: formData });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.detail || "Static scan failed");
    }
    const data = await resp.json();
    onStaticScanFinished(data);
  } catch (err) {
    document.getElementById("staticScanStatus").textContent = `Failed: ${err.message}`;
    setStatus(`Static scan failed: ${err.message}`);
  }
}

function onStaticScanFinished(data) {
  const result = data.result;
  state.currentResult = result;
  state.currentScanId = data.scan_id;
  state.scanType = "static";

  document.getElementById("staticScanStatus").textContent =
    `Scanned ${data.files_scanned} file(s) — detected: ${data.frameworks_detected.join(", ")}.`;
  setStatus(`Static scan complete — score ${result.security_score}/100, ${result.vulnerabilities.length} finding(s).`);

  document.getElementById("targetLabel").textContent = `Static scan: ${result.base_url.replace("(static scan: ", "").replace(")", "")}`;
  document.getElementById("scanMeta").textContent =
    `${data.files_scanned} file(s) scanned · frameworks: ${data.frameworks_detected.join(", ")}`;

  // Repurpose the "Inspection Sweep" card to show what the static scanner found,
  // since there's no live module-by-module sweep for a one-shot static scan.
  document.getElementById("moduleChecklist").innerHTML = result.modules_run.map((m) => `
    <div class="checklist-row done"><span class="checklist-icon">●</span><span>${m}</span></div>`).join("");
  document.getElementById("progressFill").style.width = "100%";
  document.getElementById("progressMessage").textContent = "Static analysis complete.";

  document.getElementById("exportJsonBtn").disabled = false;
  document.getElementById("exportPdfBtn").disabled = false;

  renderGauge(result.security_score);
  renderSeverityBars(result.score_breakdown);
  renderFindings();
  renderPriorityFixes(result.vulnerabilities);
}

function addManualEndpoint() {
  const path = document.getElementById("manualPath").value.trim();
  const method = document.getElementById("manualMethod").value;
  const requiresAuth = document.getElementById("manualRequiresAuth").checked;
  const paramsRaw = document.getElementById("manualParams").value.trim();
  const bodyRaw = document.getElementById("manualBody").value.trim();
  if (!path) return;

  const params = paramsRaw ? paramsRaw.split(",").map((p) => p.trim()).filter(Boolean) : [];

  let requestBodySample = null;
  if (["POST", "PUT", "PATCH"].includes(method) && bodyRaw) {
    try {
      requestBodySample = JSON.parse(bodyRaw);
    } catch (e) {
      setStatus(`Request body isn't valid JSON: ${e.message}`);
      return; // don't silently drop it — the user asked for it to be tested
    }
  }

  state.endpoints.push({
    path, method, requires_auth: requiresAuth, params, tags: [], description: "",
    request_body_sample: requestBodySample,
  });
  document.getElementById("endpointCount").textContent = `${state.endpoints.length} endpoint(s) loaded.`;
  document.getElementById("manualPath").value = "";
  document.getElementById("manualParams").value = "";
  document.getElementById("manualBody").value = "";
  document.getElementById("modalBackdrop").classList.remove("open");
}

function _updateManualBodyVisibility() {
  const method = document.getElementById("manualMethod").value;
  const showBody = ["POST", "PUT", "PATCH"].includes(method);
  document.getElementById("manualBodyLabel").style.display = showBody ? "block" : "none";
  document.getElementById("manualBody").style.display = showBody ? "block" : "none";
  document.getElementById("manualBodyHint").style.display = showBody ? "block" : "none";
}

// ---------- scan lifecycle ----------
async function startScan() {
  const baseUrl = document.getElementById("baseUrl").value.trim();
  const bearerToken = document.getElementById("bearerToken").value.trim();
  const secondaryToken = document.getElementById("secondaryToken").value.trim();
  const confirmAuthorized = document.getElementById("consentCheck").checked;

  if (!baseUrl) { setStatus("Enter a target base URL first."); return; }
  if (!state.endpoints.length) { setStatus("Import an OpenAPI spec or add at least one endpoint."); return; }
  if (!confirmAuthorized) { setStatus("You must confirm you're authorized to test this target."); return; }

  const config = {
    base_url: baseUrl,
    bearer_token: bearerToken || null,
    secondary_bearer_token: secondaryToken || null,
    endpoints: state.endpoints,
    modules_enabled: getEnabledModules(),
    requests_per_second: 5,
    confirm_authorized: true,
  };

  resetDashboard();
  state.scanType = "dynamic";
  document.getElementById("startScanBtn").disabled = true;
  document.getElementById("sweepBeam").classList.add("active");
  setStatus("Starting scan...");

  try {
    const resp = await fetch(`${BACKEND_URL}/api/scan/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ config }),
    });
    if (!resp.ok) {
      const err = await resp.json();
      throw new Error(err.detail || "Could not start scan");
    }
    const { scan_id } = await resp.json();
    state.currentScanId = scan_id;
    document.getElementById("scanMeta").textContent = `Scan ${scan_id.slice(0, 8)} running against ${baseUrl}`;
    openProgressSocket(scan_id);
  } catch (err) {
    setStatus(`Failed to start scan: ${err.message}`);
    document.getElementById("startScanBtn").disabled = false;
    document.getElementById("sweepBeam").classList.remove("active");
  }
}

function openProgressSocket(scanId) {
  const wsUrl = BACKEND_URL.replace("http", "ws") + `/ws/scan/${scanId}`;
  const ws = new WebSocket(wsUrl);

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.status === "finished") {
      onScanFinished(msg.result);
      ws.close();
      return;
    }
    onProgressEvent(msg);
  };

  ws.onerror = () => setStatus("Lost connection to the security engine.");
}

function onProgressEvent(evt) {
  setStatus(evt.message || `${evt.module}: ${evt.status}`);
  document.getElementById("progressMessage").textContent = evt.message || "";
  document.getElementById("progressFill").style.width = `${evt.percent || 0}%`;

  const row = document.querySelector(`[data-checklist="${evt.module}"]`);
  if (row) {
    row.classList.remove("running", "done", "error");
    const icon = row.querySelector(".checklist-icon");
    if (evt.status === "started") { row.classList.add("running"); icon.textContent = "◐"; }
    else if (evt.status === "completed") { row.classList.add("done"); icon.textContent = "●"; }
    else if (evt.status === "error") { row.classList.add("error"); icon.textContent = "✕"; }
  }
}

function onScanFinished(result) {
  state.currentResult = result;
  document.getElementById("startScanBtn").disabled = false;
  document.getElementById("sweepBeam").classList.remove("active");
  document.getElementById("progressFill").style.width = "100%";
  document.getElementById("progressMessage").textContent = "Inspection complete.";
  setStatus(`Scan complete — score ${result.security_score}/100, ${result.vulnerabilities.length} finding(s).`);
  document.getElementById("scanMeta").textContent =
    `${result.endpoints_tested} endpoint(s) tested · ${result.modules_run.length} module(s) run`;

  document.getElementById("exportJsonBtn").disabled = false;
  document.getElementById("exportPdfBtn").disabled = false;

  renderGauge(result.security_score);
  renderSeverityBars(result.score_breakdown);
  renderFindings();
  renderPriorityFixes(result.vulnerabilities);
}

function resetDashboard() {
  state.currentResult = null;
  document.getElementById("exportJsonBtn").disabled = true;
  document.getElementById("exportPdfBtn").disabled = true;
  document.getElementById("findingsList").innerHTML = `<div class="empty-state"><p>Scanning…</p><p class="subtle">Findings will appear here as each module completes.</p></div>`;
  document.getElementById("severityBars").innerHTML = "";
  document.getElementById("prioritySection").style.display = "none";
  renderGauge(null);
  renderModuleList();
}

// ---------- rendering ----------
function renderGauge(score) {
  const fill = document.getElementById("gaugeFill");
  const needle = document.getElementById("gaugeNeedle");
  const scoreEl = document.getElementById("gaugeScore");
  const gradeEl = document.getElementById("gaugeGrade");

  if (score === null || score === undefined) {
    fill.style.strokeDashoffset = 251.2;
    needle.style.transform = "rotate(-90deg)";
    scoreEl.textContent = "--";
    gradeEl.textContent = "—";
    fill.style.stroke = "var(--c-medium)";
    needle.style.stroke = "var(--c-brass-bright)";
    scoreEl.style.color = "var(--c-text)";
    return;
  }

  const pct = Math.max(0, Math.min(100, score)) / 100;
  fill.style.strokeDashoffset = String(251.2 * (1 - pct));
  const angle = -90 + pct * 180;
  needle.style.transform = `rotate(${angle}deg)`;

  // Stoplight scaling: red below 50, orange 50–79, green 80+.
  let color = "var(--c-critical)"; // red
  if (score >= 80) color = "var(--c-low)";        // green
  else if (score >= 50) color = "var(--c-high)";  // orange
  fill.style.stroke = color;
  needle.style.stroke = color;
  scoreEl.style.color = color;

  scoreEl.textContent = score;
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  gradeEl.textContent = `Grade ${grade}`;
}

function renderSeverityBars(breakdown) {
  const totals = (breakdown && breakdown._summary && breakdown._summary.severity_totals) || {};
  const max = Math.max(1, ...Object.values(totals));
  const container = document.getElementById("severityBars");
  container.innerHTML = SEV_ORDER.filter((s) => s !== "INFO" || totals.INFO).map((sev) => {
    const count = totals[sev] || 0;
    const width = count ? Math.max(6, (count / max) * 100) : 0;
    return `
      <div class="severity-bar-row">
        <span class="severity-bar-label" style="color:${SEV_COLOR[sev]}">${sev}</span>
        <div class="severity-bar-track"><div class="severity-bar-fill" style="width:${width}%; background:${SEV_COLOR[sev]}"></div></div>
        <span class="severity-bar-count">${count}</span>
      </div>`;
  }).join("") || `<p class="subtle">No findings recorded.</p>`;
}

function renderFindings() {
  const result = state.currentResult;
  const list = document.getElementById("findingsList");
  if (!result || !result.vulnerabilities.length) {
    list.innerHTML = `<div class="empty-state"><p>No findings.</p><p class="subtle">This target passed every enabled check — or no checks have been run yet.</p></div>`;
    return;
  }

  const filtered = state.activeFilter === "ALL"
    ? result.vulnerabilities
    : result.vulnerabilities.filter((v) => v.severity === state.activeFilter);

  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const sorted = [...filtered].sort((a, b) => order[a.severity] - order[b.severity]);

  if (!sorted.length) {
    list.innerHTML = `<div class="empty-state"><p>No findings match this filter.</p></div>`;
    return;
  }

  list.innerHTML = sorted.map((v, i) => `
    <div class="finding-card" style="--sev-color:${SEV_COLOR[v.severity]}">
      <div class="finding-top">
        <div>
          <p class="finding-issue">${escapeHtml(v.issue)}</p>
          <p class="finding-meta"><b>${v.method}</b> ${escapeHtml(v.endpoint)} &nbsp;·&nbsp; ${escapeHtml(v.owasp_category)}</p>
        </div>
        <span class="sev-stamp">${v.severity}</span>
      </div>
      <div class="finding-body" id="finding-body-${i}">
        <p><b>Description:</b> ${escapeHtml(v.description)}</p>
        <p><b>Impact:</b> ${escapeHtml(v.impact)}</p>
        <p><b>Recommendation:</b> ${escapeHtml(v.recommendation)}</p>
      </div>
      <button class="finding-toggle" data-toggle="finding-body-${i}">Show details</button>
    </div>`).join("");

  list.querySelectorAll(".finding-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const body = document.getElementById(btn.dataset.toggle);
      const open = body.classList.toggle("open");
      btn.textContent = open ? "Hide details" : "Show details";
    });
  });
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function renderPriorityFixes(vulnerabilities) {
  const section = document.getElementById("prioritySection");
  const list = document.getElementById("priorityList");
  const countEl = document.getElementById("priorityCount");

  if (!vulnerabilities || !vulnerabilities.length) {
    section.style.display = "none";
    return;
  }

  const fixes = buildPriorityFixes(vulnerabilities, 5);
  section.style.display = "block";
  countEl.textContent = `Ranked by severity — fix these first`;

  list.innerHTML = fixes.map((f, i) => `
    <div class="priority-card" style="--sev-color:${SEV_COLOR[f.severity]}">
      <div class="priority-rank">${i + 1}</div>
      <div class="priority-body">
        <div class="priority-top">
          <p class="priority-issue">${escapeHtml(f.issue)}</p>
          <span class="sev-stamp">${f.severity}</span>
        </div>
        <p class="finding-meta"><b>${f.method}</b> ${escapeHtml(f.endpoint)}</p>
        ${f.snippet ? `
          <div class="snippet-block">
            <p class="snippet-title">${escapeHtml(f.snippet.title)}</p>
            <pre class="snippet-code"><code>${escapeHtml(f.snippet.code)}</code></pre>
            <button class="btn-ghost copy-btn" data-snippet-index="${i}">Copy code</button>
          </div>
        ` : `<p class="finding-meta" style="margin-top:8px;">${escapeHtml(f.recommendation)}</p>`}
        <div class="ai-fix-block" id="aiFixBlock-${i}">
          ${renderAiFixButton(i)}
        </div>
      </div>
    </div>`).join("");

  list.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.snippetIndex);
      navigator.clipboard.writeText(fixes[idx].snippet.code).then(() => {
        const original = btn.textContent;
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = original; }, 1500);
      });
    });
  });

  list.querySelectorAll(".ai-fix-btn").forEach((btn) => {
    btn.addEventListener("click", () => handleAiFixClick(Number(btn.dataset.fixIndex), fixes));
  });
}

function renderAiFixButton(i) {
  if (!window.aegisAuth || !window.aegisAuth.isSignedIn()) {
    return `<button class="btn-ghost ai-fix-btn" data-fix-index="${i}">✦ Get AI fix (sign in required)</button>`;
  }
  if (window.aegisAuth.isPremium() && state.scanType === "static") {
    return `<button class="btn-ghost ai-fix-btn" data-fix-index="${i}">✦ Auto-apply AI fix (Premium)</button>`;
  }
  return `<button class="btn-ghost ai-fix-btn" data-fix-index="${i}">✦ Get AI fix suggestion</button>`;
}

async function handleAiFixClick(i, fixes) {
  const block = document.getElementById(`aiFixBlock-${i}`);
  const finding = fixes[i];

  if (!window.aegisAuth || !window.aegisAuth.isSignedIn()) {
    block.innerHTML = `<p class="finding-meta">Sign in from the sidebar to get an AI-generated fix for this finding.</p>`;
    return;
  }

  const useAutoFix = window.aegisAuth.isPremium() && state.scanType === "static";
  block.innerHTML = `<p class="finding-meta">Asking AI for a fix…</p>`;

  try {
    const token = window.aegisAuth.getAccessToken();
    const payload = {
      issue: finding.issue, severity: finding.severity,
      endpoint: finding.endpoint, method: finding.method,
      recommendation: finding.recommendation,
    };

    if (useAutoFix) {
      const resp = await fetch(`${BACKEND_URL}/api/ai/auto-fix`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ scan_id: state.currentScanId, finding: payload }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "Auto-fix failed");

      block.innerHTML = `
        <p class="finding-meta">✓ Patched <b>${escapeHtml(data.patched_file)}</b> — download the fixed source below.</p>
        <button class="btn-ghost ai-fix-btn" id="aiDownload-${i}">Download patched .zip</button>`;
      document.getElementById(`aiDownload-${i}`).addEventListener("click", async () => {
        if (window.aegis && window.aegis.saveReport) {
          const result = await window.aegis.saveReport(data.filename, data.path);
          setStatus(result.saved ? `Saved patched source to ${result.path}` : "Download cancelled.");
        }
      });
    } else {
      const resp = await fetch(`${BACKEND_URL}/api/ai/suggest`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.detail || "AI suggestion failed");

      const upgradeHint = !window.aegisAuth.isPremium()
        ? `<p class="field-hint">Upgrade to Premium to auto-apply fixes directly to uploaded source instead of copying manually.</p>`
        : "";
      block.innerHTML = `
        <div class="snippet-block">
          <p class="snippet-title">AI suggestion</p>
          <pre class="snippet-code"><code>${escapeHtml(data.ai_suggestion)}</code></pre>
        </div>
        ${upgradeHint}`;
    }
  } catch (err) {
    block.innerHTML = `<p class="finding-meta">AI fix failed: ${escapeHtml(err.message)}</p>`;
  }
}

// ---------- export ----------
async function exportReport(format) {
  if (!state.currentScanId) return;
  try {
    const base = state.scanType === "static"
      ? `${BACKEND_URL}/api/static-scan/${state.currentScanId}/report-path`
      : `${BACKEND_URL}/api/scan/${state.currentScanId}/report-path`;
    const resp = await fetch(`${base}?format=${format}`);
    if (!resp.ok) throw new Error("Report generation failed");
    const { path, filename } = await resp.json();

    if (window.aegis && window.aegis.saveReport) {
      const result = await window.aegis.saveReport(filename, path);
      setStatus(result.saved ? `Saved report to ${result.path}` : "Export cancelled.");
    } else {
      setStatus(`Report generated at ${path}`);
    }
  } catch (err) {
    setStatus(`Export failed: ${err.message}`);
  }
}
