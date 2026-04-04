const RELEASE_TIMESTAMP = "2026-04-04T00:00:00+05:30";
const STATUS_PHRASES = [
  "Calibrating Detectors",
  "Reading Login Pressure",
  "Mapping Exposed Services",
  "Correlating Telemetry",
  "Scoring Threat Paths",
  "Preparing Structured Output",
];

const SAMPLE_LOGS = `Apr 04 01:14:11 bastion sshd[4512]: Failed password for invalid user deploy from 203.0.113.44 port 51422 ssh2
Apr 04 01:14:28 bastion sshd[4519]: Failed password for root from 203.0.113.44 port 51428 ssh2
Apr 04 01:15:03 bastion sshd[4521]: Failed password for admin from 203.0.113.44 port 51439 ssh2
Apr 04 01:15:49 bastion sshd[4525]: Failed password for root from 203.0.113.44 port 51447 ssh2
Apr 04 01:16:12 bastion sshd[4527]: Failed password for backup from 203.0.113.44 port 51455 ssh2
2026-04-04 01:17:03 app-gateway nginx: 198.51.100.18 GET /login.php?id=1' OR 1=1 -- HTTP/1.1
2026-04-04 01:17:09 app-gateway nginx: 198.51.100.18 GET /../../etc/passwd HTTP/1.1
Apr 04 01:18:44 bastion sudo: pam_unix(sudo:auth): authentication failure; logname=dev uid=1001 euid=0 tty=/dev/pts/1 ruser=dev rhost= user=root
Apr 04 09:42:11 bastion sshd[4610]: Accepted publickey for ops from 10.0.0.12 port 52111 ssh2`;
const THEME_STORAGE_KEY = "threatscope_theme";

const state = {
  modules: {
    logs: true,
    ports: true,
    correlation: true,
  },
  lastReport: null,
  aiReady: false,
};

const els = {
  themeBtn: document.getElementById("themeBtn"),
  runAnalysisBtn: document.getElementById("runAnalysisBtn"),
  loadSampleBtn: document.getElementById("loadSampleBtn"),
  clearBtn: document.getElementById("clearBtn"),
  downloadStatsBtn: document.getElementById("downloadStatsBtn"),
  aiExplainBtn: document.getElementById("aiExplainBtn"),
  threatLevelBadge: document.getElementById("threatLevelBadge"),
  riskCard: document.getElementById("riskCard"),
  riskRing: document.getElementById("riskRing"),
  riskScore: document.getElementById("riskScore"),
  riskLevel: document.getElementById("riskLevel"),
  riskHeadline: document.getElementById("riskHeadline"),
  confidenceValue: document.getElementById("confidenceValue"),
  rulesFiredValue: document.getElementById("rulesFiredValue"),
  openPortsValue: document.getElementById("openPortsValue"),
  failedLoginsValue: document.getElementById("failedLoginsValue"),
  reasonList: document.getElementById("reasonList"),
  actionList: document.getElementById("actionList"),
  logMetrics: document.getElementById("logMetrics"),
  portMetrics: document.getElementById("portMetrics"),
  logFindingList: document.getElementById("logFindingList"),
  openPortList: document.getElementById("openPortList"),
  ruleTraceList: document.getElementById("ruleTraceList"),
  attackPathList: document.getElementById("attackPathList"),
  logScoreBadge: document.getElementById("logScoreBadge"),
  portScoreBadge: document.getElementById("portScoreBadge"),
  correlationScoreBadge: document.getElementById("correlationScoreBadge"),
  aiModelBadge: document.getElementById("aiModelBadge"),
  aiBriefContent: document.getElementById("aiBriefContent"),
  analysisMeta: document.getElementById("analysisMeta"),
  targetHost: document.getElementById("targetHost"),
  targetPorts: document.getElementById("targetPorts"),
  simulateScan: document.getElementById("simulateScan"),
  logInput: document.getElementById("logInput"),
  statusText: document.getElementById("status-text"),
  yearNow: document.getElementById("yearNow"),
  buildStamp: document.getElementById("buildStamp"),
};

function init() {
  initTheme();
  syncAdaptiveViewport();
  initTypewriter();
  startReleaseTimer();
  bindNavLinks();
  bindModuleToggles();
  bindButtons();
  bindHapticFeedback();
  resetBoard();
  hydrateAiStatus();
  window.addEventListener("resize", syncAdaptiveViewport);
}

function initTypewriter() {
  let phraseIndex = 0;
  let charIndex = 0;
  let deleting = false;

  const tick = () => {
    const phrase = STATUS_PHRASES[phraseIndex];
    if (!els.statusText) return;

    els.statusText.textContent = deleting
      ? phrase.slice(0, charIndex--)
      : phrase.slice(0, charIndex++);

    let delay = deleting ? 42 : 82;
    if (!deleting && charIndex > phrase.length) {
      deleting = true;
      delay = 1500;
    } else if (deleting && charIndex < 0) {
      deleting = false;
      phraseIndex = (phraseIndex + 1) % STATUS_PHRASES.length;
      charIndex = 0;
      delay = 320;
    }

    window.setTimeout(tick, delay);
  };

  tick();
}

function startReleaseTimer() {
  if (els.yearNow) {
    els.yearNow.textContent = String(new Date().getFullYear());
  }

  if (!els.buildStamp) return;
  const releaseTime = new Date(RELEASE_TIMESTAMP).getTime();
  if (Number.isNaN(releaseTime)) {
    els.buildStamp.textContent = "release time unavailable";
    return;
  }

  const update = () => {
    const elapsed = Math.max(0, Date.now() - releaseTime);
    const totalSeconds = Math.floor(elapsed / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    els.buildStamp.textContent = `${String(hours).padStart(2, "0")}h ${String(minutes).padStart(2, "0")}m ${String(seconds).padStart(2, "0")}s passed`;
  };

  update();
  window.setInterval(update, 1000);
}

function bindNavLinks() {
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", () => {
      document.querySelectorAll(".nav-link").forEach((node) => node.classList.remove("active"));
      link.classList.add("active");
    });
  });
}

function bindModuleToggles() {
  document.querySelectorAll(".module-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      const moduleKey = button.dataset.module;
      state.modules[moduleKey] = !state.modules[moduleKey];
      enforceModuleState(moduleKey);
    });
  });
}

function bindButtons() {
  if (els.themeBtn) {
    els.themeBtn.addEventListener("click", toggleTheme);
  }
  els.runAnalysisBtn.addEventListener("click", runAnalysis);
  els.loadSampleBtn.addEventListener("click", loadSample);
  els.clearBtn.addEventListener("click", clearWorkspace);
  els.downloadStatsBtn.addEventListener("click", downloadStats);
  els.aiExplainBtn.addEventListener("click", generateAiBrief);
}

function bindHapticFeedback() {
  document.querySelectorAll(".haptic-btn, .module-toggle").forEach((button) => {
    const triggerPress = () => {
      button.classList.add("is-pressed");
      if (navigator.vibrate) {
        navigator.vibrate(10);
      }
      window.setTimeout(() => button.classList.remove("is-pressed"), 150);
    };

    button.addEventListener("pointerdown", triggerPress);
  });
}

function updateModuleVisual(button, active) {
  button.classList.toggle("is-active", active);
  button.setAttribute("aria-pressed", String(active));
}

function enforceModuleState(preferredKey) {
  if (!state.modules.logs && !state.modules.ports && state.modules.correlation) {
    if (preferredKey === "correlation") {
      state.modules.logs = true;
    } else {
      state.modules.correlation = false;
    }
  }

  if (!state.modules.logs && !state.modules.ports && !state.modules.correlation) {
    state.modules.logs = true;
  }

  document.querySelectorAll(".module-toggle").forEach((button) => {
    const key = button.dataset.module;
    updateModuleVisual(button, state.modules[key]);
  });
}

function initTheme() {
  const storedTheme = window.localStorage.getItem(THEME_STORAGE_KEY);
  const initialTheme = storedTheme === "light" || storedTheme === "dark" ? storedTheme : "dark";
  applyTheme(initialTheme);
}

function toggleTheme() {
  const nextTheme = document.body.dataset.theme === "light" ? "dark" : "light";
  applyTheme(nextTheme);
}

function applyTheme(theme) {
  document.body.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
  window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  if (els.themeBtn) {
    const label = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
    els.themeBtn.setAttribute("aria-label", label);
    els.themeBtn.setAttribute("title", label);
  }
}

function syncAdaptiveViewport() {
  const width = window.innerWidth || document.documentElement.clientWidth;
  const coarsePointer = window.matchMedia("(pointer: coarse)").matches;
  const isAndroid = /Android/i.test(navigator.userAgent);
  const isCompactViewport = width <= 920 || coarsePointer;

  document.body.classList.toggle("is-mobile-ui", isCompactViewport);
  document.body.classList.toggle("is-android-ui", isAndroid && isCompactViewport);
}

async function hydrateAiStatus() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    state.aiReady = Boolean(data.ai_explainer_ready);
    els.aiModelBadge.textContent = state.aiReady ? "READY" : "ENV";
  } catch {
    state.aiReady = false;
    els.aiModelBadge.textContent = "ENV";
  }
}

async function runAnalysis() {
  setButtonBusy(els.runAnalysisBtn, true, "Analyzing...");
  setAiBrief("Rule engine is running. AI explanation stays separate until the analysis finishes.", "OFF");

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(buildPayload()),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Analysis request failed.");
    }

    state.lastReport = data;
    renderReport(data);
  } catch (error) {
    setBanner("HIGH", "Analysis failed", error.message, 0, 0, 0, 0, 0);
    renderList(els.reasonList, [
      {
        title: "Request error",
        detail: error.message,
      },
    ]);
    renderList(els.actionList, [
      {
        title: "Next step",
        detail: "Check that the backend is running on http://127.0.0.1:5000 and try again.",
      },
    ]);
  } finally {
    setButtonBusy(els.runAnalysisBtn, false, "Run Analysis");
  }
}

async function generateAiBrief() {
  if (!state.lastReport) {
    setAiBrief("Run the rule engine first so the AI layer has structured findings to explain.", "OFF");
    return;
  }

  setButtonBusy(els.aiExplainBtn, true, "Generating...");
  setAiBrief("Generating an NVIDIA-backed explanation from the completed report...", "RUN");

  try {
    const response = await fetch("/api/explain", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ report: state.lastReport }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "AI explanation request failed.");
    }

    setAiBrief(data.content || "No explanation returned.", data.model || "READY");
  } catch (error) {
    setAiBrief(error.message, "ERR");
  } finally {
    setButtonBusy(els.aiExplainBtn, false, "Generate AI Brief");
  }
}

function loadSample() {
  state.modules.logs = true;
  state.modules.ports = true;
  state.modules.correlation = true;

  document.querySelectorAll(".module-toggle").forEach((button) => {
    const key = button.dataset.module;
    updateModuleVisual(button, state.modules[key]);
  });

  els.targetHost.value = "perimeter-gateway";
  els.targetPorts.value = "22,80,443,8080,3389,5432,6379";
  els.simulateScan.checked = true;
  els.logInput.value = SAMPLE_LOGS;
  runAnalysis();
}

function clearWorkspace() {
  els.targetHost.value = "127.0.0.1";
  els.targetPorts.value = "22,80,443,3389,5432,6379,8080";
  els.simulateScan.checked = false;
  els.logInput.value = "";
  state.lastReport = null;
  resetBoard();
  setAiBrief("AI remains optional. Generate a brief only after the rule engine completes a run.", state.aiReady ? "READY" : "OFF");
}

function downloadStats() {
  const payload = state.lastReport || {
    generated_at: new Date().toISOString(),
    overall: {
      threat_level: els.riskLevel.textContent,
      score: Number(els.riskScore.textContent || 0),
      confidence: els.confidenceValue.textContent,
    },
    note: "No completed analysis report was available, so a lightweight UI snapshot was exported instead.",
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  link.href = url;
  link.download = `threatscope-stats-${stamp}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function buildPayload() {
  return {
    modules: { ...state.modules },
    logText: els.logInput.value.trim(),
    scanTarget: {
      host: els.targetHost.value.trim(),
      ports: els.targetPorts.value.trim(),
      simulate: els.simulateScan.checked,
      profile: els.simulateScan.checked ? els.targetHost.value.trim() : null,
    },
  };
}

function renderReport(report) {
  const overall = report.overall || {};
  const logModule = report.modules?.log_analyzer || {};
  const portModule = report.modules?.port_scanner || {};
  const correlationModule = report.modules?.correlation || {};

  setBanner(
    overall.threat_level || "LOW",
    overall.threat_level || "LOW",
    overall.headline || "Analysis complete.",
    overall.score || 0,
    Math.round((overall.confidence || 0) * 100),
    correlationModule.rules_fired?.length || 0,
    portModule.summary?.open_port_count || 0,
    logModule.summary?.failed_login_count || 0
  );

  const modulesText = Object.entries(report.input_profile?.modules || {})
    .filter(([, enabled]) => enabled)
    .map(([key]) => key.toUpperCase())
    .join(" / ");

  els.analysisMeta.textContent = `Generated ${formatTimestamp(report.generated_at)} | Modules: ${modulesText || "NONE"} | Scan mode: ${portModule.mode || "N/A"}`;

  renderList(els.reasonList, normalizeReasonItems(overall.reasons));
  renderList(els.actionList, normalizeReasonItems(overall.suggested_actions, "Action"));
  renderLogModule(logModule);
  renderPortModule(portModule);
  renderCorrelationModule(correlationModule);
  setAiBrief("Analysis complete. Generate the optional NVIDIA brief if you want a narrative explanation.", state.aiReady ? "READY" : "ENV");
}

function renderLogModule(module) {
  const summary = module.summary || {};
  els.logScoreBadge.textContent = String(module.score || 0);
  renderMetricTiles(els.logMetrics, [
    ["Lines", summary.lines_processed || 0],
    ["Failed Logins", summary.failed_login_count || 0],
    ["Suspicious IPs", summary.suspicious_ip_count || 0],
    ["Off-hours", summary.off_hours_count || 0],
  ]);

  const findings = module.findings?.length
    ? module.findings
    : [
        {
          title: module.enabled === false ? "Module disabled" : "No strong log findings",
          severity: "LOW",
          detail: module.enabled === false
            ? "Log analysis is disabled for this run."
            : "No log-based rules crossed the configured threshold.",
          evidence: [],
        },
      ];

  els.logFindingList.innerHTML = findings
    .map((finding) => {
      const evidence = (finding.evidence || []).map((item) => `<li>${escapeHtml(String(item))}</li>`).join("");
      return `
        <article class="finding-card">
          <header>
            <strong>${escapeHtml(finding.title || "Finding")}</strong>
            <span class="severity-pill ${levelClass(finding.severity || "LOW")}">${escapeHtml(finding.severity || "LOW")}</span>
          </header>
          <p>${escapeHtml(finding.detail || "")}</p>
          ${evidence ? `<ul>${evidence}</ul>` : ""}
        </article>
      `;
    })
    .join("");
}

function renderPortModule(module) {
  const summary = module.summary || {};
  els.portScoreBadge.textContent = String(module.score || 0);
  renderMetricTiles(els.portMetrics, [
    ["Mode", module.mode || "N/A"],
    ["Open Ports", summary.open_port_count || 0],
    ["High Risk", summary.high_risk_open_ports || 0],
    ["Admin Surfaces", summary.remote_admin_surfaces || 0],
  ]);

  const openPorts = module.open_ports?.length
    ? module.open_ports
    : [
        {
          service: module.enabled === false ? "Module disabled" : "No ports open",
          port: module.enabled === false ? "--" : "0",
          risk: "LOW",
          detail: module.enabled === false
            ? "Port scanning is disabled for this run."
            : "No listed ports responded during the scan.",
          surface: module.target || "n/a",
        },
      ];

  els.openPortList.innerHTML = openPorts
    .map((entry) => {
      return `
        <article class="port-chip">
          <header>
            <strong>${escapeHtml(String(entry.service))} : ${escapeHtml(String(entry.port))}</strong>
            <span class="severity-pill ${levelClass(entry.risk || "LOW")}">${escapeHtml(entry.risk || "LOW")}</span>
          </header>
          <p>${escapeHtml(entry.detail || "")}</p>
          <div class="port-meta">
            <span>Surface: ${escapeHtml(String(entry.surface || module.target || "n/a"))}</span>
            ${entry.recommended_action ? `<span>Action: ${escapeHtml(entry.recommended_action)}</span>` : ""}
          </div>
        </article>
      `;
    })
    .join("");
}

function renderCorrelationModule(module) {
  els.correlationScoreBadge.textContent = String(module.score || 0);

  const rules = module.rules_fired?.length
    ? module.rules_fired
    : [
        {
          title: module.enabled === false ? "Module disabled" : "No correlation rules fired",
          detail: module.enabled === false
            ? "Correlation is disabled for this run."
            : "The current telemetry did not trigger multi-condition correlation logic.",
          weight: 0,
          evidence: [],
        },
      ];

  els.ruleTraceList.innerHTML = rules
    .map((rule) => {
      const evidence = (rule.evidence || []).map((item) => `<li>${escapeHtml(String(item))}</li>`).join("");
      return `
        <article class="trace-card">
          <header>
            <strong>${escapeHtml(rule.title || "Rule")}</strong>
            <span class="trace-weight">+${escapeHtml(String(rule.weight || 0))}</span>
          </header>
          <p>${escapeHtml(rule.detail || "")}</p>
          ${evidence ? `<ul>${evidence}</ul>` : ""}
        </article>
      `;
    })
    .join("");

  const attackPaths = module.attack_paths?.length
    ? module.attack_paths
    : [
        {
          name: "No attack path formed",
          severity: "LOW",
          summary: "The available evidence did not create a strong chained threat path.",
        },
      ];

  els.attackPathList.innerHTML = attackPaths
    .map((path) => {
      return `
        <article class="path-card">
          <header>
            <strong>${escapeHtml(path.name || "Path")}</strong>
            <span class="severity-pill ${levelClass(path.severity || "LOW")}">${escapeHtml(path.severity || "LOW")}</span>
          </header>
          <p>${escapeHtml(path.summary || "")}</p>
        </article>
      `;
    })
    .join("");
}

function renderMetricTiles(container, items) {
  container.innerHTML = items
    .map(([label, value]) => {
      return `
        <div class="metric-tile">
          <span>${escapeHtml(String(label))}</span>
          <strong>${escapeHtml(String(value))}</strong>
        </div>
      `;
    })
    .join("");
}

function renderList(container, items) {
  container.innerHTML = items
    .map((item) => {
      return `
        <li>
          <strong>${escapeHtml(item.title || "Item")}</strong>
          <span>${escapeHtml(item.detail || "")}</span>
        </li>
      `;
    })
    .join("");
}

function setBanner(level, label, headline, score, confidence, rulesFired, openPorts, failedLogins) {
  const normalizedLevel = String(level || "LOW").toUpperCase();
  const tone = label === "Awaiting Run" ? "neutral" : levelClass(normalizedLevel);
  document.body.dataset.threatLevel = tone;

  els.threatLevelBadge.className = `threat-pill threat-${tone}`;
  els.threatLevelBadge.textContent = `Threat Level // ${label}`;

  els.riskCard.classList.remove("is-neutral", "is-low", "is-medium", "is-high");
  els.riskCard.classList.add(`is-${tone}`);
  els.riskRing.classList.remove("dial-neutral", "dial-low", "dial-medium", "dial-high");
  els.riskRing.classList.add(`dial-${tone}`);
  els.riskRing.style.setProperty("--dial-angle", `${-140 + Math.max(0, Math.min(100, Number(score) || 0)) * 2.8}deg`);

  els.riskScore.textContent = String(score);
  els.riskLevel.textContent = String(label);
  els.riskHeadline.textContent = headline;
  els.confidenceValue.textContent = `${confidence}%`;
  els.rulesFiredValue.textContent = String(rulesFired);
  els.openPortsValue.textContent = String(openPorts);
  els.failedLoginsValue.textContent = String(failedLogins);
}

function setAiBrief(content, model) {
  els.aiModelBadge.textContent = model || "OFF";
  const html = renderMarkdownLite(content);
  els.aiBriefContent.innerHTML = html;
}

function resetBoard() {
  setBanner("LOW", "Awaiting Run", "Run one or more modules to generate correlated findings.", 0, 0, 0, 0, 0);
  els.analysisMeta.textContent = "Awaiting telemetry.";
  renderList(els.reasonList, [
    {
      title: "No data processed",
      detail: "Threat reasoning will appear here after a run.",
    },
  ]);
  renderList(els.actionList, [
    {
      title: "Next step",
      detail: "Paste logs, select modules, and launch the analysis pipeline.",
    },
  ]);
  renderMetricTiles(els.logMetrics, [
    ["Lines", 0],
    ["Failed Logins", 0],
    ["Suspicious IPs", 0],
    ["Off-hours", 0],
  ]);
  renderMetricTiles(els.portMetrics, [
    ["Mode", "N/A"],
    ["Open Ports", 0],
    ["High Risk", 0],
    ["Admin Surfaces", 0],
  ]);
  els.logScoreBadge.textContent = "0";
  els.portScoreBadge.textContent = "0";
  els.correlationScoreBadge.textContent = "0";
  els.logFindingList.innerHTML = `
    <article class="finding-card">
      <header>
        <strong>Log analyzer ready</strong>
        <span class="severity-pill low">LOW</span>
      </header>
      <p>Waiting for authentication, application, or system logs.</p>
    </article>
  `;
  els.openPortList.innerHTML = `
    <article class="port-chip">
      <header>
        <strong>Port scanner ready</strong>
        <span class="severity-pill low">LOW</span>
      </header>
      <p>Waiting for a host, port list, or simulation profile.</p>
    </article>
  `;
  els.ruleTraceList.innerHTML = `
    <article class="trace-card">
      <header>
        <strong>Correlation engine idle</strong>
        <span class="trace-weight">+0</span>
      </header>
      <p>No module output available yet.</p>
    </article>
  `;
  els.attackPathList.innerHTML = `
    <article class="path-card">
      <header>
        <strong>No attack path formed</strong>
        <span class="severity-pill low">LOW</span>
      </header>
      <p>Cross-module paths appear here after the first run.</p>
    </article>
  `;
  setAiBrief("AI remains optional. Generate a brief only after the rule engine completes a run.", state.aiReady ? "READY" : "OFF");
}

function setButtonBusy(button, isBusy, label) {
  button.disabled = isBusy;
  button.textContent = label;
}

function normalizeReasonItems(items, fallbackTitle = "Reason") {
  if (!Array.isArray(items) || items.length === 0) {
    return [
      {
        title: fallbackTitle,
        detail: "No structured items were returned for this section.",
      },
    ];
  }

  return items.map((item) => {
    if (typeof item === "string") {
      return {
        title: fallbackTitle,
        detail: item,
      };
    }

    return {
      title: item.title || fallbackTitle,
      detail: item.detail || item.summary || "",
    };
  });
}

function levelClass(level) {
  const normalized = String(level || "").toLowerCase();
  if (normalized.includes("high")) return "high";
  if (normalized.includes("medium")) return "medium";
  return "low";
}

function formatTimestamp(value) {
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(new Date(value));
  } catch {
    return value || "unknown time";
  }
}

function renderMarkdownLite(markdown) {
  const safe = escapeHtml(markdown || "");
  const lines = safe.split(/\r?\n/);
  const chunks = [];
  let listItems = [];

  const flushList = () => {
    if (!listItems.length) return;
    chunks.push(`<ul>${listItems.join("")}</ul>`);
    listItems = [];
  };

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) {
      flushList();
      return;
    }

    if (trimmed.startsWith("- ")) {
      listItems.push(`<li>${trimmed.slice(2)}</li>`);
      return;
    }

    flushList();

    if (trimmed.startsWith("### ")) {
      chunks.push(`<h4>${trimmed.slice(4)}</h4>`);
      return;
    }

    if (trimmed.startsWith("## ")) {
      chunks.push(`<h4>${trimmed.slice(3)}</h4>`);
      return;
    }

    if (trimmed.startsWith("# ")) {
      chunks.push(`<h4>${trimmed.slice(2)}</h4>`);
      return;
    }

    chunks.push(`<p>${trimmed}</p>`);
  });

  flushList();
  return chunks.join("");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

window.addEventListener("load", init);
