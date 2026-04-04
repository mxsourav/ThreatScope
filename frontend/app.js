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
  runtimeMode: "boot",
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
  const flag = button.querySelector(".module-flag");
  if (flag) {
    flag.textContent = active ? "ON" : "OFF";
  }
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
    const response = await fetch(buildApiUrl("api/health"));
    const data = await response.json();
    state.aiReady = Boolean(data.ai_explainer_ready);
    state.runtimeMode = "backend";
    els.aiModelBadge.textContent = state.aiReady ? "READY" : "ENV";
  } catch {
    state.aiReady = false;
    state.runtimeMode = "static";
    els.aiModelBadge.textContent = "LOCAL";
  }
}

async function runAnalysis() {
  setButtonBusy(els.runAnalysisBtn, true, "Analyzing...");
  setAiBrief("Rule engine is running. AI explanation stays separate until the analysis finishes.", state.runtimeMode === "static" ? "LOCAL" : "OFF");

  try {
    const report = await requestAnalysis(buildPayload());
    state.lastReport = report;
    renderReport(report);
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
        detail: "Check the selected modules and telemetry input, then try again.",
      },
    ]);
  } finally {
    setButtonBusy(els.runAnalysisBtn, false, "Run Analysis");
  }
}

async function generateAiBrief() {
  if (!state.lastReport) {
    setAiBrief("Run the rule engine first so the AI layer has structured findings to explain.", state.runtimeMode === "static" ? "LOCAL" : "OFF");
    return;
  }

  if (!state.aiReady || state.runtimeMode === "static") {
    setAiBrief(
      "The static hosted build keeps scoring in the browser. NVIDIA explanation is available only when the local backend is running with a valid API key.",
      "LOCAL"
    );
    return;
  }

  setButtonBusy(els.aiExplainBtn, true, "Generating...");
  setAiBrief("Generating an NVIDIA-backed explanation from the completed report...", "RUN");

  try {
    const response = await fetch(buildApiUrl("api/explain"), {
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
  setAiBrief(getIdleAiMessage(), getIdleAiBadge());
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

async function requestAnalysis(payload) {
  try {
    const response = await fetch(buildApiUrl("api/analyze"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json();

    if (!response.ok) {
      if ([404, 405].includes(response.status) || response.status >= 500) {
        throw new Error("__STATIC_FALLBACK__");
      }
      throw new Error(data.error || "Analysis request failed.");
    }

    state.runtimeMode = "backend";
    return data;
  } catch (error) {
    if (!(error instanceof TypeError) && error.message !== "__STATIC_FALLBACK__") {
      throw error;
    }

    state.runtimeMode = "static";
    state.aiReady = false;
    els.aiModelBadge.textContent = "LOCAL";
    return buildStaticReport(payload);
  }
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

  const runtimeLabel = String(report.runtime_mode || state.runtimeMode || "static").toUpperCase();
  els.analysisMeta.textContent = `Generated ${formatTimestamp(report.generated_at)} | Runtime: ${runtimeLabel} | Modules: ${modulesText || "NONE"} | Scan mode: ${portModule.mode || "N/A"}`;

  renderList(els.reasonList, normalizeReasonItems(overall.reasons));
  renderList(els.actionList, normalizeReasonItems(overall.suggested_actions, "Action"));
  renderLogModule(logModule);
  renderPortModule(portModule);
  renderCorrelationModule(correlationModule);
  setAiBrief(
    state.runtimeMode === "static"
      ? "Static hosted mode completed the rule analysis in-browser. For NVIDIA-backed narrative explanation or live socket checks, run the Flask backend locally."
      : "Analysis complete. Generate the optional NVIDIA brief if you want a narrative explanation.",
    state.runtimeMode === "static" ? "LOCAL" : state.aiReady ? "READY" : "ENV"
  );
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
        <span class="severity-pill idle">NULL</span>
      </header>
      <p>Waiting for authentication, application, or system logs.</p>
    </article>
  `;
  els.openPortList.innerHTML = `
    <article class="port-chip">
      <header>
        <strong>Port scanner ready</strong>
        <span class="severity-pill idle">NULL</span>
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
        <span class="severity-pill idle">NULL</span>
      </header>
      <p>Cross-module paths appear here after the first run.</p>
    </article>
  `;
  setAiBrief(getIdleAiMessage(), getIdleAiBadge());
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

function buildApiUrl(path) {
  return new URL(path, window.location.href);
}

function getIdleAiBadge() {
  if (state.aiReady) return "READY";
  if (state.runtimeMode === "static") return "LOCAL";
  return "OFF";
}

function getIdleAiMessage() {
  if (state.runtimeMode === "static") {
    return "Static hosted mode keeps the rule engine in-browser. NVIDIA explanation remains optional and requires the local backend with a valid API key.";
  }
  return "AI remains optional. Generate a brief only after the rule engine completes a run.";
}

function buildStaticReport(payload) {
  const modules = payload.modules || {};
  const logsEnabled = Boolean(modules.logs);
  const portsEnabled = Boolean(modules.ports);
  const correlationEnabled = Boolean(modules.correlation);

  if (!logsEnabled && !portsEnabled && !correlationEnabled) {
    throw new Error("Enable at least one module before running an analysis.");
  }

  if (correlationEnabled && !logsEnabled && !portsEnabled) {
    throw new Error("Correlation needs log analysis, port scanning, or both to produce output.");
  }

  const logAnalysis = logsEnabled ? analyzeStaticLogs(payload.logText || "") : disabledStaticModule("log_analyzer");
  const portAnalysis = portsEnabled
    ? analyzeStaticPorts(payload.scanTarget || {})
    : disabledStaticModule("port_scanner");
  const correlation = correlationEnabled
    ? correlateStatic(logAnalysis, portAnalysis, logsEnabled, portsEnabled)
    : disabledStaticModule("correlation");

  const overall = correlationEnabled
    ? {
        threat_level: correlation.risk_level,
        score: correlation.score,
        confidence: correlation.confidence,
        headline: correlation.headline,
        reasons: correlation.reasons,
        suggested_actions: correlation.recommended_actions,
      }
    : buildStaticOverall(logAnalysis, portAnalysis);

  const suppliedLines = String(payload.logText || "")
    .split(/\r?\n/)
    .filter((line) => line.trim()).length;

  return {
    generated_at: new Date().toISOString(),
    runtime_mode: "static",
    input_profile: {
      modules: {
        logs: logsEnabled,
        ports: portsEnabled,
        correlation: correlationEnabled,
      },
      scan_target: {
        host: payload.scanTarget?.host || "127.0.0.1",
        ports: parsePorts(payload.scanTarget?.ports),
        simulate: Boolean(payload.scanTarget?.simulate),
        profile: payload.scanTarget?.simulate ? payload.scanTarget?.profile || payload.scanTarget?.host || "profile" : null,
      },
      log_lines_supplied: suppliedLines,
    },
    overall,
    modules: {
      log_analyzer: logAnalysis,
      port_scanner: portAnalysis,
      correlation,
    },
  };
}

function buildStaticOverall(logAnalysis, portAnalysis) {
  const dominant = [logAnalysis, portAnalysis].sort((a, b) => (b.score || 0) - (a.score || 0))[0];
  return {
    threat_level: dominant.risk_level || "LOW",
    score: dominant.score || 0,
    confidence: dominant.enabled ? 0.55 : 0,
    headline: "Correlation module is disabled; showing the highest single-module risk.",
    reasons: dominant.reasoning || [],
    suggested_actions: dominant.actions || [],
  };
}

function disabledStaticModule(name) {
  return {
    enabled: false,
    module: name,
    risk_level: "LOW",
    score: 0,
    summary: {},
    reasoning: [],
    actions: [],
  };
}

function analyzeStaticLogs(rawText) {
  const lines = String(rawText || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  if (!lines.length) {
    return {
      enabled: true,
      risk_level: "LOW",
      score: 0,
      summary: {
        lines_processed: 0,
        failed_login_count: 0,
        suspicious_ip_count: 0,
        off_hours_count: 0,
        pattern_matches: 0,
        privilege_escalation_count: 0,
      },
      findings: [],
      reasoning: [],
      actions: ["Provide raw auth, system, or application logs to activate log correlation."],
      success_after_failure: [],
    };
  }

  const failedEvents = [];
  const suspiciousPatterns = [];
  const offHours = [];
  const privilegeEvents = [];
  const successfulAfterFailure = [];
  const ipHits = new Map();
  let score = 0;

  lines.forEach((line, index) => {
    const sample = clipLine(line);
    const ip = extractStaticIp(line);
    const hour = extractStaticHour(line);
    const lowered = line.toLowerCase();

    if (ip) {
      ipHits.set(ip, (ipHits.get(ip) || 0) + 1);
    }

    if (hour !== null && (hour < 6 || hour >= 22)) {
      offHours.push(sample);
    }

    if (/failed password|authentication failure|invalid user|login failed|failed login/i.test(lowered)) {
      failedEvents.push(sample);
    }

    if (/accepted password|accepted publickey|session opened|login succeeded|logged in/i.test(lowered) && failedEvents.length) {
      successfulAfterFailure.push(sample);
    }

    if (/sudo:.*authentication failure|permission denied|user=root|pam_unix\(sudo:auth\)/i.test(lowered)) {
      privilegeEvents.push(sample);
    }

    if (/or\s+1=1|union\s+select|\.\.\/|etc\/passwd|<script|wp-admin|password spray|brute force|credential stuffing|sqlmap|nmap|masscan|nikto/i.test(lowered)) {
      suspiciousPatterns.push(sample);
    }
  });

  const suspiciousIpCount = [...ipHits.values()].filter((count) => count >= 2).length;
  if (failedEvents.length >= 3) score += failedEvents.length >= 8 ? 28 : 16;
  if (suspiciousPatterns.length) score += suspiciousPatterns.length >= 3 ? 30 : 20;
  if (offHours.length) score += offHours.length >= 4 ? 14 : 8;
  if (privilegeEvents.length) score += privilegeEvents.length >= 3 ? 32 : 22;
  if (suspiciousIpCount) score += suspiciousIpCount >= 2 ? 18 : 12;
  if (successfulAfterFailure.length) score += 18;
  score = Math.min(score, 100);

  const reasoning = [];
  if (failedEvents.length >= 3) reasoning.push({ title: "Repeated login failures", detail: `${failedEvents.length} failed login events were detected in the supplied log set.` });
  if (suspiciousPatterns.length) reasoning.push({ title: "Suspicious attack strings detected", detail: `${suspiciousPatterns.length} log lines matched exploit or recon indicators.` });
  if (offHours.length) reasoning.push({ title: "Unusual timing window", detail: `${offHours.length} events occurred outside the expected daytime window.` });
  if (privilegeEvents.length) reasoning.push({ title: "Privilege escalation indicators", detail: `${privilegeEvents.length} lines suggest privileged access attempts or denials.` });

  const findings = [];
  if (failedEvents.length) findings.push({ title: "Failed login cluster", severity: failedEvents.length >= 10 ? "HIGH" : "MEDIUM", detail: `${failedEvents.length} failed authentication events were found.`, evidence: failedEvents.slice(0, 2) });
  if (offHours.length) findings.push({ title: "Off-hours activity", severity: "MEDIUM", detail: `${offHours.length} events landed in the overnight monitoring window.`, evidence: offHours.slice(0, 2) });
  if (suspiciousPatterns.length) findings.push({ title: "Exploit or recon indicators", severity: "HIGH", detail: `${suspiciousPatterns.length} lines matched suspicious attack strings.`, evidence: suspiciousPatterns.slice(0, 2) });
  if (privilegeEvents.length) findings.push({ title: "Privileged access pressure", severity: "HIGH", detail: `${privilegeEvents.length} lines indicate sudo, root, or permission escalation attempts.`, evidence: privilegeEvents.slice(0, 2) });
  if (successfulAfterFailure.length) findings.push({ title: "Success after failure", severity: "HIGH", detail: "A successful session followed a related failed authentication pattern.", evidence: successfulAfterFailure.slice(0, 2) });

  return {
    enabled: true,
    risk_level: scoreToLevel(score),
    score,
    summary: {
      lines_processed: lines.length,
      failed_login_count: failedEvents.length,
      suspicious_ip_count: suspiciousIpCount,
      off_hours_count: offHours.length,
      pattern_matches: suspiciousPatterns.length,
      privilege_escalation_count: privilegeEvents.length,
    },
    findings,
    reasoning,
    actions: [
      "Retain recent auth and application logs for continued correlation.",
      "Review authentication controls and lockout policy for the targeted accounts.",
    ],
    success_after_failure: successfulAfterFailure.map((sample) => ({ sample })),
  };
}

function analyzeStaticPorts(scanTarget) {
  const host = String(scanTarget.host || "127.0.0.1").trim() || "127.0.0.1";
  const simulate = Boolean(scanTarget.simulate);
  const inputPorts = parsePorts(scanTarget.ports);
  const openPorts = simulate ? simulateProfilePorts(scanTarget.profile || host, inputPorts) : inputPorts;
  let score = 0;
  let highRisk = 0;
  let remoteAdmin = 0;

  const mappedPorts = openPorts.map((port) => {
    const mapped = mapPort(port);
    score += mapped.weight;
    if (mapped.weight >= 26) highRisk += 1;
    if (["remote-admin", "legacy-admin"].includes(mapped.surface)) remoteAdmin += 1;
    return mapped;
  });

  if (highRisk) score += highRisk === 1 ? 18 : 28;
  if (remoteAdmin >= 2) score += 12;
  score = Math.min(score, 100);

  const reasoning = [
    {
      title: simulate ? "Simulated exposure review" : "Static hosted surface review",
      detail: simulate
        ? `${mappedPorts.length} simulated services were exposed by the selected profile.`
        : "Browser-hosted mode evaluates the listed ports as declared exposure because live socket scanning is unavailable in static hosting.",
    },
  ];

  if (highRisk) {
    reasoning.push({
      title: "High-risk services exposed",
      detail: `${highRisk} exposed services are commonly abused when reachable.`,
    });
  }

  return {
    enabled: true,
    mode: simulate ? "SIMULATED" : "STATIC REVIEW",
    scan_status: simulate ? "COMPLETE" : "DECLARED",
    target: host,
    risk_level: scoreToLevel(score),
    score,
    summary: {
      ports_checked: inputPorts.length,
      open_port_count: mappedPorts.length,
      high_risk_open_ports: highRisk,
      remote_admin_surfaces: remoteAdmin,
    },
    open_ports: mappedPorts.map((port) => ({
      port: port.port,
      service: port.service,
      risk: port.risk,
      surface: port.surface,
      detail: port.detail,
      recommended_action: port.action,
    })),
    closed_ports: [],
    reasoning,
    actions: [
      "Re-scan after remediation to confirm the attack surface has been reduced.",
      "Use the local backend build when you need live socket checks against a real host.",
    ],
    error: null,
  };
}

function correlateStatic(logAnalysis, portAnalysis, logsEnabled, portsEnabled) {
  const logScore = logsEnabled ? Number(logAnalysis.score || 0) : 0;
  const portScore = portsEnabled ? Number(portAnalysis.score || 0) : 0;
  let score = Math.round(logScore * 0.6 + portScore * 0.4);
  const failedLogins = Number(logAnalysis.summary?.failed_login_count || 0);
  const offHours = Number(logAnalysis.summary?.off_hours_count || 0);
  const privilegeEscalation = Number(logAnalysis.summary?.privilege_escalation_count || 0);
  const patternMatches = Number(logAnalysis.summary?.pattern_matches || 0);
  const successAfterFailure = Array.isArray(logAnalysis.success_after_failure) ? logAnalysis.success_after_failure.length : 0;
  const openPortNumbers = new Set((portAnalysis.open_ports || []).map((item) => Number(item.port)));
  const rules = [];
  const reasons = [];
  const attackPaths = [];
  const actions = new Set([...(logAnalysis.actions || []), ...(portAnalysis.actions || [])]);

  if (failedLogins >= 5 && openPortNumbers.has(22)) {
    addStaticRule(rules, reasons, attackPaths, 18, "Credential pressure on exposed SSH", "Multiple failed logins align with an exposed SSH service.", "Remote access brute-force path");
    actions.add("Restrict SSH exposure to trusted addresses.");
  }
  if (failedLogins >= 5 && openPortNumbers.has(3389)) {
    addStaticRule(rules, reasons, attackPaths, 18, "Credential pressure on exposed RDP", "Authentication failures align with a reachable remote desktop service.", "Remote desktop intrusion path");
    actions.add("Move RDP behind VPN or a bastion host.");
  }
  if (patternMatches >= 1 && ([80, 443, 8080].some((port) => openPortNumbers.has(port)))) {
    addStaticRule(rules, reasons, attackPaths, 16, "Exploit strings against exposed web services", "Web attack signatures were found while HTTP or HTTPS services are reachable.", "Application-layer intrusion path");
    actions.add("Inspect web server access logs and WAF events around the matched requests.");
  }
  if (privilegeEscalation >= 1 && ([22, 3389, 445].some((port) => openPortNumbers.has(port)))) {
    addStaticRule(rules, reasons, attackPaths, 15, "Privilege escalation near an administrative surface", "Privileged access attempts occurred while remote administration services were available.", "Lateral movement and privilege escalation path");
  }
  if (offHours >= 2 && ([22, 3389, 5432, 6379, 9200].some((port) => openPortNumbers.has(port)))) {
    addStaticRule(rules, reasons, attackPaths, 10, "Off-hours activity around sensitive services", "Nighttime activity coincides with services that warrant closer oversight.", "Low-visibility persistence window");
  }
  if (successAfterFailure >= 1) {
    addStaticRule(rules, reasons, attackPaths, 18, "Potential brute-force success path", "A successful session appeared after related failed login attempts.", "Credential compromise path");
  }

  score += rules.reduce((sum, rule) => sum + rule.weight, 0);
  score = Math.min(score, 100);

  if (!reasons.length) {
    reasons.push({
      title: score >= 35 ? "Single-module elevated finding" : "Limited correlated risk",
      detail: score >= 35
        ? "One enabled module produced a meaningful risk score even without cross-module confirmation."
        : "The current data did not trigger strong multi-condition threat rules.",
    });
  }

  return {
    enabled: true,
    risk_level: scoreToLevel(score),
    score,
    confidence: Math.min(0.97, 0.48 + (logsEnabled ? 0.1 : 0) + (portsEnabled ? 0.1 : 0) + (0.05 * rules.length)),
    headline: score >= 70
      ? "Multiple signals align into a likely active threat path."
      : score >= 35
        ? "Cross-signal risk is present and warrants active monitoring."
        : "Current evidence suggests a contained or low-confidence threat posture.",
    reasons,
    rules_fired: rules,
    attack_paths: attackPaths,
    recommended_actions: [...actions].sort(),
  };
}

function addStaticRule(rules, reasons, attackPaths, weight, title, detail, pathName) {
  rules.push({ title, detail, weight, evidence: [] });
  reasons.push({ title, detail });
  attackPaths.push({ name: pathName, severity: scoreToLevel(weight * 4), summary: detail });
}

function parsePorts(rawPorts) {
  const source = String(rawPorts || "")
    .split(",")
    .map((chunk) => Number(chunk.trim()))
    .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);

  return [...new Set(source)].sort((a, b) => a - b).slice(0, 32).length
    ? [...new Set(source)].sort((a, b) => a - b).slice(0, 32)
    : [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 5432, 5900, 6379, 8080, 9200];
}

function simulateProfilePorts(profile, allowedPorts) {
  const normalized = String(profile || "").toLowerCase();
  let simulated = [22, 80, 443, 8080];
  if (normalized.includes("db")) simulated = [22, 5432, 6379];
  if (normalized.includes("remote") || normalized.includes("rdp")) simulated = [22, 3389, 445];
  return simulated.filter((port) => allowedPorts.includes(port));
}

function mapPort(port) {
  const serviceMap = {
    21: ["FTP", 22, "legacy-transfer", "Legacy file transfer channel", "Disable FTP or replace it with SFTP."],
    22: ["SSH", 16, "remote-admin", "Remote administration surface", "Restrict SSH to trusted sources and key-based auth."],
    23: ["Telnet", 36, "legacy-admin", "Cleartext remote administration", "Close Telnet immediately and replace it with SSH."],
    25: ["SMTP", 10, "mail", "Mail transfer service", "Confirm the mail relay is expected and hardened."],
    53: ["DNS", 9, "infra", "Domain name resolution service", "Verify recursion and access policy."],
    80: ["HTTP", 10, "web", "Web application surface", "Review web logs and enforce redirects to HTTPS."],
    443: ["HTTPS", 8, "web", "Encrypted web application surface", "Keep TLS and web application patches current."],
    445: ["SMB", 30, "lateral-movement", "File sharing and lateral movement surface", "Restrict SMB to internal trusted networks only."],
    3389: ["RDP", 28, "remote-admin", "Remote desktop administration surface", "Protect RDP with VPN, MFA, and IP allow-lists."],
    5432: ["PostgreSQL", 20, "data-store", "Database listener", "Keep the database private and limit direct client access."],
    5900: ["VNC", 26, "remote-admin", "Remote screen-sharing surface", "Close VNC externally or tunnel it through trusted paths."],
    6379: ["Redis", 32, "data-store", "High-risk in-memory datastore when exposed", "Bind Redis privately and require authentication."],
    8080: ["HTTP-Alt", 14, "web", "Alternate web or admin listener", "Confirm the alternate web port is intentional and patched."],
    9200: ["Elasticsearch", 30, "data-store", "Search API surface commonly abused when public", "Keep Elasticsearch private behind authenticated access."],
  };
  const [service, weight, surface, detail, action] = serviceMap[port] || ["Unknown", 8, "generic", "Unmapped network listener", "Validate why this service is exposed and whether it should remain open."];
  return {
    port,
    service,
    weight,
    surface,
    detail,
    action,
    risk: scoreToLevel(weight),
  };
}

function extractStaticIp(line) {
  const match = String(line).match(/(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)/);
  return match ? match[0] : null;
}

function extractStaticHour(line) {
  const isoMatch = String(line).match(/(?:\d{4}-\d{2}-\d{2}[ T])(\d{2}):\d{2}/);
  if (isoMatch) return Number(isoMatch[1]);
  const syslogMatch = String(line).match(/[A-Za-z]{3}\s+\d{1,2}\s+(\d{2}):\d{2}:\d{2}/);
  if (syslogMatch) return Number(syslogMatch[1]);
  return null;
}

function clipLine(line, limit = 140) {
  const normalized = String(line).replace(/\s+/g, " ").trim();
  return normalized.length > limit ? `${normalized.slice(0, limit - 3)}...` : normalized;
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
