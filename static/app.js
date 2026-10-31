"use strict";

/* =========================================================
   THREATNEX — FRONTEND APPLICATION
   Existing Flask routes:
   /api/stats
   /api/events
   /api/predict
   /api/simulate
   /api/reset
   ========================================================= */

const API = {
  stats: "/api/stats",
  events: "/api/events",
  predict: "/api/predict",
  simulate: "/api/simulate",
  reset: "/api/reset"
};

const CLASS_NAMES = {
  normal: "Normal",
  dos: "DoS",
  probe: "Probe",
  brute_force: "Brute force"
};

const CLASS_COLORS = {
  normal: "#39d9a2",
  dos: "#ff667d",
  probe: "#ffb45d",
  brute_force: "#ad91ff",
  unknown: "#8193ab"
};

const FEATURE_NAMES = {
  duration: "Duration",
  src_bytes: "Source bytes",
  dst_bytes: "Destination bytes",
  count: "Connection count",
  srv_count: "Service count",
  serror_rate: "SYN error rate",
  rerror_rate: "REJ error rate",
  same_srv_rate: "Same service rate",
  diff_srv_rate: "Different service rate",
  dst_host_count: "Destination host count",
  failed_logins: "Failed logins",
  num_compromised: "Compromised conditions"
};

const state = {
  stats: null,
  events: [],
  trafficChart: null,
  importanceChart: null,
  timelineChart: null,
  toastTimeout: null,
  refreshInProgress: false,
  lastError: null,
  savedSettings: {
    theme: "dark",
    notify_severity: "critical",
    page_size: 20,
    display_name: ""
  },
  activeModalEvent: null
};

const $ = (selector) => document.querySelector(selector);

const $$ = (selector) => [...document.querySelectorAll(selector)];

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

function formatNumber(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  const loc = state.savedSettings?.number_format || "en-US";
  try {
    return new Intl.NumberFormat(loc, {
      maximumFractionDigits: 2
    }).format(number);
  } catch (e) {
    return number.toLocaleString();
  }
}

function formatPercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return `${number.toFixed(1)}%`;
}

function formatTime(value) {
  if (!value) return "—";
  let date = typeof value === "number" ? new Date(value < 1e12 ? value * 1000 : value) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  const tz = state.savedSettings?.timezone;
  const options = { hour: "2-digit", minute: "2-digit", second: "2-digit" };
  if (tz && tz !== "local") {
    try { options.timeZone = tz; } catch (e) {}
  }
  return date.toLocaleTimeString([], options);
}

function formatDateTime(value) {
  if (!value) return "—";
  let date = typeof value === "number" ? new Date(value < 1e12 ? value * 1000 : value) : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);

  const tz = state.savedSettings?.timezone;
  const df = state.savedSettings?.datetime_format || "YYYY-MM-DD HH:mm:ss";

  const options = {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  };
  if (tz && tz !== "local") {
    try { options.timeZone = tz; } catch (e) {}
  }

  if (df === "ISO 8601") {
    return date.toISOString();
  }

  try {
    const formatter = new Intl.DateTimeFormat("en-US", options);
    const parts = formatter.formatToParts(date);
    const p = {};
    parts.forEach(({ type, value }) => { p[type] = value; });

    if (df === "DD/MM/YYYY HH:mm:ss") {
      return `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}:${p.second}`;
    } else if (df === "MM/DD/YYYY HH:mm:ss") {
      return `${p.month}/${p.day}/${p.year} ${p.hour}:${p.minute}:${p.second}`;
    } else {
      return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
    }
  } catch (err) {
    return date.toLocaleString([], options);
  }
}

function normalizeClass(value) {
  const text = String(value ?? "unknown")
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_");

  if (["normal", "benign", "0"].includes(text)) return "normal";
  if (text === "1") return "dos";
  if (text === "2") return "probe";
  if (text === "3") return "brute_force";

  if (
    text === "dos" ||
    text.includes("denial_of_service") ||
    text.includes("denialofservice")
  ) {
    return "dos";
  }

  if (
    text === "probe" ||
    text.includes("probing") ||
    text.includes("scan")
  ) {
    return "probe";
  }

  if (
    text.includes("brute") ||
    text.includes("guess_password")
  ) {
    return "brute_force";
  }

  return text || "unknown";
}

function displayClass(value) {
  const key = normalizeClass(value);
  return CLASS_NAMES[key] || String(value || "Unknown");
}

function normalizeSeverity(value, label) {
  const supplied = String(value ?? "").trim().toLowerCase();

  if (
    ["critical", "high", "medium", "low", "info"].includes(supplied)
  ) {
    return supplied;
  }

  const type = normalizeClass(label);

  if (type === "dos") return "high";
  if (type === "brute_force") return "high";
  if (type === "probe") return "medium";
  if (type === "normal") return "info";

  return "medium";
}

function getConfidence(event) {
  let value = event?.confidence;

  if (value === undefined || value === null) {
    value = event?.probability;
  }

  if (value === undefined || value === null) {
    value = event?.score;
  }

  if (value === undefined || value === null) {
    return null;
  }

  const number = Number(value);

  if (!Number.isFinite(number)) return null;

  // Convert fractions such as 0.92 to 92%.
  return Math.max(0, Math.min(100, number <= 1 ? number * 100 : number));
}

function normalizeEvent(event, index = 0) {
  const item = event && typeof event === "object" ? event : {};

  const label = normalizeClass(
    item.label ??
    item.prediction ??
    item.classification ??
    item.attack_type ??
    item.predicted_class
  );

  const timestamp =
    item.ts ??
    item.timestamp ??
    item.created_at ??
    item.time ??
    null;

  return {
    id: item.id ?? item.event_id ?? `EVT-${index + 1}`,
    src_ip: item.src_ip ?? item.source_ip ?? item.ip ?? "Unknown",
    label,
    severity: normalizeSeverity(item.severity, label),
    confidence: getConfidence(item),
    timestamp,
    original: item
  };
}

let cachedCsrfToken = "";

async function getCsrfToken() {
  if (cachedCsrfToken) return cachedCsrfToken;
  try {
    const res = await fetch("/api/csrf-token", { credentials: "same-origin" });
    if (res.ok) {
      const data = await res.json();
      cachedCsrfToken = data.csrf_token || "";
    }
  } catch (e) {
    console.warn("Could not fetch CSRF token:", e);
  }
  return cachedCsrfToken;
}

async function apiRequest(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = {
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(options.headers || {})
  };

  if (["POST", "PUT", "DELETE", "PATCH"].includes(method) && !headers["X-CSRF-Token"]) {
    const token = await getCsrfToken();
    if (token) {
      headers["X-CSRF-Token"] = token;
    }
  }

  const response = await fetch(url, {
    ...options,
    credentials: "same-origin",
    headers
  });

  const contentType = response.headers.get("content-type") || "";

  let data;

  if (contentType.includes("application/json")) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    let message = `Request failed (${response.status})`;

    if (data && typeof data === "object") {
      message = data.error || data.message || message;
    }

    throw new Error(message);
  }

  return data;
}

function showToast(message, type = "success", forceChime = false) {
  // Check if in-app notifications are enabled
  if (state.savedSettings?.enable_notifications === false && type !== "error" && !forceChime) {
    return;
  }

  // Record in notification history buffer
  if (typeof addNotificationHistoryItem === "function") {
    addNotificationHistoryItem({
      message,
      type,
      timestamp: new Date().toISOString()
    });
  }

  // Play audio chime if configured
  if (typeof playNotificationChime === "function") {
    if ((state.savedSettings?.notification_sound && (type === "error" || type === "warning")) || forceChime) {
      playNotificationChime();
    }
  }

  // Native browser notification if enabled
  if (state.savedSettings?.browser_notifications && ("Notification" in window) && Notification.permission === "granted") {
    if (type === "warning" || type === "error" || forceChime) {
      try {
        new Notification("THREATNEX Alert", {
          body: message,
          icon: "/static/favicon.ico"
        });
      } catch (_) {}
    }
  }

  const toast = $("#toast");
  if (!toast) return;

  toast.textContent = message;
  toast.classList.toggle("error", type === "error");
  toast.classList.toggle("warning", type === "warning");
  toast.classList.add("show");

  clearTimeout(state.toastTimeout);

  const autoDismissDelay = Math.max(2, state.savedSettings?.auto_dismiss_delay || 5) * 1000;
  const keepUntilAck = !!state.savedSettings?.keep_alerts_until_ack && (type === "error" || type === "warning");

  if (!keepUntilAck) {
    state.toastTimeout = setTimeout(() => {
      toast.classList.remove("show");
    }, autoDismissDelay);
  } else {
    toast.title = "Click to acknowledge and dismiss alert";
    toast.onclick = () => {
      toast.classList.remove("show");
      toast.onclick = null;
      toast.title = "";
    };
  }
}

/* =========================================================
   NAVIGATION
   ========================================================= */

function navigateTo(pageName) {
  const validPages = [
    "overview",
    "threats",
    "analyzer",
    "analytics",
    "about",
    "settings",
    "query",
    "investigations",
    "reports",
    "health"
  ];

  if (!validPages.includes(pageName)) return;

  $$(".page").forEach((page) => {
    page.classList.toggle("active", page.id === `page-${pageName}`);
  });

  $$(".nav-link[data-page]").forEach((button) => {
    button.classList.toggle(
      "active",
      button.dataset.page === pageName
    );
  });

  const pageLabels = {
    overview: "Dashboard",
    threats: "Threat Events",
    analyzer: "Traffic Analyzer",
    analytics: "AI Analytics",
    about: "About THREATNEX",
    settings: "Settings",
    query: "Query Center",
    investigations: "Investigations",
    reports: "SOC Reports",
    health: "System Health"
  };

  const breadcrumb = $("#breadcrumb-current");

  if (breadcrumb) {
    breadcrumb.textContent = pageLabels[pageName];
  }

  $("#sidebar")?.classList.remove("open");

  if (pageName === "overview") {
    refreshDashboard(false);
  }

  if (pageName === "analytics") {
    renderAnalytics();
  }

  if (pageName === "threats") {
    renderThreats();
  }

  if (pageName === "settings") {
    loadSettings();
  }

  if (pageName === "query") {
    loadSavedQueries();
    runQuery();
  }

  if (pageName === "investigations") {
    loadInvestigations();
  }

  if (pageName === "reports") {
    loadReports();
  }

  if (pageName === "health") {
    runHealthCheck();
  }

  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setupNavigation() {
  document.addEventListener("click", (event) => {
    const target = event.target.closest("[data-page]");

    if (!target) return;

    event.preventDefault();
    navigateTo(target.dataset.page);
  });

  $("#menu-toggle")?.addEventListener("click", () => {
    $("#sidebar")?.classList.toggle("open");
  });

  document.addEventListener("click", (event) => {
    const sidebar = $("#sidebar");
    const toggle = $("#menu-toggle");

    if (
      window.innerWidth <= 900 &&
      sidebar?.classList.contains("open") &&
      !sidebar.contains(event.target) &&
      !toggle?.contains(event.target)
    ) {
      sidebar.classList.remove("open");
    }
  });
}

/* =========================================================
   BACKEND CONNECTION STATUS
   ========================================================= */

function setConnectionStatus(connected, message = "") {
  const systemStatus = $("#system-status");
  const apiStatus = $("#api-status");
  const dot = $(".system-card-heading .status-dot");

  if (systemStatus) {
    systemStatus.textContent = connected ? "Operational" : "Disconnected";
  }

  if (apiStatus) {
    apiStatus.textContent = connected ? "Connected" : "Offline";
  }

  if (dot) {
    dot.style.background = connected ? "#39d9a2" : "#ff667d";
    dot.style.boxShadow = connected
      ? "0 0 10px #39d9a266"
      : "0 0 10px #ff667d66";
  }

  if (message) {
    state.lastError = message;
  } else if (connected) {
    state.lastError = null;
  }
}

/* =========================================================
   DASHBOARD STATISTICS
   ========================================================= */

function getCounts(stats) {
  const supplied = stats?.counts || {};

  return {
    normal: Number(supplied.normal || 0),
    dos: Number(supplied.dos || 0),
    probe: Number(supplied.probe || 0),
    brute_force: Number(supplied.brute_force || 0)
  };
}

function renderStats(stats) {
  const counts = getCounts(stats);
  const total = Number(
    stats?.total ??
    Object.values(counts).reduce((sum, value) => sum + value, 0)
  );

  const threats = Number(
    stats?.threats ??
    (counts.dos + counts.probe + counts.brute_force)
  );

  const accuracy = stats?.metrics?.accuracy;
  const criticalHigh = (stats?.severities?.critical || 0) + (stats?.severities?.high || 0);

  if ($("#stat-total")) $("#stat-total").textContent = formatNumber(total);
  if ($("#stat-threats")) $("#stat-threats").textContent = formatNumber(threats);
  if ($("#stat-critical")) $("#stat-critical").textContent = formatNumber(criticalHigh);
  if ($("#stat-normal")) $("#stat-normal").textContent = formatNumber(counts.normal);

  if ($("#stat-accuracy")) {
    $("#stat-accuracy").innerHTML =
      accuracy !== undefined && accuracy !== null
        ? `${escapeHTML(Number(accuracy).toFixed(2))}<span class="value-unit">%</span>`
        : "—";
  }

  if ($("#donut-total")) $("#donut-total").textContent = formatNumber(total);
  if ($("#sidebar-threat-count")) $("#sidebar-threat-count").textContent = formatNumber(threats);
  
  const invOpen = (stats?.investigations?.new || 0) + (stats?.investigations?.investigating || 0);
  if ($("#sidebar-investigation-count")) $("#sidebar-investigation-count").textContent = formatNumber(invOpen);

  if ($("#model-source")) {
    $("#model-source").textContent = stats?.metrics?.source
      ? `Dataset: ${stats.metrics.source}`
      : "NSL-KDD Test+ benchmark";
  }

  if ($("#threat-total")) $("#threat-total").textContent = formatNumber(total);
  if ($("#threat-dos")) $("#threat-dos").textContent = formatNumber(counts.dos);
  if ($("#threat-probe")) $("#threat-probe").textContent = formatNumber(counts.probe);
  if ($("#threat-brute")) $("#threat-brute").textContent = formatNumber(counts.brute_force);

  if ($("#metric-accuracy")) {
    $("#metric-accuracy").textContent =
      accuracy !== undefined && accuracy !== null
        ? formatPercent(accuracy)
        : "—";
  }

  if ($("#metric-train")) $("#metric-train").textContent = formatNumber(stats?.metrics?.train_samples);
  if ($("#metric-test")) $("#metric-test").textContent = formatNumber(stats?.metrics?.test_samples);
  if ($("#metric-events")) $("#metric-events").textContent = formatNumber(total);

  if ($("#last-updated")) {
    $("#last-updated").textContent = new Date().toLocaleTimeString(
      [],
      { hour: "2-digit", minute: "2-digit", second: "2-digit" }
    );
  }

  renderTrafficChart(counts);
  renderTimelineChart(stats?.timeline);
  renderSeverityBreakdown(stats?.severities, total);
  renderTopSources(stats?.top_sources);
  renderPriorityAlerts(stats?.priority_alerts);
}

function renderTrafficChart(counts) {
  const canvas = $("#traffic-chart");
  if (!canvas || typeof Chart === "undefined") return;

  const labels = ["Normal", "DoS", "Probe", "Brute force"];
  const values = [
    counts.normal,
    counts.dos,
    counts.probe,
    counts.brute_force
  ];

  const colors = [
    CLASS_COLORS.normal,
    CLASS_COLORS.dos,
    CLASS_COLORS.probe,
    CLASS_COLORS.brute_force
  ];

  if (state.trafficChart) {
    state.trafficChart.data.datasets[0].data = values;
    state.trafficChart.update();
  } else {
    const isLight = document.documentElement.dataset.theme === "light";
    state.trafficChart = new Chart(canvas, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: isLight ? "#ffffff" : "#0f1929",
          borderWidth: 4,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "76%",
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: isLight ? "#ffffff" : "#142236",
            titleColor: isLight ? "#0e1929" : "#edf4ff",
            bodyColor: isLight ? "#435670" : "#8fa5c1",
            borderColor: isLight ? "#d2dde9" : "#23364d",
            borderWidth: 1,
            padding: 12
          }
        }
      }
    });
  }

  const total = values.reduce((sum, value) => sum + value, 0);
  const legend = $("#traffic-legend");

  if (!legend) return;

  if (total === 0) {
    legend.innerHTML =
      '<div class="empty-state small-empty">No events recorded yet.</div>';
    return;
  }

  legend.innerHTML = labels.map((label, index) => {
    const key = ["normal", "dos", "probe", "brute_force"][index];
    const value = values[index];
    const percent = total ? (value / total) * 100 : 0;

    return `
      <div class="legend-item clickable-legend" data-label="${key}" title="Click to filter ${escapeHTML(label)} in Query Center" style="cursor: pointer;">
        <span class="legend-color" style="background:${colors[index]}"></span>
        <div class="legend-copy">
          <strong>${escapeHTML(label)}</strong>
          <small>${percent.toFixed(1)}% of events</small>
        </div>
        <span class="legend-value">${formatNumber(value)}</span>
      </div>
    `;
  }).join("");
}

function renderTimelineChart(timeline = []) {
  const canvas = $("#timeline-chart");
  if (!canvas || typeof Chart === "undefined") return;

  const labels = timeline.length ? timeline.map(t => {
    const parts = (t.bucket || "").split(" ");
    return parts[1] || t.bucket;
  }) : ["No Data"];

  const totals = timeline.length ? timeline.map(t => t.total || 0) : [0];
  const threats = timeline.length ? timeline.map(t => t.threats || 0) : [0];

  const isLight = document.documentElement.dataset.theme === "light";

  if (state.timelineChart) {
    state.timelineChart.data.labels = labels;
    state.timelineChart.data.datasets[0].data = totals;
    state.timelineChart.data.datasets[1].data = threats;
    state.timelineChart.update();
  } else {
    state.timelineChart = new Chart(canvas, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Total Traffic",
            data: totals,
            borderColor: isLight ? "#1868d4" : "#58a6ff",
            backgroundColor: isLight ? "rgba(24, 104, 212, 0.08)" : "rgba(88, 166, 255, 0.1)",
            fill: true,
            tension: 0.35,
            pointRadius: 4,
            pointHoverRadius: 6
          },
          {
            label: "Threat Alerts",
            data: threats,
            borderColor: isLight ? "#d12c47" : "#ff667d",
            backgroundColor: isLight ? "rgba(209, 44, 71, 0.12)" : "rgba(255, 102, 125, 0.18)",
            fill: true,
            tension: 0.35,
            pointRadius: 4,
            pointHoverRadius: 6
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: "index", intersect: false },
        scales: {
          x: {
            grid: { color: isLight ? "rgba(0,0,0,0.05)" : "rgba(255,255,255,0.05)" },
            ticks: { color: isLight ? "#627690" : "#8b9ab1", font: { size: 10 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: isLight ? "rgba(0,0,0,0.05)" : "rgba(255,255,255,0.05)" },
            ticks: { color: isLight ? "#627690" : "#8b9ab1", font: { size: 10 }, precision: 0 }
          }
        },
        plugins: {
          legend: {
            display: true,
            position: "top",
            align: "end",
            labels: {
              boxWidth: 12,
              color: isLight ? "#0e1929" : "#edf3ff",
              font: { size: 11 }
            }
          }
        }
      }
    });
  }
}

function renderSeverityBreakdown(severities = {}, total = 0) {
  const container = $("#severity-breakdown-list");
  if (!container) return;

  const sevOrder = [
    { key: "critical", label: "Critical", class: "critical" },
    { key: "high", label: "High", class: "high" },
    { key: "medium", label: "Medium", class: "medium" },
    { key: "low", label: "Low", class: "low" },
    { key: "none", label: "None (Normal)", class: "none" }
  ];

  if (!total) {
    container.innerHTML = '<div class="empty-state small-empty">No events to compute severity distribution.</div>';
    return;
  }

  container.innerHTML = sevOrder.map(item => {
    const count = severities[item.key] || 0;
    const pct = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";
    return `
      <div class="severity-bar-item" data-sev="${item.key}" title="Click to filter ${item.label} in Query Center">
        <div class="severity-bar-meta">
          <span>${item.label}</span>
          <strong>${formatNumber(count)} (${pct}%)</strong>
        </div>
        <div class="severity-bar-track">
          <div class="severity-bar-fill ${item.class}" style="width: ${pct}%;"></div>
        </div>
      </div>
    `;
  }).join("");
}

function renderTopSources(topSources = []) {
  const container = $("#top-sources-list");
  if (!container) return;

  if (!topSources || !topSources.length) {
    container.innerHTML = '<div class="empty-state small-empty">No external source activity recorded.</div>';
    return;
  }

  container.innerHTML = topSources.slice(0, 5).map(s => `
    <div class="source-ip-item" data-src-ip="${escapeHTML(s.ip)}" title="Click to inspect intelligence profile for ${escapeHTML(s.ip)}">
      <strong>${escapeHTML(s.ip)}</strong>
      <div class="source-ip-counts">
        <span class="threat-count-chip">${s.threats} threat${s.threats === 1 ? '' : 's'}</span>
        <span>${s.total} total</span>
      </div>
    </div>
  `).join("");
}

function renderPriorityAlerts(alerts = []) {
  const tbody = $("#priority-alerts-tbody");
  if (!tbody) return;

  if (!alerts || !alerts.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No uninvestigated critical or high alerts. System clear.</td></tr>';
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr class="clickable-event-row" data-event-id="${escapeHTML(a.id)}">
      <td><span class="event-id">#${escapeHTML(a.id)}</span></td>
      <td><code class="ip-address">${escapeHTML(a.src_ip)}</code></td>
      <td>${classificationBadge(a.label)}</td>
      <td>${severityBadge(a.severity)}</td>
      <td>${a.confidence !== null ? confidenceCell(a.confidence) : '—'}</td>
      <td><span class="status-badge ${escapeHTML(a.investigation_status || 'new')}">${escapeHTML(a.investigation_status || 'new')}</span></td>
      <td>${a.ts ? formatDateTime(a.ts) : '—'}</td>
      <td><button type="button" class="button button-sm button-secondary button-inspect" data-event-id="${escapeHTML(a.id)}">Triage</button></td>
    </tr>
  `).join("");
}

/* =========================================================
   EVENTS AND TABLES
   ========================================================= */

function extractEvents(response) {
  if (Array.isArray(response)) return response;

  if (response && typeof response === "object") {
    if (Array.isArray(response.events)) return response.events;
    if (Array.isArray(response.data)) return response.data;
    if (Array.isArray(response.results)) return response.results;
    if (Array.isArray(response.recent_events)) return response.recent_events;
  }

  return [];
}

function severityBadge(severity) {
  const value = normalizeSeverity(severity, "");
  return `<span class="severity-badge ${escapeHTML(value)}">${escapeHTML(value)}</span>`;
}

function classificationBadge(label) {
  const key = normalizeClass(label);

  return `
        <span class="classification ${escapeHTML(key)}">
            ${escapeHTML(displayClass(key))}
        </span>
    `;
}

function confidenceCell(value) {
  if (value === null || value === undefined) {
    return '<span style="color:#75869e">—</span>';
  }

  const safeValue = Math.max(0, Math.min(100, Number(value)));

  return `
        <div class="confidence-cell">
            <span>${safeValue.toFixed(1)}%</span>
            <span class="mini-track"><span style="width:${safeValue}%"></span></span>
        </div>
    `;
}

function renderEventRows(events, targetSelector) {
  const tbody = $(targetSelector);
  if (!tbody) return;

  if (!events.length) {
    tbody.innerHTML =
      '<tr><td colspan="8" class="table-empty">No matching events found.</td></tr>';
    return;
  }

  tbody.innerHTML = events.map((event, index) => {
    const id = event.id ?? `EVT-${index + 1}`;
    const ip = event.src_ip || "Unknown";
    const status = event.investigation_status || event.status || "new";

    return `
      <tr data-event-id="${escapeHTML(id)}" class="clickable-event-row" title="Click to investigate event details">
        <td><span class="event-id">#${escapeHTML(id)}</span></td>
        <td><span class="ip-address">${escapeHTML(ip)}</span></td>
        <td>${classificationBadge(event.label)}</td>
        <td>${severityBadge(event.severity)}</td>
        <td>${confidenceCell(event.confidence)}</td>
        <td><span class="status-badge ${escapeHTML(status)}">${escapeHTML(status)}</span></td>
        <td>${escapeHTML(formatDateTime(event.timestamp))}</td>
        <td><button type="button" class="button button-sm button-secondary button-inspect" data-event-id="${escapeHTML(id)}">Inspect</button></td>
      </tr>
    `;
  }).join("");
}

function renderRecentActivity(events) {
  const container = $("#activity-list");
  if (!container) return;

  let displayEvents = events || [];
  if (state.savedSettings?.show_normal_events === false) {
    displayEvents = displayEvents.filter((e) => normalizeClass(e.label) !== "normal");
  }

  if (!displayEvents.length) {
    container.innerHTML =
      '<div class="empty-state">No events matching current visibility preferences. Use Simulate traffic or Traffic analyzer to generate a test event.</div>';
    return;
  }

  const limit = Math.max(3, state.savedSettings?.recent_events_limit || 5);
  container.innerHTML = displayEvents.slice(0, limit).map((event) => {
    const label = normalizeClass(event.label);
    const symbol = label === "normal"
      ? "✓"
      : label === "probe"
        ? "⌕"
        : "⌁";

    const confidence = event.confidence === null
      ? ""
      : ` · ${event.confidence.toFixed(1)}% confidence`;

    return `
            <div class="activity-item">
                <div class="activity-symbol ${escapeHTML(label)}">${symbol}</div>
                <div class="activity-copy">
                    <strong>${escapeHTML(displayClass(label))} detected</strong>
                    <small>${escapeHTML(event.src_ip)}${confidence}</small>
                </div>
                <span class="activity-time">${escapeHTML(formatTime(event.timestamp))}</span>
            </div>
        `;
  }).join("");
}

function renderAllEventViews() {
  const limit = Math.max(3, state.savedSettings?.recent_events_limit || 6);
  let recentEvents = state.events || [];
  if (state.savedSettings?.show_normal_events === false) {
    recentEvents = recentEvents.filter((e) => normalizeClass(e.label) !== "normal");
  }
  const recent = recentEvents.slice(0, limit);

  renderEventRows(recent, "#recent-events-body");
  renderRecentActivity(state.events);
  renderThreats();
}

function renderThreats() {
  const search = ($("#event-search")?.value || "").trim().toLowerCase();
  const typeFilter = $("#event-type-filter")?.value || "all";
  const severityFilter = $("#event-severity-filter")?.value || "all";

  const filtered = state.events.filter((event) => {
    const searchable = [
      event.id,
      event.src_ip,
      event.label,
      displayClass(event.label),
      event.severity,
      event.timestamp
    ].join(" ").toLowerCase();

    const matchesSearch = !search || searchable.includes(search);

    const matchesType =
      typeFilter === "all" ||
      normalizeClass(event.label) === typeFilter;

    const matchesSeverity =
      severityFilter === "all" ||
      normalizeSeverity(event.severity, event.label) === severityFilter;

    return matchesSearch && matchesType && matchesSeverity;
  });

  renderEventRows(filtered, "#all-events-body");

  const label = $("#event-count-label");
  if (label) {
    label.textContent = `${filtered.length} event${filtered.length === 1 ? "" : "s"}`;
  }
}

async function loadEvents() {
  try {
    const response = await apiRequest(API.events);
    const rawEvents = extractEvents(response);

    state.events = rawEvents.map(normalizeEvent);

    renderAllEventViews();
    return true;
  } catch (error) {
    console.error("Could not load events:", error);
    return false;
  }
}

/* =========================================================
   MODEL ANALYTICS
   ========================================================= */

function metricValue(map, key) {
  if (!map || map[key] === undefined || map[key] === null) {
    return null;
  }

  const value = Number(map[key]);

  if (!Number.isFinite(value)) return null;

  // Keep values on the same percentage scale as metrics.json.
  return value;
}

function renderAnalytics() {
  const stats = state.stats;
  const metrics = stats?.metrics || {};

  $("#analytics-source").textContent =
    metrics.source || "MODEL METRICS";

  const precision = metrics.precision || {};
  const recall = metrics.recall || {};
  const f1 = metrics.f1 || {};

  const classes = [
    ...new Set([
      ...Object.keys(precision),
      ...Object.keys(recall),
      ...Object.keys(f1)
    ])
  ];

  const tbody = $("#class-metrics-body");

  if (tbody) {
    if (!classes.length) {
      tbody.innerHTML =
        '<tr><td colspan="4" class="table-empty">Per-class metrics are not available from the backend.</td></tr>';
    } else {
      tbody.innerHTML = classes.map((key) => {
        const p = metricValue(precision, key);
        const r = metricValue(recall, key);
        const score = metricValue(f1, key);

        return `
                    <tr>
                        <td>${classificationBadge(key)}</td>
                        <td>${p === null ? "—" : formatPercent(p)}</td>
                        <td>${r === null ? "—" : formatPercent(r)}</td>
                        <td>${score === null ? "—" : formatPercent(score)}</td>
                    </tr>
                `;
      }).join("");
    }
  }

  renderImportanceChart(metrics.importance);
}

function renderImportanceChart(importance) {
  const canvas = $("#importance-chart");
  const empty = $("#importance-empty");

  if (!canvas || typeof Chart === "undefined") return;

  if (!Array.isArray(importance) || importance.length === 0) {
    canvas.classList.add("hidden");
    empty?.classList.remove("hidden");
    return;
  }

  const rows = importance
    .filter((item) => Array.isArray(item) && item.length >= 2)
    .slice(0, 10)
    .reverse();

  if (!rows.length) {
    canvas.classList.add("hidden");
    empty?.classList.remove("hidden");
    return;
  }

  canvas.classList.remove("hidden");
  empty?.classList.add("hidden");

  const labels = rows.map((row) =>
    FEATURE_NAMES[row[0]] || String(row[0])
  );

  const values = rows.map((row) => Number(row[1]) || 0);

  if (state.importanceChart) {
    state.importanceChart.destroy();
  }

  const isLight = document.documentElement.dataset.theme === "light";
  state.importanceChart = new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Importance",
        data: values,
        backgroundColor: values.map((_, index) =>
          index === values.length - 1 ? "#38d8e8" : "#438de7"
        ),
        borderRadius: 5,
        borderSkipped: false,
        barThickness: 15
      }]
    },
    options: {
      indexAxis: "y",
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: isLight ? "#ffffff" : "#142236",
          titleColor: isLight ? "#0e1929" : "#edf4ff",
          bodyColor: isLight ? "#435670" : "#8fa5c1",
          borderColor: isLight ? "#d2dde9" : "#23364d",
          borderWidth: 1,
          callbacks: {
            label: (context) =>
              ` Importance: ${Number(context.raw).toFixed(4)}`
          }
        }
      },
      scales: {
        x: {
          beginAtZero: true,
          grid: { color: isLight ? "#e2ebf4" : "#18283a" },
          ticks: {
            color: isLight ? "#435670" : "#8fa5c1",
            font: { size: 9 }
          },
          border: { display: false }
        },
        y: {
          grid: { display: false },
          ticks: {
            color: isLight ? "#0e1929" : "#b7c7db",
            font: { size: 10 }
          },
          border: { display: false }
        }
      }
    }
  });
}

/* =========================================================
   REFRESH
   ========================================================= */

async function refreshDashboard(showMessage = false) {
  if (state.refreshInProgress) return;

  state.refreshInProgress = true;

  try {
    const stats = await apiRequest(API.stats);

    if (!stats || typeof stats !== "object") {
      throw new Error("The statistics endpoint returned unexpected data.");
    }

    state.stats = stats;

    renderStats(stats);
    renderAnalytics();

    const eventsLoaded = await loadEvents();

    setConnectionStatus(true);
    await checkSystemHealth();

    if (showMessage) {
      showToast(
        eventsLoaded
          ? "Dashboard refreshed successfully."
          : "Statistics refreshed, but event history could not be loaded.",
        eventsLoaded ? "success" : "error"
      );
    }
  } catch (error) {
    console.error("Dashboard refresh failed:", error);
    setConnectionStatus(false, error.message);

    if (showMessage) {
      showToast(
        `Could not refresh dashboard: ${error.message}`,
        "error"
      );
    }
  } finally {
    state.refreshInProgress = false;
  }
}

/* =========================================================
   SIMULATE TRAFFIC
   ========================================================= */

async function simulateTraffic() {
  const button = $("#simulate-button");

  if (button) {
    button.disabled = true;
    button.textContent = "Generating...";
  }

  try {
    await apiRequest(API.simulate, { method: "GET" });
    await refreshDashboard(false);
    showToast("Simulation request completed.");
  } catch (error) {
    console.error("Simulation failed:", error);
    showToast(`Simulation failed: ${error.message}`, "error");
  } finally {
    if (button) {
      button.disabled = false;
      button.innerHTML = "<span>⚡</span> Simulate traffic";
    }
  }
}

/* =========================================================
   TRAFFIC ANALYZER
   ========================================================= */

function getFormPayload(form) {
  const payload = {};

  for (const [key, value] of new FormData(form).entries()) {
    if (!key) continue;

    const number = Number(value);

    if (!Number.isFinite(number)) {
      throw new Error(`Please enter a valid number for ${key}.`);
    }

    payload[key] = number;
  }

  const requiredKeys = Object.keys(FEATURE_NAMES);

  for (const key of requiredKeys) {
    if (!(key in payload)) {
      throw new Error(`Missing required feature: ${key}`);
    }
  }

  const rates = [
    "serror_rate",
    "rerror_rate",
    "same_srv_rate",
    "diff_srv_rate"
  ];

  for (const key of rates) {
    if (payload[key] < 0 || payload[key] > 1) {
      throw new Error(`${FEATURE_NAMES[key]} must be between 0 and 1.`);
    }
  }

  for (const [key, value] of Object.entries(payload)) {
    if (value < 0) {
      throw new Error(`${FEATURE_NAMES[key] || key} cannot be negative.`);
    }
  }

  return payload;
}

function renderAnalysisResult(response) {
  const data = response && typeof response === "object" ? response : {};

  const rawLabel =
    data.label ??
    data.prediction ??
    data.predicted_class ??
    data.classification ??
    data.result ??
    "unknown";

  const label = normalizeClass(rawLabel);

  const rawSeverity = data.severity;
  const severity = normalizeSeverity(rawSeverity, label);

  let confidence = getConfidence(data);

  if (confidence === null && data.probabilities && typeof data.probabilities === "object") {
    const values = Object.values(data.probabilities).map(Number).filter(Number.isFinite);

    if (values.length) {
      confidence = Math.max(...values);
      if (confidence <= 1) confidence *= 100;
    }
  }

  $("#analysis-placeholder")?.classList.add("hidden");
  $("#analysis-result")?.classList.remove("hidden");

  $("#result-class").textContent = displayClass(label);

  const severityElement = $("#result-severity");
  severityElement.textContent = severity;
  severityElement.className = `severity-badge ${severity}`;

  $("#result-confidence").textContent =
    confidence === null ? "Not provided" : formatPercent(confidence);

  $("#confidence-bar").style.width =
    `${confidence === null ? 0 : Math.max(0, Math.min(100, confidence))}%`;

  $("#result-ip").textContent =
    data.src_ip ?? data.source_ip ?? "Not provided";

  $("#result-id").textContent =
    data.id ?? data.event_id ?? "Prediction returned";

  const message = $("#result-message");

  if (label === "normal") {
    message.textContent =
      "The model classified the supplied features as normal traffic. This is a model prediction, not a guarantee that the connection is safe.";
  } else {
    message.textContent =
      `The model classified this input as ${displayClass(label)}. Review the supplied features and investigate further where appropriate.`;
  }
}

async function analyzeTraffic(event) {
  event.preventDefault();

  const form = $("#analyzer-form");
  const button = $("#analyze-button");

  let payload;

  try {
    payload = getFormPayload(form);
  } catch (error) {
    showToast(error.message, "error");
    return;
  }

  button.disabled = true;
  button.textContent = "Analyzing...";

  try {
    // Fetch CSRF token before making the state-changing POST request.
    const tokenResp = await fetch("/api/csrf-token", {
      credentials: "same-origin",
      cache: "no-store"
    });

    if (!tokenResp.ok) {
      throw new Error(`Could not fetch CSRF token (${tokenResp.status})`);
    }

    const tokenData = await tokenResp.json();
    const csrf = tokenData.csrf_token || "";

    if (!csrf) {
      throw new Error("CSRF token is missing. Please refresh the page and log in again.");
    }

    // The backend expects a flat JSON object containing the 12 features.
    const response = await apiRequest(API.predict, {
      method: "POST",
      body: JSON.stringify(payload),
      headers: { "X-CSRF-Token": csrf }
    });

    renderAnalysisResult(response);
    showToast("Traffic analysis completed.");

    await refreshDashboard(false);
  } catch (error) {
    console.error("Traffic analysis failed:", error);

    showToast(
      `Analysis failed: ${error.message}. Check the Flask terminal for details.`,
      "error"
    );
  } finally {
    button.disabled = false;
    button.textContent = "✦ Analyze traffic";
  }
}

/* =========================================================
   EVENT FILTERS
   ========================================================= */

function setupFilters() {
  $("#event-search")?.addEventListener("input", renderThreats);
  $("#event-type-filter")?.addEventListener("change", renderThreats);
  $("#event-severity-filter")?.addEventListener("change", renderThreats);

  $("#clear-filters")?.addEventListener("click", () => {
    $("#event-search").value = "";
    $("#event-type-filter").value = "all";
    $("#event-severity-filter").value = "all";
    renderThreats();
  });

  $("#threat-refresh")?.addEventListener("click", async () => {
    const success = await loadEvents();

    showToast(
      success ? "Events refreshed." : "Could not refresh event history.",
      success ? "success" : "error"
    );
  });
}

/* =========================================================
   RESET EVENT HISTORY
   ========================================================= */

async function resetEvents() {
  const confirmed = window.confirm(
    "Are you sure you want to reset recorded events? This may permanently clear event history from the application database."
  );

  if (!confirmed) return;

  const button = $("#reset-events");
  if (button) button.disabled = true;

  try {
    // Fetch CSRF token before making the state-changing POST request.
    const tokenResp = await fetch("/api/csrf-token", {
      credentials: "same-origin",
      cache: "no-store"
    });

    if (!tokenResp.ok) {
      throw new Error(`Could not fetch CSRF token (${tokenResp.status})`);
    }

    const tokenData = await tokenResp.json();
    const csrf = tokenData.csrf_token || "";

    if (!csrf) {
      throw new Error("CSRF token is missing. Please refresh the page and log in again.");
    }

    await apiRequest(API.reset, {
      method: "POST",
      headers: { "X-CSRF-Token": csrf }
    });

    await refreshDashboard(false);
    showToast("Reset request completed.");
  } catch (error) {
    console.error("Reset failed:", error);
    showToast(`Reset failed: ${error.message}`, "error");
  } finally {
    if (button) button.disabled = false;
  }
}

/* =========================================================
   LOGOUT
   ========================================================= */

async function handleLogout() {
  const confirmed = window.confirm("Are you sure you want to log out?");
  if (!confirmed) return;

  try {
    const tokenResp = await fetch("/api/csrf-token", {
      credentials: "same-origin",
      cache: "no-store"
    });

    if (!tokenResp.ok) {
      throw new Error(`Could not fetch CSRF token (${tokenResp.status})`);
    }

    const tokenData = await tokenResp.json();
    const csrf = tokenData.csrf_token || "";

    if (!csrf) {
      throw new Error("CSRF token is missing. Please refresh the page and log in again.");
    }

    const resp = await fetch("/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      }
    });

    if (resp.ok) {
      window.location.href = "/login";
    } else {
      const data = await resp.json();
      showToast(data.error || "Logout failed.", "error");
    }
  } catch (err) {
    console.error("Logout error:", err);
    showToast("Logout failed. Check your connection.", "error");
  }
}

/* =========================================================
   USER INFO
   ========================================================= */

async function loadUserInfo() {
  try {
    const data = await apiRequest("/api/me");
    const name = data.display_name || data.username || "User";
    const initials = name.split(" ").map(w => w[0]).join("").toUpperCase().slice(0, 2) || "TN";

    const avatarEl = $("#user-avatar");
    const nameEl = $("#user-display-name");
    const roleEl = $("#user-role-label");
    const topbarAvatar = $(".topbar-avatar");

    if (avatarEl) avatarEl.textContent = initials;
    if (nameEl) nameEl.textContent = name;
    if (roleEl) roleEl.textContent = data.is_admin ? "Administrator" : "Analyst";
    if (topbarAvatar) topbarAvatar.textContent = initials;
  } catch (err) {
    console.warn("Could not load user info:", err);
  }
}

/* =========================================================
   THREATNEX ENTERPRISE SETTINGS & CONFIGURATION CENTER
   ========================================================= */

// Notification history memory buffer
if (!state.notificationHistory) {
  state.notificationHistory = [];
}

function playNotificationChime() {
  if (state.savedSettings?.notification_sound !== true) return;
  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const audioCtx = new AudioCtx();
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
    osc.frequency.exponentialRampToValueAtTime(880, audioCtx.currentTime + 0.12); // A5
    gain.gain.setValueAtTime(0.12, audioCtx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.25);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start();
    osc.stop(audioCtx.currentTime + 0.25);
  } catch (e) {
    console.debug("Audio chime not allowed or unavailable:", e);
  }
}

function requestBrowserNotificationPermission() {
  if (!("Notification" in window)) {
    showToast("Native browser notifications are not supported in this environment.", "info");
    return;
  }
  Notification.requestPermission().then((perm) => {
    if (perm === "granted") {
      showToast("Browser notification permission granted.", "success");
    } else {
      showToast("Browser notification permission was denied.", "warning");
      const chk = $("#setting-browser-notifications");
      if (chk) chk.checked = false;
    }
  });
}

function addNotificationHistoryItem(item) {
  if (!state.notificationHistory) state.notificationHistory = [];
  state.notificationHistory.unshift(item);
  if (state.notificationHistory.length > 50) {
    state.notificationHistory.pop();
  }
  renderNotificationHistory();
}

function renderNotificationHistory() {
  const container = $("#notif-history-list");
  if (!container) return;
  if (!state.notificationHistory || !state.notificationHistory.length) {
    container.innerHTML = '<div class="empty-state small-empty" style="padding: 10px;">No recent notification alerts in buffer.</div>';
    return;
  }
  container.innerHTML = state.notificationHistory.slice(0, 15).map(item => `
    <div class="notif-history-item">
      <div style="display:flex; align-items:center; gap:8px;">
        <span class="severity-dot ${item.type === 'error' ? 'red' : item.type === 'warning' ? 'orange' : 'green'}"></span>
        <span>${escapeHTML(item.message)}</span>
      </div>
      <span class="notif-time">${formatTime(item.time)}</span>
    </div>
  `).join("");
}

function clearNotificationHistory() {
  const confirmMsg = "Are you sure you want to clear your local notification alert buffer?";
  if (state.savedSettings?.confirm_destructive && !window.confirm(confirmMsg)) {
    return;
  }
  state.notificationHistory = [];
  renderNotificationHistory();
  showToast("Notification history buffer cleared.", "info");
}

function applyTheme(theme) {
  let effective = theme;
  if (effective === "system") {
    const isDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    effective = isDark ? "dark" : "light";
  } else if (effective !== "light") {
    effective = "dark";
  }

  const isLight = effective === "light";
  document.documentElement.dataset.theme = effective;
  document.body.dataset.theme = effective;

  const themeColor = document.querySelector('meta[name="theme-color"]');
  if (themeColor) {
    themeColor.setAttribute("content", isLight ? "#f0f4f9" : "#070c16");
  }

  const ind = $("#theme-active-indicator");
  if (ind) ind.textContent = isLight ? "LIGHT ENTERPRISE" : "DARK SOC";

  const darkCard = $("#theme-card-dark");
  const lightCard = $("#theme-card-light");
  const systemCard = $("#theme-card-system");
  if (darkCard) darkCard.classList.toggle("active", theme === "dark");
  if (lightCard) lightCard.classList.toggle("active", theme === "light");
  if (systemCard) systemCard.classList.toggle("active", theme === "system");

  const selectEl = $("#setting-theme");
  if (selectEl && selectEl.value !== theme) {
    selectEl.value = theme;
  }

  // Update chart palettes if initialized
  if (state.trafficChart) {
    state.trafficChart.data.datasets[0].borderColor = isLight ? "#ffffff" : "#0f1929";
    state.trafficChart.update();
  }
}

function applyAppearancePreview(prefs) {
  if (!prefs) return;
  applyTheme(prefs.theme || "dark");

  const accent = prefs.accent_preset || "cyan";
  document.documentElement.dataset.accent = accent;
  document.body.dataset.accent = accent;

  const density = prefs.density || "comfortable";
  document.body.dataset.density = density;

  const fontSize = prefs.font_size || "normal";
  document.body.dataset.fontSize = fontSize;

  const tableDensity = prefs.table_row_density || "standard";
  $$("table").forEach(tbl => {
    tbl.classList.remove("table-dense", "table-spacious");
    if (tableDensity === "compact") tbl.classList.add("table-dense");
    else if (tableDensity === "spacious") tbl.classList.add("table-spacious");
  });

  const sidebarCollapsed = prefs.sidebar_state === "collapsed";
  document.body.classList.toggle("sidebar-collapsed", sidebarCollapsed);

  const reducedMotion = !!prefs.reduced_motion;
  document.body.classList.toggle("reduced-motion", reducedMotion);
}

function getFormSettings() {
  return {
    // 1. General
    display_name: $("#setting-display-name")?.value?.trim() || "",
    default_landing_page: $("#setting-default-landing-page")?.value || "overview",
    default_time_range: $("#setting-default-time-range")?.value || "all",
    timezone: $("#setting-timezone")?.value || "local",
    datetime_format: $("#setting-datetime-format")?.value || "YYYY-MM-DD HH:mm:ss",
    number_format: $("#setting-number-format")?.value || "en-US",
    density: $("#setting-density")?.value || "comfortable",
    page_size: parseInt($("#setting-page-size")?.value || "20", 10) || 20,
    confirm_destructive: $("#setting-confirm-destructive") ? $("#setting-confirm-destructive").checked : true,
    auto_refresh: $("#setting-auto-refresh") ? $("#setting-auto-refresh").checked : true,
    refresh_interval: parseInt($("#setting-refresh-interval")?.value || "10", 10) || 10,

    // 2. Appearance
    theme: $("#setting-theme")?.value || "dark",
    accent_preset: $("#setting-accent-preset")?.value || "cyan",
    font_size: $("#setting-font-size")?.value || "normal",
    table_row_density: $("#setting-table-row-density")?.value || "standard",
    sidebar_state: $("#setting-sidebar-state")?.value || "expanded",
    chart_animations: $("#setting-chart-animations") ? $("#setting-chart-animations").checked : true,
    reduced_motion: $("#setting-reduced-motion") ? $("#setting-reduced-motion").checked : false,

    // 3. Dashboard
    show_kpis: $("#setting-show-kpis") ? $("#setting-show-kpis").checked : true,
    show_timeline: $("#setting-show-timeline") ? $("#setting-show-timeline").checked : true,
    show_threat_donut: $("#setting-show-threat-donut") ? $("#setting-show-threat-donut").checked : true,
    show_severity_breakdown: $("#setting-show-severity-breakdown") ? $("#setting-show-severity-breakdown").checked : true,
    show_top_sources: $("#setting-show-top-sources") ? $("#setting-show-top-sources").checked : true,
    show_priority_alerts: $("#setting-show-priority-alerts") ? $("#setting-show-priority-alerts").checked : true,
    show_recent_activity: $("#setting-show-recent-activity") ? $("#setting-show-recent-activity").checked : true,
    show_model_metrics: $("#setting-show-model-metrics") ? $("#setting-show-model-metrics").checked : true,
    show_system_health: $("#setting-show-system-health") ? $("#setting-show-system-health").checked : true,
    show_normal_events: $("#setting-show-normal-events") ? $("#setting-show-normal-events").checked : true,
    recent_events_limit: parseInt($("#setting-recent-events-limit")?.value || "10", 10) || 10,

    // 4. Notifications
    enable_notifications: $("#setting-enable-notifications") ? $("#setting-enable-notifications").checked : true,
    notify_severity: $("#setting-notify-severity")?.value || "critical",
    notification_sound: $("#setting-notification-sound") ? $("#setting-notification-sound").checked : false,
    browser_notifications: $("#setting-browser-notifications") ? $("#setting-browser-notifications").checked : false,
    auto_dismiss_delay: parseInt($("#setting-auto-dismiss-delay")?.value || "5", 10) ?? 5,
    keep_alerts_until_ack: $("#setting-keep-alerts-until-ack") ? $("#setting-keep-alerts-until-ack").checked : false,

    // 5. Detection
    min_alert_confidence: parseInt($("#setting-min-alert-confidence")?.value || "70", 10) || 70,
    alert_threshold_mode: $("#setting-alert-threshold-mode")?.value || "balanced",
    default_severity_filter: $("#setting-default-severity-filter")?.value || "all",
    show_confidence_percentage: $("#setting-show-confidence-percentage") ? $("#setting-show-confidence-percentage").checked : true,
    detection_policy: $("#setting-detection-policy")?.value || "legacy",
    bf_probability_threshold: parseFloat($("#setting-bf-probability-threshold")?.value || "0.35") || 0.35,

    // 6. Query Center
    default_search_time: $("#setting-default-search-time")?.value || "all",
    default_query_page_size: parseInt($("#setting-default-query-page-size")?.value || "20", 10) || 20,
    default_sort_column: $("#setting-default-sort-column")?.value || "id",
    default_sort_order: $("#setting-default-sort-order")?.value || "DESC",
    default_query_severity: $("#setting-default-query-severity")?.value || "all",
    default_query_label: $("#setting-default-query-label")?.value || "all",
    query_show_optional_columns: $("#setting-query-show-optional-columns") ? $("#setting-query-show-optional-columns").checked : true,
    remember_last_filters: $("#setting-remember-last-filters") ? $("#setting-remember-last-filters").checked : true,
    remember_query_page_size: $("#setting-remember-query-page-size") ? $("#setting-remember-query-page-size").checked : true,
    export_delimiter: $("#setting-export-delimiter")?.value || ",",
    confirm_large_export: $("#setting-confirm-large-export") ? $("#setting-confirm-large-export").checked : true,

    // 7. Event Management
    default_investigation_status: $("#setting-default-investigation-status")?.value || "all",
    default_event_sort: $("#setting-default-event-sort")?.value || "id_desc",
    event_detail_layout: $("#setting-event-detail-layout")?.value || "modal",
    confirm_event_resolve: $("#setting-confirm-event-resolve") ? $("#setting-confirm-event-resolve").checked : true,
    show_feature_details_by_default: $("#setting-show-feature-details-by-default") ? $("#setting-show-feature-details-by-default").checked : false,
    default_investigation_view: $("#setting-default-investigation-view")?.value || "all",
    preserve_query_on_modal_close: $("#setting-preserve-query-on-modal-close") ? $("#setting-preserve-query-on-modal-close").checked : true,

    // 8. Data & Retention
    retention_policy_enabled: $("#setting-retention-policy-enabled") ? $("#setting-retention-policy-enabled").checked : false,
    retention_days: parseInt($("#setting-retention-days")?.value || "90", 10) || 90,

    // 9. Export & Reports
    default_export_format: $("#setting-default-export-format")?.value || "csv",
    csv_delimiter: $("#setting-csv-delimiter")?.value || ",",
    timestamp_export_format: $("#setting-timestamp-export-format")?.value || "iso8601",
    include_confidence: $("#setting-include-confidence") ? $("#setting-include-confidence").checked : true,
    include_severity_label: $("#setting-include-severity-label") ? $("#setting-include-severity-label").checked : true,
    include_event_id: $("#setting-include-event-id") ? $("#setting-include-event-id").checked : true,
    include_features: $("#setting-include-features") ? $("#setting-include-features").checked : true,
    include_filter_summary: $("#setting-include-filter-summary") ? $("#setting-include-filter-summary").checked : true,
    export_filename_prefix: $("#setting-export-filename-prefix")?.value?.trim() || "threatnex_events",
    default_report_date_range: $("#setting-default-report-date-range")?.value || "30d"
  };
}

function populateSettingsForm(s) {
  if (!s) return;

  const setVal = (id, val) => {
    const el = $(`#${id}`);
    if (el && val !== undefined && val !== null) el.value = val;
  };
  const setChk = (id, val) => {
    const el = $(`#${id}`);
    if (el) el.checked = !!val;
  };

  // 1. General
  setVal("setting-display-name", s.display_name ?? "");
  setVal("profile-display-name-input", s.display_name ?? "");
  setVal("setting-default-landing-page", s.default_landing_page || "overview");
  setVal("setting-default-time-range", s.default_time_range || "all");
  setVal("setting-timezone", s.timezone || "local");
  setVal("setting-datetime-format", s.datetime_format || "YYYY-MM-DD HH:mm:ss");
  setVal("setting-number-format", s.number_format || "en-US");
  setVal("setting-density", s.density || "comfortable");
  setVal("setting-page-size", s.page_size || 20);
  setChk("setting-confirm-destructive", s.confirm_destructive !== false);
  setChk("setting-auto-refresh", s.auto_refresh !== false);
  setVal("setting-refresh-interval", s.refresh_interval || 10);

  // 2. Appearance
  setVal("setting-theme", s.theme || "dark");
  setVal("setting-accent-preset", s.accent_preset || "cyan");
  setVal("setting-font-size", s.font_size || "normal");
  setVal("setting-table-row-density", s.table_row_density || "standard");
  setVal("setting-sidebar-state", s.sidebar_state || "expanded");
  setChk("setting-chart-animations", s.chart_animations !== false);
  setChk("setting-reduced-motion", !!s.reduced_motion);

  // 3. Dashboard
  setChk("setting-show-kpis", s.show_kpis !== false);
  setChk("setting-show-timeline", s.show_timeline !== false);
  setChk("setting-show-threat-donut", s.show_threat_donut !== false);
  setChk("setting-show-severity-breakdown", s.show_severity_breakdown !== false);
  setChk("setting-show-top-sources", s.show_top_sources !== false);
  setChk("setting-show-priority-alerts", s.show_priority_alerts !== false);
  setChk("setting-show-recent-activity", s.show_recent_activity !== false);
  setChk("setting-show-model-metrics", s.show_model_metrics !== false);
  setChk("setting-show-system-health", s.show_system_health !== false);
  setChk("setting-show-normal-events", s.show_normal_events !== false);
  setVal("setting-recent-events-limit", s.recent_events_limit || 10);

  // 4. Notifications
  setChk("setting-enable-notifications", s.enable_notifications !== false);
  setVal("setting-notify-severity", s.notify_severity || "critical");
  setChk("setting-notification-sound", !!s.notification_sound);
  setChk("setting-browser-notifications", !!s.browser_notifications);
  setVal("setting-auto-dismiss-delay", s.auto_dismiss_delay ?? 5);
  setChk("setting-keep-alerts-until-ack", !!s.keep_alerts_until_ack);

  // 5. Detection
  setVal("setting-min-alert-confidence", s.min_alert_confidence || 70);
  setVal("setting-alert-threshold-mode", s.alert_threshold_mode || "balanced");
  setVal("setting-default-severity-filter", s.default_severity_filter || "all");
  setChk("setting-show-confidence-percentage", s.show_confidence_percentage !== false);
  setVal("setting-detection-policy", s.detection_policy || "legacy");
  setVal("setting-bf-probability-threshold", s.bf_probability_threshold ?? 0.35);

  // 6. Query Center
  setVal("setting-default-search-time", s.default_search_time || "all");
  setVal("setting-default-query-page-size", s.default_query_page_size || 20);
  setVal("setting-default-sort-column", s.default_sort_column || "id");
  setVal("setting-default-sort-order", s.default_sort_order || "DESC");
  setVal("setting-default-query-severity", s.default_query_severity || "all");
  setVal("setting-default-query-label", s.default_query_label || "all");
  setChk("setting-query-show-optional-columns", s.query_show_optional_columns !== false);
  setChk("setting-remember-last-filters", s.remember_last_filters !== false);
  setChk("setting-remember-query-page-size", s.remember_query_page_size !== false);
  setVal("setting-export-delimiter", s.export_delimiter || ",");
  setChk("setting-confirm-large-export", s.confirm_large_export !== false);

  // 7. Event Management
  setVal("setting-default-investigation-status", s.default_investigation_status || "all");
  setVal("setting-default-event-sort", s.default_event_sort || "id_desc");
  setVal("setting-event-detail-layout", s.event_detail_layout || "modal");
  setChk("setting-confirm-event-resolve", s.confirm_event_resolve !== false);
  setChk("setting-show-feature-details-by-default", !!s.show_feature_details_by_default);
  setVal("setting-default-investigation-view", s.default_investigation_view || "all");
  setChk("setting-preserve-query-on-modal-close", s.preserve_query_on_modal_close !== false);

  // 8. Data & Retention
  setChk("setting-retention-policy-enabled", !!s.retention_policy_enabled);
  setVal("setting-retention-days", s.retention_days || 90);

  // 9. Export & Reports
  setVal("setting-default-export-format", s.default_export_format || "csv");
  setVal("setting-csv-delimiter", s.csv_delimiter || ",");
  setVal("setting-timestamp-export-format", s.timestamp_export_format || "iso8601");
  setChk("setting-include-confidence", s.include_confidence !== false);
  setChk("setting-include-severity-label", s.include_severity_label !== false);
  setChk("setting-include-event-id", s.include_event_id !== false);
  setChk("setting-include-features", s.include_features !== false);
  setChk("setting-include-filter-summary", s.include_filter_summary !== false);
  setVal("setting-export-filename-prefix", s.export_filename_prefix || "threatnex_events");
  setVal("setting-default-report-date-range", s.default_report_date_range || "30d");
}

function checkSettingsDirty() {
  if (!state.savedSettings) return false;
  const current = getFormSettings();
  let isDirty = false;

  for (const [key, val] of Object.entries(current)) {
    if (state.savedSettings[key] !== undefined && state.savedSettings[key] !== val) {
      isDirty = true;
      break;
    }
  }

  const pill = $("#unsaved-status-pill");
  const banner = $("#settings-unsaved-banner");
  if (pill) pill.style.display = isDirty ? "inline-flex" : "none";
  if (banner) banner.style.display = isDirty ? "flex" : "none";

  return isDirty;
}

let autoRefreshTimer = null;

function applyAutoRefreshSettings() {
  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
  const enabled = state.savedSettings?.auto_refresh !== false;
  const intervalSec = Math.max(5, state.savedSettings?.refresh_interval || 10);
  if (enabled) {
    autoRefreshTimer = setInterval(() => {
      refreshDashboard(false);
    }, intervalSec * 1000);
  }
}

function applyDashboardPreferences() {
  const s = state.savedSettings || {};
  const kpiEl = $("#dash-widget-kpis");
  const timelineEl = $("#dash-widget-timeline");
  const donutEl = $("#dash-widget-donut");
  const sevEl = $("#dash-widget-severity");
  const srcEl = $("#dash-widget-top-sources");
  const priorityEl = $("#dash-widget-priority-alerts");
  const recentEl = $("#dash-widget-recent-activity");

  if (kpiEl) kpiEl.style.display = s.show_kpis !== false ? "" : "none";
  if (timelineEl) timelineEl.style.display = s.show_timeline !== false ? "" : "none";
  if (donutEl) donutEl.style.display = s.show_threat_donut !== false ? "" : "none";
  if (sevEl) sevEl.style.display = s.show_severity_breakdown !== false ? "" : "none";
  if (srcEl) srcEl.style.display = s.show_top_sources !== false ? "" : "none";
  if (priorityEl) priorityEl.style.display = s.show_priority_alerts !== false ? "" : "none";
  if (recentEl) recentEl.style.display = s.show_recent_activity !== false ? "" : "none";

  const midGrid = $("#dash-widget-middle-grid");
  if (midGrid) {
    const allMidHidden = (s.show_threat_donut === false) && (s.show_severity_breakdown === false) && (s.show_top_sources === false);
    midGrid.style.display = allMidHidden ? "none" : "";
  }
}

function applyAllSavedSettings() {
  if (!state.savedSettings) return;
  applyAppearancePreview(state.savedSettings);
  applyAutoRefreshSettings();
  applyDashboardPreferences();

  // User display name propagation
  const name = state.savedSettings.display_name;
  const displayNameEl = $("#user-display-name");
  if (displayNameEl) {
    if (name) {
      displayNameEl.textContent = name;
      const initials = name.split(" ").map(w => w[0]).join("").toUpperCase().slice(0, 2) || "TN";
      const avatarEl = $("#user-avatar");
      const topbarAvatar = $(".topbar-avatar");
      if (avatarEl) avatarEl.textContent = initials;
      if (topbarAvatar) topbarAvatar.textContent = initials;
    } else {
      loadUserInfo();
    }
  }
}

async function loadSettings() {
  try {
    const data = await apiRequest("/api/settings");
    const incoming = data.settings || data;
    state.savedSettings = { ...incoming };

    // Validate and sync theme & accent with localStorage
    const savedTheme = state.savedSettings.theme;
    if (savedTheme === "dark" || savedTheme === "light" || savedTheme === "system") {
      try {
        localStorage.setItem("threatnex_theme", savedTheme);
      } catch (e) {}
    }
    const savedAccent = state.savedSettings.accent_preset;
    if (savedAccent) {
      try {
        localStorage.setItem("threatnex_accent", savedAccent);
      } catch (e) {}
    }

    populateSettingsForm(state.savedSettings);
    applyAllSavedSettings();
    checkSettingsDirty();

    // Also populate System Information and security diagnostics
    loadSystemInfo();
  } catch (err) {
    console.warn("Could not load settings:", err);
  }
}

async function saveSettings() {
  const current = getFormSettings();

  // Client validation
  if (current.page_size < 5 || current.page_size > 200) {
    showToast("Page size must be between 5 and 200.", "error");
    return;
  }
  if (current.refresh_interval < 5 || current.refresh_interval > 300) {
    showToast("Refresh interval must be between 5 and 300 seconds.", "error");
    return;
  }
  if (current.min_alert_confidence < 50 || current.min_alert_confidence > 99) {
    showToast("Minimum alert confidence must be between 50% and 99%.", "error");
    return;
  }
  if (current.export_filename_prefix && !/^[a-zA-Z0-9_\-]{1,40}$/.test(current.export_filename_prefix)) {
    showToast("Export filename prefix must be alphanumeric (up to 40 characters).", "error");
    return;
  }

  const saveBtns = [$("#save-settings"), $("#save-settings-top-btn")];
  saveBtns.forEach(b => { if (b) b.disabled = true; });

  try {
    const tokenResp = await fetch("/api/csrf-token", { credentials: "same-origin", cache: "no-store" });
    if (!tokenResp.ok) throw new Error("Could not acquire security CSRF token.");
    const tokenData = await tokenResp.json();
    const csrf = tokenData.csrf_token || "";

    const res = await fetch("/api/settings", {
      method: "PUT",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify({ settings: current })
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.error || `Settings update failed with status ${res.status}`);
    }

    const resData = await res.json();
    state.savedSettings = resData.settings || current;

    const savedTheme = state.savedSettings.theme;
    if (savedTheme === "dark" || savedTheme === "light" || savedTheme === "system") {
      try {
        localStorage.setItem("threatnex_theme", savedTheme);
      } catch (e) {}
    }
    const savedAccent = state.savedSettings.accent_preset;
    if (savedAccent) {
      try {
        localStorage.setItem("threatnex_accent", savedAccent);
      } catch (e) {}
    }

    applyAllSavedSettings();
    checkSettingsDirty();
    showToast("All settings saved and applied successfully.", "success");
    await loadUserInfo();
  } catch (err) {
    console.error("Save settings error:", err);
    showToast(`Failed to save settings: ${err.message}`, "error");
  } finally {
    saveBtns.forEach(b => { if (b) b.disabled = false; });
  }
}

function cancelSettingsChanges() {
  if (!state.savedSettings) return;
  populateSettingsForm(state.savedSettings);
  applyAllSavedSettings();
  checkSettingsDirty();
  showToast("Reverted all unsaved changes to previously saved settings.", "info");
}

async function resetSectionSettings(sectionName) {
  if (!sectionName) return;
  if (state.savedSettings?.confirm_destructive) {
    const proceed = window.confirm(`Reset section "${sectionName}" preferences to factory defaults?`);
    if (!proceed) return;
  }

  try {
    const tokenResp = await fetch("/api/csrf-token", { credentials: "same-origin", cache: "no-store" });
    const tokenData = await tokenResp.json();
    const csrf = tokenData.csrf_token || "";

    const res = await fetch("/api/settings/reset", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify({ section: sectionName })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Reset failed.");
    }

    const data = await res.json();
    state.savedSettings = data.settings || state.savedSettings;

    if (state.savedSettings.theme) {
      try {
        localStorage.setItem("threatnex_theme", state.savedSettings.theme);
      } catch (e) {}
    }
    if (state.savedSettings.accent_preset) {
      try {
        localStorage.setItem("threatnex_accent", state.savedSettings.accent_preset);
      } catch (e) {}
    }

    populateSettingsForm(state.savedSettings);
    applyAllSavedSettings();
    checkSettingsDirty();
    showToast(`Section "${sectionName}" reset to factory defaults.`, "success");
    await loadUserInfo();
  } catch (err) {
    console.error("Reset section error:", err);
    showToast(`Could not reset section: ${err.message}`, "error");
  }
}

async function resetAllSettings() {
  const proceed = window.confirm("Are you sure you want to reset ALL personal preferences to factory defaults?\n\nThis will only reset your UI and operational preferences. Your event telemetry and user accounts are strictly preserved.");
  if (!proceed) return;

  try {
    const tokenResp = await fetch("/api/csrf-token", { credentials: "same-origin", cache: "no-store" });
    const tokenData = await tokenResp.json();
    const csrf = tokenData.csrf_token || "";

    const res = await fetch("/api/settings/reset", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify({})
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Reset all failed.");
    }

    const data = await res.json();
    state.savedSettings = data.settings || state.savedSettings;

    if (state.savedSettings.theme) {
      try {
        localStorage.setItem("threatnex_theme", state.savedSettings.theme);
      } catch (e) {}
    }
    if (state.savedSettings.accent_preset) {
      try {
        localStorage.setItem("threatnex_accent", state.savedSettings.accent_preset);
      } catch (e) {}
    }

    populateSettingsForm(state.savedSettings);
    applyAllSavedSettings();
    checkSettingsDirty();
    showToast("All preferences reset to factory defaults.", "success");
    await loadUserInfo();
  } catch (err) {
    console.error("Reset all error:", err);
    showToast(`Reset failed: ${err.message}`, "error");
  }
}

async function loadSystemInfo() {
  try {
    const data = await apiRequest("/api/system/info");
    if (!data) return;

    if ($("#sysinfo-platform")) $("#sysinfo-platform").textContent = data.platform_version || "THREATNEX AI-IDS v2.4.0";
    if ($("#sysinfo-python")) $("#sysinfo-python").textContent = `Python ${data.python_version || "3.12+"}`;
    if ($("#sysinfo-os")) $("#sysinfo-os").textContent = data.os || "SOC Host";
    if ($("#sysinfo-flask")) $("#sysinfo-flask").textContent = data.flask_version || "Flask 3.x";
    if ($("#sysinfo-sklearn")) $("#sysinfo-sklearn").textContent = `Scikit-learn ${data.sklearn_version || ""}`;
    if ($("#sysinfo-model")) $("#sysinfo-model").textContent = data.ml_engine?.type || "RandomForestClassifier (100 Trees)";
    if ($("#sysinfo-features")) $("#sysinfo-features").textContent = `${data.ml_engine?.feature_count || 12} Connection Summary Attributes`;
    if ($("#sysinfo-dataset")) $("#sysinfo-dataset").textContent = data.ml_engine?.evaluation_dataset || "NSL-KDD Standard Partition";
    if ($("#sysinfo-db")) $("#sysinfo-db").textContent = data.database?.status || "SQLite3 Connected";

    if ($("#sysinfo-modelfile") && data.ml_engine) {
      $("#sysinfo-modelfile").textContent = `model.joblib (${data.ml_engine.model_file_size || 'Ready'})`;
    }
    if ($("#det-model-timestamp") && data.ml_engine?.last_trained) {
      $("#det-model-timestamp").textContent = data.ml_engine.last_trained;
    }
    if ($("#det-model-availability") && data.ml_engine) {
      $("#det-model-availability").textContent = `Loaded (model.joblib, ${data.ml_engine.model_file_size || 'Ready'})`;
    }
    if ($("#cand-model-availability") && data.candidate_model) {
      const cm = data.candidate_model;
      $("#cand-model-availability").textContent = `${cm.status} (${cm.file_name}, ${cm.file_size})`;
      $("#cand-model-availability").className = cm.ready ? "text-green" : "text-amber";
    }
    if ($("#sysinfo-candidate-model") && data.candidate_model) {
      const cm = data.candidate_model;
      $("#sysinfo-candidate-model").textContent = `${cm.file_name} (${cm.file_size}, ${cm.status})`;
      $("#sysinfo-candidate-model").className = cm.ready ? "text-green" : "text-amber";
    }
    if ($("#sysinfo-policy") && data.detection_policy) {
      const dp = data.detection_policy;
      const polNames = { legacy: "Legacy (Argmax Baseline)", shadow: "Shadow Mode (Authoritative + Shadow)", experimental: "Experimental (Threshold Override)" };
      $("#sysinfo-policy").textContent = `${polNames[dp.active_policy] || dp.active_policy} (τ=${dp.threshold})`;
    }

    if (data.ml_engine?.metrics) {
      const m = data.ml_engine.metrics;
      if ($("#sysinfo-accuracy")) $("#sysinfo-accuracy").textContent = `${((m.accuracy || 0.998) * 100).toFixed(1)}%`;
      if ($("#sysinfo-f1")) $("#sysinfo-f1").textContent = `${((m.f1 || 0.998) * 100).toFixed(1)}%`;
    }

    if ($("#sysinfo-backup")) {
      if (data.backup?.verified) {
        $("#sysinfo-backup").textContent = `${data.backup.name} (${data.backup.count} backups verified)`;
        $("#sysinfo-backup").className = "text-green";
      } else {
        $("#sysinfo-backup").textContent = "Verified Backup Active";
      }
    }

    // Database statistics in Section 8
    if (data.database) {
      if ($("#db-stat-status")) $("#db-stat-status").textContent = "Connected";
      if ($("#db-stat-total-events")) $("#db-stat-total-events").textContent = formatNumber(data.database.total_events || 0);
      if ($("#db-stat-size")) $("#db-stat-size").textContent = data.database.size_formatted || "40.0 KB";
    }

    // Security info in Section 10
    if ($("#sec-csrf-status")) $("#sec-csrf-status").textContent = data.csrf_protection || "Active (X-CSRF-Token Enforced)";
    if ($("#sec-user-id")) $("#sec-user-id").textContent = `#${state.currentUser?.id || 1}`;
    if ($("#sec-username")) $("#sec-username").textContent = state.currentUser?.username || "admin";
    if ($("#sec-role")) $("#sec-role").textContent = state.currentUser?.role || "Administrator";

    // Profile info in Section 11
    if ($("#profile-username-display")) $("#profile-username-display").value = state.currentUser?.username || "admin";
    if ($("#profile-role-display")) $("#profile-role-display").value = state.currentUser?.role || "Administrator";
  } catch (err) {
    console.debug("System info load skipped:", err);
  }
}

async function handlePasswordChange() {
  const currentPassword = $("#chg-current-password")?.value || "";
  const newPassword = $("#chg-new-password")?.value || "";
  const confirmPassword = $("#chg-confirm-password")?.value || "";
  const statusEl = $("#chg-password-status");

  if (!currentPassword || !newPassword || !confirmPassword) {
    showToast("Please fill in all password fields.", "error");
    if (statusEl) { statusEl.textContent = "All fields required."; statusEl.className = "text-red"; }
    return;
  }
  if (newPassword !== confirmPassword) {
    showToast("New passwords do not match.", "error");
    if (statusEl) { statusEl.textContent = "Passwords do not match."; statusEl.className = "text-red"; }
    return;
  }
  if (newPassword.length < 6) {
    showToast("New password must be at least 6 characters.", "error");
    if (statusEl) { statusEl.textContent = "Minimum 6 characters."; statusEl.className = "text-red"; }
    return;
  }

  const btn = $("#chg-password-btn");
  if (btn) btn.disabled = true;

  try {
    const tokenResp = await fetch("/api/csrf-token", { credentials: "same-origin", cache: "no-store" });
    const tokenData = await tokenResp.json();
    const csrf = tokenData.csrf_token || "";

    const res = await fetch("/api/account/change-password", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Password update failed.");

    $("#chg-current-password").value = "";
    $("#chg-new-password").value = "";
    $("#chg-confirm-password").value = "";

    showToast("Account password updated successfully.", "success");
    if (statusEl) { statusEl.textContent = "✓ Password updated."; statusEl.className = "text-green"; }
  } catch (err) {
    showToast(err.message, "error");
    if (statusEl) { statusEl.textContent = `✗ ${err.message}`; statusEl.className = "text-red"; }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function handleDataCleanup() {
  const days = parseInt($("#setting-retention-days")?.value || "90", 10);
  const proceed = window.confirm(`Execute manual retention cleanup?\n\nThis will permanently delete historical telemetry events older than ${days} days.\nUser accounts, settings, and ML model weights are strictly preserved.`);
  if (!proceed) return;

  try {
    const tokenResp = await fetch("/api/csrf-token", { credentials: "same-origin", cache: "no-store" });
    const tokenData = await tokenResp.json();
    const csrf = tokenData.csrf_token || "";

    const res = await fetch("/api/data/cleanup", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ confirm_purge: true, retention_days: days })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Cleanup failed.");

    showToast(`Retention cleanup completed: ${data.purged_count} historical events purged.`, "success");
    loadSystemInfo();
    refreshDashboard(false);
  } catch (err) {
    showToast(`Cleanup failed: ${err.message}`, "error");
  }
}

function setupSettingsSearch() {
  const searchInput = $("#settings-search-input");
  const clearBtn = $("#settings-search-clear");
  if (!searchInput) return;

  searchInput.addEventListener("input", (e) => {
    const q = e.target.value.trim().toLowerCase();
    if (clearBtn) clearBtn.style.display = q ? "block" : "none";

    const cards = $$(".settings-section-card");
    let matchCount = 0;
    let firstMatch = null;

    cards.forEach(card => {
      card.classList.remove("search-highlight");
      if (!q) {
        card.classList.remove("search-hidden");
        return;
      }
      const text = card.textContent.toLowerCase();
      const matches = text.includes(q);
      if (matches) {
        card.classList.remove("search-hidden");
        card.classList.add("search-highlight");
        matchCount++;
        if (!firstMatch) firstMatch = card;
      } else {
        card.classList.add("search-hidden");
      }
    });

    if (q && firstMatch) {
      firstMatch.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      searchInput.value = "";
      clearBtn.style.display = "none";
      $$(".settings-section-card").forEach(c => {
        c.classList.remove("search-hidden", "search-highlight");
      });
    });
  }
}

function setupSettingsNavigation() {
  const navItems = $$(".settings-nav-item");
  navItems.forEach(item => {
    item.addEventListener("click", () => {
      navItems.forEach(i => i.classList.remove("active"));
      item.classList.add("active");

      const targetId = item.dataset.target;
      const targetCard = $(`#${targetId}`);
      if (targetCard) {
        targetCard.classList.remove("search-hidden");
        targetCard.scrollIntoView({ behavior: "smooth", block: "start" });
        targetCard.classList.add("search-highlight");
        setTimeout(() => {
          targetCard.classList.remove("search-highlight");
        }, 1500);
      }
    });
  });

  // Watch for input changes across all settings forms to enable live preview and dirty indicator
  const settingsWrapper = $("#settings-sections-wrapper");
  if (settingsWrapper) {
    settingsWrapper.addEventListener("change", (e) => {
      const current = getFormSettings();
      // Apply immediate live preview for appearance controls
      if (e.target.closest("#setsec-appearance")) {
        applyAppearancePreview(current);
      }
      checkSettingsDirty();
    });

    settingsWrapper.addEventListener("input", (e) => {
      checkSettingsDirty();
    });
  }

  // Reset section buttons
  $$(".reset-sec-btn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const sec = btn.dataset.sec;
      if (sec) resetSectionSettings(sec);
    });
  });

  $("#reset-current-section-btn")?.addEventListener("click", () => {
    const activeItem = $(".settings-nav-item.active");
    const targetId = activeItem?.dataset?.target || "";
    const sec = targetId.replace("setsec-", "");
    if (sec) resetSectionSettings(sec);
  });

  $("#reset-all-settings-btn")?.addEventListener("click", resetAllSettings);
  $("#reset-personal-prefs-btn")?.addEventListener("click", resetAllSettings);

  // Save & Cancel buttons
  $("#save-settings-top-btn")?.addEventListener("click", saveSettings);
  $("#save-settings")?.addEventListener("click", saveSettings);
  $("#cancel-settings-top-btn")?.addEventListener("click", cancelSettingsChanges);
  $("#cancel-settings")?.addEventListener("click", cancelSettingsChanges);

  // Two-way synchronization of display name inputs
  const settingDisplayInput = $("#setting-display-name");
  const profileDisplayInput = $("#profile-display-name-input");
  if (settingDisplayInput && profileDisplayInput) {
    settingDisplayInput.addEventListener("input", (e) => {
      profileDisplayInput.value = e.target.value;
    });
    profileDisplayInput.addEventListener("input", (e) => {
      settingDisplayInput.value = e.target.value;
    });
  }

  // Setting theme dropdown change
  $("#setting-theme")?.addEventListener("change", () => {
    applyAppearancePreview(getFormSettings());
    checkSettingsDirty();
  });

  // Theme cards click
  $("#theme-card-dark")?.addEventListener("click", () => {
    const themeSelect = $("#setting-theme");
    if (themeSelect) themeSelect.value = "dark";
    applyAppearancePreview(getFormSettings());
    checkSettingsDirty();
  });
  $("#theme-card-light")?.addEventListener("click", () => {
    const themeSelect = $("#setting-theme");
    if (themeSelect) themeSelect.value = "light";
    applyAppearancePreview(getFormSettings());
    checkSettingsDirty();
  });
  $("#theme-card-system")?.addEventListener("click", () => {
    const themeSelect = $("#setting-theme");
    if (themeSelect) themeSelect.value = "system";
    applyAppearancePreview(getFormSettings());
    checkSettingsDirty();
  });

  // Test notification button
  $("#test-notification-btn")?.addEventListener("click", () => {
    showToast("🔔 Test Notification: System operational (Synthetic Chime Verified)", "warning", true);
  });

  // Browser notifications toggle
  $("#setting-browser-notifications")?.addEventListener("change", (e) => {
    if (e.target.checked) requestBrowserNotificationPermission();
  });

  // Clear notification history button
  $("#clear-notif-history-btn")?.addEventListener("click", clearNotificationHistory);

  // Security password change button
  $("#chg-password-btn")?.addEventListener("click", handlePasswordChange);

  // Profile save button
  $("#save-profile-btn")?.addEventListener("click", async () => {
    const name = $("#profile-display-name-input")?.value?.trim() || "";
    const setDisplayName = $("#setting-display-name");
    if (setDisplayName) setDisplayName.value = name;
    await saveSettings();
  });

  // Profile signout button
  $("#profile-signout-btn")?.addEventListener("click", handleLogout);

  // Data cleanup execution
  $("#execute-data-cleanup-btn")?.addEventListener("click", handleDataCleanup);

  // Refresh diagnostics button
  $("#refresh-sysinfo-btn")?.addEventListener("click", () => {
    loadSystemInfo();
    showToast("System diagnostics refreshed.", "info");
  });

  setupSettingsSearch();
}

/* =========================================================
   EVENT INVESTIGATION CONSOLE & MODALS
   ========================================================= */

async function openEventModal(eventId) {
  if (!eventId) return;

  const modalBackdrop = $("#event-modal-backdrop");
  if (!modalBackdrop) return;

  $("#modal-event-id").textContent = eventId;
  $("#modal-src-ip").textContent = "Retrieving...";
  $("#modal-timestamp").textContent = "Retrieving...";
  $("#modal-classification-badge").innerHTML = "";
  $("#modal-severity-badge").innerHTML = "";
  $("#modal-confidence-badge").textContent = "...";
  $("#modal-features-grid").innerHTML = '<div class="empty-state">Loading NSL-KDD feature matrix...</div>';
  $("#modal-raw-json").textContent = "Loading...";
  if ($("#modal-triage-status")) $("#modal-triage-status").textContent = "";

  modalBackdrop.classList.add("active");
  modalBackdrop.classList.toggle("modal-as-drawer", state.savedSettings?.inv_detail_presentation === "drawer");

  try {
    let eventData = null;
    const numId = parseInt(eventId, 10);
    if (!isNaN(numId)) {
      try {
        eventData = await apiRequest(`/api/events/${numId}`);
      } catch (e) {
        console.warn("Direct event endpoint lookup fallback:", e);
      }
    }

    if (!eventData) {
      const cached = state.events.find(e => String(e.id) === String(eventId));
      if (cached) {
        eventData = {
          id: cached.id,
          ts: cached.timestamp,
          src_ip: cached.src_ip,
          label: cached.label,
          severity: cached.severity,
          confidence: cached.confidence,
          investigation_status: cached.original?.investigation_status || "new",
          analyst_notes: cached.original?.analyst_notes || "",
          features: cached.original?.features || {}
        };
      }
    }

    if (!eventData) {
      throw new Error(`Record for Event #${eventId} could not be retrieved.`);
    }

    state.activeModalEvent = eventData;

    $("#modal-event-id").textContent = eventData.id;
    $("#modal-src-ip").textContent = eventData.src_ip || "Unknown";
    $("#modal-timestamp").textContent = formatDateTime(eventData.ts || eventData.timestamp);
    $("#modal-classification-badge").innerHTML = classificationBadge(eventData.label);
    $("#modal-severity-badge").innerHTML = severityBadge(eventData.severity);
    $("#modal-confidence-badge").textContent = eventData.confidence !== undefined && eventData.confidence !== null
      ? `${Number(eventData.confidence).toFixed(1)}% Confidence`
      : "—";

    const pol = eventData.detection_policy || eventData.features?._detection_policy;
    if ($("#modal-policy-badge")) {
      if (pol) {
        if (pol.mode === "shadow") {
          const matchColor = pol.diverged ? "var(--orange)" : "var(--green)";
          const matchStatus = pol.diverged ? "DIVERGENCE" : "MATCH";
          $("#modal-policy-badge").innerHTML = `<span class="badge" style="background:rgba(0,229,255,0.12); color:var(--cyan); border:1px solid rgba(0,229,255,0.3);">Shadow Mode</span> <span class="badge" style="border:1px solid ${matchColor}; color:${matchColor}">Candidate: ${pol.candidate_label} (${matchStatus} | P(bf)=${((pol.candidate_bf_prob || 0)*100).toFixed(1)}%)</span>`;
        } else if (pol.mode === "experimental") {
          $("#modal-policy-badge").innerHTML = `<span class="badge" style="background:rgba(255,183,77,0.15); color:var(--orange); border:1px solid rgba(255,183,77,0.3);">Experimental Policy (τ=${pol.threshold})</span>`;
        } else {
          $("#modal-policy-badge").innerHTML = `<span class="badge" style="background:rgba(255,255,255,0.06); color:var(--text-dim); border:1px solid var(--border-soft);">Legacy Baseline</span>`;
        }
        $("#modal-policy-badge").style.display = "";
      } else {
        $("#modal-policy-badge").style.display = "none";
      }
    }

    if ($("#modal-inv-status")) {
      $("#modal-inv-status").value = eventData.investigation_status || "new";
    }
    if ($("#modal-analyst-notes")) {
      $("#modal-analyst-notes").value = eventData.analyst_notes || "";
    }

    const featuresSection = $("#modal-features-grid")?.closest(".investigation-section");
    if (featuresSection) {
      featuresSection.style.display = state.savedSettings?.inv_show_features !== false ? "" : "none";
    }

    const features = (eventData.features && typeof eventData.features === "object") ? eventData.features : {};
    const featureKeys = Object.keys(FEATURE_NAMES);

    const featureHtml = featureKeys.map(key => {
      const label = FEATURE_NAMES[key] || key;
      const rawVal = features[key];
      let displayVal = "—";
      if (rawVal !== undefined && rawVal !== null) {
        displayVal = typeof rawVal === "number"
          ? (Number.isInteger(rawVal) ? rawVal : Number(rawVal).toFixed(4))
          : String(rawVal);
      }
      return `
        <div class="feature-item">
          <div class="feature-info">
            <span class="feature-label">${escapeHTML(label)}</span>
            <span class="feature-key">${escapeHTML(key)}</span>
          </div>
          <span class="feature-val">${escapeHTML(displayVal)}</span>
        </div>
      `;
    }).join("");

    $("#modal-features-grid").innerHTML = featureHtml || '<div class="empty-state">No feature attributes available.</div>';
    $("#modal-raw-json").textContent = JSON.stringify(eventData, null, 2);

  } catch (err) {
    console.error("Failed to load event details:", err);
    $("#modal-features-grid").innerHTML = `<div class="empty-state error">Could not load details: ${escapeHTML(err.message)}</div>`;
    $("#modal-raw-json").textContent = JSON.stringify({ error: err.message }, null, 2);
  }
}

async function saveActiveInvestigation() {
  if (!state.activeModalEvent?.id) return;
  const status = $("#modal-inv-status")?.value || "new";
  const notes = $("#modal-analyst-notes")?.value || "";
  const statusText = $("#modal-triage-status");

  if ((status === "resolved" || status === "dismissed") && state.savedSettings?.inv_confirm_status_change !== false) {
    if (!window.confirm(`Are you sure you want to mark Event #${state.activeModalEvent.id} as "${status}"?`)) {
      return;
    }
  }

  try {
    const res = await apiRequest(`/api/events/${state.activeModalEvent.id}/investigate`, {
      method: "POST",
      body: JSON.stringify({ status, notes })
    });
    if (res.success) {
      if (statusText) statusText.textContent = "✓ Saved";
      showToast(`Event #${state.activeModalEvent.id} updated to "${status}"`, "success");
      state.activeModalEvent.investigation_status = status;
      state.activeModalEvent.analyst_notes = notes;
      refreshDashboard(false);
      if ($("#page-query")?.classList.contains("active")) {
        runQuery();
      }
      if ($("#page-investigations")?.classList.contains("active")) {
        loadInvestigations();
      }
    }
  } catch (err) {
    if (statusText) statusText.textContent = "✗ Error saving";
    showToast(`Failed to update investigation: ${err.message}`, "error");
  }
}

function closeEventModal() {
  const modalBackdrop = $("#event-modal-backdrop");
  if (modalBackdrop) modalBackdrop.classList.remove("active");
  state.activeModalEvent = null;
}

/* =========================================================
   SOURCE IP INTELLIGENCE MODAL
   ========================================================= */

async function openSourceModal(ip) {
  if (!ip) return;
  const modal = $("#source-modal-backdrop");
  if (!modal) return;

  $("#source-modal-ip").textContent = `Source IP: ${ip}`;
  $("#src-stat-total").textContent = "—";
  $("#src-stat-threats").textContent = "—";
  $("#src-stat-ratio").textContent = "—%";
  $("#src-stat-first").textContent = "—";
  $("#src-stat-last").textContent = "—";
  $("#src-labels-chips").innerHTML = "Loading breakdown...";
  $("#src-recent-events-tbody").innerHTML = '<tr><td colspan="6" class="table-empty">Loading source telemetry...</td></tr>';

  modal.style.display = "flex";

  try {
    const data = await apiRequest(`/api/sources/${encodeURIComponent(ip)}`);
    $("#src-stat-total").textContent = formatNumber(data.total);
    $("#src-stat-threats").textContent = formatNumber(data.threats);
    $("#src-stat-ratio").textContent = `${data.threat_ratio}%`;
    $("#src-stat-first").textContent = data.first_seen ? formatDateTime(data.first_seen) : "—";
    $("#src-stat-last").textContent = data.last_seen ? formatDateTime(data.last_seen) : "—";

    const chips = Object.entries(data.labels || {}).map(([lbl, cnt]) => `
      <span class="source-label-chip">
        ${classificationBadge(lbl)} <strong>${cnt}</strong>
      </span>
    `).join("");
    $("#src-labels-chips").innerHTML = chips || "<span>No labels recorded</span>";

    const eventsHtml = (data.recent_events || []).map(e => `
      <tr class="clickable-event-row" data-event-id="${escapeHTML(e.id)}">
        <td>#${e.id}</td>
        <td>${formatTime(e.ts)}</td>
        <td>${classificationBadge(e.label)}</td>
        <td>${severityBadge(e.severity)}</td>
        <td>${e.confidence ? `${Number(e.confidence).toFixed(1)}%` : '—'}</td>
        <td><span class="status-badge ${escapeHTML(e.investigation_status || 'new')}">${escapeHTML(e.investigation_status || 'new')}</span></td>
      </tr>
    `).join("");
    $("#src-recent-events-tbody").innerHTML = eventsHtml || '<tr><td colspan="6" class="table-empty">No recent events.</td></tr>';

    $("#src-modal-hunt-btn").onclick = () => {
      modal.style.display = "none";
      navigateTo("query");
      clearQuery(false);
      $("#query-ip").value = ip;
      runQuery();
    };
  } catch (err) {
    showToast(`Could not load profile for IP ${ip}: ${err.message}`, "error");
  }
}

function closeSourceModal() {
  const modal = $("#source-modal-backdrop");
  if (modal) modal.style.display = "none";
}

/* =========================================================
   SYSTEM HEALTH & SIMULATOR
   ========================================================= */

async function checkSystemHealth() {
  try {
    const health = await apiRequest("/api/health");
    const systemStatus = $("#system-status");
    const apiStatus = $("#api-status");
    const dbStatus = $("#db-status");
    const modeDesc = $("#system-mode-desc");
    const dot = $(".system-card-heading .status-dot");

    const isHealthy = health.status === "healthy";

    if (systemStatus) {
      systemStatus.textContent = isHealthy ? "Operational" : (health.status || "Degraded");
    }
    if (apiStatus) {
      apiStatus.textContent = "Online";
    }
    if (dbStatus) {
      const count = health.database?.event_count;
      dbStatus.textContent = count !== undefined ? `Ready (${count} evts)` : "Connected";
    }
    if (modeDesc) {
      modeDesc.textContent = "ML Inference (12 Features)";
    }
    if (dot) {
      dot.style.background = isHealthy ? "var(--green)" : "var(--orange)";
      dot.style.boxShadow = isHealthy ? "0 0 10px rgba(57, 217, 162, 0.4)" : "0 0 10px rgba(255, 180, 93, 0.4)";
    }
  } catch (err) {
    console.warn("Health check error:", err);
  }
}

async function runHealthCheck() {
  const start = performance.now();
  try {
    const data = await apiRequest("/api/health");
    const duration = Math.round(performance.now() - start);

    if ($("#health-db-status")) $("#health-db-status").textContent = data.database?.status === "connected" ? "Connected" : "Disconnected";
    if ($("#health-db-count")) $("#health-db-count").textContent = `${formatNumber(data.database?.event_count || 0)} events recorded`;
    if ($("#health-model-status")) $("#health-model-status").textContent = data.model?.status === "ready" ? "Ready" : "Not Loaded";
    if ($("#health-model-classes")) $("#health-model-classes").textContent = `${data.model?.classes?.length || 4} classes active`;
    if ($("#health-latency")) $("#health-latency").textContent = `${duration} ms`;
    if ($("#health-api-status")) $("#health-api-status").textContent = "Operational";
    showToast("Health diagnostics completed: All subsystems operational.", "success");
  } catch (err) {
    showToast(`Health check error: ${err.message}`, "error");
  }
}

async function triggerScenario(scenario) {
  try {
    showToast(`Simulating calibrated ${scenario} telemetry...`, "info");
    const res = await apiRequest(`/api/simulate?scenario=${encodeURIComponent(scenario)}`, {
      method: "POST"
    });
    showToast(`Test scenario generated: ${res.event?.label || scenario} event #${res.event?.id || ''}`, "success");
    await refreshDashboard(true);
  } catch (err) {
    showToast(`Simulation failed: ${err.message}`, "error");
  }
}

/* =========================================================
   THREAT HUNTING & ADVANCED QUERY CENTER
   ========================================================= */

const queryState = {
  page: 1,
  pageSize: 20,
  total: 0,
  totalPages: 1,
  selectedIds: new Set()
};

function getFormQueryParams() {
  const q = $("#query-search")?.value?.trim() || "";
  const ip = $("#query-ip")?.value?.trim() || "";
  const label = $("#query-label")?.value || "all";
  const severity = $("#query-severity")?.value || "all";
  const status = $("#query-status")?.value || "all";
  const timePreset = $("#query-time-preset")?.value || "";
  const dateFrom = $("#query-date-from")?.value || "";
  const dateTo = $("#query-date-to")?.value || "";
  const minConf = $("#query-min-conf")?.value || "";
  const maxConf = $("#query-max-conf")?.value || "";
  const sortBy = $("#query-sort-by")?.value || "id";
  const sortOrder = $("#query-sort-order")?.value || "desc";

  return {
    q,
    src_ip: ip,
    label,
    severity,
    status,
    time_preset: timePreset,
    date_from: dateFrom,
    date_to: dateTo,
    min_conf: minConf,
    max_conf: maxConf,
    sort_by: sortBy,
    sort_order: sortOrder
  };
}

function renderActiveChips() {
  const container = $("#active-filter-chips");
  if (!container) return;

  const params = getFormQueryParams();
  const chips = [];

  if (params.q) chips.push({ key: "q", label: `Search: "${params.q}"`, elId: "query-search", defaultVal: "" });
  if (params.src_ip) chips.push({ key: "src_ip", label: `IP: ${params.src_ip}`, elId: "query-ip", defaultVal: "" });
  if (params.label && params.label !== "all") chips.push({ key: "label", label: `Class: ${params.label}`, elId: "query-label", defaultVal: "all" });
  if (params.severity && params.severity !== "all") chips.push({ key: "severity", label: `Severity: ${params.severity}`, elId: "query-severity", defaultVal: "all" });
  if (params.status && params.status !== "all") chips.push({ key: "status", label: `Status: ${params.status}`, elId: "query-status", defaultVal: "all" });
  if (params.time_preset) chips.push({ key: "time_preset", label: `Time: ${params.time_preset}`, elId: "query-time-preset", defaultVal: "" });
  if (params.date_from) chips.push({ key: "date_from", label: `From: ${params.date_from}`, elId: "query-date-from", defaultVal: "" });
  if (params.date_to) chips.push({ key: "date_to", label: `To: ${params.date_to}`, elId: "query-date-to", defaultVal: "" });
  if (params.min_conf) chips.push({ key: "min_conf", label: `Min Conf: ${params.min_conf}%`, elId: "query-min-conf", defaultVal: "" });
  if (params.max_conf) chips.push({ key: "max_conf", label: `Max Conf: ${params.max_conf}%`, elId: "query-max-conf", defaultVal: "" });

  if (!chips.length) {
    container.innerHTML = "";
    return;
  }

  container.innerHTML = chips.map(c => `
    <span class="filter-chip">
      <span>${escapeHTML(c.label)}</span>
      <button type="button" class="chip-remove" data-target-id="${c.elId}" data-default-val="${c.defaultVal}" aria-label="Remove filter">✕</button>
    </span>
  `).join("");

  container.querySelectorAll(".chip-remove").forEach(btn => {
    btn.addEventListener("click", () => {
      const target = $(`#${btn.dataset.targetId}`);
      if (target) {
        target.value = btn.dataset.defaultVal;
        queryState.page = 1;
        runQuery();
      }
    });
  });
}

async function runQuery() {
  const btn = $("#run-query");
  if (btn) { btn.disabled = true; btn.textContent = "Hunting..."; }

  renderActiveChips();

  try {
    const params = getFormQueryParams();
    const urlParams = new URLSearchParams();

    Object.entries(params).forEach(([k, v]) => {
      if (v !== "" && v !== "all" && v !== null && v !== undefined) {
        urlParams.set(k, v);
      }
    });

    const pageSizeSelect = $("#query-page-size");
    const pageSize = pageSizeSelect ? parseInt(pageSizeSelect.value, 10) : 20;
    queryState.pageSize = pageSize;

    urlParams.set("page", queryState.page);
    urlParams.set("page_size", pageSize);

    const data = await apiRequest(`/api/query?${urlParams.toString()}`);

    const results = data.results || (Array.isArray(data) ? data : []);
    const total = data.total !== undefined ? data.total : results.length;
    const totalPages = data.total_pages || Math.ceil(total / pageSize) || 1;

    queryState.total = total;
    queryState.totalPages = totalPages;

    renderQueryResults(results, total, queryState.page, pageSize, totalPages);
  } catch (err) {
    console.error("Query failed:", err);
    showToast(`Threat hunting query failed: ${err.message}`, "error");
    renderQueryResults([], 0, 1, 20, 1);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "⌕ Run Query"; }
  }
}

function renderQueryResults(events, total, page, pageSize, totalPages) {
  const tbody = $("#query-results-body");
  const countBadge = $("#query-results-count");
  const infoEl = $("#query-pagination-info");
  const pageDisplay = $("#query-page-display");
  const prevBtn = $("#query-prev-page");
  const nextBtn = $("#query-next-page");

  if (countBadge) countBadge.textContent = `${formatNumber(total)} event${total === 1 ? '' : 's'} matched`;

  const startIdx = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const endIdx = Math.min(page * pageSize, total);
  if (infoEl) infoEl.textContent = `Showing ${startIdx}-${endIdx} of ${formatNumber(total)}`;
  if (pageDisplay) pageDisplay.textContent = `Page ${page} of ${totalPages || 1}`;

  if (prevBtn) prevBtn.disabled = page <= 1;
  if (nextBtn) nextBtn.disabled = page >= totalPages;

  // Reset row selection state
  queryState.selectedIds.clear();
  updateBulkToolbar();
  const selectAllBox = $("#select-all-query-rows");
  if (selectAllBox) selectAllBox.checked = false;

  if (!tbody) return;

  if (!events.length) {
    tbody.innerHTML = `<tr><td colspan="9" class="table-empty">No matching telemetry events found for specified parameters.</td></tr>`;
    return;
  }

  tbody.innerHTML = events.map((evt) => {
    const e = normalizeEvent(evt);
    const status = e.original?.investigation_status || "new";

    return `
      <tr data-event-id="${escapeHTML(e.id)}" class="clickable-event-row">
        <td><input type="checkbox" class="row-select-checkbox" data-event-id="${escapeHTML(e.id)}"></td>
        <td><span class="event-id">#${escapeHTML(e.id)}</span></td>
        <td>${e.timestamp ? formatDateTime(e.timestamp) : "—"}</td>
        <td><code class="ip-address ip-link" data-ip="${escapeHTML(e.src_ip)}" title="Click to view IP profile">${escapeHTML(e.src_ip)}</code></td>
        <td>${classificationBadge(e.label)}</td>
        <td>${severityBadge(e.severity)}</td>
        <td>${e.confidence !== null ? confidenceCell(e.confidence) : "—"}</td>
        <td><span class="status-badge ${escapeHTML(status)}">${escapeHTML(status)}</span></td>
        <td>
          <button type="button" class="button button-sm button-secondary button-inspect" data-event-id="${escapeHTML(e.id)}">Triage</button>
        </td>
      </tr>`;
  }).join("");

  // Attach row checkboxes
  tbody.querySelectorAll(".row-select-checkbox").forEach(box => {
    box.addEventListener("change", (e) => {
      const id = parseInt(e.target.dataset.eventId, 10);
      if (e.target.checked) {
        queryState.selectedIds.add(id);
      } else {
        queryState.selectedIds.delete(id);
      }
      updateBulkToolbar();
    });
  });

  // Attach IP link clicks
  tbody.querySelectorAll(".ip-link").forEach(el => {
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      openSourceModal(el.dataset.ip);
    });
  });
}

function updateBulkToolbar() {
  const toolbar = $("#bulk-toolbar");
  const countBadge = $("#selected-count-badge");
  const count = queryState.selectedIds.size;

  if (countBadge) countBadge.textContent = `${count} selected`;
  if (toolbar) {
    toolbar.style.display = count > 0 ? "flex" : "none";
  }
}

function clearQuery(shouldRerun = true) {
  if ($("#query-search")) $("#query-search").value = "";
  if ($("#query-ip")) $("#query-ip").value = "";
  if ($("#query-label")) $("#query-label").value = "all";
  if ($("#query-severity")) $("#query-severity").value = "all";
  if ($("#query-status")) $("#query-status").value = "all";
  if ($("#query-time-preset")) $("#query-time-preset").value = "";
  if ($("#query-date-from")) $("#query-date-from").value = "";
  if ($("#query-date-to")) $("#query-date-to").value = "";
  if ($("#query-min-conf")) $("#query-min-conf").value = "";
  if ($("#query-max-conf")) $("#query-max-conf").value = "";
  if ($("#query-sort-by")) $("#query-sort-by").value = "id";
  if ($("#query-sort-order")) $("#query-sort-order").value = "desc";

  $$(".preset-btn").forEach(btn => btn.classList.toggle("active", btn.dataset.preset === "all"));

  queryState.page = 1;
  queryState.selectedIds.clear();
  updateBulkToolbar();
  renderActiveChips();

  if (shouldRerun) runQuery();
}

function applyQueryPreset(presetName) {
  clearQuery(false);

  $$(".preset-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.preset === presetName);
  });

  if (presetName === "critical_high") {
    $("#query-severity").value = "critical";
  } else if (presetName === "recent_threats") {
    $("#query-time-preset").value = "24h";
  } else if (presetName === "needs_investigation") {
    $("#query-status").value = "new";
  } else if (presetName === "low_conf") {
    $("#query-max-conf").value = "70";
  } else if (presetName === "false_positives") {
    $("#query-status").value = "false_positive";
  } else if (presetName === "normal") {
    $("#query-label").value = "normal";
  }

  queryState.page = 1;
  runQuery();
}

async function loadSavedQueries() {
  const select = $("#saved-queries-select");
  if (!select) return;
  try {
    const list = await apiRequest("/api/saved-queries");
    select.innerHTML = '<option value="">— Select a saved search query —</option>' + 
      (list || []).map(q => `<option value="${escapeHTML(q.id)}" data-params='${escapeHTML(JSON.stringify(q.query_params))}'>${escapeHTML(q.name)}</option>`).join("");
  } catch (err) {
    console.warn("Could not load saved queries:", err);
  }
}

async function saveCurrentQuery(name) {
  if (!name?.trim()) return;
  const params = getFormQueryParams();
  try {
    await apiRequest("/api/saved-queries", {
      method: "POST",
      body: JSON.stringify({ name: name.trim(), query_params: params })
    });
    showToast(`Saved search "${name}" created.`, "success");
    $("#save-query-modal-backdrop").style.display = "none";
    $("#save-query-name-input").value = "";
    loadSavedQueries();
  } catch (err) {
    showToast(`Failed to save query: ${err.message}`, "error");
  }
}

async function deleteSelectedSavedQuery() {
  const select = $("#saved-queries-select");
  const queryId = select?.value;
  if (!queryId) {
    showToast("Please select a saved query to delete.", "info");
    return;
  }
  try {
    await apiRequest(`/api/saved-queries/${queryId}`, { method: "DELETE" });
    showToast("Saved query removed.", "success");
    loadSavedQueries();
  } catch (err) {
    showToast(`Could not delete query: ${err.message}`, "error");
  }
}

function applySelectedSavedQuery() {
  const select = $("#saved-queries-select");
  const opt = select?.selectedOptions[0];
  if (!opt || !opt.dataset.params) return;

  try {
    const params = JSON.parse(opt.dataset.params);
    clearQuery(false);

    if (params.q) $("#query-search").value = params.q;
    if (params.src_ip) $("#query-ip").value = params.src_ip;
    if (params.label) $("#query-label").value = params.label;
    if (params.severity) $("#query-severity").value = params.severity;
    if (params.status) $("#query-status").value = params.status;
    if (params.time_preset) $("#query-time-preset").value = params.time_preset;
    if (params.date_from) $("#query-date-from").value = params.date_from;
    if (params.date_to) $("#query-date-to").value = params.date_to;
    if (params.min_conf) $("#query-min-conf").value = params.min_conf;
    if (params.max_conf) $("#query-max-conf").value = params.max_conf;
    if (params.sort_by) $("#query-sort-by").value = params.sort_by;
    if (params.sort_order) $("#query-sort-order").value = params.sort_order;

    queryState.page = 1;
    runQuery();
    showToast(`Applied saved search: "${opt.textContent}"`, "info");
  } catch (err) {
    console.warn("Could not apply query params:", err);
  }
}

async function applyBulkStatus() {
  const status = $("#bulk-status-select")?.value || "investigating";
  const ids = Array.from(queryState.selectedIds);
  if (!ids.length) return;

  if ((status === "resolved" || status === "dismissed") && state.savedSettings?.inv_confirm_status_change !== false) {
    if (!window.confirm(`Are you sure you want to mark ${ids.length} selected event(s) as "${status}"?`)) {
      return;
    }
  }

  try {
    const res = await apiRequest("/api/events/bulk-investigate", {
      method: "POST",
      body: JSON.stringify({ ids, status })
    });
    showToast(`Bulk updated ${res.updated_count || ids.length} events to "${status}"`, "success");
    queryState.selectedIds.clear();
    updateBulkToolbar();
    runQuery();
    refreshDashboard(false);
  } catch (err) {
    showToast(`Bulk update failed: ${err.message}`, "error");
  }
}

function triggerCSVDownload(url, filename = "events.csv") {
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function getExportSettingsParams() {
  const s = state.savedSettings || {};
  const params = new URLSearchParams();
  params.set("format", s.export_format || "csv");
  params.set("delimiter", s.export_csv_delimiter || ",");
  params.set("filename_prefix", s.export_filename_prefix || "threatnex_export");
  params.set("include_features", s.export_include_features ? "true" : "false");
  params.set("include_confidence", s.export_include_confidence !== false ? "true" : "false");
  params.set("include_severity_label", s.export_include_severity_label !== false ? "true" : "false");
  params.set("include_event_id", s.export_include_event_id !== false ? "true" : "false");
  params.set("timestamp_format", s.export_timestamp_format || "ISO 8601");
  return params;
}

function exportSelectedCSV() {
  const ids = Array.from(queryState.selectedIds);
  if (!ids.length) {
    showToast("No rows selected for export.", "info");
    return;
  }
  const s = state.savedSettings || {};
  if (ids.length > 500 && s.query_confirm_large_exports !== false) {
    if (!window.confirm(`You are about to export ${ids.length} selected events. Continue?`)) return;
  }
  const params = getExportSettingsParams();
  params.set("ids", ids.join(","));
  const ext = (s.export_format || "csv") === "json" ? "json" : "csv";
  showToast(`Downloading export for ${ids.length} selected events...`, "info");
  triggerCSVDownload(`/api/export?${params.toString()}`, `${s.export_filename_prefix || "threatnex_export"}_selected.${ext}`);
}

function exportFilteredCSV() {
  const s = state.savedSettings || {};
  if ((queryState.total || 0) > 500 && s.query_confirm_large_exports !== false) {
    if (!window.confirm(`You are about to export ${queryState.total} filtered events. Continue?`)) return;
  }
  const params = getExportSettingsParams();
  const formParams = getFormQueryParams();
  Object.entries(formParams).forEach(([k, v]) => {
    if (v !== "" && v !== "all" && v !== null && v !== undefined) {
      params.set(k, v);
    }
  });
  const ext = (s.export_format || "csv") === "json" ? "json" : "csv";
  showToast("Downloading filtered export...", "info");
  triggerCSVDownload(`/api/export?${params.toString()}`, `${s.export_filename_prefix || "threatnex_export"}_filtered.${ext}`);
}

function exportAllCSV() {
  const s = state.savedSettings || {};
  if ((state.stats?.total_events || 0) > 500 && s.query_confirm_large_exports !== false) {
    if (!window.confirm("You are about to export the complete event history. Continue?")) return;
  }
  const params = getExportSettingsParams();
  const ext = (s.export_format || "csv") === "json" ? "json" : "csv";
  showToast("Downloading complete event history export...", "info");
  triggerCSVDownload(`/api/export?${params.toString()}`, `${s.export_filename_prefix || "threatnex_export"}_all.${ext}`);
}

/* =========================================================
   INVESTIGATIONS CONSOLE & REPORTS
   ========================================================= */

async function loadInvestigations() {
  const activeTab = $("#inv-status-tabs .pill-btn.active")?.dataset.status || "all";
  const params = new URLSearchParams();
  if (activeTab && activeTab !== "all") params.set("status", activeTab);
  params.set("page_size", "50");
  params.set("sort_by", "id");
  params.set("sort_order", "desc");

  try {
    const res = await apiRequest(`/api/query?${params.toString()}`);
    const results = extractEvents(res);

    if (state.stats?.investigations) {
      const inv = state.stats.investigations;
      if ($("#inv-stat-new")) $("#inv-stat-new").textContent = formatNumber(inv.new || 0);
      if ($("#inv-stat-investigating")) $("#inv-stat-investigating").textContent = formatNumber(inv.investigating || 0);
      if ($("#inv-stat-resolved")) $("#inv-stat-resolved").textContent = formatNumber(inv.resolved || 0);
      if ($("#inv-stat-false-positive")) $("#inv-stat-false-positive").textContent = formatNumber(inv.false_positive || 0);
      const closed = (inv.resolved || 0) + (inv.false_positive || 0);
      const totalThreats = state.stats.threats || 0;
      if ($("#inv-stat-closure-rate")) {
        $("#inv-stat-closure-rate").textContent = totalThreats ? ((closed / totalThreats) * 100).toFixed(1) : "100.0";
      }
    }

    const tbody = $("#investigations-table-body");
    if (!tbody) return;

    if (!results.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No investigation cases found for selected status.</td></tr>';
      return;
    }

    tbody.innerHTML = results.map(r => `
      <tr class="clickable-event-row" data-event-id="${escapeHTML(r.id)}">
        <td><span class="event-id">#${escapeHTML(r.id)}</span></td>
        <td>${r.ts ? formatDateTime(r.ts) : '—'}</td>
        <td><code class="ip-address ip-link" data-ip="${escapeHTML(r.src_ip)}">${escapeHTML(r.src_ip)}</code></td>
        <td>${classificationBadge(r.label)}</td>
        <td>${severityBadge(r.severity)}</td>
        <td><span class="status-badge ${escapeHTML(r.investigation_status || 'new')}">${escapeHTML(r.investigation_status || 'new')}</span></td>
        <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHTML(r.analyst_notes || 'No notes')}">
          ${escapeHTML(r.analyst_notes || '—')}
        </td>
        <td><button type="button" class="button button-sm button-secondary button-inspect" data-event-id="${escapeHTML(r.id)}">Triage</button></td>
      </tr>
    `).join("");

    tbody.querySelectorAll(".ip-link").forEach(el => {
      el.addEventListener("click", (e) => {
        e.stopPropagation();
        openSourceModal(el.dataset.ip);
      });
    });
  } catch (err) {
    showToast(`Failed to load investigations: ${err.message}`, "error");
  }
}

async function loadReports() {
  try {
    const data = await apiRequest("/api/reports/summary");
    if ($("#report-timestamp")) $("#report-timestamp").textContent = new Date().toLocaleString();
    if ($("#rep-total")) $("#rep-total").textContent = formatNumber(data.total_events);
    if ($("#rep-threats")) $("#rep-threats").textContent = formatNumber(data.threat_events);
    if ($("#rep-threat-pct")) $("#rep-threat-pct").textContent = `${data.threat_percentage}% threat ratio`;
    if ($("#rep-normal")) $("#rep-normal").textContent = formatNumber(data.normal_events);
    const closed = (data.investigations?.resolved || 0) + (data.investigations?.false_positive || 0);
    if ($("#rep-closed")) $("#rep-closed").textContent = formatNumber(closed);
    if ($("#rep-resolution-rate")) $("#rep-resolution-rate").textContent = `${data.resolution_rate}%`;

    const attacksTbody = $("#report-attacks-tbody");
    if (attacksTbody) {
      const attacks = data.attack_breakdown || [];
      if (!attacks.length) {
        attacksTbody.innerHTML = '<tr><td colspan="3" class="table-empty">No malicious attack events recorded.</td></tr>';
      } else {
        attacksTbody.innerHTML = attacks.map(a => {
          const share = data.threat_events ? ((a.count / data.threat_events) * 100).toFixed(1) : 0;
          return `
            <tr>
              <td>${classificationBadge(a.label)}</td>
              <td>${formatNumber(a.count)}</td>
              <td>${share}%</td>
            </tr>
          `;
        }).join("");
      }
    }

    const actorsTbody = $("#report-actors-tbody");
    if (actorsTbody) {
      const actors = data.top_threat_sources || [];
      if (!actors.length) {
        actorsTbody.innerHTML = '<tr><td colspan="4" class="table-empty">No threat actor IPs recorded.</td></tr>';
      } else {
        actorsTbody.innerHTML = actors.map(a => `
          <tr>
            <td><code class="ip-address">${escapeHTML(a.ip)}</code></td>
            <td>${formatNumber(a.total)}</td>
            <td><span class="threat-count-chip">${formatNumber(a.threats)}</span></td>
            <td><button class="button button-sm button-secondary report-view-src-btn" data-ip="${escapeHTML(a.ip)}">Profile</button></td>
          </tr>
        `).join("");
        actorsTbody.querySelectorAll(".report-view-src-btn").forEach(btn => {
          btn.addEventListener("click", () => openSourceModal(btn.dataset.ip));
        });
      }
    }

    const unresTbody = $("#report-unresolved-tbody");
    if (unresTbody) {
      const unres = data.priority_unresolved || [];
      if (!unres.length) {
        unresTbody.innerHTML = '<tr><td colspan="6" class="table-empty">No open critical or high incidents.</td></tr>';
      } else {
        unresTbody.innerHTML = unres.map(u => `
          <tr class="clickable-event-row" data-event-id="${escapeHTML(u.id)}">
            <td>#${u.id}</td>
            <td><code class="ip-address">${escapeHTML(u.src_ip)}</code></td>
            <td>${classificationBadge(u.label)}</td>
            <td>${severityBadge(u.severity)}</td>
            <td>${u.confidence ? `${Number(u.confidence).toFixed(1)}%` : '—'}</td>
            <td><span class="status-badge ${escapeHTML(u.investigation_status || 'new')}">${escapeHTML(u.investigation_status || 'new')}</span></td>
          </tr>
        `).join("");
      }
    }

    if (data.model_info?.metrics) {
      if ($("#rep-model-accuracy")) $("#rep-model-accuracy").textContent = formatPercent(data.model_info.metrics.accuracy);
      if ($("#rep-model-f1")) $("#rep-model-f1").textContent = formatPercent(data.model_info.metrics.weighted_f1 || data.model_info.metrics.accuracy);
    }
  } catch (err) {
    showToast(`Could not load report data: ${err.message}`, "error");
  }
}

/* =========================================================
   INITIALIZATION & EVENT LISTENERS
   ========================================================= */

function setupQueryCenter() {
  $("#run-query")?.addEventListener("click", () => {
    queryState.page = 1;
    runQuery();
  });
  $("#clear-query")?.addEventListener("click", () => clearQuery(true));
  $("#export-filtered-csv-btn")?.addEventListener("click", exportFilteredCSV);
  $("#export-csv-btn")?.addEventListener("click", exportAllCSV);
  $("#export-selected-csv-btn")?.addEventListener("click", exportSelectedCSV);
  $("#bulk-apply-status-btn")?.addEventListener("click", applyBulkStatus);

  // Pagination controls
  $("#query-prev-page")?.addEventListener("click", () => {
    if (queryState.page > 1) {
      queryState.page--;
      runQuery();
    }
  });
  $("#query-next-page")?.addEventListener("click", () => {
    if (queryState.page < queryState.totalPages) {
      queryState.page++;
      runQuery();
    }
  });
  $("#query-page-size")?.addEventListener("change", (e) => {
    queryState.pageSize = parseInt(e.target.value, 10);
    queryState.page = 1;
    runQuery();
  });

  // Master checkbox
  $("#select-all-query-rows")?.addEventListener("change", (e) => {
    const checked = e.target.checked;
    $$("#query-results-body .row-select-checkbox").forEach(box => {
      box.checked = checked;
      const id = parseInt(box.dataset.eventId, 10);
      if (checked) {
        queryState.selectedIds.add(id);
      } else {
        queryState.selectedIds.delete(id);
      }
    });
    updateBulkToolbar();
  });

  // Preset buttons
  $$(".preset-btn").forEach(btn => {
    btn.addEventListener("click", () => applyQueryPreset(btn.dataset.preset));
  });

  // Saved queries actions
  $("#load-saved-query-btn")?.addEventListener("click", applySelectedSavedQuery);
  $("#delete-saved-query-btn")?.addEventListener("click", deleteSelectedSavedQuery);
  $("#open-save-query-modal-btn")?.addEventListener("click", () => {
    $("#save-query-modal-backdrop").style.display = "flex";
  });
  $("#save-query-modal-close-btn")?.addEventListener("click", () => {
    $("#save-query-modal-backdrop").style.display = "none";
  });
  $("#save-query-cancel-btn")?.addEventListener("click", () => {
    $("#save-query-modal-backdrop").style.display = "none";
  });
  $("#save-query-confirm-btn")?.addEventListener("click", () => {
    saveCurrentQuery($("#save-query-name-input")?.value);
  });
}

function setupEventListeners() {
  $("#refresh-button")?.addEventListener("click", () => {
    refreshDashboard(true);
  });

  $("#simulate-button")?.addEventListener("click", simulateTraffic);
  $("#open-simulator-btn")?.addEventListener("click", () => navigateTo("health"));
  $("#analyzer-form")?.addEventListener("submit", analyzeTraffic);
  $("#reset-events")?.addEventListener("click", resetEvents);
  $("#logout-button")?.addEventListener("click", handleLogout);

  // Settings preview alert cancel button
  $("#cancel-preview-btn")?.addEventListener("click", cancelSettingsChanges);

  // Delegated table row & inspect button clicks for investigation modal
  document.addEventListener("click", (event) => {
    const inspectBtn = event.target.closest(".button-inspect");
    if (inspectBtn) {
      event.preventDefault();
      event.stopPropagation();
      const eventId = inspectBtn.dataset.eventId || inspectBtn.getAttribute("data-id");
      if (eventId) openEventModal(eventId);
      return;
    }

    const row = event.target.closest("tbody tr[data-event-id]");
    if (row && !event.target.closest("button") && !event.target.closest("a") && !event.target.closest("input")) {
      const eventId = row.dataset.eventId;
      if (eventId) openEventModal(eventId);
    }
  });

  // Investigation Modal Buttons
  $("#modal-close-btn")?.addEventListener("click", closeEventModal);
  $("#modal-dismiss-btn")?.addEventListener("click", closeEventModal);
  $("#modal-save-inv-btn")?.addEventListener("click", saveActiveInvestigation);
  $("#modal-view-src-btn")?.addEventListener("click", () => {
    const ip = state.activeModalEvent?.src_ip;
    if (ip) {
      closeEventModal();
      openSourceModal(ip);
    }
  });

  $("#event-modal-backdrop")?.addEventListener("click", (e) => {
    if (e.target.id === "event-modal-backdrop") closeEventModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeEventModal();
      closeSourceModal();
    }
  });

  // Source IP Modal Buttons
  $("#source-modal-close-btn")?.addEventListener("click", closeSourceModal);
  $("#source-modal-dismiss-btn")?.addEventListener("click", closeSourceModal);
  $("#source-modal-backdrop")?.addEventListener("click", (e) => {
    if (e.target.id === "source-modal-backdrop") closeSourceModal();
  });

  // Modal Copy JSON
  $("#modal-copy-json-btn")?.addEventListener("click", () => {
    const jsonText = $("#modal-raw-json")?.textContent || "";
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(jsonText).then(() => {
        showToast("Event JSON copied to clipboard.", "success");
      }).catch(() => {
        showToast("Could not copy to clipboard.", "error");
      });
    } else {
      showToast("Clipboard API not available.", "info");
    }
  });

  // Interactive Dashboard Clicks (KPI cards, Donut legend, Severity bars, Top sources)
  $$(".clickable-stat[data-nav-query]").forEach(card => {
    card.addEventListener("click", () => {
      const filter = card.dataset.navQuery;
      navigateTo("query");
      applyQueryPreset(filter);
    });
  });

  document.addEventListener("click", (e) => {
    const legendItem = e.target.closest(".clickable-legend");
    if (legendItem) {
      const lbl = legendItem.dataset.label;
      navigateTo("query");
      clearQuery(false);
      $("#query-label").value = lbl;
      runQuery();
      return;
    }

    const sevItem = e.target.closest(".severity-bar-item");
    if (sevItem) {
      const sev = sevItem.dataset.sev;
      navigateTo("query");
      clearQuery(false);
      $("#query-severity").value = sev;
      runQuery();
      return;
    }

    const srcItem = e.target.closest(".source-ip-item");
    if (srcItem) {
      const ip = srcItem.dataset.srcIp;
      if (ip) openSourceModal(ip);
      return;
    }
  });

  // Simulation scenario triggers
  $$(".trigger-scenario-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      triggerScenario(btn.dataset.scenario);
    });
  });

  // Timeline range pills
  $$("#timeline-range-pills .pill-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $$("#timeline-range-pills .pill-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      showToast(`Activity timeline filtered for ${btn.textContent}`, "info");
    });
  });

  // Investigation status tabs
  $$("#inv-status-tabs .pill-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      $$("#inv-status-tabs .pill-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      loadInvestigations();
    });
  });

  $("#refresh-investigations-btn")?.addEventListener("click", loadInvestigations);
  $("#health-ping-btn")?.addEventListener("click", runHealthCheck);
  $("#print-report-btn")?.addEventListener("click", () => window.print());
  $("#report-export-csv-btn")?.addEventListener("click", exportAllCSV);

  setupFilters();
  setupNavigation();
  setupQueryCenter();
  setupSettingsNavigation();
}

async function initializeApp() {
  setupEventListeners();

  await loadSettings();
  await refreshDashboard(false);
  await checkSystemHealth();
  await loadUserInfo();

  // Navigate to preferred landing page if no specific hash is set
  const hash = window.location.hash ? window.location.hash.replace("#", "").trim() : "";
  if (!hash && state.savedSettings?.default_landing_page && state.savedSettings.default_landing_page !== "dashboard") {
    navigateTo(state.savedSettings.default_landing_page);
  }

  // Active auto-refresh driven by user configuration
  applyAutoRefreshSettings();
}

document.addEventListener("DOMContentLoaded", initializeApp);