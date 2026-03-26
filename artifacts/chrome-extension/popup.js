// PhishShield Guardian — Popup script
// Fetches the scan result for the current tab from the background worker
// and renders it in the popup UI.

const DEFAULT_API_URL = "http://localhost:8080/api";
const PHISHSHIELD_APP_URL = "https://phishshield.replit.app";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function show(id) { document.getElementById(id).style.display = "flex"; }
function hide(id) { document.getElementById(id).style.display = "none"; }
function text(id, val) { document.getElementById(id).textContent = val; }

function circumference(r) { return 2 * Math.PI * r; }
const RADIUS = 30;
const CIRC = circumference(RADIUS);

function setRingProgress(score, classification) {
  const fill = document.getElementById("ring-fill");
  const color = classification === "phishing" ? "#DC2626"
              : classification === "suspicious" ? "#F59E0B"
              : "#16A34A";
  const offset = CIRC - (score / 100) * CIRC;
  fill.style.strokeDasharray = `${CIRC}`;
  fill.style.strokeDashoffset = offset;
  fill.style.stroke = color;
  document.getElementById("score-num").style.color = color;
}

// ─── Render functions ─────────────────────────────────────────────────────────

function renderResult(result, tabUrl) {
  hide("state-loading");
  hide("state-error");

  if (!result) {
    show("state-error");
    return;
  }

  const { riskScore, classification, reasons = [], flags = [], domain, isIndianBankingRelated } = result;

  if (classification === "safe") {
    hide("state-result");
    show("state-safe");
    document.getElementById("safe-domain-text").textContent = domain || new URL(tabUrl || "").hostname;
    return;
  }

  show("state-result");

  // Score ring
  text("score-num", riskScore);
  setRingProgress(riskScore, classification);

  // Verdict badge
  const badge = document.getElementById("verdict-badge");
  badge.textContent = classification.charAt(0).toUpperCase() + classification.slice(1);
  badge.className = `verdict-badge ${classification}`;
  text("score-label", `Risk score ${riskScore}/100`);

  // Domain
  text("domain-text", domain || "—");

  // Indian banking alert
  if (isIndianBankingRelated) {
    document.getElementById("india-alert").style.display = "block";
  } else {
    document.getElementById("india-alert").style.display = "none";
  }

  // Reasons
  const reasonsList = document.getElementById("reasons-list");
  reasonsList.innerHTML = reasons.slice(0, 4).map(r =>
    `<li class="reason-item">${escapeHtml(r)}</li>`
  ).join("") || `<li class="reason-item" style="color:#475569">No specific reason text available.</li>`;

  // Flags as chips
  const flagsWrap = document.getElementById("flags-wrap");
  const chipClass = classification === "phishing" ? "" : "amber";
  flagsWrap.innerHTML = flags.slice(0, 6).map(f =>
    `<span class="flag-chip ${chipClass}">${escapeHtml(f)}</span>`
  ).join("") || `<span style="color:#475569;font-size:12px">None</span>`;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ─── Main init ────────────────────────────────────────────────────────────────

async function init() {
  // Show loading immediately
  show("state-loading");
  ["state-result", "state-safe", "state-error"].forEach(hide);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { show("state-error"); hide("state-loading"); return; }

  const tabUrl = tab.url;

  // Ask background for cached result
  chrome.runtime.sendMessage({ type: "GET_TAB_RESULT", tabId: tab.id }, result => {
    hide("state-loading");
    if (chrome.runtime.lastError) { show("state-error"); return; }
    renderResult(result, tabUrl);
  });

  // Re-scan button (result view)
  document.getElementById("btn-recheck").addEventListener("click", () => {
    show("state-loading");
    ["state-result", "state-safe", "state-error"].forEach(hide);
    chrome.runtime.sendMessage({ type: "RECHECK_TAB", tabId: tab.id, url: tabUrl }, () => {
      chrome.runtime.sendMessage({ type: "GET_TAB_RESULT", tabId: tab.id }, result => {
        hide("state-loading");
        renderResult(result, tabUrl);
      });
    });
  });

  // Re-scan button (safe view)
  document.getElementById("btn-recheck-safe").addEventListener("click", () => {
    show("state-loading");
    ["state-result", "state-safe", "state-error"].forEach(hide);
    chrome.runtime.sendMessage({ type: "RECHECK_TAB", tabId: tab.id, url: tabUrl }, () => {
      chrome.runtime.sendMessage({ type: "GET_TAB_RESULT", tabId: tab.id }, result => {
        hide("state-loading");
        renderResult(result, tabUrl);
      });
    });
  });

  // Open PhishShield web app buttons
  const openApp = () => chrome.tabs.create({ url: PHISHSHIELD_APP_URL });
  document.getElementById("btn-open").addEventListener("click", openApp);
  document.getElementById("btn-open-safe").addEventListener("click", openApp);
}

// ─── Settings panel ───────────────────────────────────────────────────────────

document.getElementById("settings-toggle").addEventListener("click", () => {
  const panel = document.getElementById("settings-panel");
  panel.style.display = panel.style.display === "block" ? "none" : "block";
});

// Load saved API URL
chrome.storage.sync.get({ apiUrl: DEFAULT_API_URL }, data => {
  document.getElementById("api-url-input").value = data.apiUrl;
});

document.getElementById("save-api-url").addEventListener("click", () => {
  const newUrl = document.getElementById("api-url-input").value.trim();
  if (!newUrl) return;
  chrome.storage.sync.set({ apiUrl: newUrl }, () => {
    const msg = document.getElementById("save-msg");
    msg.style.display = "block";
    setTimeout(() => { msg.style.display = "none"; }, 2000);
  });
});

// ─── Boot ─────────────────────────────────────────────────────────────────────

init();
