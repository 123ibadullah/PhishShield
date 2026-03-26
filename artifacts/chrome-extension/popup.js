// PhishShield Guardian — Popup script

const PHISHSHIELD_APP_URL = "https://phishshield.replit.app";

const CIRC = 2 * Math.PI * 30; // circumference for r=30 ring

function show(id) { const el = document.getElementById(id); if (el) el.style.display = "flex"; }
function hide(id) { const el = document.getElementById(id); if (el) el.style.display = "none"; }
function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderResult(result, tabUrl) {
  hide("state-loading");

  if (!result || result.classification === "safe") {
    hide("state-result");
    show("state-safe");
    try {
      const domain = result?.domain || new URL(tabUrl || "").hostname;
      setText("safe-domain-text", domain);
    } catch { /* ignore */ }
    return;
  }

  show("state-result");

  const { riskScore, classification, reasons = [], flags = [], domain, isIndianBankingRelated } = result;

  // Score ring
  const fill  = document.getElementById("ring-fill");
  const color = classification === "phishing" ? "#DC2626" : "#F59E0B";
  fill.style.stroke = color;
  fill.style.strokeDasharray  = `${CIRC}`;
  fill.style.strokeDashoffset = CIRC - (riskScore / 100) * CIRC;
  document.getElementById("score-num").style.color = color;
  setText("score-num", riskScore);

  // Verdict badge
  const badge = document.getElementById("verdict-badge");
  badge.textContent = classification.charAt(0).toUpperCase() + classification.slice(1);
  badge.className   = `verdict-badge ${classification}`;
  setText("score-label", `Risk score ${riskScore} / 100`);

  // Domain
  setText("domain-text", domain || "—");

  // Indian banking alert
  document.getElementById("india-alert").style.display = isIndianBankingRelated ? "block" : "none";

  // Reasons
  const reasonsList = document.getElementById("reasons-list");
  reasonsList.innerHTML = reasons.slice(0, 4).map(r =>
    `<li class="reason-item">${escapeHtml(r)}</li>`
  ).join("") || `<li class="reason-item" style="color:#475569">No specific reason available.</li>`;

  // Flags as chips
  const chipClass = classification === "phishing" ? "" : "amber";
  const flagsWrap = document.getElementById("flags-wrap");
  flagsWrap.innerHTML = flags.slice(0, 6).map(f =>
    `<span class="flag-chip ${chipClass}">${escapeHtml(f)}</span>`
  ).join("") || `<span style="color:#475569;font-size:12px">None</span>`;
}

async function rescan(tab) {
  show("state-loading");
  ["state-result", "state-safe"].forEach(hide);
  await chrome.runtime.sendMessage({ type: "RECHECK_TAB", tabId: tab.id, url: tab.url });
  const result = await chrome.runtime.sendMessage({ type: "GET_TAB_RESULT", tabId: tab.id });
  hide("state-loading");
  renderResult(result, tab.url);
}

async function init() {
  show("state-loading");
  ["state-result", "state-safe"].forEach(hide);

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { hide("state-loading"); return; }

  const result = await chrome.runtime.sendMessage({ type: "GET_TAB_RESULT", tabId: tab.id });
  hide("state-loading");
  renderResult(result, tab.url);

  const openApp = () => chrome.tabs.create({ url: PHISHSHIELD_APP_URL });

  document.getElementById("btn-recheck").addEventListener("click",      () => rescan(tab));
  document.getElementById("btn-recheck-safe").addEventListener("click", () => rescan(tab));
  document.getElementById("btn-open").addEventListener("click",          openApp);
  document.getElementById("btn-open-safe").addEventListener("click",     openApp);
}

init();
