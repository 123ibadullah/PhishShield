// PhishShield Guardian — Background Service Worker
// Checks each tab's URL against the PhishShield API and broadcasts
// the result to the content script so it can show/hide the overlay.

const DEFAULT_API_URL = "http://localhost:8080/api";

// In-memory cache keyed by URL to avoid hammering the API for the same page
const resultCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Internal pages we never check (new tab, settings, extensions themselves, etc.)
const SKIP_PROTOCOLS = ["chrome:", "chrome-extension:", "edge:", "about:", "data:", "file:"];

function shouldSkipUrl(url) {
  if (!url) return true;
  return SKIP_PROTOCOLS.some(p => url.startsWith(p));
}

async function getApiUrl() {
  return new Promise(resolve => {
    chrome.storage.sync.get({ apiUrl: DEFAULT_API_URL }, data => {
      resolve(data.apiUrl || DEFAULT_API_URL);
    });
  });
}

async function checkUrl(url) {
  // Return cached result if fresh
  const cached = resultCache.get(url);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    return cached.data;
  }

  const apiUrl = await getApiUrl();
  try {
    const response = await fetch(`${apiUrl}/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      console.warn("PhishShield API error:", response.status);
      return null;
    }

    const data = await response.json();
    resultCache.set(url, { data, ts: Date.now() });
    return data;
  } catch (err) {
    console.warn("PhishShield: API unreachable —", err.message);
    return null;
  }
}

function updateBadge(tabId, result) {
  if (!result) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  const score = result.riskScore;
  let color;
  let text;

  if (result.classification === "phishing") {
    color = "#DC2626"; // red
    text = score.toString();
  } else if (result.classification === "suspicious") {
    color = "#F59E0B"; // amber
    text = score.toString();
  } else {
    color = "#16A34A"; // green
    text = "✓";
  }

  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text });
}

async function analyzeTab(tabId, url) {
  if (shouldSkipUrl(url)) return;

  const result = await checkUrl(url);
  updateBadge(tabId, result);

  // Store the latest result for this tab so the popup can read it
  chrome.storage.session.set({ [`tab_${tabId}`]: result || null });

  // Push the result to the content script if the page is still open
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: "PHISHSHIELD_RESULT",
      data: result,
      url,
    });
  } catch {
    // Content script may not be ready yet — that's fine
  }
}

// ─── Event listeners ──────────────────────────────────────────────────────────

// Check URL every time a tab finishes loading
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    analyzeTab(tabId, tab.url);
  }
});

// Clear badge when tab navigates away
chrome.tabs.onRemoved.addListener(tabId => {
  chrome.storage.session.remove(`tab_${tabId}`);
});

// Respond to content script and popup requests
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_RESULT") {
    // Content script asking for the cached result for the current tab
    const tabId = sender.tab?.id;
    if (!tabId) { sendResponse(null); return; }
    chrome.storage.session.get(`tab_${tabId}`, data => {
      sendResponse(data[`tab_${tabId}`] ?? null);
    });
    return true; // keep channel open for async response
  }

  if (message.type === "GET_TAB_RESULT") {
    // Popup asking for the result for a specific tab
    const { tabId } = message;
    chrome.storage.session.get(`tab_${tabId}`, data => {
      sendResponse(data[`tab_${tabId}`] ?? null);
    });
    return true;
  }

  if (message.type === "RECHECK_TAB") {
    // Popup requested a fresh check
    const { tabId, url } = message;
    resultCache.delete(url);
    analyzeTab(tabId, url).then(() => sendResponse({ ok: true }));
    return true;
  }
});
