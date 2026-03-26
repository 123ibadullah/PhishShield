// PhishShield Guardian — Background Service Worker
// All detection runs locally inside the extension — no external API needed.
// This means instant results, no auth issues, and works offline.

// ─── Detection rules (mirrored from the PhishShield backend) ─────────────────

const SUSPICIOUS_TLDS = [
  ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
  ".top", ".club", ".online", ".site", ".icu", ".work",
  ".loan", ".click", ".link", ".biz",
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
  "short.io", "rebrand.ly", "cutt.ly", "tiny.cc", "bl.ink",
  "clk.sh", "is.gd", "v.gd",
];

const LOOKALIKE_PATTERNS = [
  [/paypa[l1]|payp4l/i,                          "PayPal lookalike domain"],
  [/g00gle|g0ogle|gooogle/i,                     "Google lookalike domain"],
  [/amaz0n|am4zon|amazzon/i,                     "Amazon lookalike domain"],
  [/faceb00k|f4cebook|faceb0ok/i,                "Facebook lookalike domain"],
  [/sb[i1]-|sb[i1]\.|sbi-online|sbi_online/i,   "SBI lookalike domain"],
  [/hdf[c0]-|hdfcbank-/i,                        "HDFC lookalike domain"],
  [/icic[i1]-|icicibankk/i,                      "ICICI lookalike domain"],
  [/payt[m0]-|paytrn/i,                          "Paytm lookalike domain"],
  [/ph0nepe|phonep3/i,                           "PhonePe lookalike domain"],
  [/[a-z]+-secure-|secure-[a-z]+\./i,           "Fake 'secure' domain pattern"],
  [/[a-z]+-update\./i,                           "Fake 'update' domain pattern"],
  [/[a-z]+-verify\./i,                           "Fake 'verify' domain pattern"],
  [/[a-z]+-alert\./i,                            "Fake 'alert' domain pattern"],
  [/[a-z]+-kyc\./i,                              "Fake 'KYC' domain pattern"],
  [/[a-z]+-reward\./i,                           "Fake 'reward' domain pattern"],
  [/[a-z]+-claim\./i,                            "Fake 'claim' domain pattern"],
];

const INDIA_BANKS = [
  "sbi", "hdfc", "icici", "axisbank", "pnb", "kotak",
  "yesbank", "indusind", "bankofbaroda", "canarabank", "unionbank",
];

const INDIA_SERVICES = [
  "paytm", "phonepe", "gpay", "bhimupi", "irctc", "uidai",
  "aadhaar", "incometax", "epfo", "nsdl", "cibil",
];

function extractDomain(url) {
  try {
    const normalized = url.startsWith("http") ? url : "https://" + url;
    return new URL(normalized).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^/\s?#]+)/i);
    return match ? match[1].toLowerCase() : url;
  }
}

function checkUrl(url) {
  if (!url || !url.startsWith("http")) return null;

  const domain = extractDomain(url);
  const flags = [];
  const reasons = [];
  let score = 0;

  // Suspicious TLD
  const tld = "." + domain.split(".").pop();
  if (SUSPICIOUS_TLDS.includes(tld)) {
    flags.push(`Suspicious TLD: ${tld}`);
    reasons.push(`This site uses the "${tld}" domain, which is commonly used in phishing campaigns.`);
    score += 30;
  }

  // URL shortener
  if (URL_SHORTENERS.some(s => domain.includes(s))) {
    flags.push("URL shortener detected");
    reasons.push("A link shortener hides the real destination — the site you end up at could be anything.");
    score += 25;
  }

  // Lookalike domain
  let lookalikMatched = false;
  for (const [pattern, label] of LOOKALIKE_PATTERNS) {
    if (pattern.test(domain)) {
      flags.push(label);
      reasons.push(`"${domain}" appears to impersonate a trusted brand (${label}). This is a classic phishing tactic.`);
      score += 45;
      lookalikMatched = true;
      break;
    }
  }

  // Deep subdomain structure
  if (domain.split(".").length > 3) {
    flags.push("Complex subdomain structure");
    reasons.push("Fake sites often use deep subdomains to look like part of a legitimate website.");
    score += 15;
  }

  // Numbers in primary domain
  if (/[0-9]/.test(domain.split(".")[0])) {
    flags.push("Numbers in domain name");
    reasons.push("Legitimate brands rarely use numbers in their domain name — a common sign of a spoofed site.");
    score += 10;
  }

  // Unusually long URL
  if (url.length > 100) {
    flags.push("Unusually long URL");
    reasons.push("Phishing links are often deliberately long to discourage inspection.");
    score += 10;
  }

  // Sensitive URL parameters
  if (/token=|session=|verify=|otp=|password=|pin=/i.test(url)) {
    flags.push("Sensitive parameters in URL");
    reasons.push("The URL contains sensitive fields (OTP, token, password) in the address — a red flag for credential theft.");
    score += 20;
  }

  // Deceptive keywords in domain
  if (/secure|login|verify|account|update|confirm|kyc|claim|reward/i.test(domain)) {
    flags.push("Deceptive keyword in domain");
    reasons.push(`The domain uses a word like "secure", "login", or "kyc" to appear trustworthy.`);
    score += 15;
  }

  // Indian banking / payment context
  const domainStripped = domain.toLowerCase().replace(/[-_.]/g, "");
  const matchedBank = INDIA_BANKS.find(b => domainStripped.includes(b));
  const matchedService = INDIA_SERVICES.find(s => domainStripped.includes(s));
  const isIndianBankingRelated = !!(matchedBank || matchedService);

  if (isIndianBankingRelated && score > 15) {
    const brandName = (matchedBank || matchedService).toUpperCase();
    reasons.push(
      matchedBank
        ? `This looks like a fake ${brandName} banking page. Real banks will NEVER ask for your OTP or PIN through a link.`
        : `This appears to impersonate ${brandName}. Never enter your UPI PIN or Aadhaar details on suspicious sites.`
    );
    score = Math.min(score + 20, 100);
  }

  const finalScore = Math.min(score, 100);
  const classification = finalScore >= 71 ? "phishing" : finalScore >= 31 ? "suspicious" : "safe";

  // Which parts of the URL to highlight
  const suspiciousParts = [];
  if (SUSPICIOUS_TLDS.includes(tld)) suspiciousParts.push({ part: tld, reason: "Suspicious TLD" });
  if (lookalikMatched) suspiciousParts.push({ part: domain, reason: "Lookalike domain" });

  return { url, domain, riskScore: finalScore, classification, flags, reasons, isIndianBankingRelated, suspiciousParts };
}

// ─── Internal pages we never check ───────────────────────────────────────────

const SKIP_PREFIXES = ["chrome:", "chrome-extension:", "edge:", "about:", "data:", "file:"];

function shouldSkip(url) {
  return !url || SKIP_PREFIXES.some(p => url.startsWith(p));
}

// ─── Per-tab result cache ─────────────────────────────────────────────────────

const tabResults  = new Map(); // tabId → result
const allowedUrls = new Set(); // URLs the user has explicitly approved (allow once)

function analyzeTab(tabId, url) {
  if (shouldSkip(url)) {
    chrome.action.setBadgeText({ tabId, text: "" });
    tabResults.delete(tabId);
    return;
  }

  const result = checkUrl(url);
  tabResults.set(tabId, result);

  updateBadge(tabId, result);

  // Push result to content script
  chrome.tabs.sendMessage(tabId, { type: "PHISHSHIELD_RESULT", data: result, url })
    .catch(() => {}); // content script may not be ready yet — that's fine
}

function updateBadge(tabId, result) {
  if (!result || result.classification === "safe") {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  const color = result.classification === "phishing" ? "#DC2626" : "#F59E0B";
  const text  = result.classification === "phishing" ? result.riskScore.toString() : "!";
  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text });
}

// ─── Extension's own warning page URL prefix ──────────────────────────────────

function getWarningUrl(result, originalUrl) {
  const params = new URLSearchParams({
    url:    originalUrl,
    score:  result.riskScore,
    level:  result.classification,
    reasons: JSON.stringify(result.reasons || []),
    india:  result.isIndianBankingRelated ? "1" : "0",
    dest:   originalUrl,
  });
  return chrome.runtime.getURL("warning.html") + "?" + params.toString();
}

// ─── Event listeners ──────────────────────────────────────────────────────────

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // ── Intercept at navigation start (before page loads) ──
  // changeInfo.url is only set when the URL actually changes (new navigation)
  if (changeInfo.url && !shouldSkip(changeInfo.url)) {
    const url = changeInfo.url;

    // Don't intercept our own warning page
    const warningBase = chrome.runtime.getURL("warning.html");
    if (url.startsWith(warningBase)) return;

    const result = checkUrl(url);
    if (!result) return;

    tabResults.set(tabId, result);
    updateBadge(tabId, result);

    if (result.classification === "phishing" || result.classification === "suspicious") {
      // If user already approved this URL (clicked "proceed anyway"), let it load
      if (allowedUrls.has(url)) {
        allowedUrls.delete(url); // allow once only
        return;
      }
      // Redirect to our built-in warning page immediately
      chrome.tabs.update(tabId, { url: getWarningUrl(result, url) });
      return;
    }
  }

  // ── After page fully loads: update badge + push result to content script ──
  if (changeInfo.status === "complete" && tab.url) {
    // Don't re-analyze our own warning page
    const warningBase = chrome.runtime.getURL("warning.html");
    if (tab.url.startsWith(warningBase)) return;

    analyzeTab(tabId, tab.url);
  }
});

chrome.tabs.onRemoved.addListener(tabId => {
  tabResults.delete(tabId);
});

// Respond to messages from content script and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // Content script asking for the result for the current tab
  if (message.type === "GET_RESULT") {
    const tabId = sender.tab?.id;
    const tabUrl = sender.tab?.url;
    if (!tabId) { sendResponse(null); return true; }

    let result = tabResults.get(tabId);

    // If no cached result yet (race condition), analyze now and cache it
    if (!result && tabUrl && !shouldSkip(tabUrl)) {
      result = checkUrl(tabUrl);
      if (result) {
        tabResults.set(tabId, result);
        updateBadge(tabId, result);
      }
    }
    sendResponse(result ?? null);
    return true;
  }

  // Popup asking for the result of a specific tab
  if (message.type === "GET_TAB_RESULT") {
    sendResponse(tabResults.get(message.tabId) ?? null);
    return true;
  }

  if (message.type === "RECHECK_TAB") {
    const { tabId, url } = message;
    analyzeTab(tabId, url);
    sendResponse({ ok: true });
    return true;
  }

  // User clicked "proceed anyway" on the warning page — allow this URL once
  if (message.type === "ALLOW_URL") {
    allowedUrls.add(message.url);
    sendResponse({ ok: true });
    return true;
  }

  // Content script finished scanning page text & inputs
  if (message.type === "CONTENT_ANALYSIS") {
    const tabId  = sender.tab?.id;
    const tabUrl = sender.tab?.url;
    if (!tabId) { sendResponse(null); return true; }

    const { contentScore = 0, contentReasons = [] } = message;

    // Get the existing URL-based result (or create a neutral baseline)
    let base = tabResults.get(tabId);
    if (!base && tabUrl && !shouldSkip(tabUrl)) {
      base = checkUrl(tabUrl);
      if (base) tabResults.set(tabId, base);
    }
    if (!base) {
      base = {
        riskScore: 0, classification: "safe",
        reasons: [], flags: [],
        url: tabUrl, domain: extractDomain(tabUrl || ""),
        isIndianBankingRelated: false,
      };
    }

    const { forcePhishing = false } = message;

    // Combine URL score + content score (content capped at 60)
    let combined  = Math.min((base.riskScore || 0) + Math.min(contentScore, 60), 100);
    let newClass  = combined >= 71 ? "phishing" : combined >= 31 ? "suspicious" : "safe";

    // Rule 1: contentScore > 40 alone → always phishing
    if (contentScore > 40) newClass = "phishing";

    // Rule 2: strong keywords + sensitive inputs → force score >= 75 and phishing
    if (forcePhishing) {
      combined  = Math.max(combined, 75);
      newClass  = "phishing";
    }

    const updated = {
      ...base,
      riskScore:       combined,
      classification:  newClass,
      reasons:         [...(base.reasons || []), ...contentReasons],
      contentAnalyzed: true,
    };

    tabResults.set(tabId, updated);
    updateBadge(tabId, updated);

    // Return the merged result to the content script so it can show overlay/banner
    sendResponse(updated);
    return true;
  }
});
