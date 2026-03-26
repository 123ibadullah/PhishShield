// PhishShield Guardian — Content Script
// Injects a full-screen warning overlay when a phishing site is detected.
// For suspicious (medium-risk) sites, shows a dismissible top banner instead.

(function () {
  "use strict";

  let overlayEl = null;
  let bannerEl = null;
  const DISMISSED_KEY = `phishshield_dismissed_${location.hostname}`;

  // Don't show anything if the user already dismissed the warning on this page
  function wasDismissed() {
    try { return sessionStorage.getItem(DISMISSED_KEY) === "1"; } catch { return false; }
  }

  function markDismissed() {
    try { sessionStorage.setItem(DISMISSED_KEY, "1"); } catch { /* ignore */ }
  }

  // ─── Utility: highlight suspicious parts of the URL ───────────────────────

  function highlightUrl(url, suspiciousParts) {
    if (!suspiciousParts || suspiciousParts.length === 0) {
      return `<span class="ps-url-text">${escapeHtml(url)}</span>`;
    }
    let highlighted = escapeHtml(url);
    suspiciousParts.forEach(({ part }) => {
      const escaped = escapeHtml(part);
      highlighted = highlighted.replaceAll(
        escaped,
        `<mark class="ps-url-mark">${escaped}</mark>`
      );
    });
    return `<span class="ps-url-text">${highlighted}</span>`;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ─── Simple-language explanation generator (Hinglish, rule-based) ──────────

  function generateSimpleExplanation(reasons, score, isIndian) {
    const r = reasons.join(" ").toLowerCase();
    const lines = [];

    if (score >= 80) {
      lines.push("🚨 Yeh website almost certainly ek SCAM hai. Isko turant band karo aur kuch bhi mat daalo.");
    } else if (score >= 50) {
      lines.push("⚠️ Yeh website bahut suspicious lag rahi hai. Apni koi bhi personal ya financial details mat daalo.");
    } else {
      lines.push("⚠️ Yeh website thodi suspicious hai. Kuch bhi share karne se pehle soch lo.");
    }

    if (/otp/.test(r))
      lines.push("🔐 Yeh page aapka OTP maang raha hai — real banks kabhi bhi OTP kisi link ke through nahi maangte. Yeh clearly ek scam hai.");
    if (/pin|password/.test(r))
      lines.push("🔑 Yeh page aapka password ya PIN maang raha hai — koi bhi genuine website aisa kabhi nahi karta.");
    if (/cvv/.test(r))
      lines.push("💳 Yeh page aapka CVV number maang raha hai — yeh aapke card ka secret code hai. Ise share mat karo.");
    if (/kyc/.test(r))
      lines.push("📋 Yeh page KYC ke naam par aapki details maang raha hai — scammers aksar KYC ka naam use karke log thagate hain.");
    if (/aadhaar/.test(r))
      lines.push("🪪 Yeh page aapka Aadhaar number maang raha hai — ise kisi bhi unknown website pe kabhi mat daalo.");
    if (/pan card|pan number/.test(r))
      lines.push("🪪 Yeh page aapka PAN card number maang raha hai — link pe share mat karo.");
    if (/suspend|block|restrict/.test(r))
      lines.push("🚫 Yeh page keh raha hai aapka account band ho jayega — yeh ek scam trick hai. Ghabrao mat.");
    if (/urgency|act now|immediately|within.*hours/.test(r))
      lines.push("⏰ Yeh page aapko jaldi karwane ki koshish kar raha hai — scammers hamesha yahi karte hain. Ruko, sochho, phir decide karo.");
    if (/input fields|sensitive input/.test(r))
      lines.push("📝 Is page pe ek form hai jo aapki private information maang raha hai — aise forms kabhi mat bharo.");
    if (/prize|reward|lottery|free gift|free offer/.test(r))
      lines.push("🎁 Yeh page free prize ya reward dene ka wada kar raha hai — yeh ek laalach wala trap hai.");
    if (/lookalike|impersonat|fake.*domain|spoofed/.test(r))
      lines.push("🎭 Yeh website kisi trusted brand ki copy lag rahi hai — URL dhyan se dekho, yeh original website nahi hai.");
    if (/sbi|hdfc|icici|paytm|phonepe|upi|bank/.test(r))
      lines.push("🏦 Yeh ek naqli bank ya payment website lag rahi hai — apne bank ko seedha official number pe call karo.");
    if (/suspicious.*tld|\.xyz|\.tk|\.ml|\.cf|\.gq/.test(r))
      lines.push("🌐 Is website ka address (URL) suspicious hai — real banks aur companies aisi websites use nahi karte.");

    if (isIndian) {
      lines.push("✅ Safe rehne ke liye: link close karo, apne bank ka official app kholo ya helpline pe call karo. Koi bhi OTP, PIN ya password kisi ke saath share mat karo.");
    } else {
      lines.push("✅ Agar koi bhi doubt ho — page band karo. Apni koi bhi personal ya financial details mat daalo.");
    }
    return lines;
  }

  // ─── Full-screen phishing overlay ─────────────────────────────────────────

  function showPhishingOverlay(result) {
    if (overlayEl || wasDismissed()) return;

    const { riskScore, reasons = [], suspiciousParts = [], isIndianBankingRelated } = result;
    const url = location.href;

    const reasonsHtml = reasons.slice(0, 4).map(r =>
      `<li class="ps-reason">${escapeHtml(r)}</li>`
    ).join("");

    const indianWarning = isIndianBankingRelated
      ? `<div class="ps-india-warning">
           🏦 This looks like a fake banking or UPI-related site.<br>
           Real banks like SBI, HDFC, and ICICI will <strong>never</strong> ask for your OTP, PIN, or Aadhaar details through a link.
         </div>`
      : "";

    const html = `
      <div id="ps-backdrop"></div>
      <div id="ps-card" role="alertdialog" aria-modal="true" aria-label="Phishing Warning">
        <div class="ps-header">
          <div class="ps-icon">🛡</div>
          <div>
            <div class="ps-title">⚠ This website may be a phishing attempt</div>
            <div class="ps-score">Risk score: <strong>${riskScore}/100</strong> — High risk</div>
          </div>
        </div>

        <div class="ps-url-box">
          <div class="ps-url-label">Suspicious URL:</div>
          ${highlightUrl(url, suspiciousParts)}
        </div>

        ${indianWarning}

        ${reasonsHtml ? `
          <div class="ps-reasons-label">Why we flagged this site:</div>
          <ul class="ps-reasons">${reasonsHtml}</ul>
        ` : ""}

        <button id="ps-explain" class="ps-btn-explain">💬 Explain in simple language</button>
        <div id="ps-explain-box" class="ps-explain-box" style="display:none"></div>

        <div class="ps-actions">
          <button id="ps-close-tab" class="ps-btn-primary">✕ Close this tab</button>
          <button id="ps-proceed" class="ps-btn-ghost">Proceed anyway (not recommended)</button>
        </div>

        <div class="ps-footer">
          Powered by PhishShield AI — Real-time phishing protection for India
        </div>
      </div>
    `;

    overlayEl = document.createElement("div");
    overlayEl.id = "ps-overlay";
    overlayEl.innerHTML = html;
    injectStyles();
    document.documentElement.appendChild(overlayEl);

    document.body.style.overflow = "hidden";

    overlayEl.querySelector("#ps-close-tab").addEventListener("click", () => {
      window.close();
      setTimeout(() => { location.href = "about:blank"; }, 300);
    });

    overlayEl.querySelector("#ps-proceed").addEventListener("click", () => {
      markDismissed();
      removeOverlay();
    });

    // ── Explain button ──
    overlayEl.querySelector("#ps-explain").addEventListener("click", () => {
      const box = overlayEl.querySelector("#ps-explain-box");
      const btn = overlayEl.querySelector("#ps-explain");
      if (box.style.display !== "none") {
        box.style.display = "none";
        btn.textContent = "💬 Explain in simple language";
        return;
      }
      const lines = generateSimpleExplanation(reasons, riskScore, isIndianBankingRelated);
      box.innerHTML = "<div class='ps-explain-title'>Simple Explanation</div>" +
        lines.map(l => `<div class="ps-explain-line">${escapeHtml(l)}</div>`).join("");
      box.style.display = "block";
      btn.textContent = "✕ Hide explanation";
    });
  }

  // ─── Top banner for suspicious (medium-risk) sites ────────────────────────

  function showSuspiciousBanner(result) {
    if (bannerEl || overlayEl || wasDismissed()) return;

    const { riskScore } = result;

    bannerEl = document.createElement("div");
    bannerEl.id = "ps-banner";
    bannerEl.innerHTML = `
      <div class="ps-banner-icon">⚠</div>
      <div class="ps-banner-text">
        <strong>Caution:</strong> This site has suspicious patterns (risk score ${riskScore}/100). 
        Verify it is genuine before entering any personal details.
      </div>
      <button id="ps-banner-dismiss" class="ps-banner-close" title="Dismiss">✕</button>
    `;
    injectStyles();
    document.documentElement.appendChild(bannerEl);

    bannerEl.querySelector("#ps-banner-dismiss").addEventListener("click", () => {
      markDismissed();
      removeBanner();
    });
  }

  function removeOverlay() {
    if (overlayEl) { overlayEl.remove(); overlayEl = null; }
    document.body.style.overflow = "";
  }

  function removeBanner() {
    if (bannerEl) { bannerEl.remove(); bannerEl = null; }
  }

  // ─── CSS injected as a <style> tag ────────────────────────────────────────

  function injectStyles() {
    if (document.getElementById("ps-styles")) return;
    const style = document.createElement("style");
    style.id = "ps-styles";
    style.textContent = `
      #ps-overlay {
        position: fixed; inset: 0; z-index: 2147483647;
        display: flex; align-items: center; justify-content: center;
        padding: 16px; box-sizing: border-box;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      }
      #ps-backdrop {
        position: absolute; inset: 0;
        background: rgba(0, 0, 0, 0.85);
        backdrop-filter: blur(6px);
        -webkit-backdrop-filter: blur(6px);
      }
      #ps-card {
        position: relative; z-index: 1;
        background: #0f172a;
        border: 2px solid #DC2626;
        border-radius: 16px;
        padding: 28px 32px;
        max-width: 560px; width: 100%;
        box-shadow: 0 0 60px rgba(220, 38, 38, 0.4), 0 25px 50px rgba(0,0,0,0.6);
        color: #f1f5f9;
      }
      .ps-header {
        display: flex; align-items: flex-start; gap: 16px; margin-bottom: 20px;
      }
      .ps-icon {
        font-size: 36px; line-height: 1; flex-shrink: 0;
      }
      .ps-title {
        font-size: 18px; font-weight: 700; color: #FCA5A5; line-height: 1.3;
        margin-bottom: 4px;
      }
      .ps-score {
        font-size: 13px; color: #94a3b8;
      }
      .ps-url-box {
        background: #1e293b; border: 1px solid #334155;
        border-radius: 8px; padding: 12px 14px; margin-bottom: 16px;
        word-break: break-all;
      }
      .ps-url-label {
        font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
        color: #64748b; margin-bottom: 6px; font-weight: 600;
      }
      .ps-url-text { font-size: 12px; font-family: monospace; color: #cbd5e1; }
      .ps-url-mark {
        background: rgba(220, 38, 38, 0.25); color: #FCA5A5;
        border-radius: 3px; padding: 0 2px;
        outline: 1px solid rgba(220, 38, 38, 0.5);
      }
      .ps-india-warning {
        background: rgba(245, 158, 11, 0.12);
        border: 1px solid rgba(245, 158, 11, 0.35);
        border-radius: 8px; padding: 12px 14px;
        color: #FCD34D; font-size: 13px; line-height: 1.5;
        margin-bottom: 16px;
      }
      .ps-reasons-label {
        font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
        color: #64748b; margin-bottom: 8px; font-weight: 600;
      }
      .ps-reasons {
        list-style: none; margin: 0 0 20px; padding: 0;
        display: flex; flex-direction: column; gap: 6px;
      }
      .ps-reason {
        font-size: 13px; color: #cbd5e1; line-height: 1.4;
        padding-left: 18px; position: relative;
      }
      .ps-reason::before {
        content: "›"; position: absolute; left: 0;
        color: #DC2626; font-weight: 700;
      }
      .ps-actions {
        display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px;
      }
      .ps-btn-primary {
        flex: 1; min-width: 140px;
        background: #DC2626; color: white; border: none;
        border-radius: 8px; padding: 11px 18px;
        font-size: 14px; font-weight: 600; cursor: pointer;
        transition: background 0.15s;
      }
      .ps-btn-primary:hover { background: #B91C1C; }
      .ps-btn-ghost {
        flex: 1; min-width: 140px;
        background: transparent; color: #64748b;
        border: 1px solid #334155; border-radius: 8px;
        padding: 11px 18px; font-size: 13px; cursor: pointer;
        transition: color 0.15s, border-color 0.15s;
      }
      .ps-btn-ghost:hover { color: #94a3b8; border-color: #475569; }
      .ps-btn-explain {
        width: 100%; margin-bottom: 12px;
        background: #0f172a; color: #64748b;
        border: 1px dashed #334155; border-radius: 8px;
        padding: 10px 16px; font-size: 13px; font-weight: 600;
        cursor: pointer; transition: background 0.15s, color 0.15s;
        text-align: center;
      }
      .ps-btn-explain:hover { background: #1e293b; color: #94a3b8; }
      .ps-explain-box {
        background: #0a1628; border: 1px solid #1e3a5f;
        border-radius: 10px; padding: 14px 16px; margin-bottom: 14px;
      }
      .ps-explain-title {
        font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em;
        color: #3b82f6; font-weight: 700; margin-bottom: 10px;
      }
      .ps-explain-line {
        font-size: 13px; color: #cbd5e1; line-height: 1.6; margin-bottom: 6px;
      }
      .ps-footer {
        font-size: 11px; color: #475569; text-align: center; padding-top: 4px;
      }

      /* Suspicious banner */
      #ps-banner {
        position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
        background: #78350f;
        border-bottom: 2px solid #F59E0B;
        display: flex; align-items: center; gap: 10px;
        padding: 10px 16px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-size: 13px; color: #FDE68A;
        box-shadow: 0 4px 20px rgba(245, 158, 11, 0.3);
      }
      .ps-banner-icon { font-size: 18px; flex-shrink: 0; }
      .ps-banner-text { flex: 1; line-height: 1.4; }
      .ps-banner-close {
        background: none; border: none; color: #FDE68A;
        font-size: 18px; cursor: pointer; padding: 2px 6px;
        border-radius: 4px; flex-shrink: 0; opacity: 0.7;
        transition: opacity 0.15s;
      }
      .ps-banner-close:hover { opacity: 1; }
    `;
    document.documentElement.appendChild(style);
  }

  // ─── Listen for results from the background worker ────────────────────────

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type !== "PHISHSHIELD_RESULT") return;
    const { data } = message;
    if (!data) return;

    if (data.classification === "phishing") {
      showPhishingOverlay(data);
    } else if (data.classification === "suspicious") {
      showSuspiciousBanner(data);
    }
  });

  // ─── Request result on page load, with retry logic ────────────────────────
  // The background may not have finished analysis yet (race condition),
  // so we retry a few times with increasing delays.

  let shown = false;

  function handleResult(result) {
    if (!result || shown) return;
    if (result.classification === "phishing" || result.classification === "suspicious") {
      shown = true;
    }
    if (result.classification === "phishing") {
      showPhishingOverlay(result);
    } else if (result.classification === "suspicious") {
      showSuspiciousBanner(result);
    }
  }

  function requestResult(attempt) {
    if (shown) return;
    chrome.runtime.sendMessage({ type: "GET_RESULT" }, (result) => {
      if (chrome.runtime.lastError) return;
      if (result) {
        handleResult(result);
      } else if (attempt < 5) {
        // Back off: 200ms → 400ms → 800ms → 1200ms → 2000ms
        const delay = [200, 400, 800, 1200, 2000][attempt];
        setTimeout(() => requestResult(attempt + 1), delay);
      }
    });
  }

  requestResult(0);

  // ─── Content-based phishing detection ───────────────────────────────────
  // Runs after the page has rendered, scans visible text and input fields.
  // Sends findings to background which merges them with the URL-based score.

  // Strong-signal keywords — any match counts as a serious phishing indicator
  const STRONG_PATTERNS = [
    { re: /\botp\b/i,                    score: 30, label: "This page is requesting an OTP (one-time password)" },
    { re: /enter\s+your\s+(pin|password)/i, score: 30, label: "This page is asking for your PIN or password" },
    { re: /\bcvv\b/i,                    score: 30, label: "This page is requesting your card CVV" },
    { re: /kyc\s*(verification|update|required)/i, score: 25, label: "This page claims to require KYC verification" },
    { re: /(verify|confirm|update)\s+your\s+(account|details|identity)/i, score: 25, label: "Suspicious account verification request detected" },
    { re: /\baadhaar\b/i,                score: 25, label: "This page is requesting Aadhaar details" },
    { re: /\b(pan\s*card|pan\s*number)\b/i, score: 25, label: "This page is requesting PAN card details" },
    { re: /account.{0,20}(suspend|block|restrict)/i, score: 25, label: "This page claims your account is suspended or restricted" },
  ];

  // Supporting signals — add weight but not enough alone to force phishing
  const SUPPORT_PATTERNS = [
    { re: /urgent.{0,30}(verify|update|confirm|login)/i, score: 20, label: "Urgency language combined with a login or verification request" },
    { re: /(act now|immediately|within \d+ hours)/i,     score: 20, label: "High-pressure urgency language detected" },
    { re: /bank\s+(account|details|number)/i,            score: 15, label: "This page is asking for bank account details" },
    { re: /won.{0,30}(prize|reward|lottery|cash)/i,      score: 15, label: "Prize or reward scam language detected" },
    { re: /free\s+(gift|offer|reward|iphone|cash)/i,     score: 10, label: "Fake free offer language detected" },
  ];

  const SENSITIVE_INPUT_RE = /otp|pin|password|cvv|card.?number|aadhaar|pan/i;

  function analyzePageContent() {
    if (!document.body) return;
    if (location.href.includes("warning.html")) return;
    if (!location.href.startsWith("http")) return;

    let contentScore     = 0;
    const contentReasons = [];
    const seen           = new Set();
    let strongHits       = 0; // count of strong-signal matches

    const text = document.body.innerText.slice(0, 15000);

    // 1. Strong patterns
    for (const { re, score, label } of STRONG_PATTERNS) {
      if (re.test(text) && !seen.has(label)) {
        seen.add(label);
        contentScore += score;
        contentReasons.push(label);
        strongHits++;
      }
    }

    // 2. Supporting patterns
    for (const { re, score, label } of SUPPORT_PATTERNS) {
      if (re.test(text) && !seen.has(label)) {
        seen.add(label);
        contentScore += score;
        contentReasons.push(label);
      }
    }

    // 3. Sensitive input fields → +40
    let hasSensitiveInputs = false;
    for (const input of document.querySelectorAll("input")) {
      const attrs = [input.type, input.name, input.id, input.placeholder].join(" ");
      if (input.type === "password" || SENSITIVE_INPUT_RE.test(attrs)) {
        hasSensitiveInputs = true;
        break;
      }
    }

    if (hasSensitiveInputs) {
      contentScore += 40;
      contentReasons.push("This page contains sensitive input fields (password, OTP, or PIN)");
    }

    // forcePhishing = strong keywords present AND sensitive inputs found
    const forcePhishing = strongHits > 0 && hasSensitiveInputs;

    contentScore = Math.min(contentScore, 60); // slightly higher cap to let serious pages reach 75+
    if (contentScore === 0) return;

    chrome.runtime.sendMessage(
      { type: "CONTENT_ANALYSIS", contentScore, contentReasons, hasSensitiveInputs, forcePhishing },
      (updatedResult) => {
        if (chrome.runtime.lastError || !updatedResult) return;
        handleResult(updatedResult);
      }
    );
  }

  // Wait 1.5 s for the page to render before scanning
  setTimeout(analyzePageContent, 1500);
})();
