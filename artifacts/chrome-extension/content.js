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

    // Lock scroll
    document.body.style.overflow = "hidden";

    overlayEl.querySelector("#ps-close-tab").addEventListener("click", () => {
      window.close();
      // Fallback: navigate to a safe page if tab can't be closed
      setTimeout(() => { location.href = "about:blank"; }, 300);
    });

    overlayEl.querySelector("#ps-proceed").addEventListener("click", () => {
      markDismissed();
      removeOverlay();
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
})();
