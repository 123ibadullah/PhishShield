var params  = new URLSearchParams(location.search);
var url     = params.get("url")    || "";
var score   = parseInt(params.get("score") || "0", 10);
var level   = params.get("level")  || "phishing";
var reasons = JSON.parse(params.get("reasons") || "[]");
var india   = params.get("india")  === "1";
var dest    = params.get("dest")   || "";

var isSuspicious = level === "suspicious";

// Apply amber theme for suspicious, red stays default
if (isSuspicious) document.body.classList.add("suspicious");

// Title / subtitle
document.getElementById("page-title").textContent =
  isSuspicious ? "Suspicious Site Warning" : "Phishing Site Blocked";
document.getElementById("page-subtitle").textContent =
  isSuspicious
    ? "PhishShield Guardian flagged this page — proceed with caution"
    : "PhishShield Guardian stopped this page from loading";
document.getElementById("shield-icon").textContent = isSuspicious ? "⚠️" : "🛡";

// Score
document.getElementById("score-circle").textContent = score;
document.getElementById("score-label").textContent  = "Risk Score: " + score + "/100";
document.getElementById("score-desc").textContent   =
  isSuspicious
    ? "This site shows signs of suspicious activity"
    : "This site has been identified as a phishing threat";

// URL
document.getElementById("url-text").textContent = url;

// Indian banking alert
if (india) document.getElementById("india-alert").style.display = "block";

// Reasons
var list  = document.getElementById("reasons-list");
var items = reasons.length ? reasons : ["This site matched multiple suspicious indicators."];
items.forEach(function(r) {
  var li = document.createElement("li");
  li.className   = "reason-item";
  li.textContent = r;
  list.appendChild(li);
});

// ─── Simple-language explanation generator ────────────────────────────────────
// Rule-based: maps detected signals → plain Hinglish sentences anyone can read.

function generateSimpleExplanation(reasons, score, isIndian) {
  var r = reasons.join(" ").toLowerCase();
  var lines = [];

  // ── Lead sentence based on risk level ──
  if (score >= 80) {
    lines.push("🚨 Yeh website almost certainly ek SCAM hai. Isko turant band karo aur kuch bhi mat daalo.");
  } else if (score >= 50) {
    lines.push("⚠️ Yeh website bahut suspicious lag rahi hai. Apni koi bhi personal ya financial details mat daalo.");
  } else {
    lines.push("⚠️ Yeh website thodi suspicious hai. Kuch bhi share karne se pehle soch lo.");
  }

  // ── Signal-specific sentences ──
  if (/otp/.test(r)) {
    lines.push("🔐 Yeh page aapka OTP maang raha hai — real banks kabhi bhi OTP kisi link ke through nahi maangte. Yeh clearly ek scam hai.");
  }
  if (/pin|password/.test(r)) {
    lines.push("🔑 Yeh page aapka password ya PIN maang raha hai — koi bhi genuine website aisa kabhi nahi karta.");
  }
  if (/cvv/.test(r)) {
    lines.push("💳 Yeh page aapka CVV number maang raha hai — yeh aapke debit/credit card ka secret code hai. Ise kisi ke saath share mat karo.");
  }
  if (/kyc/.test(r)) {
    lines.push("📋 Yeh page KYC ke naam par aapki details maang raha hai — scammers aksar KYC ka naam use karke log thagate hain.");
  }
  if (/aadhaar/.test(r)) {
    lines.push("🪪 Yeh page aapka Aadhaar number maang raha hai — ise kisi bhi unknown website pe kabhi mat daalo.");
  }
  if (/pan card|pan number/.test(r)) {
    lines.push("🪪 Yeh page aapka PAN card number maang raha hai — yeh ek sensitive document hai, link pe share mat karo.");
  }
  if (/suspend|block|restrict/.test(r)) {
    lines.push("🚫 Yeh page keh raha hai aapka account band ho jayega — yeh ek typical scam trick hai jo aapko ghabra ke jaldi kuch karne par majboor karti hai. Ghabrao mat.");
  }
  if (/urgency|act now|immediately|within.*hours/.test(r)) {
    lines.push("⏰ Yeh page aapko jaldi karwane ki koshish kar raha hai — scammers hamesha yahi karte hain taaki aap sochne ka time na lo. Ruko, sochho, phir decide karo.");
  }
  if (/input fields|sensitive input/.test(r)) {
    lines.push("📝 Is page pe ek form hai jo aapki private information maang raha hai — aise forms kabhi mat bharo agar aapko page pe shak ho.");
  }
  if (/prize|reward|lottery|free gift|free offer/.test(r)) {
    lines.push("🎁 Yeh page aapko free prize ya reward dene ka wada kar raha hai — yeh ek laalach wala trap hai. Koi bhi cheez free nahi milti, especially online.");
  }
  if (/lookalike|impersonat|fake.*domain|spoofed/.test(r)) {
    lines.push("🎭 Yeh website kisi trusted brand ki copy lag rahi hai — URL dhyan se dekho, yeh original website nahi hai.");
  }
  if (/sbi|hdfc|icici|paytm|phonepe|upi|bank/.test(r)) {
    lines.push("🏦 Yeh ek naqli bank ya payment website lag rahi hai — apne bank ko seedha official number pe call karo. Kisi link pe kuch bhi mat daalo.");
  }
  if (/suspicious.*tld|\.xyz|\.tk|\.ml|\.cf|\.gq/.test(r)) {
    lines.push("🌐 Is website ka address (URL) suspicious hai — real banks aur companies aisi websites use nahi karte.");
  }

  // ── Final advice ──
  if (isIndian) {
    lines.push("✅ Safe rehne ke liye: link close karo, apne bank ka official app kholo ya helpline pe call karo. Koi bhi OTP, PIN ya password kisi ke saath share mat karo — bank wale bhi nahi maangte.");
  } else {
    lines.push("✅ Agar koi bhi doubt ho — page band karo. Apni koi bhi personal ya financial details mat daalo.");
  }

  return lines;
}

document.getElementById("btn-explain").addEventListener("click", function() {
  var box  = document.getElementById("explain-box");
  var list = document.getElementById("explain-list");

  if (box.style.display !== "none") {
    box.style.display = "none";
    document.getElementById("btn-explain").textContent = "💬 Explain in simple language";
    return;
  }

  var lines = generateSimpleExplanation(reasons, score, india);
  list.innerHTML = "";
  lines.forEach(function(line) {
    var li = document.createElement("li");
    li.className   = "explain-item";
    li.textContent = line;
    list.appendChild(li);
  });

  box.style.display = "block";
  document.getElementById("btn-explain").textContent = "✕ Hide explanation";
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
});

// Buttons
document.getElementById("btn-back").addEventListener("click", function() {
  chrome.tabs.getCurrent(function(tab) {
    if (tab) {
      chrome.tabs.update(tab.id, { url: "https://www.google.com" });
    } else if (history.length > 1) {
      history.back();
    } else {
      window.close();
    }
  });
});

document.getElementById("btn-proceed").addEventListener("click", function() {
  if (!dest) return;
  chrome.runtime.sendMessage({ type: "ALLOW_URL", url: dest }, function() {
    location.href = dest;
  });
});
