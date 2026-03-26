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
