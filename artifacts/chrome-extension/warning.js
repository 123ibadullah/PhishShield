const params  = new URLSearchParams(location.search);
const url     = params.get("url")   || "";
const score   = parseInt(params.get("score") || "0", 10);
const reasons = JSON.parse(params.get("reasons") || "[]");
const india   = params.get("india") === "1";
const dest    = params.get("dest")  || "";

document.getElementById("score-circle").textContent = score;
document.getElementById("score-label").textContent  = "Risk Score: " + score + "/100";
document.getElementById("url-text").textContent     = url;

if (india) document.getElementById("india-alert").style.display = "block";

const list = document.getElementById("reasons-list");
const items = reasons.length ? reasons : ["This site matched multiple phishing indicators."];
items.forEach(function(r) {
  var li = document.createElement("li");
  li.className   = "reason-item";
  li.textContent = r;
  list.appendChild(li);
});

document.getElementById("btn-back").addEventListener("click", function() {
  if (history.length > 1) history.back();
  else window.close();
});

document.getElementById("btn-proceed").addEventListener("click", function() {
  if (!dest) return;
  chrome.runtime.sendMessage({ type: "ALLOW_URL", url: dest }, function() {
    location.href = dest;
  });
});
