// PhishGuard popup.js

let enabled = true;
let history = [];

// Load state
chrome.storage.local.get(["pgEnabled", "scanHistory"], (res) => {
  enabled = res.pgEnabled !== false;
  history = res.scanHistory || [];
  updateToggleUI();
  renderFeed(history);
  updateStats(history);
});

// Toggle
document.getElementById("toggle").addEventListener("click", () => {
  enabled = !enabled;
  chrome.storage.local.set({ pgEnabled: enabled });
  chrome.runtime.sendMessage({ type: "PG_TOGGLE", enabled });
  updateToggleUI();
});

// Open dashboard
document.getElementById("open-dashboard").addEventListener("click", () => {
  chrome.tabs.create({ url: "http://localhost:8000/dashboard" });
});

// Clear badge
document.getElementById("clear-badge").addEventListener("click", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) chrome.action.setBadgeText({ text: "", tabId: tabs[0].id });
  });
});

// Live updates from background
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "LIVE_RESULT") {
    const r = msg.result;
    history.unshift({
      id: r.id,
      verdict: r.verdict,
      score: r.score,
      timestamp: r.timestamp,
      reason: r.reasons?.[0] || "",
    });
    if (history.length > 50) history.pop();
    renderFeed(history);
    updateStats(history);
  }
});

// Also load from background on open
chrome.runtime.sendMessage({ type: "GET_HISTORY" }, (res) => {
  if (res?.history?.length) {
    history = res.history;
    renderFeed(history);
    updateStats(history);
  }
});

function updateToggleUI() {
  const el = document.getElementById("toggle");
  const lbl = document.getElementById("toggle-label");
  el.classList.toggle("on", enabled);
  lbl.textContent = enabled ? "ON" : "OFF";
}

function renderFeed(items) {
  const feed = document.getElementById("feed");
  if (!items.length) {
    feed.innerHTML = '<div class="empty">No scans yet — open an email to start.</div>';
    return;
  }
  feed.innerHTML = items.slice(0, 20).map((item) => {
    const dotClass = `dot-${item.verdict || "error"}`;
    const time = item.timestamp
      ? new Date(item.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      : "";
    const label = item.reason
      ? item.reason.slice(0, 40) + (item.reason.length > 40 ? "…" : "")
      : item.verdict;
    return `
      <div class="feed-item">
        <div class="dot ${dotClass}"></div>
        <div class="feed-text">${label}</div>
        <div class="feed-score">${item.score ?? "—"}</div>
      </div>`;
  }).join("");
}

function updateStats(items) {
  document.getElementById("stat-total").textContent      = items.length;
  document.getElementById("stat-threats").textContent    = items.filter((i) => i.verdict === "threat").length;
  document.getElementById("stat-suspicious").textContent = items.filter((i) => i.verdict === "suspicious").length;
}
