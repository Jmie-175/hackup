// PhishGuard background.js — service worker
const API_BASE = "http://localhost:8000";
let ws = null;
let scanHistory = [];

function connectWebSocket() {
  try {
    ws = new WebSocket(`ws://localhost:8000/stream`);
    ws.onmessage = (e) => {
      try {
        const result = JSON.parse(e.data);
        updateHistory(result);
        notifyPopup({ type: "LIVE_RESULT", result });
      } catch (_) {}
    };
    ws.onclose = () => setTimeout(connectWebSocket, 3000);
    ws.onerror  = () => ws.close();
  } catch (_) {}
}

connectWebSocket();

// Message handler
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SCAN_EMAIL") {
    handleScan(msg.payload, sender.tab?.id);
    return true;
  }
  if (msg.type === "GET_HISTORY") {
    sendResponse({ history: scanHistory.slice(0, 20) });
    return true;
  }
  if (msg.type === "PG_TOGGLE") {
    chrome.storage.local.set({ pgEnabled: msg.enabled });
    broadcastToTabs(msg);
  }
});

async function handleScan(payload, tabId) {
  try {
    const resp = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const result = await resp.json();

    // Update badge
    setBadge(result.score, result.verdict, tabId);
    updateHistory(result);

    // Send result back to content script
    if (tabId) {
      chrome.tabs.sendMessage(tabId, { type: "SCAN_RESULT", result });
    }

    // Push notification for high-risk
    if (result.verdict === "threat") {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: "PhishGuard: Phishing Detected",
        message: result.reasons[0] || "High-risk email detected.",
        priority: 2,
      });
    }

    notifyPopup({ type: "LIVE_RESULT", result });
  } catch (err) {
    console.error("[PhishGuard] Scan failed:", err);
    if (tabId) {
      chrome.tabs.sendMessage(tabId, {
        type: "SCAN_RESULT",
        result: { verdict: "error", score: 0, reasons: ["Backend unreachable"], signals: [] },
      });
    }
  }
}

function setBadge(score, verdict, tabId) {
  const colors = { threat: "#E24B4A", suspicious: "#EF9F27", safe: "#1D9E75", error: "#888" };
  const color = colors[verdict] || "#888";
  const text  = verdict === "error" ? "!" : String(score);
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

function updateHistory(result) {
  scanHistory.unshift({
    id: result.id,
    verdict: result.verdict,
    score: result.score,
    timestamp: result.timestamp || new Date().toISOString(),
    reason: result.reasons?.[0] || "",
  });
  if (scanHistory.length > 50) scanHistory.pop();
  chrome.storage.local.set({ scanHistory });
}

function notifyPopup(msg) {
  chrome.runtime.sendMessage(msg).catch(() => {});
}

function broadcastToTabs(msg) {
  chrome.tabs.query({ url: "https://mail.google.com/*" }, (tabs) => {
    tabs.forEach((tab) => chrome.tabs.sendMessage(tab.id, msg).catch(() => {}));
  });
}
