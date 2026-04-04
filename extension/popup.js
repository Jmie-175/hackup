// PhishGuard popup.js

const API = 'http://localhost:8000';
let enabled = true;
let history = [];

// ── Boot ─────────────────────────────────────────────────────────────────────
chrome.storage.local.get(['pgEnabled', 'scanHistory', 'pgSettings'], (res) => {
  enabled  = res.pgEnabled !== false;
  history  = res.scanHistory || [];

  updateToggleUI();
  renderFeed(history);
  updateStats(history);

  // Restore settings toggles
  const settings = res.pgSettings || {};
  ['overlay', 'autoscan', 'notifs', 'tooltips'].forEach((key) => {
    const el = document.getElementById(`setting-${key}`);
    if (!el) return;
    // Default on for overlay, autoscan, tooltips; off for notifs
    const defaultOn = key !== 'notifs';
    const isOn = key in settings ? settings[key] : defaultOn;
    el.classList.toggle('on', isOn);
  });
});

// ── Tab switching ─────────────────────────────────────────────────────────────
document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    const target = btn.dataset.tab;

    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));

    btn.classList.add('active');
    document.getElementById(`panel-${target}`).classList.add('active');
  });
});

// ── Master toggle ─────────────────────────────────────────────────────────────
document.getElementById('toggle').addEventListener('click', () => {
  enabled = !enabled;
  chrome.storage.local.set({ pgEnabled: enabled });
  chrome.runtime.sendMessage({ type: 'PG_TOGGLE', enabled });
  updateToggleUI();
});

function updateToggleUI() {
  const el  = document.getElementById('toggle');
  const lbl = document.getElementById('toggle-label');
  const sub = document.getElementById('header-sub');
  el.classList.toggle('on', enabled);
  lbl.textContent = enabled ? 'ON' : 'OFF';
  if (sub) sub.textContent = enabled ? 'AI SHIELD ACTIVE' : 'SHIELD PAUSED';
}

// ── Settings mini-toggles ─────────────────────────────────────────────────────
document.querySelectorAll('.mini-toggle').forEach((el) => {
  el.addEventListener('click', () => {
    el.classList.toggle('on');
    const key = el.dataset.setting;
    const val = el.classList.contains('on');
    chrome.storage.local.get('pgSettings', (res) => {
      const s = res.pgSettings || {};
      s[key] = val;
      chrome.storage.local.set({ pgSettings: s });
      chrome.runtime.sendMessage({ type: 'PG_SETTING', key, value: val });
    });
  });
});

// ── Quick Scan ────────────────────────────────────────────────────────────────
document.getElementById('scan-btn').addEventListener('click', async () => {
  const content   = document.getElementById('scan-input').value.trim();
  const inputType = document.getElementById('scan-type').value;
  const btn       = document.getElementById('scan-btn');
  const resultBox = document.getElementById('scan-result');

  if (!content) return;

  btn.textContent = 'Analysing…';
  btn.disabled    = true;
  resultBox.style.display = 'none';

  try {
    const resp = await fetch(`${API}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, input_type: inputType, source: 'extension' }),
    });
    const r = await resp.json();

    const verdictEl = document.getElementById('result-verdict');
    const reasonEl  = document.getElementById('result-reason');
    const labels    = { threat: 'Phishing Detected', suspicious: 'Suspicious', safe: 'Looks Safe' };

    verdictEl.textContent  = `${labels[r.verdict] || r.verdict} — ${r.score}/100`;
    verdictEl.className    = `result-verdict ${r.verdict}`;
    reasonEl.textContent   = r.reasons?.[0] || r.explanation || '';
    resultBox.style.display = 'block';

    // Add to local history
    history.unshift({ id: r.id, verdict: r.verdict, score: r.score,
                      timestamp: r.timestamp, reason: r.reasons?.[0] || '' });
    if (history.length > 50) history.pop();
    chrome.storage.local.set({ scanHistory: history });
    renderFeed(history);
    updateStats(history);
  } catch (err) {
    const verdictEl        = document.getElementById('result-verdict');
    verdictEl.textContent  = 'Error — backend unreachable';
    verdictEl.className    = 'result-verdict';
    document.getElementById('result-reason').textContent = 'Make sure the PhishGuard backend is running on port 8000.';
    document.getElementById('scan-result').style.display = 'block';
  } finally {
    btn.textContent = 'Analyse';
    btn.disabled    = false;
  }
});

// ── Footer buttons ────────────────────────────────────────────────────────────
document.getElementById('open-dashboard').addEventListener('click', () => {
  chrome.tabs.create({ url: 'http://localhost:5173' });
});

document.getElementById('clear-badge').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) chrome.action.setBadgeText({ text: '', tabId: tabs[0].id });
  });
});

// ── Live updates from background ──────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === 'LIVE_RESULT') {
    const r = msg.result;
    history.unshift({
      id: r.id, verdict: r.verdict, score: r.score,
      timestamp: r.timestamp, reason: r.reasons?.[0] || '',
    });
    if (history.length > 50) history.pop();
    renderFeed(history);
    updateStats(history);
  }
});

// Pull history from background on popup open
chrome.runtime.sendMessage({ type: 'GET_HISTORY' }, (res) => {
  if (res?.history?.length) {
    history = res.history;
    renderFeed(history);
    updateStats(history);
  }
});

// ── Render helpers ────────────────────────────────────────────────────────────
function renderFeed(items) {
  const feed = document.getElementById('feed');
  if (!items.length) {
    feed.innerHTML = '<div class="empty">No scans yet — open an email to start.</div>';
    return;
  }
  feed.innerHTML = items.slice(0, 20).map((item) => {
    const dotClass = `dot-${item.verdict || 'error'}`;
    const time     = item.timestamp
      ? new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      : '';
    const label = item.reason
      ? item.reason.slice(0, 42) + (item.reason.length > 42 ? '…' : '')
      : item.verdict || '—';
    return `
      <div class="feed-item">
        <div class="dot ${dotClass}"></div>
        <div class="feed-content">
          <div class="feed-text">${label}</div>
          <div class="feed-time">${time}</div>
        </div>
        <div class="feed-score">${item.score ?? '—'}</div>
      </div>`;
  }).join('');
}

function updateStats(items) {
  document.getElementById('stat-total').textContent      = items.length;
  document.getElementById('stat-threats').textContent    = items.filter((i) => i.verdict === 'threat').length;
  document.getElementById('stat-suspicious').textContent = items.filter((i) => i.verdict === 'suspicious').length;
}
