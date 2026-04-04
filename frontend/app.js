// CyberShield app.js — main application controller

const API = "http://localhost:8000";
let currentScanId = null;
let ws = null;

// ── Tab routing ──────────────────────────────────────────────
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${tab}`)?.classList.add("active");
    if (tab === "stats") loadStats();
    if (tab === "campaigns") loadCampaigns();
  });
});

// ── Input mode switching ─────────────────────────────────────
document.querySelectorAll(".mode-tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".mode-tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    ["email", "url", "attachment"].forEach((m) => {
      document.getElementById(`mode-${m}`).style.display = m === btn.dataset.mode ? "block" : "none";
    });
  });
});

// ── Example chips ────────────────────────────────────────────
const EXAMPLES = {
  phish_email: `Subject: URGENT: Your PayPal account has been LIMITED\nFrom: security@paypa1-alert.net\n\nDear Valued Customer,\n\nWe detected unusual activity on your account. You MUST verify within 24 hours or your account will be permanently closed.\n\nClick here to verify: http://paypa1-secure-verification.com/login?ref=urgent`,
  phish_bank: `Subject: Your Chase Account Will Be Closed\nFrom: alerts@chase-secure-bank.xyz\n\nIMPORTANT: Suspicious login detected from Russia. Verify your account immediately at http://192.168.1.254/chase/verify.php or lose access permanently.`,
  safe_email: `Subject: Team standup notes — Thursday\nFrom: sarah@ourcompany.com\n\nHi team, quick recap from today's standup. We're on track for the Q2 deadline. Next sync is Monday at 10am. Deck is on Google Drive as usual.`,
  phish_url: "http://app1e-id-verify.com/account/login?redirect=https://apple.com",
  ip_url: "http://192.168.0.1:8080/paypal/login.php?session=abc123",
  safe_url: "https://github.com/anthropics/anthropic-sdk-python",
};

document.querySelectorAll(".chip[data-example]").forEach((chip) => {
  chip.addEventListener("click", () => {
    const val = EXAMPLES[chip.dataset.example];
    if (!val) return;
    if (chip.dataset.example.includes("url")) {
      document.querySelector('.mode-tab[data-mode="url"]').click();
      document.getElementById("url-input").value = val;
    } else {
      document.querySelector('.mode-tab[data-mode="email"]').click();
      document.getElementById("email-input").value = val;
    }
  });
});

// ── File drop zone ───────────────────────────────────────────
const dropZone = document.getElementById("drop-zone");
dropZone?.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("over"); });
dropZone?.addEventListener("dragleave", () => dropZone.classList.remove("over"));
dropZone?.addEventListener("drop", (e) => {
  e.preventDefault(); dropZone.classList.remove("over");
  handleFile(e.dataTransfer.files[0]);
});
document.getElementById("file-input")?.addEventListener("change", (e) => handleFile(e.target.files[0]));
let selectedFile = null;
function handleFile(file) {
  if (!file) return;
  selectedFile = file;
  document.getElementById("drop-zone").style.display = "none";
  const box = document.getElementById("file-selected");
  box.style.display = "block";
  box.textContent = `📎 ${file.name}  (${(file.size / 1024).toFixed(1)} KB)`;
}

// ── Analyze ──────────────────────────────────────────────────
document.getElementById("analyze-btn").addEventListener("click", runAnalysis);

async function runAnalysis() {
  const activeMode = document.querySelector(".mode-tab.active")?.dataset.mode;
  let content = "";
  let inputType = "email";

  if (activeMode === "email") {
    content = document.getElementById("email-input").value.trim();
    inputType = "email";
  } else if (activeMode === "url") {
    content = document.getElementById("url-input").value.trim();
    inputType = "url";
  } else if (activeMode === "attachment") {
    if (!selectedFile) { alert("Please select a file first."); return; }
    content = await fileToBase64(selectedFile);
    inputType = "attachment_base64";
  }

  if (!content) { alert("Please enter content to analyze."); return; }

  setLoading(true);
  document.getElementById("result-panel").style.display = "none";

  try {
    const resp = await fetch(`${API}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, input_type: inputType, source: "paste" }),
    });
    if (!resp.ok) throw new Error(`Backend error ${resp.status}`);
    const result = await resp.json();
    currentScanId = result.id;
    renderResult(result);
  } catch (err) {
    alert(`Analysis failed: ${err.message}\n\nMake sure the backend is running on port 8000.`);
  } finally {
    setLoading(false);
  }
}

function setLoading(on) {
  document.getElementById("analyze-btn").disabled = on;
  document.getElementById("progress-bar").classList.toggle("active", on);
  document.getElementById("scanning-text").classList.toggle("active", on);
}

// ── Render result ────────────────────────────────────────────
function renderResult(r) {
  const panel = document.getElementById("result-panel");
  panel.style.display = "block";

  // Score ring (Chart.js doughnut)
  const color = r.score >= 70 ? "#E24B4A" : r.score >= 40 ? "#EF9F27" : "#1D9E75";
  const ctx = document.getElementById("score-ring").getContext("2d");
  if (window._scoreChart) window._scoreChart.destroy();
  window._scoreChart = new Chart(ctx, {
    type: "doughnut",
    data: { datasets: [{ data: [r.score, 100 - r.score], backgroundColor: [color, "#1e2530"], borderWidth: 0 }] },
    options: { cutout: "75%", plugins: { legend: { display: false }, tooltip: { enabled: false } } },
  });
  document.getElementById("score-num").textContent = r.score;
  document.getElementById("score-num").style.color = color;

  // Verdict badge
  const badge = document.getElementById("verdict-badge");
  badge.className = `verdict-badge ${r.verdict}`;
  const icons = { threat: "⚠", suspicious: "⚡", safe: "✓" };
  badge.textContent = `${icons[r.verdict] || "●"}  ${r.verdict.toUpperCase()}`;
  document.getElementById("verdict-summary").textContent = r.reasons?.[0] || "";

  // AI-gen badge
  const aiBadge = document.getElementById("ai-gen-badge");
  aiBadge.style.display = (r.ai_generated_score >= 65) ? "inline-block" : "none";

  // Signals
  const grid = document.getElementById("signals-grid");
  grid.innerHTML = (r.signals || []).map((s) => `
    <div class="signal-card ${s.severity}">
      <div class="signal-name">${s.name}</div>
      <div class="signal-value">${s.score}/100</div>
      <div class="signal-detail">${s.detail}</div>
    </div>`).join("");

  // Explanation
  document.getElementById("explain-box").textContent = r.explanation || "No explanation available.";

  // Attack chain
  const chainSection = document.getElementById("attack-chain-section");
  if (r.chain?.length) {
    chainSection.style.display = "block";
    document.getElementById("chain-wrap").innerHTML = r.chain.map((node, i) => `
      ${i > 0 ? '<span class="chain-arrow">→</span>' : ""}
      <div class="chain-node ${node.verdict}">${node.stage.toUpperCase()}<br>
        <small>${node.value.slice(0, 40)}</small>
      </div>`).join("");
  } else {
    chainSection.style.display = "none";
  }

  // Feedback buttons
  document.getElementById("fp-btn").onclick = () => sendFeedback(r.id, "false_positive");
  document.getElementById("fn-btn").onclick = () => sendFeedback(r.id, "false_negative");

  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ── Stats ────────────────────────────────────────────────────
async function loadStats() {
  try {
    const data = await fetch(`${API}/stats`).then((r) => r.json());
    document.getElementById("s-total").textContent = data.total_scanned;
    document.getElementById("s-threats").textContent = data.threats_detected;
    document.getElementById("s-suspicious").textContent = data.suspicious_detected;
    document.getElementById("s-rate").textContent = data.detection_rate + "%";

    // Trend chart
    const tc = document.getElementById("trend-chart").getContext("2d");
    if (window._trendChart) window._trendChart.destroy();
    window._trendChart = new Chart(tc, {
      type: "line",
      data: {
        labels: data.daily_trend.map((d) => d.date.slice(5)),
        datasets: [
          { label: "Total", data: data.daily_trend.map((d) => d.total), borderColor: "#4a5568", tension: 0.3, fill: false },
          { label: "Threats", data: data.daily_trend.map((d) => d.threats), borderColor: "#E24B4A", tension: 0.3, fill: false },
        ],
      },
      options: {
        plugins: { legend: { labels: { color: "#8899aa", font: { size: 11 } } } },
        scales: { x: { ticks: { color: "#4a5568" }, grid: { color: "#1e2530" } }, y: { ticks: { color: "#4a5568" }, grid: { color: "#1e2530" } } },
      },
    });

    // Category chart
    if (data.top_threat_types.length) {
      const cc = document.getElementById("category-chart").getContext("2d");
      if (window._catChart) window._catChart.destroy();
      window._catChart = new Chart(cc, {
        type: "bar",
        data: {
          labels: data.top_threat_types.map((t) => t.type.slice(0, 16)),
          datasets: [{ data: data.top_threat_types.map((t) => t.count), backgroundColor: "#f5a623" }],
        },
        options: {
          plugins: { legend: { display: false } },
          scales: { x: { ticks: { color: "#4a5568" }, grid: { color: "#1e2530" } }, y: { ticks: { color: "#4a5568" }, grid: { color: "#1e2530" } } },
        },
      });
    }

    // Recent list
    document.getElementById("recent-list").innerHTML = data.recent_scans.map((s) => `
      <div class="recent-item">
        <div class="r-dot ${s.verdict}"></div>
        <span class="r-time">${new Date(s.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
        <span style="flex:1;font-size:11px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
          ${s.verdict.toUpperCase()} — score ${s.score}
        </span>
        <span class="r-source">${s.source}</span>
        <span class="r-score">${s.score}</span>
      </div>`).join("") || "<div class='empty-state'>No scans yet.</div>";

  } catch (e) {
    console.error("Stats load failed:", e);
  }
}

async function loadCampaigns() {
  try {
    const data = await fetch(`${API}/stats`).then((r) => r.json());
    const el = document.getElementById("campaigns-list");
    el.innerHTML = '<div class="empty-state">Campaign clustering requires multiple scans. Keep scanning!</div>';
  } catch (_) { }
}

async function sendFeedback(scanId, correction) {
  try {
    await fetch(`${API}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId, correction }),
    });
    alert("Feedback submitted — thank you!");
  } catch (_) { alert("Backend unreachable."); }
}

// ── WebSocket live feed ───────────────────────────────────────
function connectWS() {
  ws = new WebSocket("ws://localhost:8000/stream");
  ws.onopen = () => {
    document.querySelector(".live-dot").classList.add("connected");
    document.getElementById("live-status").textContent = "Live";
  };
  ws.onmessage = (e) => {
    try {
      const r = JSON.parse(e.data);
      LiveFeed.push(r);
    } catch (_) { }
  };
  ws.onclose = () => {
    document.querySelector(".live-dot").classList.remove("connected");
    document.getElementById("live-status").textContent = "Reconnecting…";
    setTimeout(connectWS, 3000);
  };
}
connectWS();

// ── Helpers ──────────────────────────────────────────────────
function fileToBase64(file) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(r.result.split(",")[1]);
    r.onerror = rej;
    r.readAsDataURL(file);
  });
}
