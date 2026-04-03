// PhishGuard ribbon.js — injects risk banners into Gmail email view

const COLORS = {
  threat:     { bg: "#FFF0F0", border: "#E24B4A", text: "#A32D2D", label: "Phishing detected" },
  suspicious: { bg: "#FFFBF0", border: "#EF9F27", text: "#854F0B", label: "Suspicious email"  },
  safe:       { bg: "#F0FFF8", border: "#1D9E75", text: "#085041", label: "Looks safe"        },
  error:      { bg: "#F5F5F5", border: "#999999", text: "#444444", label: "Scan unavailable"  },
};

// Listen for results dispatched by content.js
document.addEventListener("pg:result", (e) => {
  const result = e.detail;
  renderRibbon(result);
  if (result.score >= 40) renderTooltipsOnLinks(result);
});

function renderRibbon(result) {
  const old = document.getElementById("pg-ribbon");
  if (old) old.remove();

  const emailBody = document.querySelector(".a3s.aiL");
  if (!emailBody) return;

  const c = COLORS[result.verdict] || COLORS.error;
  const ribbon = document.createElement("div");
  ribbon.id = "pg-ribbon";
  ribbon.style.cssText = [
    `background:${c.bg}`,
    `border-left:4px solid ${c.border}`,
    "padding:10px 16px",
    "margin-bottom:10px",
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
    "font-size:13px",
    "border-radius:0 6px 6px 0",
    "display:flex",
    "align-items:flex-start",
    "justify-content:space-between",
    "gap:12px",
  ].join(";");

  const score = result.score ?? 0;
  const verdict = result.verdict ?? "error";
  const reason  = result.reasons?.[0] ?? "No details available";

  ribbon.innerHTML = `
    <div style="flex:1">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <span style="font-weight:600;color:${c.text}">${c.label}</span>
        <span style="background:${c.border};color:#fff;font-size:11px;
              padding:1px 8px;border-radius:10px;font-weight:500">
          Risk ${score}/100
        </span>
        ${result.ai_generated_score >= 65
          ? `<span style="background:#7F77DD;color:#fff;font-size:11px;
                  padding:1px 8px;border-radius:10px;font-weight:500">AI-generated</span>`
          : ""}
      </div>
      <div style="color:${c.text};opacity:0.85;font-size:12px;line-height:1.4">${reason}</div>
    </div>
    <button id="pg-details-btn" style="
      background:transparent;border:1px solid ${c.border};color:${c.text};
      padding:4px 10px;font-size:12px;cursor:pointer;border-radius:4px;
      white-space:nowrap;flex-shrink:0">
      Details ↗
    </button>
  `;

  emailBody.parentNode.insertBefore(ribbon, emailBody);

  document.getElementById("pg-details-btn")?.addEventListener("click", () => {
    showDetailsDrawer(result);
  });
}

function renderTooltipsOnLinks(result) {
  document.querySelectorAll(".a3s.aiL a").forEach((link) => {
    const tip = document.createElement("span");
    const isHigh = result.score >= 70;
    tip.style.cssText = [
      `background:${isHigh ? "#E24B4A" : "#EF9F27"}`,
      "color:#fff",
      "font-size:10px",
      "padding:1px 5px",
      "border-radius:3px",
      "margin-left:4px",
      "vertical-align:middle",
      "font-family:sans-serif",
      "pointer-events:none",
    ].join(";");
    tip.textContent = isHigh ? "⚠ phish" : "? suspicious";
    link.style.outline = `1px solid ${isHigh ? "#E24B4A" : "#EF9F27"}`;
    link.insertAdjacentElement("afterend", tip);
  });
}

function showDetailsDrawer(result) {
  const old = document.getElementById("pg-drawer");
  if (old) { old.remove(); return; }

  const drawer = document.createElement("div");
  drawer.id = "pg-drawer";
  drawer.style.cssText = [
    "position:fixed",
    "top:0;right:0",
    "width:360px;height:100vh",
    "background:#fff",
    "border-left:1px solid #ddd",
    "box-shadow:-4px 0 20px rgba(0,0,0,0.12)",
    "z-index:99999",
    "overflow-y:auto",
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif",
    "font-size:13px",
  ].join(";");

  const c = COLORS[result.verdict] || COLORS.error;
  const signalsHtml = (result.signals || [])
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .map((s) => {
      const barColor = s.severity === "red" ? "#E24B4A"
                     : s.severity === "yellow" ? "#EF9F27" : "#1D9E75";
      return `
        <div style="margin-bottom:10px">
          <div style="display:flex;justify-content:space-between;margin-bottom:3px">
            <span style="font-weight:500">${s.name}</span>
            <span style="color:${barColor};font-weight:600">${s.score}</span>
          </div>
          <div style="background:#eee;border-radius:3px;height:4px;overflow:hidden">
            <div style="background:${barColor};width:${s.score}%;height:100%;border-radius:3px"></div>
          </div>
          <div style="color:#666;font-size:11px;margin-top:2px">${s.detail}</div>
        </div>`;
    }).join("");

  drawer.innerHTML = `
    <div style="padding:16px;border-bottom:1px solid #eee;
                display:flex;justify-content:space-between;align-items:center">
      <span style="font-weight:600;font-size:14px;color:${c.text}">
        PhishGuard Analysis
      </span>
      <button id="pg-close-drawer" style="border:none;background:none;
              font-size:18px;cursor:pointer;color:#666">×</button>
    </div>
    <div style="padding:16px">
      <div style="text-align:center;margin-bottom:16px">
        <div style="font-size:40px;font-weight:700;color:${c.border}">${result.score}</div>
        <div style="font-size:12px;color:#666">Risk score / 100</div>
        <div style="margin-top:6px;font-weight:600;color:${c.text}">${c.label.toUpperCase()}</div>
      </div>
      <div style="background:#f7f7f7;border-radius:6px;padding:12px;
                  margin-bottom:16px;font-size:12px;line-height:1.6;color:#444">
        ${result.explanation || "No explanation available."}
      </div>
      <div style="font-weight:600;margin-bottom:10px;color:#333">Signal breakdown</div>
      ${signalsHtml || "<div style='color:#888'>No signals available</div>"}
      <div style="margin-top:16px;padding-top:12px;border-top:1px solid #eee">
        <div style="font-size:11px;color:#999;margin-bottom:6px">Was this wrong?</div>
        <div style="display:flex;gap:8px">
          <button onclick="pgSendFeedback('${result.id}','false_positive')"
            style="flex:1;padding:6px;border:1px solid #ddd;border-radius:4px;
                   background:#fff;cursor:pointer;font-size:12px;color:#555">
            Not phishing
          </button>
          <button onclick="pgSendFeedback('${result.id}','false_negative')"
            style="flex:1;padding:6px;border:1px solid #ddd;border-radius:4px;
                   background:#fff;cursor:pointer;font-size:12px;color:#555">
            Missed threat
          </button>
        </div>
      </div>
    </div>`;

  document.body.appendChild(drawer);
  document.getElementById("pg-close-drawer")?.addEventListener("click", () => drawer.remove());
}

window.pgSendFeedback = async (scanId, correction) => {
  try {
    await fetch("http://localhost:8000/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId, correction }),
    });
    alert("Feedback submitted. Thank you!");
  } catch (_) {
    alert("Could not reach PhishGuard backend.");
  }
};
