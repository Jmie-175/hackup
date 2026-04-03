// PhishGuard ribbon.js — risk banner + 5-tab analysis drawer

const THEME = {
  bg: "#020817", fg: "#f8fafc", primary: "#3b82f6",
  border: "#1e293b", card: "rgba(15,23,42,0.8)", muted: "#94a3b8",
};

const VERDICT_COLORS = {
  threat:     { bg:"rgba(239,68,68,0.1)",   border:"#ef4444", text:"#fecaca", label:"PHISHING ATTACK"    },
  suspicious: { bg:"rgba(245,158,11,0.1)",  border:"#f59e0b", text:"#fef3c7", label:"SUSPICIOUS ACTIVITY"},
  safe:       { bg:"rgba(16,185,129,0.1)",  border:"#10b981", text:"#d1fae5", label:"SCAN VERIFIED"      },
  error:      { bg:"rgba(100,116,139,0.1)", border:"#64748b", text:"#f1f5f9", label:"SCAN FAILED"        },
};

const ATTACK_ICONS = {
  credential_harvest: "🎣",
  bec:                "🏢",
  spear_phish:        "🎯",
  malware_delivery:   "💀",
  social_engineering: "🧠",
  ai_generated:       "🤖",
  unknown:            "❓",
};

// ── Styles (injected once) ────────────────────────────────────────────────
function injectStyles() {
  if (document.getElementById("pg-styles")) return;
  const s = document.createElement("style");
  s.id = "pg-styles";
  s.innerHTML = `
    @keyframes pg-slide-in { from{transform:translateX(100%)} to{transform:translateX(0)} }
    .pg-card {
      background:${THEME.card}; border:1px solid ${THEME.border};
      border-radius:12px; padding:16px; margin-bottom:14px;
      transition:border-color 0.2s;
    }
    .pg-card:hover { border-color:${THEME.primary}; }
    .pg-tab-btn {
      position:relative; flex:1; padding:12px 4px;
      background:transparent; border:none;
      border-bottom:2px solid transparent;
      cursor:pointer; transition:all 0.2s;
      display:flex; align-items:center; justify-content:center;
      overflow:visible;
    }
    .pg-tab-btn svg {
      width:20px; height:20px;
      stroke:${THEME.muted}; stroke-width:1.7;
      stroke-linecap:round; stroke-linejoin:round;
      fill:none; transition:stroke 0.2s; display:block;
    }
    .pg-tab-btn.active { border-bottom-color:${THEME.primary}; }
    .pg-tab-btn.active svg { stroke:#fff; }
    .pg-tab-btn:hover:not(.active) svg { stroke:${THEME.fg}; }
    .pg-tab-tip {
      position:absolute; bottom:calc(100% + 8px); left:50%;
      transform:translateX(-50%) translateY(4px);
      background:#1e293b; color:#e2e8f0;
      font-size:10px; font-weight:700; letter-spacing:0.5px;
      white-space:nowrap; padding:4px 10px;
      border-radius:6px; border:1px solid #334155;
      pointer-events:none; opacity:0;
      transition:opacity 0.15s, transform 0.15s;
      text-transform:uppercase; font-family:'Inter',sans-serif;
      z-index:100001;
    }
    .pg-tab-tip::after {
      content:''; position:absolute; top:100%; left:50%;
      transform:translateX(-50%);
      border:4px solid transparent; border-top-color:#334155;
    }
    .pg-tab-btn:hover .pg-tab-tip {
      opacity:1; transform:translateX(-50%) translateY(0);
    }
    .pg-tab-content { display:none; }
    .pg-tab-content.active { display:block; animation:pg-fade 0.2s ease; }
    @keyframes pg-fade { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }
    .pg-action-btn {
      border:1px solid ${THEME.border}; background:transparent; color:${THEME.fg};
      padding:9px 12px; border-radius:8px; cursor:pointer; font-size:12px;
      font-weight:600; transition:all 0.2s; font-family:'Inter',sans-serif; flex:1;
    }
    .pg-action-btn:hover { background:rgba(255,255,255,0.05); border-color:#fff; }
    .pg-pill {
      display:inline-block; padding:2px 10px; border-radius:20px;
      font-size:10px; font-weight:700; letter-spacing:0.5px;
    }
    .pg-bar-wrap {
      background:rgba(255,255,255,0.05); border-radius:10px;
      height:6px; overflow:hidden; margin:6px 0;
    }
    .pg-bar { height:100%; border-radius:10px; transition:width 0.6s ease; }
  `;
  document.head.appendChild(s);
}

// ── Ribbon banner ─────────────────────────────────────────────────────────
document.addEventListener("pg:result", (e) => {
  renderRibbon(e.detail);
  if (e.detail.score >= 40) renderTooltipsOnLinks(e.detail);
});

function renderRibbon(result) {
  const old = document.getElementById("pg-ribbon");
  if (old) old.remove();
  const emailBody = document.querySelector(".a3s.aiL");
  if (!emailBody) return;

  injectStyles();
  const c = VERDICT_COLORS[result.verdict] || VERDICT_COLORS.error;
  const cls = result.classification;
  const score = result.score ?? 0;
  const reason = (result.reasons?.[0] ?? "Analysis complete").toUpperCase();

  // Attachment warning badge
  const dangerousAtts = (result.attachments || []).filter(a => a.risk_score >= 40);
  const attBadge = dangerousAtts.length
    ? `<span class="pg-pill" style="background:rgba(239,68,68,0.2);color:#fca5a5;border:1px solid #ef4444">
         ⚠ ${dangerousAtts.length} RISKY ATTACHMENT${dangerousAtts.length > 1 ? "S" : ""}
       </span>`
    : "";

  // Attack type badge
  const attackBadge = cls && cls.attack_type !== "unknown"
    ? `<span class="pg-pill" style="background:rgba(59,130,246,0.15);color:#93c5fd;border:1px solid #3b82f6">
         ${ATTACK_ICONS[cls.attack_type] || ""} ${cls.attack_type_label}
       </span>`
    : "";

  const ribbon = document.createElement("div");
  ribbon.id = "pg-ribbon";
  ribbon.style.cssText = `
    background:${THEME.bg}; border:1px solid ${THEME.border};
    border-left:4px solid ${c.border}; padding:14px 20px; margin-bottom:20px;
    font-family:'Inter',-apple-system,sans-serif; font-size:13px; border-radius:12px;
    display:flex; align-items:center; justify-content:space-between; gap:16px;
    box-shadow:0 10px 30px -10px rgba(0,0,0,0.5); color:${THEME.fg};
    position:relative; overflow:hidden;
  `;

  ribbon.innerHTML = `
    <div style="position:absolute;inset:0;background:${c.bg};pointer-events:none;z-index:0"></div>
    <div style="flex:1;position:relative;z-index:1">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:5px">
        <span style="font-weight:800;font-size:11px;letter-spacing:1px;color:${c.border}">${c.label}</span>
        <span style="width:4px;height:4px;border-radius:50%;background:${THEME.border}"></span>
        <span style="font-weight:700;color:#fff">${score}% RISK</span>
        ${result.ai_generated_score >= 65
          ? `<span class="pg-pill" style="background:linear-gradient(45deg,#7c3aed,#4f46e5);color:#fff">🤖 AI-DETECTED</span>`
          : ""}
        ${attackBadge}
        ${attBadge}
      </div>
      <div style="color:${THEME.muted};font-size:12px;font-weight:500">${reason}</div>
    </div>
    <button id="pg-details-btn" style="
      background:rgba(255,255,255,0.05);border:1px solid ${THEME.border};color:#fff;
      padding:8px 16px;font-size:12px;cursor:pointer;border-radius:8px;font-weight:600;
      transition:all 0.2s;position:relative;z-index:1;white-space:nowrap;
      font-family:'Inter',sans-serif">
      Analyze Details ↗
    </button>
  `;

  emailBody.parentNode.insertBefore(ribbon, emailBody);
  const btn = ribbon.querySelector("#pg-details-btn");
  btn.onmouseover = () => { btn.style.borderColor=c.border; btn.style.background="rgba(255,255,255,0.1)"; };
  btn.onmouseout  = () => { btn.style.borderColor=THEME.border; btn.style.background="rgba(255,255,255,0.05)"; };
  btn.onclick = () => showDetailsDrawer(result);
}

// ── Link tooltips ─────────────────────────────────────────────────────────
function renderTooltipsOnLinks(result) {
  const isHigh = result.score >= 70;
  const color  = isHigh ? VERDICT_COLORS.threat.border : VERDICT_COLORS.suspicious.border;
  document.querySelectorAll(".a3s.aiL a").forEach((link) => {
    link.style.boxShadow   = `inset 0 -2px 0 ${color}`;
    link.style.color       = color;
    link.style.fontWeight  = "600";
    link.style.textDecoration = "none";
  });
}

// ── Tabbed drawer ─────────────────────────────────────────────────────────
function showDetailsDrawer(result) {
  const old = document.getElementById("pg-drawer");
  if (old) { old.remove(); return; }
  injectStyles();

  const c   = VERDICT_COLORS[result.verdict] || VERDICT_COLORS.error;
  const cls = result.classification;

  // ── Tab definitions ────────────────────────────────────────────────────
  // Tab 1: Overview
  // Tab 2: Signals
  // Tab 3: URLs
  // Tab 4: Attachments
  // Tab 5: Actions
  const TAB_SVGS = {
    overview:    `<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>`,
    signals:     `<svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`,
    urls:        `<svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
    attachments: `<svg viewBox="0 0 24 24"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>`,
    actions:     `<svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`,
  };
  const tabs = [
    { id:"overview",     label:"Overview"    },
    { id:"signals",      label:"Signals"     },
    { id:"urls",         label:"URLs"        },
    { id:"attachments",  label:"Attachments" },
    { id:"actions",      label:"Actions"     },
  ];

  const drawer = document.createElement("div");
  drawer.id = "pg-drawer";
  drawer.style.cssText = `
    position:fixed; top:0; right:0; width:420px; height:100vh;
    background:rgba(2,8,23,0.97); backdrop-filter:blur(12px);
    border-left:1px solid ${THEME.border}; box-shadow:-10px 0 50px rgba(0,0,0,0.5);
    z-index:100000; display:flex; flex-direction:column;
    color:${THEME.fg}; font-family:'Inter',-apple-system,sans-serif;
    animation:pg-slide-in 0.3s cubic-bezier(0,0,0.2,1);
  `;

  // ── Header ─────────────────────────────────────────────────────────────
  drawer.innerHTML = `
    <div style="padding:20px 24px;border-bottom:1px solid ${THEME.border};
                display:flex;justify-content:space-between;align-items:center;
                background:rgba(255,255,255,0.02);flex-shrink:0">
      <div>
        <div style="font-size:10px;color:${THEME.primary};font-weight:800;
                    letter-spacing:2px;margin-bottom:2px">THREAT ANALYSIS</div>
        <div style="font-weight:700;font-size:16px;color:#fff">PhishGuard Intelligence</div>
      </div>
      <button id="pg-close-drawer" style="
        border:none;background:rgba(255,255,255,0.05);width:32px;height:32px;
        border-radius:50%;color:#fff;cursor:pointer;font-size:18px;
        display:flex;align-items:center;justify-content:center">×</button>
    </div>

    <!-- Tab bar -->
    <div style="display:flex;border-bottom:1px solid ${THEME.border};
                padding:0 16px;flex-shrink:0;background:rgba(255,255,255,0.01)">
      ${tabs.map(t => `
        <button class="pg-tab-btn${t.id==="overview"?" active":""}" data-tab="${t.id}" aria-label="${t.label}">
          ${TAB_SVGS[t.id]}
          <span class="pg-tab-tip">${t.label}</span>
        </button>`).join("")}
    </div>

    <!-- Scrollable content -->
    <div id="pg-tab-body" style="flex:1;overflow-y:auto;padding:20px 20px 32px">

      <!-- ── TAB: OVERVIEW ── -->
      <div class="pg-tab-content active" id="pg-tab-overview">
        <div class="pg-card" style="text-align:center;border:2px solid ${c.border};background:rgba(255,255,255,0.01)">
          <div style="font-size:60px;font-weight:900;color:#fff;line-height:1;margin-bottom:4px">${result.score}</div>
          <div style="font-size:11px;color:${THEME.muted};font-weight:700;letter-spacing:1px">COMPOSITE RISK INDEX</div>
          <div style="margin-top:12px">
            <span class="pg-pill" style="background:${c.border};color:#fff;font-size:12px;padding:4px 16px">${c.label}</span>
          </div>
          ${result.ai_generated_score >= 65
            ? `<div style="margin-top:10px">
                 <span class="pg-pill" style="background:rgba(124,58,237,0.2);color:#c4b5fd;border:1px solid #7c3aed">
                   🤖 AI-Generated Content Detected (${result.ai_generated_score}%)
                 </span>
               </div>`
            : ""}
        </div>

        ${cls ? `
        <div class="pg-card">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
            <span style="font-size:22px">${ATTACK_ICONS[cls.attack_type] || "❓"}</span>
            <div>
              <div style="font-weight:700;color:#fff;font-size:13px">${cls.attack_type_label}</div>
              <div style="font-size:10px;color:${THEME.muted};letter-spacing:1px">ATTACK CLASSIFICATION</div>
            </div>
            <span class="pg-pill" style="margin-left:auto;background:rgba(59,130,246,0.15);
                  color:#93c5fd;border:1px solid rgba(59,130,246,0.3)">
              ${cls.confidence}% confidence
            </span>
          </div>
          <div style="font-size:12px;color:${THEME.muted};line-height:1.6;margin-bottom:10px">
            ${cls.attack_type_description}
          </div>
          ${cls.target_brand
            ? `<div style="font-size:11px;color:${THEME.fg}">
                 🎯 Target brand: <strong style="color:${c.border}">${cls.target_brand}</strong>
               </div>`
            : ""}
          ${cls.target_persona
            ? `<div style="font-size:11px;color:${THEME.fg};margin-top:4px">
                 👤 Target persona: <strong style="color:#f59e0b">${cls.target_persona}</strong>
               </div>`
            : ""}
        </div>` : ""}

        <div class="pg-card">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
            <span style="font-size:16px">✨</span>
            <span style="font-weight:700;font-size:13px;color:#fff">AI Threat Insight</span>
          </div>
          <div style="font-size:12px;line-height:1.7;color:${THEME.fg};opacity:0.9">
            ${result.explanation || "No explanation available."}
          </div>
        </div>

        ${result.reasons?.length ? `
        <div class="pg-card">
          <div style="font-weight:700;font-size:11px;color:${THEME.muted};letter-spacing:1px;margin-bottom:10px">
            TOP RISK REASONS
          </div>
          ${result.reasons.map((r,i) => `
            <div style="display:flex;gap:10px;margin-bottom:8px;font-size:12px">
              <span style="color:${c.border};font-weight:700;flex-shrink:0">${i+1}.</span>
              <span style="color:${THEME.fg};line-height:1.5">${r}</span>
            </div>`).join("")}
        </div>` : ""}
      </div>

      <!-- ── TAB: SIGNALS ── -->
      <div class="pg-tab-content" id="pg-tab-signals">
        <div style="font-size:11px;color:${THEME.muted};margin-bottom:14px;letter-spacing:0.5px">
          ${(result.signals||[]).filter(s=>s.score>0).length} of ${(result.signals||[]).length} signals triggered
        </div>
        ${(result.signals || [])
            .filter(s => s.score > 0)
            .sort((a,b) => b.score - a.score)
            .map(s => {
              const color = s.severity==="red" ? "#ef4444"
                          : s.severity==="yellow" ? "#f59e0b" : "#10b981";
              return `
                <div class="pg-card" style="border-left:3px solid ${color};border-radius:0 12px 12px 0;padding:12px 14px">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                    <span style="font-weight:700;font-size:12px;color:#fff">${s.name}</span>
                    <span style="font-family:monospace;color:${color};font-weight:700;font-size:14px">${s.score}</span>
                  </div>
                  <div class="pg-bar-wrap">
                    <div class="pg-bar" style="width:${s.score}%;background:${color}"></div>
                  </div>
                  <div style="color:${THEME.muted};font-size:11px;margin-top:4px;line-height:1.4">${s.detail}</div>
                </div>`;
            }).join("") ||
            `<div style="color:${THEME.muted};font-size:12px;text-align:center;padding:30px">
               No high-risk signals triggered.
             </div>`}
      </div>

      <!-- ── TAB: URLs ── -->
      <div class="pg-tab-content" id="pg-tab-urls">
        ${(result.urls_found||[]).length === 0
          ? `<div style="color:${THEME.muted};font-size:12px;text-align:center;padding:30px">No URLs found in this email.</div>`
          : (result.urls_found||[]).map((url, i) => {
              const isShort = url.length > 60;
              const displayUrl = isShort ? url.slice(0,60)+"…" : url;
              const hasIp  = /https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(url);
              const hasSus = /paypa1|g00gle|amaz0n|micros0ft|\.xyz|\.tk|\.gq/.test(url);
              const isShortener = /bit\.ly|tinyurl|t\.co|goo\.gl/.test(url);
              const risk = hasIp ? "red" : hasSus ? "red" : isShortener ? "yellow" : "green";
              const riskColor = risk==="red"?"#ef4444":risk==="yellow"?"#f59e0b":"#10b981";
              const riskLabel = risk==="red"?"HIGH RISK":risk==="yellow"?"SUSPICIOUS":"LOW RISK";
              const flags = [
                hasIp       && "IP address host",
                hasSus      && "Lookalike/suspicious domain",
                isShortener && "URL shortener",
              ].filter(Boolean);
              return `
                <div class="pg-card" style="border-left:3px solid ${riskColor};border-radius:0 12px 12px 0">
                  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
                    <span style="font-size:11px;color:${THEME.muted};font-weight:700">URL ${i+1}</span>
                    <span class="pg-pill" style="background:rgba(${risk==="red"?"239,68,68":risk==="yellow"?"245,158,11":"16,185,129"},0.15);
                          color:${riskColor};border:1px solid ${riskColor}">${riskLabel}</span>
                  </div>
                  <div style="font-family:monospace;font-size:11px;color:${THEME.fg};
                              word-break:break-all;margin-bottom:8px;
                              background:rgba(255,255,255,0.03);padding:8px;border-radius:6px">
                    ${displayUrl}
                  </div>
                  ${flags.length
                    ? `<div style="display:flex;flex-wrap:wrap;gap:4px">
                         ${flags.map(f=>`<span class="pg-pill" style="background:rgba(239,68,68,0.1);
                                color:#fca5a5;border:1px solid rgba(239,68,68,0.3)">${f}</span>`).join("")}
                       </div>`
                    : `<div style="font-size:11px;color:${THEME.muted}">No obvious URL threats detected</div>`}
                </div>`;
            }).join("")}
      </div>

      <!-- ── TAB: ATTACHMENTS ── -->
      <div class="pg-tab-content" id="pg-tab-attachments">
        ${!(result.attachments?.length)
          ? `<div style="color:${THEME.muted};font-size:12px;text-align:center;padding:30px">
               No attachments detected in this email.
             </div>`
          : result.attachments.map(att => {
              const vc = att.verdict==="malicious" ? "#ef4444"
                       : att.verdict==="suspicious" ? "#f59e0b" : "#10b981";
              const vl = att.verdict==="malicious" ? "MALICIOUS"
                       : att.verdict==="suspicious" ? "SUSPICIOUS" : "CLEAN";
              const ext = att.filename.split(".").pop()?.toUpperCase() || "?";
              const flags = [
                att.macro_detected     && "VBA macros detected",
                att.js_detected        && "Embedded JavaScript",
                att.extension_spoofed  && "Extension spoofing",
              ].filter(Boolean);
              return `
                <div class="pg-card" style="border-left:3px solid ${vc};border-radius:0 12px 12px 0">
                  <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
                    <div style="width:36px;height:36px;border-radius:8px;background:rgba(255,255,255,0.05);
                                border:1px solid ${vc};display:flex;align-items:center;justify-content:center;
                                font-size:11px;font-weight:800;color:${vc};flex-shrink:0">${ext}</div>
                    <div style="flex:1;min-width:0">
                      <div style="font-weight:700;color:#fff;font-size:13px;
                                  overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
                        ${att.filename}
                      </div>
                      <div style="font-size:11px;color:${THEME.muted}">${att.file_type}</div>
                    </div>
                    <div style="text-align:right;flex-shrink:0">
                      <div style="font-family:monospace;font-size:18px;font-weight:700;color:${vc}">${att.risk_score}</div>
                      <span class="pg-pill" style="background:rgba(${att.verdict==="malicious"?"239,68,68":att.verdict==="suspicious"?"245,158,11":"16,185,129"},0.15);
                            color:${vc};border:1px solid ${vc}">${vl}</span>
                    </div>
                  </div>
                  <div class="pg-bar-wrap">
                    <div class="pg-bar" style="width:${att.risk_score}%;background:${vc}"></div>
                  </div>
                  ${flags.length
                    ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:8px">
                         ${flags.map(f=>`<span class="pg-pill" style="background:rgba(239,68,68,0.1);
                                color:#fca5a5;border:1px solid rgba(239,68,68,0.3)">⚠ ${f}</span>`).join("")}
                       </div>`
                    : ""}
                  ${att.signals?.filter(s=>s.score>20).map(s => `
                    <div style="margin-top:8px;font-size:11px;color:${THEME.muted};
                                border-top:1px solid ${THEME.border};padding-top:8px">
                      <strong style="color:${THEME.fg}">${s.name}:</strong> ${s.detail}
                    </div>`).join("") || ""}
                </div>`;
            }).join("")}
      </div>

      <!-- ── TAB: ACTIONS ── -->
      <div class="pg-tab-content" id="pg-tab-actions">
        <!-- Quick actions -->
        <div class="pg-card">
          <div style="font-weight:700;font-size:12px;color:#fff;margin-bottom:12px">Quick Actions</div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <button class="pg-action-btn" onclick="pgCopyReport(${JSON.stringify(JSON.stringify({
              verdict: "__VERDICT__", score: "__SCORE__", attack: "__ATK__", reasons: "__REASONS__"
            }))})">
              📋 Copy Threat Report
            </button>
            <button class="pg-action-btn" id="pg-mark-spam-btn">
              🚫 Mark as Spam &amp; Delete
            </button>
            <button class="pg-action-btn" id="pg-open-dash-btn">
              📊 Open PhishGuard Dashboard
            </button>
          </div>
        </div>

        <!-- Feedback -->
        <div class="pg-card">
          <div style="font-weight:700;font-size:12px;color:#fff;margin-bottom:4px">Improve Detection</div>
          <div style="font-size:11px;color:${THEME.muted};margin-bottom:12px">
            Was this scan wrong? Your feedback trains our model.
          </div>
          <div style="display:flex;gap:8px">
            <button class="pg-action-btn" id="pg-fb-safe">✅ Not Phishing</button>
            <button class="pg-action-btn" id="pg-fb-phish">⚠ Missed Threat</button>
          </div>
        </div>

        <!-- Email metadata -->
        <div class="pg-card">
          <div style="font-weight:700;font-size:12px;color:#fff;margin-bottom:10px">Scan Metadata</div>
          <div style="font-size:11px;color:${THEME.muted};line-height:2">
            <div><span style="color:${THEME.fg}">Scan ID:</span> <span style="font-family:monospace;font-size:10px">__SCAN_ID__</span></div>
            <div><span style="color:${THEME.fg}">Signals run:</span> __SIG_COUNT__</div>
            <div><span style="color:${THEME.fg}">URLs found:</span> __URL_COUNT__</div>
            <div><span style="color:${THEME.fg}">Attachments:</span> __ATT_COUNT__</div>
            <div><span style="color:${THEME.fg}">AI-gen score:</span> __AI_SCORE__%</div>
          </div>
        </div>
      </div>

    </div><!-- end scrollable body -->
  `;

  // ── Fill dynamic placeholders in Actions tab ──────────────────────────
  const actionsTab = drawer.querySelector("#pg-tab-actions");
  actionsTab.innerHTML = actionsTab.innerHTML
    .replace("__VERDICT__", result.verdict)
    .replace("__SCORE__",   result.score)
    .replace("__ATK__",     result.classification?.attack_type_label || "unknown")
    .replace("__REASONS__", (result.reasons||[]).join(" | "))
    .replace("__SCAN_ID__", result.id?.slice(0,8)+"…" || "—")
    .replace("__SIG_COUNT__", result.signals?.length || 0)
    .replace("__URL_COUNT__", result.urls_found?.length || 0)
    .replace("__ATT_COUNT__", result.attachments?.length || 0)
    .replace("__AI_SCORE__", result.ai_generated_score || 0);

  document.body.appendChild(drawer);

  // ── Tab switching ─────────────────────────────────────────────────────
  drawer.querySelectorAll(".pg-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      drawer.querySelectorAll(".pg-tab-btn").forEach(b => b.classList.remove("active"));
      drawer.querySelectorAll(".pg-tab-content").forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      drawer.querySelector(`#pg-tab-${btn.dataset.tab}`)?.classList.add("active");
    });
  });

  // ── Button wiring ─────────────────────────────────────────────────────
  drawer.querySelector("#pg-close-drawer").onclick = () => drawer.remove();
  drawer.querySelector("#pg-fb-safe").onclick  = () => pgSendFeedback(result.id, "false_positive", drawer);
  drawer.querySelector("#pg-fb-phish").onclick = () => pgSendFeedback(result.id, "false_negative", drawer);
  drawer.querySelector("#pg-open-dash-btn").onclick = () =>
    window.open("http://localhost:5173", "_blank");
  drawer.querySelector("#pg-mark-spam-btn").onclick = () => {
    alert("To mark as spam: use Gmail's Report Spam button in the toolbar above the email.");
  };

  // Copy report button
  drawer.querySelector(".pg-action-btn").onclick = () => {
    const report = [
      `PhishGuard Threat Report`,
      `Verdict: ${result.verdict.toUpperCase()} (${result.score}/100)`,
      `Attack type: ${result.classification?.attack_type_label || "unknown"}`,
      `Reasons: ${(result.reasons||[]).join("; ")}`,
      `Scan ID: ${result.id}`,
    ].join("\n");
    navigator.clipboard.writeText(report).then(() => {
      drawer.querySelector(".pg-action-btn").textContent = "✅ Copied!";
      setTimeout(() => { drawer.querySelector(".pg-action-btn").textContent = "📋 Copy Threat Report"; }, 2000);
    });
  };
}

// ── Feedback ──────────────────────────────────────────────────────────────
window.pgSendFeedback = async (scanId, correction, drawer) => {
  try {
    const btns = drawer.querySelectorAll("#pg-fb-safe, #pg-fb-phish");
    btns.forEach(b => { b.disabled=true; b.style.opacity="0.5"; });
    await fetch("http://localhost:8000/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scan_id: scanId, correction }),
    });
    btns.forEach(b => { b.textContent = "✅ Feedback sent!"; b.style.color = THEME.primary; });
  } catch (_) {
    alert("Could not reach PhishGuard backend.");
  }
};