// CyberShield content.js — Gmail observer + attachment scraper

let isEnabled = true;
let lastScannedHash = null;

chrome.storage.local.get(["pgEnabled"], (res) => {
  isEnabled = res.pgEnabled !== false;
});

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "PG_TOGGLE") isEnabled = msg.enabled;
  if (msg.type === "SCAN_RESULT") {
    removeScanningIndicator();
    injectRibbon(msg.result);
    decorateLinks(msg.result);
  }
});

// ── MutationObserver ──────────────────────────────────────────────────────
const observer = new MutationObserver(() => {
  if (!isEnabled) return;

  const emailBody = document.querySelector(".a3s.aiL");
  const subjectEl = document.querySelector(".hP");
  const senderEl  = document.querySelector(".gD");

  if (!emailBody) return;

  const contentHash = (emailBody.innerText || "").slice(0, 200);
  if (contentHash === lastScannedHash) return;
  lastScannedHash = contentHash;

  const old = document.getElementById("pg-ribbon");
  if (old) old.remove();

  const attachments = scrapeAttachments();

  const payload = {
    content:     buildEmailText(emailBody, subjectEl, senderEl),
    input_type:  "email",
    source:      "extension",
    attachments: attachments,
  };

  chrome.runtime.sendMessage({ type: "SCAN_EMAIL", payload });
  showScanningIndicator(emailBody, attachments.length);
});

observer.observe(document.body, { childList: true, subtree: true });

// ── Attachment scraper ────────────────────────────────────────────────────
function scrapeAttachments() {
  const attachments = [];

  // Gmail attachment chips — multiple selector strategies for resilience
  const selectors = [
    "[data-tooltip][aria-label*='Download']",
    ".aZo",       // attachment chip
    ".aQH .aZo",
    "[download]", // direct download links
  ];

  const seen = new Set();
  for (const sel of selectors) {
    document.querySelectorAll(sel).forEach((el) => {
      const label = el.getAttribute("aria-label") ||
                    el.getAttribute("data-tooltip") ||
                    el.innerText || "";

      // Extract filename from label like "invoice.pdf (120 KB)"
      const nameMatch = label.match(/^(.+?\.\w{2,5})/);
      if (!nameMatch) return;

      const filename = nameMatch[1].trim();
      if (seen.has(filename)) return;
      seen.add(filename);

      // Extract size if present
      const sizeMatch = label.match(/([\d.]+)\s*(KB|MB)/i);
      let sizeBytes = 0;
      if (sizeMatch) {
        const num  = parseFloat(sizeMatch[1]);
        const unit = sizeMatch[2].toUpperCase();
        sizeBytes  = unit === "MB" ? num * 1024 * 1024 : num * 1024;
      }

      attachments.push({ filename, size: Math.round(sizeBytes), mimeType: "" });
    });
  }

  return attachments;
}

// ── Email text builder ────────────────────────────────────────────────────
function buildEmailText(body, subjectEl, senderEl) {
  const subject = subjectEl ? `Subject: ${subjectEl.innerText}\n` : "";
  const sender  = senderEl
    ? `From: ${senderEl.getAttribute("email") || senderEl.innerText}\n`
    : "";
  return `${sender}${subject}\n${body.innerText}`;
}

// ── Scanning indicator ────────────────────────────────────────────────────
function showScanningIndicator(emailBody, attachmentCount = 0) {
  removeScanningIndicator();

  if (!document.getElementById("pg-scan-styles")) {
    const s = document.createElement("style");
    s.id = "pg-scan-styles";
    s.innerHTML = `
      @keyframes pg-pulse  { 0%,100%{opacity:1}  50%{opacity:0.4} }
      @keyframes pg-bar    { 0%{transform:translateX(-100%)} 100%{transform:translateX(400%)} }
      @keyframes pg-spin   { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
    `;
    document.head.appendChild(s);
  }

  const attNote = attachmentCount > 0
    ? ` + ${attachmentCount} attachment${attachmentCount > 1 ? "s" : ""}`
    : "";

  const ind = document.createElement("div");
  ind.id = "pg-ribbon";
  ind.style.cssText = `
    background:#020817; border:1px solid #1e293b; border-left:4px solid #3b82f6;
    padding:14px 20px; margin-bottom:20px; font-family:'Inter',-apple-system,sans-serif;
    font-size:13px; border-radius:12px; display:flex; align-items:center; gap:14px;
    color:#f8fafc; position:relative; overflow:hidden;
    box-shadow:0 10px 30px -10px rgba(0,0,0,0.5);
  `;

  ind.innerHTML = `
    <div style="position:absolute;bottom:0;left:0;right:0;height:2px;
                background:rgba(59,130,246,0.15);overflow:hidden;">
      <div style="height:100%;width:30%;background:#3b82f6;border-radius:2px;
                  animation:pg-bar 1.4s ease-in-out infinite;"></div>
    </div>
    <div style="width:20px;height:20px;border-radius:50%;flex-shrink:0;
                border:2px solid rgba(59,130,246,0.2);border-top-color:#3b82f6;
                animation:pg-spin 0.8s linear infinite;"></div>
    <div style="flex:1;">
      <div style="font-weight:700;font-size:11px;letter-spacing:1px;
                  color:#3b82f6;margin-bottom:2px;">CYBERSHIELD SCANNING</div>
      <div style="font-size:12px;color:#64748b;font-weight:500;
                  animation:pg-pulse 1.8s ease-in-out infinite;">
        Analyzing sender, URLs, content${attNote}…
      </div>
    </div>
    <div style="width:32px;height:32px;border-radius:8px;flex-shrink:0;
                background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.2);
                display:flex;align-items:center;justify-content:center;font-size:16px;">🛡</div>
  `;

  emailBody.parentNode.insertBefore(ind, emailBody);
}

function removeScanningIndicator() {
  const old = document.getElementById("pg-ribbon");
  if (old) old.remove();
}

function injectRibbon(result) {
  document.dispatchEvent(new CustomEvent("pg:result", { detail: result }));
}

function decorateLinks(result) {
  if (result.score < 40) return;
  const isHigh = result.score >= 70;
  document.querySelectorAll(".a3s.aiL a").forEach((link) => {
    link.style.outline       = isHigh ? "2px solid #ef4444" : "1px solid #f59e0b";
    link.style.outlineOffset = "2px";
    link.title = `CyberShield: ${isHigh ? "high-risk" : "suspicious"} link (score ${result.score})`;
  });
}
