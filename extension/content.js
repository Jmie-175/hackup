// PhishGuard content.js — Gmail observer + attachment scraper

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
  showScanningIndicator(emailBody, attachments.length);

  // Fetch attachment content asynchronously, then send combined scan payload
  fetchAndScan(emailBody, subjectEl, senderEl, attachments);
});

observer.observe(document.body, { childList: true, subtree: true });

// ── Async scan dispatcher ─────────────────────────────────────────────────
async function fetchAndScan(emailBody, subjectEl, senderEl, attachments) {
  // Try to fetch actual file bytes for each attachment (max 5 MB each)
  const attachmentFiles = await fetchAttachmentContents(attachments);

  const payload = {
    content:     buildEmailText(emailBody, subjectEl, senderEl),
    input_type:  "email",
    source:      "extension",
    // Metadata for any attachments (used as fallback when content fetch fails)
    attachments: attachments.map(({ filename, size, mimeType }) => ({
      filename, size, mimeType,
    })),
    // Actual file content for deep static analysis (only populated when fetch succeeded)
    attachment_files: attachmentFiles.length > 0 ? attachmentFiles : undefined,
  };

  chrome.runtime.sendMessage({ type: "SCAN_EMAIL", payload });
}

// ── Attachment scraper (metadata + download URL) ──────────────────────────
function scrapeAttachments() {
  const attachments = [];
  const seen = new Set();

  // Gmail attachment chips — try multiple selectors for resilience
  const chipSelectors = [".aZo", ".aQH .aZo", ".aqK .aZo"];

  for (const sel of chipSelectors) {
    document.querySelectorAll(sel).forEach((chip) => {
      const label =
        chip.getAttribute("aria-label") ||
        chip.getAttribute("data-tooltip") ||
        chip.querySelector("[aria-label]")?.getAttribute("aria-label") ||
        chip.innerText ||
        "";

      const nameMatch = label.match(/^(.+?\.\w{2,5})/);
      if (!nameMatch) return;

      const filename = nameMatch[1].trim();
      if (seen.has(filename)) return;
      seen.add(filename);

      const sizeMatch = label.match(/([\d.]+)\s*(KB|MB)/i);
      let sizeBytes = 0;
      if (sizeMatch) {
        const num  = parseFloat(sizeMatch[1]);
        const unit = sizeMatch[2].toUpperCase();
        sizeBytes  = unit === "MB" ? num * 1024 * 1024 : num * 1024;
      }

      attachments.push({
        filename,
        size:        Math.round(sizeBytes),
        mimeType:    "",
        downloadUrl: _findDownloadUrl(chip),
      });
    });
  }

  // Sweep for explicit [download] links and download-labelled anchors
  document.querySelectorAll("[download], [aria-label*='Download'][href]").forEach((el) => {
    const label =
      el.getAttribute("aria-label") ||
      el.getAttribute("data-tooltip") ||
      el.getAttribute("download") ||
      "";
    const nameMatch = label.match(/^(.+?\.\w{2,5})/);
    if (!nameMatch) return;
    const filename = nameMatch[1].trim();
    if (seen.has(filename)) return;
    seen.add(filename);
    attachments.push({ filename, size: 0, mimeType: "", downloadUrl: el.href || null });
  });

  return attachments;
}

/** Walk upward and inward from a chip element to locate a Gmail attachment download href. */
function _findDownloadUrl(chip) {
  // 1. Check for explicit download links (disp=attd is the 'Download' action)
  const downloadLink = 
    chip.querySelector("a[href*='disp=attd']") || 
    chip.querySelector("a[href*='view=att']") ||
    chip.querySelector("a[download]") ||
    chip.closest("a[href*='disp=attd']") ||
    chip.closest("a[href*='view=att']");
  
  if (downloadLink) return downloadLink.href;

  // 2. Scan the containing card for any 'Download' action elements
  const container = chip.closest("[role='listitem']") || chip.closest(".aZo") || chip.parentElement;
  if (container) {
    const actionLinks = container.querySelectorAll("a[href]");
    for (const link of actionLinks) {
       const h = link.href;
       if (h.includes("disp=attd") || h.includes("view=att") || h.includes("disp=safe")) {
         return h;
       }
    }
  }

  // 3. Last resort: any Google-hosted link inside the chip
  const anyLink = chip.querySelector("a[href]");
  if (anyLink && (anyLink.href.includes("mail.google.com") || anyLink.href.includes("googleusercontent.com"))) {
    return anyLink.href;
  }

  return null;
}

// ── Attachment content fetcher ────────────────────────────────────────────
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024; // 5 MB hard cap per file

async function fetchAttachmentContents(attachments) {
  const results = [];
  console.log(`[PhishGuard] Attempting to fetch content for ${attachments.length} attachments...`);

  for (const att of attachments) {
    if (!att.downloadUrl) {
      console.warn(`[PhishGuard] No download URL found for: ${att.filename}`);
      continue;
    }
    if (att.size > MAX_ATTACHMENT_BYTES) {
      console.warn(`[PhishGuard] File too large to fetch: ${att.filename} (${att.size} bytes)`);
      continue;
    }

    try {
      console.log(`[PhishGuard] Fetching: ${att.filename} from ${att.downloadUrl.slice(0, 50)}...`);
      const resp = await fetch(att.downloadUrl, { credentials: "include" });
      
      if (!resp.ok) {
        console.warn(`[PhishGuard] Fetch failed for ${att.filename}: HTTP ${resp.status}`);
        continue;
      }

      const blob = await resp.blob();
      console.log(`[PhishGuard] Successfully fetched ${att.filename} (${blob.size} bytes)`);

      const b64 = await _blobToBase64(blob);
      results.push({
        filename:    att.filename,
        content_b64: b64,
        mime_type:   blob.type || att.mimeType || "",
      });
    } catch (err) {
      console.error(`[PhishGuard] Content fetch error for ${att.filename}:`, err.message);
    }
  }

  return results;
}

function _blobToBase64(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      // FileReader result: "data:<mime>;base64,<data>" — strip the URI prefix
      const b64 = reader.result.split(",")[1];
      resolve(b64);
    };
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
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
    ? ` + fetching ${attachmentCount} attachment${attachmentCount > 1 ? "s" : ""}`
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
                  color:#3b82f6;margin-bottom:2px;">PHISHGUARD SCANNING</div>
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
    link.title = `PhishGuard: ${isHigh ? "high-risk" : "suspicious"} link (score ${result.score})`;
  });
}
