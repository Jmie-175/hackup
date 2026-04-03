// PhishGuard content.js — watches Gmail for email opens
// Runs inside mail.google.com

let isEnabled = true;

// Restore toggle state
chrome.storage.local.get(["pgEnabled"], (res) => {
  isEnabled = res.pgEnabled !== false;
});

// Listen for toggle changes from popup
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "PG_TOGGLE") {
    isEnabled = msg.enabled;
  }
});

// Listen for scan results from background
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "SCAN_RESULT") {
    injectRibbon(msg.result);
    decorateLinks(msg.result.score);
  }
});

// MutationObserver — fires when Gmail opens an email
const observer = new MutationObserver(() => {
  if (!isEnabled) return;

  const emailBody = document.querySelector(".a3s.aiL");
  const subjectEl = document.querySelector(".hP");
  const senderEl  = document.querySelector(".gD");

  if (!emailBody || emailBody.dataset.pgScanned) return;

  emailBody.dataset.pgScanned = "true";

  const links = [...emailBody.querySelectorAll("a")]
    .map((a) => a.href)
    .filter(Boolean)
    .slice(0, 10);

  const payload = {
    content: buildEmailText(emailBody, subjectEl, senderEl),
    input_type: "email",
    source: "extension",
  };

  chrome.runtime.sendMessage({ type: "SCAN_EMAIL", payload });
  showScanningIndicator(emailBody);
});

observer.observe(document.body, { childList: true, subtree: true });

function buildEmailText(body, subjectEl, senderEl) {
  const subject = subjectEl ? `Subject: ${subjectEl.innerText}\n` : "";
  const sender  = senderEl  ? `From: ${senderEl.getAttribute("email") || senderEl.innerText}\n` : "";
  return `${sender}${subject}\n${body.innerText}`;
}

function showScanningIndicator(emailBody) {
  const old = document.getElementById("pg-ribbon");
  if (old) old.remove();

  const ind = document.createElement("div");
  ind.id = "pg-ribbon";
  ind.style.cssText =
    "background:#f0f0f0;border-left:3px solid #999;padding:8px 14px;" +
    "margin-bottom:8px;font-size:13px;font-family:sans-serif;color:#555;border-radius:0 4px 4px 0;";
  ind.textContent = "🛡 PhishGuard scanning…";
  emailBody.parentNode.insertBefore(ind, emailBody);
}

function injectRibbon(result) {
  // delegated to ribbon.js via custom event
  document.dispatchEvent(new CustomEvent("pg:result", { detail: result }));
}

function decorateLinks(score) {
  if (score < 40) return;
  document.querySelectorAll(".a3s.aiL a").forEach((link) => {
    link.style.outline = score >= 70 ? "2px solid #E24B4A" : "1px solid #EF9F27";
    link.title = `PhishGuard: suspicious link (score ${score})`;
  });
}
