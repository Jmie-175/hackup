"""
Gmail attachment extractor for the Chrome extension.
content.js passes attachment metadata (filename, size, type) found in the
Gmail DOM. This module scores them without needing the actual file bytes,
using filename patterns, MIME type, and size heuristics.

For actual file content analysis, attachment_static.py is used when the
user uploads a file through the dashboard.
"""
import re
from models.scan_models import AttachmentResult, SignalResult

HIGH_RISK_EXT  = {".exe",".bat",".cmd",".ps1",".vbs",".js",".jse",
                  ".wsf",".scr",".pif",".com",".hta",".msi",".dll"}
MEDIUM_RISK_EXT= {".doc",".docx",".xls",".xlsx",".ppt",".pptx",
                  ".pdf",".zip",".rar",".7z",".iso",".img"}

SUSPICIOUS_NAME_PATTERNS = [
    r"invoice", r"payment", r"urgent", r"statement", r"receipt",
    r"refund", r"verification", r"account.*update", r"password",
    r"contract", r"offer", r"salary", r"wire",
    r"\.exe\.", r"\.pdf\.", r"\s{4,}",   # double ext or space padding
]

SAFE_MIME_TYPES = {
    "image/jpeg","image/png","image/gif","image/webp",
    "text/plain","text/csv",
    "application/json",
}


def score_attachment_metadata(
    filename: str,
    mime_type: str = "",
    size_bytes: int = 0,
) -> AttachmentResult:
    """Score an attachment based on name/type/size without file content."""
    signals: list[SignalResult] = []
    name_lower = filename.lower()
    ext = "." + name_lower.rsplit(".", 1)[-1] if "." in name_lower else ""

    # 1. Extension risk
    if ext in HIGH_RISK_EXT:
        signals.append(SignalResult(name="File extension", score=85, severity="red",
            detail=f"High-risk executable: {ext}"))
    elif ext in MEDIUM_RISK_EXT:
        signals.append(SignalResult(name="File extension", score=35, severity="yellow",
            detail=f"Document type with macro/script risk: {ext}"))
    else:
        signals.append(SignalResult(name="File extension", score=5, severity="green",
            detail=f"Extension {ext or 'unknown'} — low inherent risk"))

    # 2. MIME type mismatch
    mime_score = 0
    mime_detail = "MIME type consistent with extension"
    if mime_type and mime_type not in SAFE_MIME_TYPES:
        if ext == ".pdf" and "pdf" not in mime_type:
            mime_score = 75
            mime_detail = f"MIME '{mime_type}' doesn't match .pdf extension"
        elif ext in (".doc",".docx") and "word" not in mime_type and "office" not in mime_type:
            mime_score = 60
            mime_detail = f"MIME '{mime_type}' doesn't match Office extension"
    signals.append(SignalResult(name="MIME type", score=mime_score,
        severity="red" if mime_score >= 60 else "green", detail=mime_detail))

    # 3. Double extension
    parts = name_lower.split(".")
    double_score = 0
    if len(parts) >= 3 and ("." + parts[-2]) in (HIGH_RISK_EXT | MEDIUM_RISK_EXT):
        double_score = 88
    signals.append(SignalResult(name="Double extension", score=double_score,
        severity="red" if double_score else "green",
        detail="Double extension — possible spoofing" if double_score else "No double extension"))

    # 4. Suspicious filename
    name_hits = [p for p in SUSPICIOUS_NAME_PATTERNS if re.search(p, name_lower)]
    name_score = min(len(name_hits) * 18, 65)
    signals.append(SignalResult(name="Filename pattern", score=name_score,
        severity="yellow" if name_score > 20 else "green",
        detail=f"Suspicious keywords: {', '.join(name_hits[:3]) or 'none'}"))

    # 5. File size anomaly
    size_score = 0
    size_detail = f"Size: {size_bytes:,} bytes"
    if 0 < size_bytes < 600 and ext in (".exe",".pdf",".docx"):
        size_score = 45
        size_detail += " — suspiciously small (possible dropper stub)"
    signals.append(SignalResult(name="File size", score=size_score,
        severity="yellow" if size_score else "green", detail=size_detail))

    # Composite score
    if signals:
        risk_score = min(int(sum(s.score for s in signals) / len(signals) * 1.4), 100)
        max_sig = max(s.score for s in signals)
        if max_sig >= 80:
            risk_score = max(risk_score, 65)
    else:
        risk_score = 0

    verdict = "malicious" if risk_score >= 70 else "suspicious" if risk_score >= 40 else "clean"

    return AttachmentResult(
        filename=filename,
        risk_score=risk_score,
        verdict=verdict,
        file_type=mime_type or ext or "unknown",
        signals=signals,
        macro_detected=False,
        js_detected=False,
        extension_spoofed=double_score >= 80,
    )


def score_attachments_from_dom(attachments: list[dict]) -> list[AttachmentResult]:
    """Score a list of attachment dicts from the Gmail DOM scrape."""
    return [
        score_attachment_metadata(
            filename=a.get("filename", "unknown"),
            mime_type=a.get("mimeType", ""),
            size_bytes=a.get("size", 0),
        )
        for a in attachments
    ]
