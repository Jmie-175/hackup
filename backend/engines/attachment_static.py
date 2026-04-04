"""
attachment_static.py — Static analysis of uploaded file content.

Receives a base64-encoded file from the dashboard upload form and performs:
  - Magic bytes check (true file type vs stated extension)
  - Office macro detection via oletools
  - PDF embedded JavaScript / action detection via pdfminer
  - Double-extension and suspicious filename patterns
  - File size anomalies

Called by scan.py as: analyse_attachment_b64(filename, base64_content)
Returns: list[SignalResult]
"""
import base64
import re
import io
from models.scan_models import SignalResult

# High-risk extensions that should never arrive in email
HIGH_RISK_EXT = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
                 ".wsf", ".scr", ".pif", ".com", ".hta", ".msi", ".dll"}

MEDIUM_RISK_EXT = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                   ".pdf", ".zip", ".rar", ".7z", ".iso", ".img"}

# Magic bytes signatures → (true_type, label)
MAGIC_SIGNATURES = [
    (b"PK\x03\x04",           "zip/Office Open XML"),
    (b"\xd0\xcf\x11\xe0",     "OLE2 (legacy Office / .doc/.xls)"),
    (b"%PDF",                  "PDF"),
    (b"MZ",                    "Windows PE executable"),
    (b"\x7fELF",               "ELF executable (Linux)"),
    (b"#!/",                   "Shell script"),
    (b"\xca\xfe\xba\xbe",     "Java class file"),
    (b"Rar!",                  "RAR archive"),
    (b"\x1f\x8b",             "GZip archive"),
]

SUSPICIOUS_FILENAME_PATTERNS = [
    r"invoice", r"payment", r"urgent", r"statement", r"receipt",
    r"refund", r"verification", r"account.*update", r"password",
    r"contract", r"offer", r"salary", r"wire", r"remittance",
    r"\s{4,}",           # whitespace padding to hide extension
]


def _decode_b64(content: str) -> bytes:
    """Decode base64, stripping data URI prefix if present."""
    if "," in content and content.startswith("data:"):
        content = content.split(",", 1)[1]
    # Add padding if needed
    content = content.strip()
    missing = len(content) % 4
    if missing:
        content += "=" * (4 - missing)
    return base64.b64decode(content)


def _get_magic_type(data: bytes) -> str | None:
    for magic, label in MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            return label
    return None


def _check_office_macros(data: bytes, ext: str) -> tuple[bool, str]:
    """Detect VBA macros in Office files using oletools if available."""
    try:
        from oletools.olevba import VBA_Parser
        vba = VBA_Parser("file" + ext, data=data)
        if vba.detect_vba_macros():
            macros = list(vba.extract_macros())
            return True, f"{len(macros)} VBA macro(s) detected"
        return False, "No macros detected"
    except ImportError:
        # oletools not installed — fall back to pattern search
        if b"AutoOpen" in data or b"Auto_Open" in data or b"Document_Open" in data:
            return True, "Macro auto-execution keyword found (AutoOpen/Auto_Open)"
        if b"Shell(" in data or b"WScript" in data or b"PowerShell" in data:
            return True, "Suspicious shell execution pattern in Office file"
        return False, "Macro scan skipped (oletools not installed)"
    except Exception as e:
        return False, f"Macro scan error: {str(e)[:60]}"


def _check_pdf_js(data: bytes) -> tuple[bool, str]:
    """Detect embedded JavaScript or suspicious actions in PDF."""
    try:
        # Quick byte-pattern scan (no pdfminer needed)
        suspicious = []
        if b"/JavaScript" in data or b"/JS" in data:
            suspicious.append("JavaScript action")
        if b"/OpenAction" in data:
            suspicious.append("OpenAction (auto-runs on open)")
        if b"/AA" in data:
            suspicious.append("Additional Actions")
        if b"/Launch" in data:
            suspicious.append("Launch action (runs external program)")
        if b"/EmbeddedFile" in data:
            suspicious.append("Embedded file within PDF")
        if b"/RichMedia" in data:
            suspicious.append("Rich media embed")

        if suspicious:
            return True, f"PDF suspicious elements: {', '.join(suspicious)}"
        return False, "No embedded JS or suspicious actions found"
    except Exception as e:
        return False, f"PDF scan error: {str(e)[:60]}"


def analyse_attachment_b64(filename: str, content: str) -> list[SignalResult]:
    """
    Main entry point called by routers/scan.py.
    Decodes base64 file content and runs static analysis.
    Returns list[SignalResult].
    """
    signals: list[SignalResult] = []
    name_lower = filename.lower()
    parts = name_lower.rsplit(".", 1)
    ext = "." + parts[-1] if len(parts) == 2 else ""

    # ── Decode ────────────────────────────────────────────────────────────
    try:
        data = _decode_b64(content)
    except Exception as e:
        signals.append(SignalResult(
            name="File decode",
            score=30,
            severity="yellow",
            detail=f"Could not decode file: {str(e)[:80]}"
        ))
        return signals

    file_size = len(data)

    # ── 1. Extension risk ─────────────────────────────────────────────────
    if ext in HIGH_RISK_EXT:
        ext_score, ext_sev = 90, "red"
        ext_detail = f"High-risk executable extension: {ext}"
    elif ext in MEDIUM_RISK_EXT:
        ext_score, ext_sev = 35, "yellow"
        ext_detail = f"Document type with macro/script potential: {ext}"
    else:
        ext_score, ext_sev = 5, "green"
        ext_detail = f"Extension {ext or 'unknown'} — low inherent risk"

    signals.append(SignalResult(name="File extension", score=ext_score,
                                severity=ext_sev, detail=ext_detail))

    # ── 2. Magic bytes / true file type ───────────────────────────────────
    magic_type = _get_magic_type(data)
    magic_score = 0
    magic_detail = f"Magic bytes consistent with {ext or 'unknown'}"

    if magic_type:
        # Check for dangerous mismatch: stated as PDF but is actually EXE
        if "executable" in magic_type.lower() and ext not in (".exe", ".com", ".scr"):
            magic_score = 95
            magic_detail = f"DANGEROUS: File claims to be {ext} but is a {magic_type}"
        elif magic_type == "Windows PE executable" or magic_type == "ELF executable (Linux)":
            magic_score = 90
            magic_detail = f"Executable file detected: {magic_type}"
        elif "OLE2" in magic_type and ext in (".doc", ".xls", ".ppt"):
            magic_score = 20
            magic_detail = f"Legacy Office format (OLE2) — macro-capable: {magic_type}"
        elif ext == ".pdf" and magic_type != "PDF":
            magic_score = 75
            magic_detail = f"File claims .pdf but magic bytes show: {magic_type}"
        else:
            magic_detail = f"File type confirmed: {magic_type}"

    signals.append(SignalResult(name="Magic bytes / file type",
                                score=magic_score,
                                severity="red" if magic_score >= 70 else "yellow" if magic_score > 0 else "green",
                                detail=magic_detail))

    # ── 3. Double extension detection ────────────────────────────────────
    all_parts = name_lower.split(".")
    double_score = 0
    double_detail = "No double extension detected"
    if len(all_parts) >= 3:
        hidden_ext = "." + all_parts[-2]
        if hidden_ext in HIGH_RISK_EXT or hidden_ext in MEDIUM_RISK_EXT:
            double_score = 92
            double_detail = f"Double extension: ...{hidden_ext}{ext} — likely spoofing"
    signals.append(SignalResult(name="Double extension", score=double_score,
                                severity="red" if double_score else "green",
                                detail=double_detail))

    # ── 4. Suspicious filename patterns ───────────────────────────────────
    name_hits = [p for p in SUSPICIOUS_FILENAME_PATTERNS if re.search(p, name_lower)]
    name_score = min(len(name_hits) * 18, 65)
    signals.append(SignalResult(
        name="Filename suspicion",
        score=name_score,
        severity="yellow" if name_score > 20 else "green",
        detail=f"Suspicious filename keywords: {', '.join(name_hits[:3]) or 'none'}"
    ))

    # ── 5. Office macro detection ─────────────────────────────────────────
    if ext in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".xlsm", ".docm"):
        macro_found, macro_detail = _check_office_macros(data, ext)
        macro_score = 85 if macro_found else 0
        signals.append(SignalResult(
            name="Office macros",
            score=macro_score,
            severity="red" if macro_found else "green",
            detail=macro_detail
        ))
    else:
        signals.append(SignalResult(name="Office macros", score=0, severity="green",
                                    detail=f"Not an Office file ({ext})"))

    # ── 6. PDF embedded JavaScript ────────────────────────────────────────
    if ext == ".pdf" or magic_type == "PDF":
        js_found, js_detail = _check_pdf_js(data)
        js_score = 80 if js_found else 0
        signals.append(SignalResult(
            name="PDF embedded JS",
            score=js_score,
            severity="red" if js_found else "green",
            detail=js_detail
        ))
    else:
        signals.append(SignalResult(name="PDF embedded JS", score=0, severity="green",
                                    detail="Not a PDF file"))

    # ── 7. File size anomaly ──────────────────────────────────────────────
    size_score = 0
    size_detail = f"File size: {file_size:,} bytes"
    if 0 < file_size < 512 and ext in (".exe", ".pdf", ".docx"):
        size_score = 50
        size_detail += " — suspiciously small for this type (possible dropper stub)"
    elif file_size > 50_000_000:
        size_score = 20
        size_detail += " — unusually large attachment"
    signals.append(SignalResult(name="File size", score=size_score,
                                severity="yellow" if size_score else "green",
                                detail=size_detail))

    return signals
