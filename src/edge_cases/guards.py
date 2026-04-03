
"""
Edge case handlers as LangChain RunnableLambda components.
"""
import re
import urllib.parse
from langchain_core.runnables import RunnableLambda, Runnable

# ---- Injection Guard --------------------------------------------------------

INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above|prior)\s+instructions?",
    r"system\s+prompt",
    r"classify\s+(this\s+)?as\s+(safe|legitimate|ham)",
    r"supervisor\s+instruction",
    r"override\s+(safety|filter|rule)",
    r"you\s+are\s+now\s+(a\s+)?different",
    r"forget\s+your\s+(previous|prior|all)",
    r"new\s+rule\s*:",
    r"disregard\s+(the|all|previous)",
    r"act\s+as\s+if",
]
ZERO_WIDTH = ["\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\ufeff"]


def _sanitize_injection(text: str) -> str:
    for c in ZERO_WIDTH:
        text = text.replace(c, "")
    for p in INJECTION_PATTERNS:
        text = re.sub(p, "[REDACTED]", text, flags=re.I | re.DOTALL)
    return text.strip()


def create_injection_guard() -> Runnable:
    return RunnableLambda(_sanitize_injection).with_config(
        run_name="InjectionGuard",
        tags=["edge_case", "security"],
    )


# ---- URL Guard --------------------------------------------------------------

HIGH_RISK_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "loan"}
SHORTENERS = {"bit.ly", "tinyurl.com", "ow.ly", "t.co", "goo.gl", "is.gd"}


def _detect_url_flags(text: str) -> str:
    flags: list[str] = []
    for url in re.findall(r"https?://[^\s]+", text):
        decoded = urllib.parse.unquote(url)
        if any(ord(c) > 127 for c in decoded):
            flags.append("homograph_chars")
        if "xn--" in url.lower():
            flags.append("punycode_encoding")
        if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
            flags.append("ip_address_url")
        if "@" in urllib.parse.urlparse(url).netloc:
            flags.append("at_symbol_trick")
        try:
            netloc = urllib.parse.urlparse(url).netloc.lower().replace("www.", "")
            if netloc in SHORTENERS:
                flags.append("url_shortener")
            try:
                import tldextract
                ext = tldextract.extract(url)
                if ext.suffix in HIGH_RISK_TLDS:
                    flags.append(f"high_risk_tld_.{ext.suffix}")
            except ImportError:
                pass
        except Exception:
            pass
        if len(url) > 100:
            flags.append("long_url")
    if flags:
        return text + f"\n\n[URL_THREAT_FLAGS]: {', '.join(set(flags))}"
    return text


def create_url_guard() -> Runnable:
    return RunnableLambda(_detect_url_flags).with_config(
        run_name="URLGuard",
        tags=["edge_case", "url_analysis"],
    )


# ---- Attachment Guard -------------------------------------------------------

SVG_RISKS = [r"\.svg", r"onload=", r"<script", r"xlink:href", r"foreignObject"]
HTML_RISKS = [r"\.html?", r"blob:", r"base64", r"atob\(", r"document\.write"]
PDF_RISKS  = [r"\.pdf", r"/js\b", r"openaction", r"launchurl", r"embedded.*exe"]
QR_RISKS   = [r"qr.?code", r"scan.*verify", r"scan.*authenticat"]
EXE_EXT    = r"\b\w+\.(exe|bat|ps1|vbs|jar|js)\b"


def _flag_attachments(text: str) -> str:
    flags: list[str] = []

    def hits(patterns):
        return any(re.search(p, text, re.I) for p in patterns)

    if hits(SVG_RISKS):  flags.append("svg_script_risk")
    if hits(HTML_RISKS): flags.append("html_smuggling_risk")
    if hits(PDF_RISKS):  flags.append("malicious_pdf_risk")
    if hits(QR_RISKS):   flags.append("qr_quishing_risk")
    for ext in set(re.findall(EXE_EXT, text, re.I)):
        flags.append(f"dangerous_ext_{ext}")
    if flags:
        return text + f"\n\n[ATTACHMENT_FLAGS]: {', '.join(flags)}"
    return text


def create_attachment_guard() -> Runnable:
    return RunnableLambda(_flag_attachments).with_config(
        run_name="AttachmentGuard",
        tags=["edge_case", "attachment_analysis"],
    )


# ---- Composed pre-processor -------------------------------------------------

def build_input_preprocessor() -> Runnable:
    """Chains all three guards: InjectionGuard | URLGuard | AttachmentGuard"""
    return (
        create_injection_guard()
        | create_url_guard()
        | create_attachment_guard()
    ).with_config(run_name="InputPreprocessor")
