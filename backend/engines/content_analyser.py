import re
from models.scan_models import SignalResult

URGENCY_PATTERNS = [
    r"urgent", r"immediately", r"within \d+ hours?", r"account.*suspended",
    r"verify.*now", r"click here", r"final warning", r"act now",
    r"limited time", r"expire[sd]?", r"unusual activity", r"unauthorized",
]

CREDENTIAL_PATTERNS = [
    r"enter.*password", r"confirm.*account", r"update.*payment",
    r"verify.*identity", r"login.*details", r"bank.*details",
    r"social security", r"credit card", r"otp|one.time.pass",
]

BRAND_IMPERSONATION = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "hdfc", "sbi", "icici", "chase", "wells fargo",
    "instagram", "whatsapp", "linkedin", "dropbox", "docusign",
]

SUSPICIOUS_SENDER_PATTERNS = [
    r"noreply@(?!.*\.(com|org|net)$)",
    r"support@.*\d{4,}",
    r"security.*alert@",
    r"no-reply@.*\.xyz",
    r"verify@",
]


def analyse_content(text: str, sender: str = "", subject: str = "") -> list[SignalResult]:
    signals = []
    text_lower = text.lower()

    # Urgency score
    urgency_hits = [p for p in URGENCY_PATTERNS if re.search(p, text_lower)]
    urgency_score = min(len(urgency_hits) * 15, 90)
    signals.append(SignalResult(
        name="Urgency language",
        score=urgency_score,
        severity="red" if urgency_score > 40 else "yellow" if urgency_score > 0 else "green",
        detail=f"{len(urgency_hits)} urgency trigger(s): {', '.join(urgency_hits[:3]) or 'none'}",
    ))

    # Credential harvesting
    cred_hits = [p for p in CREDENTIAL_PATTERNS if re.search(p, text_lower)]
    cred_score = min(len(cred_hits) * 20, 95)
    signals.append(SignalResult(
        name="Credential request",
        score=cred_score,
        severity="red" if cred_score > 30 else "green",
        detail=f"{len(cred_hits)} credential pattern(s) detected",
    ))

    # Brand impersonation
    brands_found = [b for b in BRAND_IMPERSONATION if b in text_lower or b in subject.lower()]
    brand_score = 60 if brands_found else 0
    # Reduce if sender domain matches brand
    if brands_found and sender:
        for brand in brands_found:
            if brand in sender.lower():
                brand_score = 0
                break
    signals.append(SignalResult(
        name="Brand impersonation",
        score=brand_score,
        severity="red" if brand_score > 0 else "green",
        detail=f"Brand(s) referenced: {', '.join(brands_found) or 'none'}",
    ))

    # Suspicious sender
    sender_score = 0
    sender_detail = "Sender pattern looks normal"
    if sender:
        for p in SUSPICIOUS_SENDER_PATTERNS:
            if re.search(p, sender.lower()):
                sender_score = 70
                sender_detail = f"Suspicious sender pattern: {sender}"
                break
        if not sender_score and "@" in sender:
            domain = sender.split("@")[-1]
            if any(brand in text_lower and brand not in domain for brand in brands_found):
                sender_score = 80
                sender_detail = f"Sender domain '{domain}' doesn't match referenced brand"

    signals.append(SignalResult(
        name="Sender authenticity",
        score=sender_score,
        severity="red" if sender_score > 50 else "yellow" if sender_score > 0 else "green",
        detail=sender_detail,
    ))

    # Grammar / quality (rough proxy: excessive caps, special chars)
    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    grammar_score = int(caps_ratio * 200) if caps_ratio > 0.15 else 0
    grammar_score = min(grammar_score, 60)
    signals.append(SignalResult(
        name="Text quality",
        score=grammar_score,
        severity="yellow" if grammar_score > 20 else "green",
        detail=f"Caps ratio {caps_ratio:.1%} — {'excessive' if grammar_score > 20 else 'normal'}",
    ))

    return signals
