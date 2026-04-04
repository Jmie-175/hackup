"""
Phishing type classifier.
Identifies the specific attack type from signal patterns + content,
returning a PhishingClassification with confidence and target info.

Attack types:
  credential_harvest  — fake login page link, brand impersonation
  bec                 — Business Email Compromise, CEO/CFO fraud
  spear_phish         — targeted, personalised, named recipient
  malware_delivery    — attachment with macros/JS, drive-by download link
  social_engineering  — urgency/fear manipulation, no specific brand
  ai_generated        — LLM-written phishing detected
  unknown             — insufficient signals
"""
import re
from models.scan_models import SignalResult, PhishingClassification

ATTACK_LABELS = {
    "credential_harvest":  "Credential Harvesting",
    "bec":                 "Business Email Compromise (BEC)",
    "spear_phish":         "Spear Phishing",
    "malware_delivery":    "Malware Delivery",
    "social_engineering":  "Social Engineering",
    "ai_generated":        "AI-Generated Phishing",
    "unknown":             "Unknown Threat",
}

ATTACK_DESCRIPTIONS = {
    "credential_harvest":  "Attempts to steal login credentials via a fake brand login page or form.",
    "bec":                 "Impersonates an executive or trusted colleague to authorise fraudulent transfers or actions.",
    "spear_phish":         "Highly targeted attack using personal details to appear legitimate to a specific individual.",
    "malware_delivery":    "Delivers malware via a malicious attachment or drive-by download link.",
    "social_engineering":  "Uses psychological pressure, fear, or urgency to manipulate the recipient into acting.",
    "ai_generated":        "Content shows strong LLM-writing fingerprints — likely crafted by an AI to evade filters.",
    "unknown":             "Insufficient signals to classify the attack type with confidence.",
}

# BEC keywords
BEC_PATTERNS = [
    r"wire transfer", r"bank transfer", r"urgent payment",
    r"ceo|cfo|cto|president|executive",
    r"invoice.*attached", r"pay.*immediately",
    r"confidential.*request", r"do not (tell|inform|share)",
    r"gift card", r"itunes|amazon gift",
]

# Spear phish indicators
SPEAR_PATTERNS = [
    r"dear \w+ \w+",           # uses full name
    r"as (we|you) discussed",
    r"following up on",
    r"per our (last |recent )?conversation",
    r"your (team|department|manager)",
    r"your (recent |last )?(order|purchase|application|submission)",
]

# Malware delivery indicators
MALWARE_PATTERNS = [
    r"open.*attachment", r"see.*attached", r"download.*file",
    r"enable.*macro", r"enable.*content",
    r"view.*document", r"invoice.*\.doc", r"receipt.*\.pdf",
    r"drive\.google\.com", r"dropbox\.com/s/", r"wetransfer",
]

# Credential harvesting indicators
CRED_HARVEST_PATTERNS = [
    r"click.*verify", r"confirm.*account", r"update.*password",
    r"sign in.*below", r"log.*in.*here",
    r"your.*account.*suspended", r"restore.*access",
    r"verify.*identity", r"re-?enter.*credentials",
]


def classify_phishing(
    text: str,
    signals: list[SignalResult],
    ai_gen_score: int = 0,
) -> PhishingClassification:

    text_lower = text.lower()
    signal_names = {s.name for s in signals if s.score >= 35}

    scores: dict[str, int] = {t: 0 for t in ATTACK_LABELS}

    # ── AI-generated check (highest priority if confident) ────────────────
    if ai_gen_score >= 70:
        scores["ai_generated"] += 60
    elif ai_gen_score >= 50:
        scores["ai_generated"] += 25

    # ── BEC signals ───────────────────────────────────────────────────────
    bec_hits = sum(1 for p in BEC_PATTERNS if re.search(p, text_lower))
    scores["bec"] += bec_hits * 18
    # BEC usually has no brand impersonation — it's internal spoofing
    if "Brand impersonation" not in signal_names and "Sender authenticity" in signal_names:
        scores["bec"] += 20

    # ── Spear phish signals ───────────────────────────────────────────────
    spear_hits = sum(1 for p in SPEAR_PATTERNS if re.search(p, text_lower))
    scores["spear_phish"] += spear_hits * 15
    # Low link count + personal tone = spear phish
    link_count = len(re.findall(r"https?://", text))
    if spear_hits >= 2 and link_count <= 1:
        scores["spear_phish"] += 20

    # ── Malware delivery signals ──────────────────────────────────────────
    malware_hits = sum(1 for p in MALWARE_PATTERNS if re.search(p, text_lower))
    scores["malware_delivery"] += malware_hits * 15
    # Attachment signals from static analyser boost this
    if any(s in signal_names for s in ["Office macros", "PDF embedded JS",
                                        "Magic bytes / file type", "Double extension"]):
        scores["malware_delivery"] += 40

    # ── Credential harvesting signals ─────────────────────────────────────
    cred_hits = sum(1 for p in CRED_HARVEST_PATTERNS if re.search(p, text_lower))
    scores["credential_harvest"] += cred_hits * 14
    if "Brand impersonation" in signal_names:
        scores["credential_harvest"] += 20
    if "Display-name spoof" in signal_names:
        scores["credential_harvest"] += 15
    if "Lookalike domain" in signal_names or "IP as hostname" in signal_names:
        scores["credential_harvest"] += 20

    # ── Social engineering (catch-all) ────────────────────────────────────
    if "Urgency language" in signal_names:
        scores["social_engineering"] += 30
    if "Credential request" in signal_names:
        scores["social_engineering"] += 15

    # ── Pick winner ───────────────────────────────────────────────────────
    best = max(scores, key=lambda k: scores[k])
    best_score = scores[best]

    if best_score < 20:
        best = "unknown"
        confidence = 20
    else:
        confidence = min(best_score, 95)

    # ── Extract target ────────────────────────────────────────────────────
    target_brand = _extract_brand(text_lower)
    target_persona = _extract_persona(text_lower, best)

    return PhishingClassification(
        attack_type=best,
        attack_type_label=ATTACK_LABELS[best],
        attack_type_description=ATTACK_DESCRIPTIONS[best],
        confidence=confidence,
        target_brand=target_brand,
        target_persona=target_persona,
    )


BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "hdfc", "sbi", "icici", "chase", "wells fargo",
    "instagram", "linkedin", "coinbase", "binance", "dhl", "fedex",
    "irs", "hmrc", "twitter", "dropbox", "docusign",
]


def _extract_brand(text: str) -> str | None:
    for b in BRANDS:
        if b in text:
            return b.title()
    return None


def _extract_persona(text: str, attack_type: str) -> str | None:
    if attack_type == "bec":
        for role in ["ceo", "cfo", "cto", "president", "director", "manager"]:
            if role in text:
                return role.upper()
        return "Executive"
    if re.search(r"it (department|team|support|helpdesk)", text):
        return "IT Staff"
    if re.search(r"(customer|client) (service|support)", text):
        return "Customer"
    return None
