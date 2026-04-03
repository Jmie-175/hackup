from models.scan_models import SignalResult
from config import settings

# Signal weights — higher = more influence on final score
WEIGHTS = {
    "Urgency language":     0.12,
    "Credential request":   0.18,
    "Brand impersonation":  0.15,
    "Sender authenticity":  0.18,
    "Text quality":         0.05,
    "IP as hostname":       0.20,
    "Domain TLD":           0.08,
    "Subdomain depth":      0.06,
    "Lookalike domain":     0.20,
    "URL shortener":        0.08,
    "URL encoding":         0.05,
    "Path keywords":        0.08,
}

DEFAULT_WEIGHT = 0.08


def compute_score(signals: list[SignalResult]) -> int:
    if not signals:
        return 0

    weighted_sum = 0.0
    total_weight = 0.0

    for signal in signals:
        w = WEIGHTS.get(signal.name, DEFAULT_WEIGHT)
        weighted_sum += signal.score * w
        total_weight += w

    if total_weight == 0:
        return 0

    raw = weighted_sum / total_weight

    # Boost: if any single signal is critical (≥85), floor the score at 65
    max_signal = max(s.score for s in signals)
    if max_signal >= 85:
        raw = max(raw, 65)

    return min(int(raw), 100)


def get_verdict(score: int) -> str:
    if score >= settings.threshold_suspicious:
        return "threat"
    if score >= settings.threshold_safe:
        return "suspicious"
    return "safe"


def top_reasons(signals: list[SignalResult], n: int = 3) -> list[str]:
    flagged = [s for s in signals if s.score > 30]
    flagged.sort(key=lambda s: s.score, reverse=True)
    return [f"{s.name}: {s.detail}" for s in flagged[:n]] or ["No significant threat indicators detected"]
