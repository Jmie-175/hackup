"""
Risk engine — weighted multi-signal scoring with input-type awareness.
Optimizations over v1:
  - Input-type specific weight profiles (email vs URL vs attachment)
  - Confidence decay: low-confidence signals weighted down
  - Hard floor raised for critical signal combinations
  - Explainability: returns contributing signals sorted by impact
"""
from models.scan_models import SignalResult
from config import settings

# Weight profiles per input type
WEIGHTS_EMAIL = {
    "Urgency language":     0.11,
    "Credential request":   0.16,
    "Brand impersonation":  0.13,
    "Sender authenticity":  0.16,
    "Display-name spoof":   0.20,  # new high-weight signal
    "Text quality":         0.04,
    "Link density":         0.08,
    "IP as hostname":       0.14,
    "Domain TLD":           0.07,
    "Subdomain depth":      0.05,
    "Lookalike domain":     0.18,
    "URL shortener":        0.07,
    "URL encoding":         0.04,
    "Path keywords":        0.06,
}

WEIGHTS_URL = {
    "IP as hostname":    0.25,
    "Lookalike domain":  0.25,
    "Domain TLD":        0.15,
    "URL shortener":     0.12,
    "Subdomain depth":   0.10,
    "URL encoding":      0.08,
    "Path keywords":     0.10,
}

WEIGHTS_ATTACHMENT = {
    "File extension":         0.20,
    "Magic bytes / file type": 0.25,
    "Double extension":        0.25,
    "Filename suspicion":      0.12,
    "Office macros":           0.20,
    "PDF embedded JS":         0.18,
    "File size":               0.05,
}

WEIGHT_MIXED = {**WEIGHTS_EMAIL, **WEIGHTS_ATTACHMENT}
DEFAULT_WEIGHT = 0.08

# Signal combinations that should hard-floor the score
CRITICAL_COMBOS = [
    # Display-name spoof + any credential request → always at least 75
    ({"Display-name spoof", "Credential request"}, 75),
    # IP host + path keywords → at least 70
    ({"IP as hostname", "Path keywords"}, 70),
    # Lookalike + brand impersonation → at least 72
    ({"Lookalike domain", "Brand impersonation"}, 72),
    # Double extension + macros → at least 80
    ({"Double extension", "Office macros"}, 80),
]


def _get_weights(signals: list[SignalResult]) -> dict:
    names = {s.name for s in signals}
    
    has_attachment = "File extension" in names or "Magic bytes / file type" in names
    has_email = any(n in names for n in WEIGHTS_EMAIL.keys())

    if has_attachment and has_email:
        return WEIGHT_MIXED
    if has_attachment:
        return WEIGHTS_ATTACHMENT
    
    # URL-only mode detection
    if len(names & set(WEIGHTS_URL.keys())) >= 3 and "Urgency language" not in names:
        return WEIGHTS_URL
        
    return WEIGHTS_EMAIL


def compute_score(signals: list[SignalResult]) -> int:
    if not signals:
        return 0

    weights_dict = _get_weights(signals)
    
    # 1. Base Score: Maximum signal (weighted)
    # The strongest indicator defines the risk baseline
    max_score = 0.0
    for s in signals:
        w = weights_dict.get(s.name, DEFAULT_WEIGHT)
        # Weight scales the impact of the signal (0.8x to 1.2x)
        impact_factor = 0.8 + (min(w / DEFAULT_WEIGHT, 2.0) * 0.2)
        effective_score = s.score * impact_factor
        if effective_score > max_score:
            max_score = effective_score

    # 2. Accumulation: Additive contribution from secondary strong signals
    # Secondary indicators should add confidence to the primary threat
    accumulation = 0.0
    # Sort signals to keep logic deterministic
    sorted_signals = sorted(signals, key=lambda x: x.score, reverse=True)
    for s in sorted_signals[1:]: # Skip the max signal (already captured)
        if s.score >= 35:
            w = weights_dict.get(s.name, DEFAULT_WEIGHT)
            # Secondaries contribute 15% of their value scaled by weight
            accumulation += (s.score * 0.15 * (w / DEFAULT_WEIGHT))

    final_score = max_score + accumulation

    # 3. Hard Rules / Critical Overrides
    # Any signal >= 85 (Red) forces a Threat verdict floor
    if any(s.score >= 85 for s in signals):
        final_score = max(final_score, 75)
    
    # Combination overrides (e.g. Lookalike + Brand Imposed)
    triggered_names = {s.name for s in signals if s.score >= 40}
    for combo, floor in CRITICAL_COMBOS:
        if combo.issubset(triggered_names):
            final_score = max(final_score, floor)

    return min(int(final_score), 100)


def get_verdict(score: int) -> str:
    if score >= settings.threshold_suspicious:
        return "threat"
    if score >= settings.threshold_safe:
        return "suspicious"
    return "safe"


def top_reasons(signals: list[SignalResult], n: int = 3) -> list[str]:
    flagged = [s for s in signals if s.score > 25]
    flagged.sort(key=lambda s: s.score, reverse=True)
    return [f"{s.name}: {s.detail}" for s in flagged[:n]] or ["No significant threat indicators detected"]


def contributing_signals(signals: list[SignalResult]) -> list[SignalResult]:
    """Return signals sorted by score descending, for explainability."""
    return sorted([s for s in signals if s.score > 0], key=lambda s: s.score, reverse=True)
