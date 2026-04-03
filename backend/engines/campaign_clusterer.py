"""
campaign_clusterer.py — Phishing campaign clustering.

Groups similar phishing emails into campaigns using lightweight
TF-IDF cosine similarity (no model required — works offline).

When a new scan arrives, it's compared against all known campaign
centroids. If similarity > threshold, it joins that campaign.
Otherwise a new campaign is started.

Called by scan.py as:
  campaign_id = assign_campaign(scan_id, content, score) -> str | None

Campaign store is in-memory for speed (dict).
Production would persist to the campaigns DB table.
"""
import re
import math
import uuid
from collections import Counter


# ── Simple TF-IDF cosine similarity ──────────────────────────────────────────

STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to",
    "for", "of", "with", "by", "from", "as", "is", "was", "are", "were",
    "be", "been", "being", "have", "has", "had", "do", "does", "did",
    "will", "would", "could", "should", "may", "might", "shall", "can",
    "not", "no", "nor", "so", "yet", "both", "either", "neither",
    "this", "that", "these", "those", "it", "its", "your", "our", "my",
    "their", "his", "her", "we", "you", "i", "he", "she", "they",
    "click", "here", "please", "thank", "dear", "regards", "sincerely",
}


def _tokenize(text: str) -> list[str]:
    text = text.lower()
    text = re.sub(r"https?://\S+", " URL ", text)      # replace URLs with token
    text = re.sub(r"[\w.+-]+@[\w.-]+", " EMAIL ", text) # replace emails
    text = re.sub(r"\d+", " NUM ", text)                # normalize numbers
    tokens = re.findall(r"\b[a-z]{3,}\b", text)
    return [t for t in tokens if t not in STOPWORDS]


def _tf(tokens: list[str]) -> dict[str, float]:
    if not tokens:
        return {}
    count = Counter(tokens)
    total = len(tokens)
    return {word: freq / total for word, freq in count.items()}


def _cosine_similarity(vec_a: dict[str, float], vec_b: dict[str, float]) -> float:
    if not vec_a or not vec_b:
        return 0.0
    common = set(vec_a) & set(vec_b)
    if not common:
        return 0.0
    dot = sum(vec_a[w] * vec_b[w] for w in common)
    mag_a = math.sqrt(sum(v ** 2 for v in vec_a.values()))
    mag_b = math.sqrt(sum(v ** 2 for v in vec_b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


def _content_fingerprint(text: str) -> dict[str, float]:
    """Return TF vector for campaign comparison."""
    tokens = _tokenize(text)
    return _tf(tokens)


# ── Campaign store ────────────────────────────────────────────────────────────

# campaign_id → {centroid, count, sample_content, avg_score, label}
_campaigns: dict[str, dict] = {}

SIMILARITY_THRESHOLD = 0.35   # emails above this join the same campaign
MAX_CAMPAIGNS = 200            # prune oldest when exceeded


def _extract_campaign_label(content: str) -> str:
    """Generate a short descriptive label for a new campaign."""
    # Try subject line
    subject_match = re.search(r"Subject:\s*(.+)", content, re.IGNORECASE)
    if subject_match:
        subject = subject_match.group(1).strip()[:50]
        return f'Emails like: "{subject}"'

    # Try brand
    brands = ["paypal", "amazon", "apple", "microsoft", "google", "netflix",
              "hdfc", "sbi", "icici", "chase", "instagram", "linkedin",
              "coinbase", "fedex", "dhl", "irs", "docusign"]
    text_lower = content.lower()
    for brand in brands:
        if brand in text_lower:
            return f"{brand.title()} impersonation campaign"

    # Fallback
    words = _tokenize(content)
    top = Counter(words).most_common(3)
    if top:
        return "Campaign: " + " + ".join(w for w, _ in top)
    return "Uncategorised campaign"


def _update_centroid(old_centroid: dict[str, float],
                     new_vec: dict[str, float],
                     count: int) -> dict[str, float]:
    """
    Online centroid update: weighted average of old centroid and new vector.
    This avoids storing all documents while keeping the centroid accurate.
    """
    all_keys = set(old_centroid) | set(new_vec)
    updated = {}
    for k in all_keys:
        old_val = old_centroid.get(k, 0.0)
        new_val = new_vec.get(k, 0.0)
        # Weighted update: (old * (n-1) + new) / n
        updated[k] = (old_val * (count - 1) + new_val) / count
    return updated


def assign_campaign(scan_id: str, content: str, score: float) -> str | None:
    """
    Main entry point called by routers/scan.py.

    Compares content against existing campaign centroids.
    Assigns to best matching campaign (if similarity >= threshold)
    or creates a new campaign.

    Args:
        scan_id: UUID of the current scan
        content: Raw email text
        score:   Risk score (float 0-100)

    Returns:
        campaign_id (str) or None if content is too short to cluster
    """
    tokens = _tokenize(content)
    if len(tokens) < 10:
        return None   # too short to cluster meaningfully

    vec = _tf(tokens)

    # ── Find best matching campaign ───────────────────────────────────────
    best_campaign_id = None
    best_similarity  = 0.0

    for cid, campaign in _campaigns.items():
        sim = _cosine_similarity(vec, campaign["centroid"])
        if sim > best_similarity:
            best_similarity = sim
            best_campaign_id = cid

    # ── Join existing campaign ────────────────────────────────────────────
    if best_campaign_id and best_similarity >= SIMILARITY_THRESHOLD:
        c = _campaigns[best_campaign_id]
        c["count"] += 1
        c["avg_score"] = (c["avg_score"] * (c["count"] - 1) + score) / c["count"]
        c["centroid"] = _update_centroid(c["centroid"], vec, c["count"])
        c["scan_ids"].append(scan_id)
        return best_campaign_id

    # ── Start new campaign ────────────────────────────────────────────────
    campaign_id = str(uuid.uuid4())
    _campaigns[campaign_id] = {
        "id":           campaign_id,
        "label":        _extract_campaign_label(content),
        "centroid":     vec,
        "count":        1,
        "avg_score":    score,
        "scan_ids":     [scan_id],
    }

    # Prune oldest campaigns if over limit
    if len(_campaigns) > MAX_CAMPAIGNS:
        # Remove campaigns with only 1 member (singletons) first
        singletons = [k for k, v in _campaigns.items() if v["count"] == 1]
        for k in singletons[:50]:
            del _campaigns[k]

    return campaign_id


def get_campaign(campaign_id: str) -> dict | None:
    """Return campaign metadata by ID."""
    return _campaigns.get(campaign_id)


def get_all_campaigns(min_count: int = 1) -> list[dict]:
    """
    Return all campaigns sorted by member count descending.
    Used by the campaigns stats endpoint.
    """
    campaigns = [
        {
            "id":        c["id"],
            "label":     c["label"],
            "count":     c["count"],
            "avg_score": round(c["avg_score"], 1),
        }
        for c in _campaigns.values()
        if c["count"] >= min_count
    ]
    return sorted(campaigns, key=lambda x: x["count"], reverse=True)
