"""
multistage_tracker.py — Multi-stage attack chain tracking.

Correlates scans across the email → URL → payload attack progression.
Each scan can start a new chain or be linked to a parent chain,
building a graph of how a single attack unfolds across stages.

Called by scan.py as:
  chain_id   = start_chain(content, stage, verdict, score, parent_chain_id)
  chain_nodes = get_chain(chain_id)

Chain is stored in-memory (dict) for speed. Persisted to DB via scan_log.
For the hackathon this is sufficient; production would use Redis or DB rows.
"""
import uuid
import re
import hashlib
from datetime import datetime, timezone
from models.scan_models import AttackChainNode

# In-memory store: chain_id → list[AttackChainNode]
_chains: dict[str, list[AttackChainNode]] = {}

# Content fingerprint → chain_id (for correlation across scans)
_fingerprint_index: dict[str, str] = {}

STAGE_ORDER = {"email": 0, "url": 1, "payload": 2}


def _fingerprint(content: str) -> str:
    """
    Create a short fingerprint of content for correlation.
    Uses domain + key phrases so slightly different content still correlates.
    """
    text = content.lower()

    # Extract domains
    domains = re.findall(r"https?://([a-z0-9.\-]+)", text)

    # Extract the first 3 significant words of the subject line if present
    subject_match = re.search(r"subject:\s*(.+)", text, re.IGNORECASE)
    subject_words = []
    if subject_match:
        words = re.findall(r"[a-z]{4,}", subject_match.group(1).lower())
        subject_words = words[:3]

    # Extract sender domain
    sender_match = re.search(r"from:.*?@([a-z0-9.\-]+)", text, re.IGNORECASE)
    sender_domain = sender_match.group(1) if sender_match else ""

    fingerprint_str = "|".join(sorted(domains[:3]) + subject_words + [sender_domain])
    return hashlib.md5(fingerprint_str.encode()).hexdigest()[:12]


def _extract_display_value(content: str, stage: str) -> str:
    """Extract a short human-readable label for the chain node."""
    if stage == "email":
        subject = re.search(r"Subject:\s*(.+)", content, re.IGNORECASE)
        sender  = re.search(r"From:\s*.*?<?[\w.+-]+@([\w.-]+)>?", content, re.IGNORECASE)
        parts = []
        if sender:
            parts.append(f"@{sender.group(1)}")
        if subject:
            parts.append(subject.group(1).strip()[:40])
        return " — ".join(parts) if parts else "Email (no headers)"

    elif stage == "url":
        urls = re.findall(r"https?://([a-z0-9.\-/]+)", content.lower())
        return urls[0][:60] if urls else content[:60]

    elif stage == "payload":
        # For attachments, content might be filename or base64 prefix
        if len(content) < 100:
            return content[:60]
        return f"Attachment ({len(content)} bytes encoded)"

    return content[:60]


def start_chain(
    content: str,
    stage: str,
    verdict: str,
    score: int,
    parent_chain_id: str | None = None,
) -> str:
    """
    Start a new chain node or append to an existing chain.

    If parent_chain_id is provided, appends to that chain.
    Otherwise checks the fingerprint index to see if this content
    is related to a previous scan, and links them automatically.

    Returns chain_id (str).
    """
    node = AttackChainNode(
        stage=stage,
        value=_extract_display_value(content, stage),
        verdict=verdict,
        score=score,
    )

    # Case 1: Explicitly linked to a parent chain
    if parent_chain_id and parent_chain_id in _chains:
        existing_stages = {n.stage for n in _chains[parent_chain_id]}
        if stage not in existing_stages:
            _chains[parent_chain_id].append(node)
            # Keep chain sorted by stage order
            _chains[parent_chain_id].sort(key=lambda n: STAGE_ORDER.get(n.stage, 99))
        return parent_chain_id

    # Case 2: Check fingerprint index for automatic correlation
    fp = _fingerprint(content)
    if fp in _fingerprint_index:
        chain_id = _fingerprint_index[fp]
        if chain_id in _chains:
            existing_stages = {n.stage for n in _chains[chain_id]}
            if stage not in existing_stages:
                _chains[chain_id].append(node)
                _chains[chain_id].sort(key=lambda n: STAGE_ORDER.get(n.stage, 99))
            return chain_id

    # Case 3: New chain
    chain_id = str(uuid.uuid4())
    _chains[chain_id] = [node]
    _fingerprint_index[fp] = chain_id

    # Prune old chains to avoid unbounded memory (keep last 500)
    if len(_chains) > 500:
        oldest_keys = list(_chains.keys())[:100]
        for k in oldest_keys:
            del _chains[k]

    return chain_id


def get_chain(chain_id: str) -> list[AttackChainNode]:
    """
    Retrieve all nodes in a chain, sorted by attack stage progression.
    Returns empty list if chain_id not found.
    """
    return _chains.get(chain_id, [])


def get_all_chains() -> dict[str, list[AttackChainNode]]:
    """Return all tracked chains (for stats/debugging)."""
    return dict(_chains)


def chain_summary(chain_id: str) -> dict:
    """Return a summary dict for a chain — used in stats endpoint."""
    nodes = get_chain(chain_id)
    if not nodes:
        return {}
    max_score = max(n.score for n in nodes)
    worst_verdict = "threat" if any(n.verdict == "threat" for n in nodes) \
        else "suspicious" if any(n.verdict == "suspicious" for n in nodes) \
        else "safe"
    return {
        "chain_id": chain_id,
        "stages": [n.stage for n in nodes],
        "max_score": max_score,
        "verdict": worst_verdict,
        "node_count": len(nodes),
    }
