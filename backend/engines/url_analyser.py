import re
import httpx
from urllib.parse import urlparse
from models.scan_models import SignalResult

SUSPICIOUS_TLDS = {".xyz", ".top", ".click", ".loan", ".work", ".gq", ".tk", ".ml", ".cf", ".icu", ".cyou", ".live", ".guru"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "short.io"}
IP_PATTERN = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
ENCODED_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")
LOOKALIKE_CHARS = re.compile(r"[0оО][a-z]|[1lI][a-z]|rn(?=[a-z])")  # paypa1, rnable


def extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s\"'<>]+", text)


async def follow_redirects(url: str, max_hops: int = 5) -> list[str]:
    chain = [url]
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            current = url
            for _ in range(max_hops):
                r = await client.head(current)
                if r.status_code in (301, 302, 303, 307, 308) and "location" in r.headers:
                    current = r.headers["location"]
                    chain.append(current)
                else:
                    break
    except Exception:
        pass
    return chain


def analyse_url(url: str) -> list[SignalResult]:
    signals = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        return [SignalResult(name="URL parse", score=50, severity="yellow", detail="Could not parse URL")]

    # IP as host
    ip_score = 85 if IP_PATTERN.match(url) else 0
    signals.append(SignalResult(
        name="IP as hostname",
        score=ip_score,
        severity="red" if ip_score else "green",
        detail="Direct IP address used instead of domain name" if ip_score else "Uses domain name",
    ))

    # Suspicious TLD
    tld_score = 0
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            tld_score = 60
            break
    signals.append(SignalResult(
        name="Domain TLD",
        score=tld_score,
        severity="yellow" if tld_score else "green",
        detail=f"TLD flagged as high-risk" if tld_score else f"TLD appears normal",
    ))

    # Subdomain depth
    subdomain_count = domain.count(".")
    # Increase weight of subdomain depth
    subdomain_score = min((subdomain_count - 1) * 25, 80) if subdomain_count > 2 else 0
    signals.append(SignalResult(
        name="Subdomain depth",
        score=subdomain_score,
        severity="yellow" if subdomain_score > 30 else "green",
        detail=f"{subdomain_count} subdomain level(s)",
    ))

    # Lookalike characters
    lookalike = LOOKALIKE_CHARS.search(domain)
    lookalike_score = 80 if lookalike else 0
    signals.append(SignalResult(
        name="Lookalike domain",
        score=lookalike_score,
        severity="red" if lookalike_score else "green",
        detail=f"Homoglyph detected: '{lookalike.group()}'" if lookalike else "No lookalike chars found",
    ))

    # URL shortener
    shortener_score = 50 if any(s in domain for s in SHORTENERS) else 0
    signals.append(SignalResult(
        name="URL shortener",
        score=shortener_score,
        severity="yellow" if shortener_score else "green",
        detail="URL shortened — true destination hidden" if shortener_score else "Direct URL",
    ))

    # Excessive encoding
    encoded_matches = ENCODED_PATTERN.findall(url)
    encode_score = min(len(encoded_matches) * 10, 60)
    signals.append(SignalResult(
        name="URL encoding",
        score=encode_score,
        severity="yellow" if encode_score > 20 else "green",
        detail=f"{len(encoded_matches)} encoded segment(s) detected",
    ))

    # Login/credential path keywords
    path_keywords = ["login", "signin", "verify", "account", "secure", "update", "confirm"]
    path_hits = [k for k in path_keywords if k in path]
    path_score = min(len(path_hits) * 15, 60)
    signals.append(SignalResult(
        name="Path keywords",
        score=path_score,
        severity="yellow" if path_score > 20 else "green",
        detail=f"Sensitive path keywords: {', '.join(path_hits) or 'none'}",
    ))

    return signals


def analyse_urls_in_text(text: str) -> list[SignalResult]:
    urls = extract_urls(text)
    if not urls:
        return [SignalResult(name="URL presence", score=0, severity="green", detail="No URLs found in content")]

    all_signals = []
    for url in urls[:3]:  # analyse top 3 URLs
        all_signals.extend(analyse_url(url))

    # Aggregate: take max score per signal type
    aggregated: dict[str, SignalResult] = {}
    for s in all_signals:
        if s.name not in aggregated or s.score > aggregated[s.name].score:
            aggregated[s.name] = s

    return list(aggregated.values())
