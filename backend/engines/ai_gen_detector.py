"""
ai_gen_detector.py — Heuristic detection of AI-generated phishing emails.

LLM-written emails have detectable fingerprints vs. human-written ones:
  - Unusually high lexical diversity (no repeated filler words)
  - Zero typos / perfectly consistent punctuation
  - Rigid 3-paragraph structure with intro/body/CTA
  - Overly formal grammar with no contractions
  - Generic placeholder patterns ("Dear Customer", "your account")
  - Unnaturally balanced sentence lengths

Called by scan.py as: get_ai_gen_details(content) -> dict
Returns: {"ai_generated_score": int, "indicators": list[str], "reasoning": str}
"""
import re
import math


def _lexical_diversity(text: str) -> float:
    """Type-Token Ratio: unique words / total words. LLMs score high (>0.72)."""
    words = re.findall(r"\b[a-z]+\b", text.lower())
    if len(words) < 20:
        return 0.0
    return len(set(words)) / len(words)


def _avg_sentence_length(text: str) -> float:
    sentences = re.split(r"[.!?]+", text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 8]
    if not sentences:
        return 0.0
    lengths = [len(s.split()) for s in sentences]
    return sum(lengths) / len(lengths)


def _sentence_length_variance(text: str) -> float:
    """Low variance = uniform sentence lengths = LLM tell."""
    sentences = re.split(r"[.!?]+", text)
    sentences = [s.strip() for s in sentences if len(s.strip()) > 8]
    if len(sentences) < 3:
        return 999.0   # not enough data — return high variance (human-like)
    lengths = [len(s.split()) for s in sentences]
    mean = sum(lengths) / len(lengths)
    variance = sum((l - mean) ** 2 for l in lengths) / len(lengths)
    return variance


def _count_typos(text: str) -> int:
    """Count common English typo patterns as proxy for human writing."""
    typo_patterns = [
        r"\b(teh|adn|taht|recieve|definately|occured|seperate|wierd|alot)\b",
        r"\b(youre|dont|cant|wont|didnt|doesnt|isnt|wasnt)\b",  # missing apostrophes
        r"\s{2,}(?!\n)",                                          # double spaces mid-sentence
        r"[a-z]\.[A-Z]",                                          # missing space after period
    ]
    count = 0
    for p in typo_patterns:
        count += len(re.findall(p, text))
    return count


def _paragraph_structure_score(text: str) -> int:
    """
    Exactly 3 paragraphs with intro + body + CTA is a strong LLM tell.
    Returns 0-40 score contribution.
    """
    paragraphs = [p.strip() for p in re.split(r"\n\n+", text) if len(p.strip()) > 20]
    if len(paragraphs) == 3:
        # Check for CTA in last paragraph
        last = paragraphs[-1].lower()
        has_cta = any(kw in last for kw in [
            "click", "verify", "confirm", "log in", "sign in",
            "visit", "follow", "please", "immediately", "now"
        ])
        return 40 if has_cta else 20
    elif len(paragraphs) == 2:
        return 10
    return 0


def _formality_score(text: str) -> int:
    """
    LLMs tend to write formally. Contractions signal human writing.
    Returns 0-25 score.
    """
    text_lower = text.lower()
    contraction_count = len(re.findall(
        r"\b(i'm|you're|we're|they're|it's|don't|can't|won't|didn't|"
        r"doesn't|isn't|wasn't|couldn't|shouldn't|wouldn't|i've|we've|"
        r"you've|i'd|we'd|you'd|they'd|i'll|we'll|you'll)\b",
        text_lower
    ))
    word_count = len(text.split())
    if word_count < 10:
        return 0
    contraction_ratio = contraction_count / word_count
    # No contractions at all = very formal = LLM-like
    if contraction_ratio == 0:
        return 25
    elif contraction_ratio < 0.01:
        return 12
    return 0


def _generic_greeting_score(text: str) -> int:
    """
    LLMs use generic greetings. Named greetings suggest human/spear.
    Returns 0-20 score.
    """
    text_lower = text[:200].lower()
    generic = [
        r"dear (customer|user|member|account holder|valued customer|sir|madam)",
        r"hello (there|customer|user)",
        r"greetings",
        r"to whom it may concern",
        r"dear (account|email) (holder|owner)",
    ]
    for p in generic:
        if re.search(p, text_lower):
            return 20
    return 0


def _repetition_score(text: str) -> int:
    """
    Humans repeat filler words; LLMs have high variety.
    Returns score 0-15: HIGH score = LOW repetition = LLM-like.
    """
    words = re.findall(r"\b[a-z]{4,}\b", text.lower())
    if len(words) < 30:
        return 0
    from collections import Counter
    freq = Counter(words)
    # Most common non-stopword appearing >3 times suggests human repetition
    stopwords = {"that", "this", "with", "from", "your", "have", "been",
                 "will", "they", "their", "about", "which", "when", "what",
                 "were", "more", "also", "into", "than", "some", "such"}
    content_words = {w: c for w, c in freq.items() if w not in stopwords}
    max_repeat = max(content_words.values()) if content_words else 0
    # Low max_repeat relative to word count = LLM-like high diversity
    if max_repeat <= 2 and len(words) > 80:
        return 15
    elif max_repeat <= 1 and len(words) > 40:
        return 10
    return 0


def get_ai_gen_details(content: str) -> dict:
    """
    Main entry point called by routers/scan.py.

    Args:
        content: Raw email text

    Returns:
        {
          "ai_generated_score": int (0-100),
          "indicators": list[str],
          "reasoning": str
        }
    """
    if not content or len(content.strip()) < 50:
        return {
            "ai_generated_score": 0,
            "indicators": [],
            "reasoning": "Content too short for AI-generation analysis."
        }

    indicators = []
    score = 0

    # ── 1. Lexical diversity ──────────────────────────────────────────────
    ttr = _lexical_diversity(content)
    if ttr > 0.78:
        score += 22
        indicators.append(f"Very high lexical diversity (TTR={ttr:.2f}) — typical of LLM output")
    elif ttr > 0.70:
        score += 12
        indicators.append(f"High lexical diversity (TTR={ttr:.2f})")

    # ── 2. Zero typos ─────────────────────────────────────────────────────
    typo_count = _count_typos(content)
    if typo_count == 0 and len(content) > 200:
        score += 15
        indicators.append("No typos or punctuation errors — unusually clean for human email")
    elif typo_count >= 3:
        score = max(0, score - 10)  # typos are a strong human signal — reduce score

    # ── 3. Paragraph structure ────────────────────────────────────────────
    para_score = _paragraph_structure_score(content)
    score += para_score
    if para_score >= 40:
        indicators.append("Classic 3-paragraph structure (intro + body + CTA) — common LLM template")
    elif para_score > 0:
        indicators.append("Structured 2-section format typical of AI-generated content")

    # ── 4. Sentence length variance ───────────────────────────────────────
    variance = _sentence_length_variance(content)
    if variance < 8:
        score += 18
        indicators.append(f"Very uniform sentence lengths (variance={variance:.1f}) — LLM fingerprint")
    elif variance < 18:
        score += 8
        indicators.append(f"Low sentence length variance ({variance:.1f})")

    # ── 5. Formal language / no contractions ─────────────────────────────
    formal_score = _formality_score(content)
    score += formal_score
    if formal_score >= 25:
        indicators.append("No contractions used — overly formal register common in LLM output")
    elif formal_score > 0:
        indicators.append("Very low contraction frequency — formal tone")

    # ── 6. Generic greeting ───────────────────────────────────────────────
    greet_score = _generic_greeting_score(content)
    score += greet_score
    if greet_score:
        indicators.append("Generic impersonal greeting (e.g. 'Dear Customer') — LLM placeholder pattern")

    # ── 7. Low word repetition ────────────────────────────────────────────
    rep_score = _repetition_score(content)
    score += rep_score
    if rep_score:
        indicators.append("Unusually low content-word repetition — matches LLM high-diversity output")

    # Clamp to 0-100
    score = max(0, min(score, 100))

    # ── Build reasoning ───────────────────────────────────────────────────
    if score >= 70:
        reasoning = f"Strong AI-generation signals detected (score {score}/100). This email exhibits multiple LLM fingerprints including {', '.join(ind.split('—')[0].strip().lower() for ind in indicators[:2])}."
    elif score >= 40:
        reasoning = f"Moderate AI-generation likelihood (score {score}/100). Some LLM-typical patterns present but not conclusive."
    else:
        reasoning = f"Low AI-generation likelihood (score {score}/100). Writing style appears consistent with human authorship."

    return {
        "ai_generated_score": score,
        "indicators": indicators,
        "reasoning": reasoning
    }
