import httpx
import json
import re
from config import settings


async def _call_ollama(model: str, prompt: str, system: str = "") -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{settings.ollama_base_url}/api/chat",
            json={"model": model, "messages": messages, "stream": False},
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


def _parse_json(text: str) -> dict:
    text = re.sub(r"```json|```", "", text).strip()
    # Find first { ... } block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(text)


async def classify_content(content: str, input_type: str) -> dict:
    """Fast classification using phi3:mini for overlay speed."""
    system = (
        "You are a cybersecurity analyst specializing in phishing detection. "
        "Always respond with valid JSON only, no markdown, no extra text."
    )
    prompt = f"""Analyze this {input_type} for phishing indicators.

CONTENT:
{content[:3000]}

Return ONLY this JSON:
{{
  "verdict": "safe|suspicious|threat",
  "score": <0-100>,
  "top_reason": "<one sentence>",
  "urgency_detected": true|false,
  "impersonation_detected": true|false,
  "suspicious_links": true|false
}}"""
    raw = await _call_ollama(settings.fast_model, prompt, system)
    return _parse_json(raw)


async def explain_detection(content: str, signals: list, score: int) -> dict:
    """Strict phishing detection prompt - biased towards higher detection"""
    
    system = (
        "You are a highly vigilant senior cybersecurity analyst specialized in phishing detection. "
        "You have a strong bias towards classifying emails as suspicious or threat when any red flags exist. "
        "Err on the side of caution. It is better to flag a potentially legitimate email than to miss a real phishing attempt."
    )

    signal_summary = "\n".join(
        f"- {s.get('name', 'Signal')}: {s.get('detail', '')} (score: {s.get('score', 0)})" 
        for s in signals
    )

    prompt = f"""Analyze this email for phishing risk.

RISK SCORE FROM SIGNALS: {score}/100

DETECTED SIGNALS:
{signal_summary}

EMAIL CONTENT:
{content[:3000]}

Task: Determine if this is likely a phishing or social engineering attempt.
Be very strict — if there is any credible suspicion (urgency, credential request, brand impersonation, suspicious link, lookalike domain, etc.), classify it as suspicious or threat.

Return ONLY valid JSON in this exact format:

{{
  "explanation": "Write 4-7 detailed sentences explaining the risk. Always cite specific evidence from the content and signals. Never say the email looks safe unless there are ZERO red flags.",
  "reasons": ["Clear reason 1", "Clear reason 2", "Clear reason 3"],
  "attack_type": "credential_harvest | bec | social_engineering | malware_delivery | unknown",
  "target_brand": "PayPal | Chase | HDFC | Apple | Microsoft | Google | null",
  "confidence": <70 to 100>
}}

Prioritize safety: If in doubt, flag it as suspicious/threat."""

    try:
        raw = await _call_ollama(settings.primary_model, prompt, system)
        result = _parse_json(raw)
        
        # Force better explanation if model is still lazy
        exp = result.get("explanation", "").strip().lower()
        if len(exp) < 50 or "content analysis complete" in exp or "no explanation" in exp:
            result["explanation"] = (
                f"This email scored {score}/100 due to multiple concerning signals including "
                + ", ".join([s.get('name','signal') for s in signals if s.get('score',0) > 30]) 
                + ". The combination strongly indicates a phishing attempt."
            )
        
        return result
    except Exception:
        # Safe strict fallback
        return {
            "explanation": f"Multiple phishing indicators detected (score: {score}/100). Signals include urgency, suspicious links, or brand impersonation. Treat with high caution.",
            "reasons": ["Multiple high-risk signals present"],
            "attack_type": "social_engineering",
            "target_brand": None,
            "confidence": 75
        }

async def detect_ai_generated(content: str) -> dict:
    """Score likelihood that content was written by an LLM."""
    system = "You are an expert in detecting AI-generated text. Respond with JSON only."
    prompt = f"""Analyze whether this email was likely written by an AI/LLM.

Look for: unusually perfect grammar, high lexical diversity, no typos, 
overly formal tone, templated structure, lack of personal details.

EMAIL:
{content[:2000]}

Return ONLY:
{{
  "ai_generated_score": <0-100>,
  "indicators": ["<indicator 1>", "<indicator 2>"],
  "reasoning": "<one sentence>"
}}"""
    raw = await _call_ollama(settings.fast_model, prompt, system)
    return _parse_json(raw)


async def interpret_sandbox_behavior(behavior: dict) -> dict:
    """Interpret sandbox syscall/network output."""
    system = "You are a malware analyst. Respond with JSON only."
    prompt = f"""A file was executed in a sandbox. Analyze the behavior:

Suspicious syscalls: {behavior.get('suspicious_syscalls', [])}
Network attempts: {behavior.get('network_attempts', [])}
Files written: {behavior.get('files_written', [])}

Return ONLY:
{{
  "verdict": "clean|suspicious|malicious",
  "score": <0-100>,
  "summary": "<one sentence>",
  "reasons": ["<reason 1>", "<reason 2>"]
}}"""
    raw = await _call_ollama(settings.primary_model, prompt, system)
    return _parse_json(raw)
