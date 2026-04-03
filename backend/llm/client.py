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
    """Deep explanation using mistral:7b."""
    system = (
        "You are a cybersecurity analyst. Provide detailed, accurate threat analysis. "
        "Always respond with valid JSON only."
    )
    signal_summary = "\n".join(
        f"- {s['name']}: {s['detail']} (score: {s['score']})" for s in signals
    )
    prompt = f"""A phishing scan produced these signals (composite score: {score}/100):

{signal_summary}

CONTENT EXCERPT:
{content[:2000]}

Return ONLY this JSON:
{{
  "explanation": "<3-5 sentence technical explanation citing specific evidence>",
  "reasons": ["<reason 1>", "<reason 2>", "<reason 3>"],
  "attack_type": "<credential_harvest|bec|malware_delivery|social_engineering|unknown>",
  "target_brand": "<brand name or null>",
  "confidence": <0-100>
}}"""
    raw = await _call_ollama(settings.primary_model, prompt, system)
    return _parse_json(raw)


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
