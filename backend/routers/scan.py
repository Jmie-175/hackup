import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, ScanLog
from models.scan_models import ScanRequest, ScanResult
from engines.content_analyser import analyse_content
from engines.url_analyser import analyse_urls_in_text
from scoring.risk_engine import compute_score, get_verdict, top_reasons
from llm.client import explain_detection, detect_ai_generated
from routers.stream import broadcast
from config import settings

router = APIRouter()


@router.post("", response_model=ScanResult)
async def scan(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    scan_id = str(uuid.uuid4())

    # Run all signal engines
    content_signals = analyse_content(
        request.content,
        sender=_extract_sender(request.content),
        subject=_extract_subject(request.content),
    )
    url_signals = analyse_urls_in_text(request.content)

    all_signals = content_signals + url_signals

    # Compute composite score
    score = compute_score(all_signals)
    verdict = get_verdict(score)
    reasons = top_reasons(all_signals)

    # Deep explanation (only for suspicious/threat to keep overlay fast)
    explanation = "Content analysis complete."
    attack_type = "unknown"
    target_brand = None
    ai_gen_score = None

    if score >= settings.threshold_safe:
        try:
            signals_dicts = [s.model_dump() for s in all_signals]
            llm_result = await explain_detection(request.content, signals_dicts, score)
            explanation = llm_result.get("explanation", explanation)
            attack_type = llm_result.get("attack_type", "unknown")
            target_brand = llm_result.get("target_brand")
            if llm_result.get("reasons"):
                reasons = llm_result["reasons"]
        except Exception:
            pass  # fall back to heuristic reasons

    # AI-generated detection (optional, async)
    if score >= 40:
        try:
            ai_result = await detect_ai_generated(request.content)
            ai_gen_score = ai_result.get("ai_generated_score", 0)
        except Exception:
            pass

    result = ScanResult(
        id=scan_id,
        verdict=verdict,
        score=score,
        reasons=reasons,
        signals=all_signals,
        explanation=explanation,
        chain=None,
        campaign_id=None,
        ai_generated_score=ai_gen_score,
        timestamp=datetime.now(timezone.utc),
    )

    # Persist to DB
    log = ScanLog(
        id=scan_id,
        input_type=request.input_type,
        verdict=verdict,
        score=score,
        reasons=reasons,
        signals=[s.model_dump() for s in all_signals],
        chain=None,
        source=request.source,
    )
    db.add(log)
    await db.commit()

    # Broadcast to WebSocket clients
    await broadcast(result.model_dump(mode="json"))

    return result


def _extract_sender(text: str) -> str:
    import re
    m = re.search(r"From:\s*.*?<?([\w.+-]+@[\w.-]+)>?", text, re.IGNORECASE)
    return m.group(1) if m else ""


def _extract_subject(text: str) -> str:
    import re
    m = re.search(r"Subject:\s*(.+)", text, re.IGNORECASE)
    return m.group(1).strip() if m else ""
