import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, ScanLog
from models.scan_models import ScanRequest, ScanResult
from engines.content_analyser import analyse_content
from engines.url_analyser import analyse_urls_in_text, analyse_url
from engines.attachment_static import analyse_attachment_b64
from engines.attachment_extractor import score_attachments_from_dom
from engines.ai_gen_detector import get_ai_gen_details
from engines.phishing_classifier import classify_phishing
from engines.multistage_tracker import start_chain, get_chain
from engines.campaign_clusterer import assign_campaign
from scoring.risk_engine import compute_score, get_verdict, top_reasons
from llm.client import explain_detection
from routers.stream import broadcast
from config import settings

router = APIRouter()


@router.post("", response_model=ScanResult)
async def scan(request: ScanRequest, db: AsyncSession = Depends(get_db)):
    scan_id = str(uuid.uuid4())
    all_signals = []
    attachment_results = []

    # ── Signal engines ────────────────────────────────────────────────────
    if request.input_type == "attachment_base64":
        filename = request.filename or "unknown.bin"
        all_signals.extend(analyse_attachment_b64(filename, request.content))

    elif request.input_type == "url":
        all_signals.extend(analyse_url(request.content))

    else:  # email
        sender  = _extract_sender(request.content)
        subject = _extract_subject(request.content)
        all_signals.extend(analyse_content(request.content, sender=sender, subject=subject))
        all_signals.extend(analyse_urls_in_text(request.content))

        # Score any attachments passed from Gmail DOM
        if request.attachments:
            attachment_results = score_attachments_from_dom(request.attachments)
            # Boost main score if any attachment is suspicious/malicious
            for att in attachment_results:
                if att.risk_score >= 40:
                    all_signals.extend(att.signals)

    # ── Score + verdict ───────────────────────────────────────────────────
    score   = compute_score(all_signals)
    verdict = get_verdict(score)
    reasons = top_reasons(all_signals)

    # ── AI-gen detection (heuristic, free) ────────────────────────────────
    ai_gen_score = 0
    if request.input_type == "email":
        ai_info      = get_ai_gen_details(request.content)
        ai_gen_score = ai_info.get("ai_generated_score", 0)

    # ── Phishing type classification ──────────────────────────────────────
    classification = classify_phishing(request.content, all_signals, ai_gen_score)

    # ── LLM explanation (suspicious/threat only) ──────────────────────────
    explanation = "Content analysis complete. No significant threats detected."
    if score >= settings.threshold_safe:
        try:
            llm_result = await explain_detection(
                request.content, [s.model_dump() for s in all_signals], score
            )
            explanation = llm_result.get("explanation", explanation)
            if llm_result.get("reasons"):
                reasons = llm_result["reasons"]
        except Exception:
            pass

    # ── Multi-stage chain tracking ────────────────────────────────────────
    chain_id = start_chain(
        content=request.content,
        stage=_stage_from_type(request.input_type),
        verdict=verdict,
        score=score,
    )
    chain_nodes = get_chain(chain_id)

    # ── Campaign clustering ───────────────────────────────────────────────
    campaign_id = None
    if verdict in ("threat", "suspicious") and request.input_type == "email":
        campaign_id = assign_campaign(scan_id, request.content, float(score))

    # ── URLs extracted ────────────────────────────────────────────────────
    import re
    urls_found = re.findall(r"https?://[^\s\"'<>]+", request.content)[:10]

    # ── Build result ──────────────────────────────────────────────────────
    result = ScanResult(
        id=scan_id,
        verdict=verdict,
        score=score,
        reasons=reasons,
        signals=all_signals,
        explanation=explanation,
        classification=classification,
        attachments=attachment_results if attachment_results else None,
        chain=chain_nodes if len(chain_nodes) > 1 else None,
        campaign_id=campaign_id,
        ai_generated_score=ai_gen_score if ai_gen_score > 0 else None,
        urls_found=urls_found if urls_found else None,
        timestamp=datetime.now(timezone.utc),
    )

    # ── Persist ───────────────────────────────────────────────────────────
    log = ScanLog(
        id=scan_id,
        input_type=request.input_type,
        verdict=verdict,
        score=score,
        reasons=reasons,
        signals=[s.model_dump() for s in all_signals],
        chain=[n.model_dump() for n in chain_nodes] if chain_nodes else None,
        campaign_id=campaign_id,
        source=request.source,
    )
    db.add(log)
    await db.commit()

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

def _stage_from_type(input_type: str) -> str:
    if input_type == "url": return "url"
    if input_type == "attachment_base64": return "payload"
    return "email"
