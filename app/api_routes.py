
"""
API routes -- /analyze, /feedback, /health, /stats, /ingest
"""
import time
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from src.utils.tracing import LatencyTracker
from src.utils.logger import log

router = APIRouter()

# In-memory feedback store
feedback_log: list[dict] = []


class AnalysisRequest(BaseModel):
    query: str
    user_context: dict | None = None
    enable_tracing: bool = True


class FeedbackRequest(BaseModel):
    query: str
    verdict: str
    correct_label: str
    notes: str = ""


@router.get("/health")
async def health(request: Request):
    rag = getattr(request.app.state, "rag_store", None)
    return {
        "status": "ok",
        "framework": "langchain-lcel",
        "knowledge_base_chunks": rag.count() if rag else 0,
        "groq_model": "llama-3-8b-8192",
    }


@router.post("/analyze")
async def analyze(req: AnalysisRequest, request: Request):
    chain = request.app.state.rag_chain
    tracker = LatencyTracker()
    callbacks = [tracker] if req.enable_tracing else []

    try:
        verdict = await chain.ainvoke(
            {"query": req.query},
            config={"callbacks": callbacks},
        )
    except Exception as e:
        log.error("chain_invocation_failed", error=str(e))
        raise HTTPException(status_code=503, detail=f"Chain failed: {str(e)}")

    result = {
        **verdict.model_dump(),
        "latency": {
            "total_ms": tracker.total_ms,
            "llm_ms": tracker.llm_ms,
            "tokens_used": tracker.tokens_used,
        },
        "framework": "langchain-lcel",
    }

    log.info(
        "analysis_complete",
        verdict=verdict.verdict,
        risk_score=verdict.risk_score,
        total_ms=tracker.total_ms,
    )
    return result


@router.post("/feedback")
async def feedback(req: FeedbackRequest):
    entry = req.model_dump()
    entry["timestamp"] = time.time()
    feedback_log.append(entry)
    log.info("feedback_received", correct_label=req.correct_label)
    return {"status": "recorded", "total_feedback": len(feedback_log)}


@router.get("/stats")
async def stats(request: Request):
    rag = request.app.state.rag_store
    return {
        "knowledge_base_chunks": rag.count(),
        "feedback_entries": len(feedback_log),
        "framework": "langchain-lcel",
    }


@router.post("/ingest")
async def ingest(request: Request):
    rag = request.app.state.rag_store
    from src.ingestion.loader import load_all
    from src.ingestion.chunker import chunk_documents
    rag.reset()
    docs = load_all("./data/raw")
    chunks = chunk_documents(docs)
    stored = rag.add_documents(chunks)
    return {"status": "ingested", "chunks_stored": stored}
