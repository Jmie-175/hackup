
"""
FastAPI entrypoint -- LangChain LCEL pipeline startup + static frontend.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api_routes import router
from src.retrieval.vector_store import PhishingRAGStore
from src.generation.llm_chain import build_rag_chain
from src.utils.logger import log


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: build vector store -> auto-ingest if empty -> build LCEL chain."""
    log.info("phishguard_langchain_starting")

    # 1. Vector store
    rag_store = PhishingRAGStore()

    # 2. Auto-ingest if empty
    if rag_store.count() == 0:
        log.info("knowledge_base_empty_ingesting")
        from src.ingestion.loader import load_all
        from src.ingestion.chunker import chunk_documents
        docs = load_all("./data/raw")
        chunks = chunk_documents(docs)
        stored = rag_store.add_documents(chunks)
        log.info("ingestion_complete", chunks_stored=stored)
    else:
        log.info("knowledge_base_ready", count=rag_store.count())

    # 3. Build LCEL chain
    rag_chain = build_rag_chain(rag_store)

    app.state.rag_store = rag_store
    app.state.rag_chain = rag_chain

    log.info("phishguard_ready", framework="langchain-lcel")
    yield
    log.info("phishguard_shutdown")


app = FastAPI(
    title="PhishGuard RAG API (LangChain LCEL)",
    description="Real-time phishing detection: ChatGroq + LangChain LCEL + ChromaDB",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# Serve the HTML/CSS/JS frontend
frontend_path = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.isdir(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_ui():
        return FileResponse(os.path.join(frontend_path, "index.html"))
