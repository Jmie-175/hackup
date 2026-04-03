
"""
LangChain Chroma vector store -- persistent, LangChain VectorStore interface.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from langchain_chroma import Chroma
from langchain_core.documents import Document
from src.ingestion.embedder import get_embeddings
from config.rag_config import rag_config
from src.utils.logger import log


class PhishingRAGStore:
    COLLECTION_NAME = "phishing_knowledge"

    def __init__(self, path: str = None):
        self.path = path or rag_config.chroma_path
        self.embeddings = get_embeddings()
        self.vectorstore = Chroma(
            collection_name=self.COLLECTION_NAME,
            embedding_function=self.embeddings,
            persist_directory=self.path,
        )
        log.info("lc_vector_store_ready", path=self.path, count=self.count())

    # ── Write ──────────────────────────────────────────────────────────────────

    def add_documents(self, docs: list[Document]) -> int:
        """Add LangChain Documents to the vector store."""
        if not docs:
            return 0
        self.vectorstore.add_documents(docs)
        log.info("lc_documents_added", count=len(docs))
        return len(docs)

    # ── Read ───────────────────────────────────────────────────────────────────

    def query(self, text: str, top_k: int = None, filter_metadata: dict | None = None) -> list[dict]:
        """
        Similarity search. Returns list of dicts with 'text', 'metadata', 'score'.
        """
        top_k = top_k or rag_config.top_k
        kwargs: dict = {"k": top_k}
        if filter_metadata:
            kwargs["filter"] = filter_metadata

        try:
            results = self.vectorstore.similarity_search_with_relevance_scores(text, **kwargs)
        except Exception as e:
            log.warning("similarity_search_failed", error=str(e))
            # Fallback to plain similarity search without score threshold
            plain = self.vectorstore.similarity_search(text, k=top_k)
            return [{"text": d.page_content, "metadata": d.metadata, "score": 0.5} for d in plain]

        docs = []
        for doc, score in results:
            # Chroma can return scores outside [0,1]; clamp and always include top results
            clamped = max(0.0, min(1.0, score))
            docs.append({
                "text": doc.page_content,
                "metadata": doc.metadata,
                "score": round(clamped, 4),
            })
        docs.sort(key=lambda d: d["score"], reverse=True)
        return docs

    def as_retriever(self, top_k: int = None, score_threshold: float = None):
        """Returns a LangChain BaseRetriever for use in LCEL chains."""
        return self.vectorstore.as_retriever(
            search_type="similarity",
            search_kwargs={"k": top_k or rag_config.top_k},
        )

    # ── Admin ──────────────────────────────────────────────────────────────────

    def count(self) -> int:
        try:
            return self.vectorstore._collection.count()
        except Exception:
            return 0

    def reset(self) -> None:
        try:
            self.vectorstore._collection.delete(where={})
        except Exception:
            # Some versions need delete by IDs
            ids = self.vectorstore._collection.get()["ids"]
            if ids:
                self.vectorstore._collection.delete(ids=ids)
        log.warning("lc_vector_store_reset")
