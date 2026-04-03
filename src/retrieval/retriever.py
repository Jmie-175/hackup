
"""
LangChain retriever -- MultiQueryRetriever + optional ContextualCompression.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from langchain_core.retrievers import BaseRetriever
from langchain_core.documents import Document
from config.rag_config import rag_config
from config.langchain_config import langchain_config
from src.utils.logger import log


def build_retriever(rag_store, llm=None, top_k: int = None) -> BaseRetriever:
    """
    Build the appropriate retriever based on config flags.
    Level 1: Base similarity retriever (default)
    Level 2: MultiQueryRetriever (better recall, costs 1 extra LLM call)
    Level 3: ContextualCompressionRetriever (best precision, slower)
    """
    top_k = top_k or rag_config.top_k
    base_retriever = rag_store.as_retriever(top_k=top_k)

    if langchain_config.use_multiquery_retriever and llm is not None:
        from langchain.retrievers import MultiQueryRetriever
        log.info("retriever_mode", mode="multi_query")
        retriever = MultiQueryRetriever.from_llm(
            retriever=base_retriever,
            llm=llm,
            include_original=True,
        )
    else:
        log.info("retriever_mode", mode="base_similarity")
        retriever = base_retriever

    if langchain_config.use_reranking:
        try:
            from langchain.retrievers import ContextualCompressionRetriever
            from langchain_community.cross_encoders import HuggingFaceCrossEncoder
            from langchain.retrievers.document_compressors import CrossEncoderReranker
            reranker_model = HuggingFaceCrossEncoder(
                model_name="cross-encoder/ms-marco-MiniLM-L-6-v2"
            )
            compressor = CrossEncoderReranker(model=reranker_model, top_n=top_k)
            retriever = ContextualCompressionRetriever(
                base_retriever=retriever,
                base_compressor=compressor,
            )
        except ImportError:
            log.warning("reranking_skipped", reason="langchain-cross-encoder not installed")

    return retriever


def format_docs(docs: list[Document]) -> str:
    """Format retrieved documents for injection into the prompt context."""
    if not docs:
        return "No relevant context retrieved from the knowledge base."
    return "\n\n---\n\n".join(
        f"[Source: {d.metadata.get('section', 'KB')} | Type: {d.metadata.get('type', '?')}]\n{d.page_content}"
        for d in docs
    )
