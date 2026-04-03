
"""
Embedder -- LangChain HuggingFaceEmbeddings wrapper.
Swappable: change model_name to use OpenAI, Cohere, etc.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from langchain_huggingface import HuggingFaceEmbeddings
from config.rag_config import rag_config


def get_embeddings(model_name: str = None) -> HuggingFaceEmbeddings:
    """
    Returns a LangChain-compatible embeddings object.
    Default: all-MiniLM-L6-v2 (384-dim, fast, CPU-friendly).
    """
    name = model_name or rag_config.embedding_model
    print(f"  [EMB] Loading embeddings model: {name}")
    return HuggingFaceEmbeddings(
        model_name=name,
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},
    )
