
"""
Groq API configuration -- model params, retry settings.
"""
from pydantic_settings import BaseSettings


class RAGConfig(BaseSettings):
    chroma_path: str = "./data/processed"
    embedding_model: str = "all-MiniLM-L6-v2"
    chunk_size: int = 512
    chunk_overlap: int = 64
    top_k: int = 5
    min_score_threshold: float = 0.1
    rerank_enabled: bool = False
    hyde_enabled: bool = True

    class Config:
        env_file = ".env"
        extra = "ignore"


rag_config = RAGConfig()
