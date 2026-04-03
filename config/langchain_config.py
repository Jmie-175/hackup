
"""
LangChain pipeline configuration -- LCEL flags, caching, LangSmith tracing.
"""
import os
from dotenv import load_dotenv

load_dotenv()


class LangChainConfig:
    # --- LangSmith tracing (optional) ---
    langsmith_enabled: bool = bool(os.getenv("LANGSMITH_API_KEY"))
    langsmith_project: str = os.getenv("LANGSMITH_PROJECT", "phishguard-rag")
    langsmith_endpoint: str = os.getenv("LANGSMITH_ENDPOINT", "https://api.smith.langchain.com")

    # --- Pipeline ---
    use_multiquery_retriever: bool = False   # adds 1 extra LLM call per query
    use_reranking: bool = False              # requires cross-encoder
    streaming_enabled: bool = False

    # --- Caching ---
    cache_enabled: bool = True              # InMemoryCache to skip repeat LLM calls


langchain_config = LangChainConfig()


def setup_tracing() -> None:
    """Configure LangSmith environment variables if API key is present."""
    if langchain_config.langsmith_enabled:
        os.environ["LANGSMITH_TRACING"] = "true"
        os.environ["LANGSMITH_PROJECT"] = langchain_config.langsmith_project
        os.environ["LANGSMITH_ENDPOINT"] = langchain_config.langsmith_endpoint
        print(f"  [TRACE] LangSmith enabled -> project: {langchain_config.langsmith_project}")
    else:
        os.environ.setdefault("LANGSMITH_TRACING", "false")


def setup_cache() -> None:
    """Enable InMemory LLM caching."""
    if langchain_config.cache_enabled:
        try:
            from langchain_core.globals import set_llm_cache
            from langchain_community.cache import InMemoryCache
            set_llm_cache(InMemoryCache())
            print("  [CACHE] InMemoryCache enabled")
        except Exception as e:
            print(f"  [CACHE] Skipped: {e}")
