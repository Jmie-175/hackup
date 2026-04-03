
"""
LangSmith tracing utilities -- callback handler + latency tracking.
"""
import time
from typing import Any
from langchain_core.callbacks import AsyncCallbackHandler
from src.utils.logger import log


class LatencyTracker(AsyncCallbackHandler):
    """Async callback that tracks total chain latency and LLM token count."""

    def __init__(self):
        self.start_time: float | None = None
        self.total_ms: float = 0.0
        self.llm_ms: float = 0.0
        self.tokens_used: int = 0
        self._llm_start: float | None = None

    async def on_chain_start(self, serialized: dict, inputs: dict, **kwargs: Any) -> None:
        self.start_time = time.perf_counter()

    async def on_chain_end(self, outputs: dict, **kwargs: Any) -> None:
        if self.start_time:
            self.total_ms = round((time.perf_counter() - self.start_time) * 1000, 2)

    async def on_llm_start(self, serialized: dict, prompts: list, **kwargs: Any) -> None:
        self._llm_start = time.perf_counter()

    async def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        if self._llm_start:
            self.llm_ms = round((time.perf_counter() - self._llm_start) * 1000, 2)
        try:
            self.tokens_used = response.llm_output.get("token_usage", {}).get("total_tokens", 0)
        except Exception:
            pass

    async def on_chain_error(self, error: Exception, **kwargs: Any) -> None:
        if self.start_time:
            self.total_ms = round((time.perf_counter() - self.start_time) * 1000, 2)
        log.error("chain_error", error=str(error), elapsed_ms=self.total_ms)
