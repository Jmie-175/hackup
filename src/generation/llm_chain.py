
"""
LCEL RAG Pipeline -- the heart of PhishGuard LangChain migration.

Pipeline flow:
  raw_query
    -> InputPreprocessor (injection | url | attachment guards)
    -> RunnablePassthrough.assign(context, pre_analysis_flags, query)
    -> RAG_PROMPT (ChatPromptTemplate)
    -> ChatGroq (llama-3-8b-8192)
    -> safe_parse -> PhishingVerdict
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from langchain_groq import ChatGroq
from langchain_core.runnables import RunnablePassthrough, RunnableLambda, Runnable

from config.groq_config import groq_config
from config.langchain_config import langchain_config, setup_tracing, setup_cache
from src.generation.prompts import RAG_PROMPT
from src.generation.output_parser import safe_parse
from src.edge_cases.guards import build_input_preprocessor
from src.retrieval.retriever import format_docs


def get_llm(model: str = None, temperature: float = None) -> ChatGroq:
    """Returns a configured ChatGroq instance."""
    return ChatGroq(
        groq_api_key=groq_config.api_key or os.getenv("GROQ_API_KEY", ""),
        model_name=model or groq_config.model,
        temperature=temperature or groq_config.temperature,
        max_tokens=groq_config.max_tokens,
        streaming=langchain_config.streaming_enabled,
    )


def build_rag_chain(rag_store) -> Runnable:
    """
    Build the full LCEL PhishGuard pipeline.
    Accepts {"query": str}, returns PhishingVerdict.
    """
    setup_cache()
    setup_tracing()

    llm = get_llm()

    from src.retrieval.retriever import build_retriever
    retriever = build_retriever(rag_store, llm=llm)

    preprocessor = build_input_preprocessor()

    def extract_flags(text: str) -> str:
        lines = [
            line for line in text.splitlines()
            if line.startswith("[URL_THREAT_FLAGS]") or line.startswith("[ATTACHMENT_FLAGS]")
        ]
        return "\n".join(lines) if lines else "None detected"

    def clean_query(text: str) -> str:
        return "\n".join(
            line for line in text.splitlines()
            if not (line.startswith("[URL_THREAT_FLAGS]") or line.startswith("[ATTACHMENT_FLAGS]"))
        ).strip()

    # After preprocessor returns a string, wrap it back into a dict
    # so RunnablePassthrough.assign() receives the required dict input.
    def wrap_to_dict(annotated_text: str) -> dict:
        return {"query": annotated_text}

    chain: Runnable = (
        RunnableLambda(lambda x: x["query"])
        | preprocessor
        | RunnableLambda(wrap_to_dict)            # string -> {"query": annotated_text}
        | RunnablePassthrough.assign(
            # Branch 1: retrieve context from ChromaDB
            context=RunnableLambda(lambda x: clean_query(x["query"]))
                    | retriever
                    | RunnableLambda(format_docs),
            # Branch 2: extract guard flag annotations for prompt variable
            pre_analysis_flags=RunnableLambda(lambda x: extract_flags(x["query"])),
            # Branch 3: strip flag lines from the final user-visible query
            query=RunnableLambda(lambda x: clean_query(x["query"])),
        )
        | RAG_PROMPT
        | llm
        | RunnableLambda(lambda msg: safe_parse(msg.content))
    ).with_config(run_name="PhishGuardRAGChain")

    return chain
