
"""
Chunker -- LangChain RecursiveCharacterTextSplitter for Document splitting.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from config.rag_config import rag_config


def get_splitter(
    chunk_size: int = None,
    chunk_overlap: int = None,
) -> RecursiveCharacterTextSplitter:
    """Return a configured RecursiveCharacterTextSplitter."""
    return RecursiveCharacterTextSplitter(
        chunk_size=chunk_size or rag_config.chunk_size,
        chunk_overlap=chunk_overlap or rag_config.chunk_overlap,
        separators=["\n\n", "\n", ". ", "! ", "? ", " ", ""],
        keep_separator=True,
        add_start_index=True,
    )


def chunk_documents(docs: list[Document]) -> list[Document]:
    """
    Split a list of LangChain Documents using RecursiveCharacterTextSplitter.
    Preserves all metadata and adds chunk_index to each split.
    """
    splitter = get_splitter()
    split_docs: list[Document] = []

    for doc in docs:
        chunks = splitter.split_documents([doc])
        for i, chunk in enumerate(chunks):
            chunk.metadata["chunk_index"] = i
        split_docs.extend(chunks)

    print(f"  [CHUNK] Split {len(docs)} docs -> {len(split_docs)} chunks")
    return split_docs
