
"""
Updated ingestion script for LangChain-based pipeline.
Usage: python ingest.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
load_dotenv()

from src.ingestion.loader import load_all
from src.ingestion.chunker import chunk_documents
from src.retrieval.vector_store import PhishingRAGStore


def main():
    print("\n[PhishGuard] LangChain Knowledge Base Ingestion")
    print("=" * 54)

    print("\n[1] Loading raw documents ...")
    docs = load_all("./data/raw")
    print(f"    Loaded {len(docs)} document sections")

    print("\n[2] Chunking with RecursiveCharacterTextSplitter ...")
    chunks = chunk_documents(docs)
    print(f"    Created {len(chunks)} chunks")

    print("\n[3] Storing in ChromaDB (LangChain Chroma) ...")
    store = PhishingRAGStore()

    if store.count() > 0:
        print(f"    Vector store already has {store.count()} items.")
        ans = input("    Reset and re-ingest? [y/N]: ").strip().lower()
        if ans == "y":
            store.reset()
        else:
            print("    Skipping ingestion.")
            return

    stored = store.add_documents(chunks)
    print(f"    Stored {stored} chunks in ChromaDB -> ./data/processed")

    print("\n[4] Quick retrieval test ...")
    results = store.query("urgent paypal login verify account", top_k=3)
    if results:
        for i, r in enumerate(results):
            print(f"    [{i+1}] score={r['score']} | {r['metadata'].get('section','?')} | {r['text'][:80]}...")
    else:
        print("    (no results above threshold -- this is OK on first run)")

    print("\n[OK] Ingestion complete! Start the server with:")
    print("     uvicorn app.main:app --reload\n")


if __name__ == "__main__":
    main()
