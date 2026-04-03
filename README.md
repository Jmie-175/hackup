
<div align="center">
  <h1>🛡️ PhishGuard RAG</h1>
  <p><b>State-of-the-Art, Local-First RAG-Powered Phishing Detection Engine</b></p>
  <p>Powered by <b>Groq (Llama-3)</b> + <b>LangChain LCEL</b> + <b>FastAPI</b></p>
</div>

---

## 📖 What is PhishGuard?
PhishGuard is a high-performance, real-time phishing detection chatbot. It acts as an expert cybersecurity analyst that investigates suspicious emails, URLs, and messages. Instead of relying purely on outdated blocklists, PhishGuard uses a **Retrieval-Augmented Generation (RAG)** architecture. It retrieves context from a synthesized knowledge base of modern phishing tactics (2020–2026) and uses advanced LLM reasoning (via Groq and Llama-3) to determine if a message is a threat.

It provides a transparent, explainable verdict, breaking down its reasoning step-by-step and scoring individual threat vectors like urgency, sender mismatch, and malicious attachments.

---

## 🎯 Why PhishGuard?
Phishing attacks have evolved. Attackers now use AI to draft perfect emails, employ HTML smuggling to bypass scanners, and use zero-width characters to break regex rules. Legacy signature-based tools cannot keep up.
1. **Context-Aware:** Understands the psychological triggers (urgency, scarcity) used by attackers.
2. **Defensible Explanations:** Doesn't just say `BLOCK`. It provides SHAP-style feature scores and natural language reasoning (XAI) so users learn *why* something is dangerous.
3. **Adversarial Resilience:** Pre-processes inputs to strip zero-width characters and neutralize prompt-injection attacks targeting the LLM itself.
4. **Blazing Fast:** Built on Groq's LPU architecture, inference latency is under 500ms, making real-time chat possible.

---

## ✨ Core Features
- 🧠 **Explainable AI (XAI)**: Outputs clear verdicts (`PHISHING`, `LEGITIMATE`, `UNCERTAIN`) with a 0-100 risk score and step-by-step Chain-of-Thought (CoT).
- ⚡ **Ultra-Low Latency**: Backed by Llama-3 via Groq for instant processing.
- 🔗 **Advanced RAG Pipeline**: LangChain LCEL implementation with ChromaDB, hybrid sentence-chunking, and extensible querying (MultiQuery, reranking support).
- 🛡️ **Edge-Case Guards**: Dedicated pre-processing Runnables that catch Homograph URLs, Punycode tricks, zero-width spaces, and malicious attachment footprints (SVG/HTML/QR).
- 🎨 **Premium Zero-Dependency UI**: A stunning, dark-themed vanilla HTML/JS/CSS frontend with animated risk gauges and feature breakdown bars.
- 📡 **Production-Ready API**: Fully typed FastAPI integration with structured Pydantic outputs and latency tracking.

---

## 🛠️ Tech Stack

### AI & Pipeline
- **Orchestration**: [LangChain (v0.3+)](https://python.langchain.com/) - LCEL pipeline architecture.
- **LLM Engine**: [Groq API](https://groq.com/) using `llama-3-8b-8192` (Swappable to Mixtral).
- **Embeddings**: [HuggingFace Embeddings](https://huggingface.co/) (`all-MiniLM-L6-v2`) via `sentence-transformers`.
- **Vector Database**: [ChromaDB](https://www.trychroma.com/) for persistent, multi-modal local embeddings.

### Backend
- **Framework**: [FastAPI](https://fastapi.tiangolo.com/) - Async Python framework.
- **Server**: [Uvicorn](https://www.uvicorn.org/).
- **Validation**: [Pydantic](https://docs.pydantic.dev/) for strict JSON output parsing and application config.

### Frontend
- **Design Structure**: Vanilla HTML5.
- **Styling**: Vanilla CSS3 (CSS Variables, Flexbox, CSS Grid, Glassmorphism).
- **Interactivity**: Vanilla JavaScript (ES6 Modules, Fetch API, DOM manipulation). *No React, No Tailwind — raw performance.*

---

## 🧠 Architecture Flowchart

```text
User Query (via UI / HTTP POST /analyze)
       │
       ▼
┌─────────────────────────────────────────────────────┐
│ 1. InputPreprocessor (LangChain RunnableLambda)     │
│    ├── InjectionGuard: Removes prompt injection     │
│    ├── URLGuard: Flags Punycode/Homographs          │
│    └── AttachmentGuard: Flags .exe, .svg scripts    │
└─────────────────────────────────────────────────────┘
       │  (Annotated & Sanitized Query)
       ▼
┌─────────────────────────────────────────────────────┐
│ 2. Parallel RAG Retrieval (RunnablePassthrough)     │
│    ├── Clean Query sent to ChromaDB Retriever       │
│    ├── Fetches top-k relevant cybersecurity rules   │
│    └── Formats DB chunks as text                    │
└─────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│ 3. LLM Prompt Construction (ChatPromptTemplate)     │
│    Injects: {context}, {pre_analysis_flags}, {query}│
└─────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────┐
│ 4. Groq Inference Engine (`llama-3-8b-8192`)        │
│    Executes Chain-of-Thought (CoT) reasoning        │
└─────────────────────────────────────────────────────┘
       │  (Raw JSON String)
       ▼
┌─────────────────────────────────────────────────────┐
│ 5. Validation (`PydanticOutputParser`)              │
│    Outputs strictly typed `PhishingVerdict` model   │
└─────────────────────────────────────────────────────┘
       │
       ▼
🖥️ UI Renders Animated Verdict & Feature Scores
```

---

## 🚀 How to Run Locally

### 1. Prerequisites
- Python 3.11 or higher
- A free Groq API key: Get one at [console.groq.com](https://console.groq.com)

### 2. Setup the Environment
Clone the repository and set up a virtual environment:
```bash
git clone <repo-url>
cd phishing-rag-chatbot

# Create virtual environment
python -m venv venv

# Activate it (Windows)
venv\Scripts\activate
# Activate it (Mac/Linux)
# source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configuration
Make a copy of the environment template and insert your API key:
```bash
copy .env.example .env     # On Mac/Linux: cp .env.example .env
```
Edit `.env` and assign your Groq key:
```env
GROQ_API_KEY=gsk_your_actual_key_here
```

### 5. Ingest the Knowledge Base (One-Time)
Load the cybersecurity rules into the local vector database (ChromaDB):
```bash
# Before running this, ensure your console supports UTF-8 (or run with PYTHONUTF8=1)
python ingest.py
```
*This splits `data/raw/phishing_knowledge.md` into embeddings and saves them in `./data/processed`.*

### 6. Start the Server
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
*(If you encounter encoding issues on Windows, prefix it with `$env:PYTHONUTF8=1; uvicorn...`)*

### 7. Access the App
Open your browser and navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 📡 API Endpoints

You can explore the interactive API docs by going to `http://localhost:8000/docs` while the server runs.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Check system status, model name, and ChromaDB DB count. |
| `POST` | `/analyze` | Main LCEL analysis. Accepts `{"query": "email content..."}`. Returns parsed `PhishingVerdict`. |
| `POST` | `/feedback`| Logging endpoint for users to submit 👍/👎 feedback. |
| `POST` | `/ingest` | Triggers a live re-ingestion of the `data/raw` contents into the vector store. |
| `GET` | `/stats` | View loaded chunks and received feedback metrics. |

---

## 🎛️ Configuration & Tuning

Inside `config/langchain_config.py`, you can fine-tune the pipeline:

| Setting | Default | Explanation |
|:---|:---:|:---|
| `use_multiquery_retriever` | `False` | Has the LLM rewrite the search query in 3 ways to pull broader context. Increases latency. |
| `use_reranking` | `False` | Uses a HuggingFace Cross-Encoder to rerank DB results for ultra-precision. (Requires installing `langchain-cross-encoder`). |
| `cache_enabled` | `True` | Caches identical LLM requests in memory to save Groq API calls. |
| `langsmith_enabled`| `auto` | Activates LangSmith tracing if `LANGSMITH_API_KEY` is in your `.env`. |

---

## 🧪 Testing

We use `pytest` to validate the RAG components and edge cases.
*Note: Due to API limits, you may want to mock the LLM calls or rely on local unit tests for the pipeline.*

```bash
# Run the LangChain Component Migration suite
pytest tests/test_langchain_migration.py -v

# Run the Edge Case/Attack Vector suite
pytest tests/edge_case_suite.py -v
```

---

<div align="center">
  <i>Built for the <b>HackUP 2026 AI Engineering Track</b></i><br>
  Let's make the internet safer, one token at a time.
</div>
