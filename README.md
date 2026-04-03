# PhishGuard 🛡

**AI-powered real-time phishing detection** across emails, URLs, and attachments.

Built for the AI/ML & Cybersecurity Hackathon — Topic 01: AI-Powered Phishing Detection System.

---

## Features

| Feature | Status |
|---|---|
| Email content NLP analysis | ✅ |
| URL heuristics (lookalike, IP, TLD, encoding) | ✅ |
| Multi-signal risk scoring with explainability | ✅ |
| Gmail overlay via Chrome extension | ✅ |
| Real-time WebSocket live feed | ✅ |
| AI-generated phishing detection | ✅ |
| Attachment static analysis | ✅ |
| Campaign clustering | 🔜 V2 |
| Docker sandbox (dynamic analysis) | 🔜 V2 |

---

## Quick Start

### 1. Install Ollama + pull models
```bash
# Install Ollama: https://ollama.com
ollama pull mistral:7b
ollama pull phi3:mini
```

### 2. Start the backend
```bash
cd backend
pip install -r requirements.txt
cp ../.env.example ../.env
mkdir -p ../data
uvicorn main:app --reload --port 8000
```

### 3. Open the dashboard
```
Open frontend/index.html in your browser
```

### 4. Load the Chrome extension
```
1. Go to chrome://extensions/
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the extension/ folder
5. Open Gmail — PhishGuard is active
```

### 5. (Optional) Run with Docker
```bash
docker compose up
```

---

## Architecture

```
User → Dashboard (frontend/)     → POST /scan → FastAPI (backend/)
     → Gmail (extension/)        →                ├── content_analyser.py
                                                  ├── url_analyser.py
                                                  ├── scoring/risk_engine.py
                                                  ├── llm/client.py (Ollama)
                                                  └── database.py (SQLite)
                                  ← WS /stream ← Real-time result push
```

---

## Detection Signals

1. **Urgency language** — fear/pressure trigger patterns
2. **Credential request** — asks for passwords, OTPs, card details
3. **Brand impersonation** — PayPal, Chase, Apple etc. referenced but sender doesn't match
4. **Sender authenticity** — reply-to mismatch, suspicious domain patterns
5. **IP as hostname** — direct IP in URL
6. **Lookalike domain** — homoglyph characters (paypa1, rn vs m)
7. **Suspicious TLD** — .xyz, .click, .tk, .gq
8. **URL shortener** — hides true destination
9. **Subdomain depth** — excessive nesting
10. **URL encoding** — obfuscated characters
11. **Path keywords** — /login, /verify, /confirm
12. **Text quality** — excessive caps, abnormal formatting

---

## Score Thresholds

| Score | Verdict | Action |
|---|---|---|
| 0–39 | ✅ Safe | Deliver normally |
| 40–69 | ⚡ Suspicious | Show warning banner |
| 70–100 | ⚠ Threat | Quarantine + notification |

---

## Tech Stack

- **Backend**: FastAPI + Python 3.11
- **AI**: Ollama (Mistral 7B + Phi-3 Mini) — 100% local, no data leaves machine
- **Database**: SQLite via SQLAlchemy
- **Frontend**: Vanilla HTML/CSS/JS + Chart.js
- **Extension**: Chrome Manifest V3
- **Sandbox**: Docker + strace/tcpdump (V2)
