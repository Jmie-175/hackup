# PhishGuard 🛡

**AI-powered real-time phishing detection** for emails, URLs, and attachments.

Built for the AI/ML & Cybersecurity Hackathon.

### Key Updates (v1.1)
- Switched primary model to **Llama 3.1 8B** → significantly better reasoning and precision
- Increased detection sensitivity (lower thresholds)
- Improved LLM prompts for detailed, consistent explanations
- Better false-negative reduction on phishing emails and links

---

## Features

| Feature                        | Status |
|--------------------------------|--------|
| Real-time Gmail overlay        | ✅     |
| Multi-signal heuristic analysis| ✅     |
| URL threat detection           | ✅     |
| AI-generated content detection | ✅     |
| Detailed explanations          | ✅     |
| Chrome Extension               | ✅     |
| Local LLM (no data sent out)   | ✅     |
| Attachment static analysis     | ✅     |
| Sandbox dynamic analysis       | 🔜 V2  |

---

## Quick Start

### 1. Install Ollama + Models

```bash
ollama pull llama3.1:8b
ollama pull phi3:mini
2. Start the Backend
Bashcd backend
pip install -r requirements.txt

# Copy environment file
cp ../.env.example ../.env

# Recommended settings for higher sensitivity:
# THRESHOLD_SAFE=25
# THRESHOLD_SUSPICIOUS=55
# PRIMARY_MODEL=llama3.1:8b-instruct

mkdir -p ../data
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
3. Load the Chrome Extension

Go to chrome://extensions/
Enable Developer mode
Click Load unpacked → select the extension/ folder

4. Open the Dashboard
Open frontend/index.html in your browser (or click "Open Dashboard" in the extension popup).

Recommended Configuration (for higher phishing detection)
In .env:
envPRIMARY_MODEL=llama3.1:8b
FAST_MODEL=phi3:mini

# More sensitive detection
THRESHOLD_SAFE=25
THRESHOLD_SUSPICIOUS=55

Detection Signals

Urgency language
Credential harvesting requests
Brand impersonation
Suspicious sender & lookalike domains
IP addresses in URLs
URL shorteners, encoding, suspicious paths
Text quality anomalies


Tech Stack

Backend: FastAPI + Python 3.11
AI: Ollama (Llama 3.1 8B Instruct + Phi-3 Mini) — fully local
Database: SQLite
Frontend: Vanilla HTML/CSS/JS + Chart.js
Extension: Chrome Manifest V3


How to Run with Docker
Bashdocker compose up --build
For sandbox (V2):
Bashdocker compose --profile sandbox up

Made with ❤️ for better phishing protection.