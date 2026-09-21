# BugCopilot 🐛

> **AI-assisted bug bounty research tool for authorized security researchers.**  
> Combines passive recon automation with an interactive LLM analysis assistant and professional report generation.

---

## ⚖️ Important — Authorized Use Only

BugCopilot is designed exclusively for **authorized bug bounty researchers**. It requires explicit authorization confirmation before any scanning begins and enforces scope rules on every action. Unauthorized security testing is illegal and unethical.

---

## Features

| Module | Description |
|---|---|
| **🎯 Scope Gate** | Authorization form with wildcard in/out-scope patterns — blocks all scanning without confirmation |
| **🔍 Passive Recon** | Subdomain enum (crt.sh + DNS), tech fingerprinting, JS endpoint/secret extraction, robots.txt, header/cookie checks, CVE lookup |
| **🤖 AI Analysis Chat** | Paste HTTP requests or observations → plausibility, safe next steps, CVSS estimate, bounty tier, duplicate risk |
| **📝 Report Generator** | CVSS 3.1 calculator + H1/Bugcrowd/Intigriti/generic markdown export |
| **📅 Timeline Tracker** | Submission dates, SLA deadlines, escalation reminders |
| **🏆 Target Picker** | Rank programs by scope × payout × newness score |

---

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/Minilikes/BugCopilot.git
cd BugCopilot
pip install -r requirements.txt
```

### 2. Configure LLM

```bash
cp .env.example .env
# Edit .env and add your API key
```

Supported providers (all use OpenAI-compatible API):

| Provider | `LLM_BASE_URL` | `LLM_MODEL` |
|---|---|---|
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o` |
| **Google Gemini** | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-2.0-flash` |
| **Anthropic Claude** | `https://api.anthropic.com/v1` | `claude-3-5-sonnet-20241022` |
| **Ollama** (local, free) | `http://localhost:11434/v1` | `llama3.2` |

### 3. Launch

```bash
python run.py
# Opens http://localhost:8000 automatically
```

---

## Usage Flow

1. **`/scope`** — Set up an authorized scope session (program name, domain, in/out-scope patterns, auth confirmation)
2. **`/recon`** — Run passive recon steps one at a time (each is a separate opt-in button)
3. **`/analysis`** — Paste HTTP requests or observations into the AI chat for vulnerability assessment
4. **`/report`** — Fill in finding details, use the CVSS calculator, export to your platform's format
5. **`/timeline`** — Track submission dates and SLA deadlines
6. **`/targets`** — Rank programs by opportunity score to prioritize your time

---

## Tech Stack

- **Backend**: FastAPI + Uvicorn + SQLite (via SQLModel)
- **Frontend**: Vanilla HTML/CSS/JS — no build step required
- **LLM**: OpenAI-compatible SDK (bring your own key)
- **Recon**: `httpx`, `beautifulsoup4`, `dnspython`, NVD API v2, OSV.dev, crt.sh

---

## Ethical Constraints (Always Enforced)

- ✅ Passive recon only (DNS, HTTP headers, crt.sh, public APIs)  
- ✅ Rate-limited requests (never floods)  
- ✅ All active steps are opt-in and explicit  
- ✅ Scope gate blocks out-of-scope targets  
- ❌ No brute-force, DoS, or account enumeration  
- ❌ No destructive payloads — ever  

---

## Project Structure

```
bugcopilot/
├── run.py                      ← One-command launcher
├── .env.example                ← Copy to .env, add API key
├── requirements.txt
├── backend/
│   ├── main.py                 ← FastAPI app
│   ├── config.py
│   ├── db.py
│   ├── models/                 ← SQLModel tables
│   ├── services/
│   │   ├── scope_guard.py      ← Wildcard scope enforcement
│   │   ├── recon_engine.py     ← Passive recon methods
│   │   ├── llm_client.py       ← LLM chat client
│   │   ├── cve_lookup.py       ← NVD + OSV.dev
│   │   ├── cvss.py             ← CVSS 3.1 calculator
│   │   └── report_templates.py ← Platform report formatters
│   └── routers/                ← API route handlers
└── frontend/
    ├── index.html              ← Dashboard
    ├── scope.html
    ├── recon.html
    ├── analysis.html
    ├── report.html
    ├── targets.html
    ├── timeline.html
    └── assets/
        ├── style.css
        └── app.js
```

---

## License

MIT — for authorized security research only. The authors are not responsible for any misuse.
