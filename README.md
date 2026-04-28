# Aghora — Malware Analysis Platform

A local, privacy-first malware analysis platform that combines static analysis tooling, AI-powered triage, and interactive threat graph visualisation — all running on your machine with no cloud dependency.

![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white)
![React](https://img.shields.io/badge/React-61DAFB?style=flat&logo=react&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)
![Ollama](https://img.shields.io/badge/LLM-Ollama-black?style=flat)

---

## Features

| Capability | Details |
|---|---|
| **Static Analysis** | File info, entropy, PE headers, imports, strings extraction |
| **Packer Detection** | Detect-It-Easy (DIE) integration |
| **Reverse Engineering** | Ghidra headless decompilation — on-demand per function via chat |
| **AI Triage** | Local LLM (Ollama/Gemma) identifies malware family, intent, and IOCs |
| **Threat Graph** | Interactive 6-cluster radial graph: network IOCs, persistence, API techniques, PE sections, AI findings |
| **AI Chat** | Ask questions about the sample in natural language — chat history persisted per session |
| **PDF Report** | One-click professional report export |
| **Session History** | SQLite-backed history with rename and delete |
| **ZIP Support** | Automatic extraction with AES-256 password support (`infected`, `malware`, etc.) |

---

## Architecture

```
┌─────────────────────────────────────┐
│         React Frontend (Vite)       │
│  Upload · Graph · History · Chat    │
└────────────────┬────────────────────┘
                 │ HTTP / WebSocket
┌────────────────▼────────────────────┐
│       FastAPI Backend (Python)      │
│  server.py · malware_analyzer.py   │
└──┬──────────┬──────────┬────────────┘
   │          │          │
┌──▼───┐  ┌──▼────┐  ┌──▼───────────┐
│Tools │  │Ollama │  │  SQLite DB   │
│  DIE │  │ (LLM) │  │ sessions +   │
│Ghidra│  │Gemma  │  │ chat history │
│pefile│  └───────┘  └──────────────┘
└──────┘
```

---

## Prerequisites

| Tool | Purpose | Required |
|---|---|---|
| Node.js 18+ | Frontend build | Yes |
| Python 3.10+ | Backend | Yes |
| [Ollama](https://ollama.ai) | Local LLM inference | Yes |
| [Ghidra](https://ghidra-sre.org) | Function decompilation | Optional |
| [Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy) | Packer/compiler detection | Optional |

---

## Quick Start

### 1. Clone and install frontend dependencies

```bash
git clone https://github.com/KarthikeyaThotak/Aghora.git
cd Aghora
npm install
npm run dev
```

### 2. Set up the Python backend

```bash
cd python_agent
pip install -r requirements.txt
pip install pyzipper        # AES-256 encrypted ZIP support
```

Copy the environment template and configure it:

```bash
cp env.example .env
```

Edit `.env`:

```env
# LLM — local Ollama (default)
LLM_PROVIDER=ollama
LLM_MODEL=gemma4:e4b
OLLAMA_BASE_URL=http://localhost:11434

# Optional: explicit tool paths (auto-detected if on PATH)
# DIE_PATH=C:\Tools\die\die.exe
# GHIDRA_HOME=C:\Tools\ghidra

# Analysis output directory
LOGS_DIR=analysis_logs
```

### 3. Pull the LLM model

```bash
ollama pull gemma4:e4b
```

### 4. Start the backend

```bash
python server.py
```

Server starts on `http://localhost:8000`.

### 5. Open the app

Navigate to `http://localhost:5173`.

---

## Usage

### Analysing a sample

1. Go to the **Upload** tab and drop an executable or ZIP file
2. Password-protected ZIPs are extracted automatically — standard passwords (`infected`, `malware`, `virus`) are tried, including AES-256 encrypted archives from MalwareBazaar
3. Analysis runs through 5 stages: static tools → AI triage → graph build
4. Switch to the **Graph** tab to explore the interactive threat graph
5. Open **AI Analyst** (top-right button) to chat about the sample

### AI Chat commands

| Input | Result |
|---|---|
| `list functions` | All functions extracted by Ghidra with sizes and addresses |
| `decompile FUN_00401234` | On-demand C pseudocode for that function |
| `what malware family is this?` | Three-layer identification: structural → operational → attribution |
| `list the main IOCs` | IPs, domains, URLs, registry keys, file paths |
| `what persistence mechanisms are used?` | Registry Run keys, scheduled tasks, services |
| `what is the SHA-256 hash?` | Exact hash from analysis data |
| `what does this malware do?` | Full capability and intent breakdown |

### History tab

All sessions are stored in SQLite locally. Click any entry to reload its graph and chat history. Sessions can be renamed or deleted.

---

## Project Structure

```
Aghora/
├── src/                            # React frontend (TypeScript)
│   ├── components/
│   │   ├── Workspace.tsx           # Main layout — tabs + chat panel
│   │   ├── GraphView.tsx           # Interactive threat graph
│   │   ├── FileUpload.tsx          # Upload with live progress bar
│   │   ├── AiChat.tsx              # Chat panel with suggested questions
│   │   └── PreviousAnalysis.tsx    # Session history with rename/delete
│   ├── hooks/
│   │   ├── useAIChat.ts            # Chat state + history reload on session switch
│   │   └── useChartAgent.ts        # WebSocket + graph REST API
│   └── contexts/
│       └── AnalysisSessionContext.tsx
│
└── python_agent/                   # FastAPI backend (Python)
    ├── server.py                   # All REST + WebSocket endpoints
    ├── malware_analyzer.py         # 5-stage analysis orchestrator
    ├── malware_tools.py            # Tool wrappers: PE, strings, Ghidra, DIE, heuristics
    ├── ai_analyzer.py              # LLM integration, chat memory, family identification
    ├── database.py                 # SQLite: sessions + chat history
    ├── report_generator.py         # PDF report builder
    └── agent.py                    # Graph update helper
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check |
| `POST` | `/api/analysis/upload` | Upload file and trigger analysis |
| `GET` | `/api/analysis/status/{id}` | Live progress (step/total/message) |
| `POST` | `/api/analysis/chat` | Send chat message to AI analyst |
| `GET` | `/api/sessions` | List all sessions newest-first |
| `GET` | `/api/sessions/{id}` | Get single session record |
| `GET` | `/api/sessions/{id}/chat` | Load persisted chat history |
| `GET` | `/api/sessions/{id}/functions` | List Ghidra-extracted functions |
| `PATCH` | `/api/sessions/{id}/rename` | Rename session display name |
| `DELETE` | `/api/sessions/{id}` | Delete session and chat history |
| `GET` | `/api/graph/{id}` | Get threat graph nodes and connections |
| `GET` | `/report/{id}` | Download PDF analysis report |

---

## Supported File Types

**Executables:** `.exe` `.dll` `.sys` `.scr` `.ocx` `.com` `.drv` `.cpl`

**Archives:** `.zip` — plain or AES-256 encrypted (MalwareBazaar standard passwords tried automatically)

---

## Malware Family Identification

When asked about family or intent, the AI reasons through three layers:

1. **Structural** — strings, imports, compiler/packer, imphash, PE entropy
2. **Operational** — capability fingerprint from API clusters (RAT, stealer, ransomware, loader, keylogger)
3. **Attribution** — mutex names, hardcoded ports, known artifact strings (AsyncRAT, NjRAT, QuasarRAT, XWorm, RedLine, AgentTesla, Remcos, DCRat, Emotet, Cobalt Strike)

The model always commits to a best-guess family with a confidence level and cites specific evidence.

---

## Roadmap

- [ ] YARA rule matching
- [ ] VirusTotal hash lookup
- [ ] Dynamic analysis sandbox integration
- [ ] MITRE ATT&CK technique tagging
- [ ] Multi-file campaign correlation

---

## Disclaimer

Aghora is a security research and education tool. Only analyse files you own or have explicit permission to analyse, or samples obtained from legitimate threat intelligence repositories (MalwareBazaar, theZoo, etc.). The authors accept no responsibility for misuse.

---

## License

MIT
