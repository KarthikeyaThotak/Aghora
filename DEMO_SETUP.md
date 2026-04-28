# Aghora — Demo Setup Guide (ISC² Chapter Presentation, Apr 28)

## What you need running on presentation day

| Service | Port | Purpose |
|---|---|---|
| Ollama | 11434 | Local LLM (Gemma) |
| Python backend | 8000 | Analysis engine + API |
| Vite frontend | 5173 | Web UI |

---

## Step 1 — Install Ollama and pull Gemma (do this TODAY, takes time)

1. Download Ollama from https://ollama.com/download (Windows installer)
2. After install, open a terminal and run:

```
ollama pull gemma4:e4b
```

This downloads the model. Do it on your home WiFi, not the venue.

To verify it works:
```
ollama run gemma4:e4b
>>> Tell me about Blind Eagle APT
```

---

## Step 2 — Start the Python backend

Open a terminal in the `python_agent` folder:

```cmd
cd C:\Users\karth\Projects\Cybersecurity\Aghora\Aghora\python_agent

pip install -r requirements.txt --break-system-packages

python server.py
```

You should see:
```
✓ Loaded .env file from: ...\python_agent\.env
[AI] Using local Ollama backend → http://localhost:11434/v1  model: gemma3:4b
✓ Ollama client initialized (model: gemma3:4b)
INFO:     Uvicorn running on http://0.0.0.0:8000
```

Quick health check — open http://localhost:8000 in your browser. Should show JSON with `"status": "online"`.

---

## Step 3 — Start the frontend

Open a second terminal in the project root:

```cmd
cd C:\Users\karth\Projects\Cybersecurity\Aghora\Aghora

npm install
npm run dev
```

Open http://localhost:5173 in Chrome.

---

## Step 4 — Demo run-through (practice this before April 28)

### Good demo sample file:
Use a **known safe** PE file with interesting strings for the demo — e.g. a known malware sample from MalwareBazaar that you've already analyzed, or use `notepad.exe` for a quick smoke test.

For a real demo: download a Grandoreiro or Blind Eagle sample from MalwareBazaar (https://bazaar.abuse.ch) — this ties directly into your threat group research.

### Demo flow (30 min talk):

1. **Show the interface** (~2 min) — explain the three panels: upload, graph, AI chat
2. **Upload the sample** — drag and drop into the upload zone
3. **Watch the analysis run** — show the terminal (backend logs) projected alongside
4. **Graph appears automatically** — nodes for IPs, domains, registry keys
5. **Click a node** — show the detail panel (IOC metadata)
6. **Chat with the AI** — ask these questions live:
   - *"What malware family is this from?"*
   - *"What are the main IOCs I should add to my SIEM?"*
   - *"What persistence mechanisms does this use?"*
   - *"How would I detect this at the network level?"*
7. **Show the log files** — `analysis_logs/` folder with structured JSON output

---

## Fallback plan (if WiFi/Ollama fails at venue)

Switch to OpenAI in 10 seconds:

Edit `python_agent/.env`:
```
LLM_PROVIDER=openai
```

Restart server. Done. Your OpenAI key is already in the .env.

---

## If tools (DIE, PE-Studio, Strings) aren't found

No problem. The platform now includes a **Python-native string extractor** as fallback.
You'll still get: SHA256, file size, extracted strings, IPs, domains, registry keys, and full AI analysis.
The graph will still populate. It just won't have the DiE/PE-Studio deep PE analysis.

To get the full experience, make sure these are present (they're already in your Downloads):
- `C:\Users\karth\Downloads\die_win64_portable_3.10_x64\die.exe`
- `C:\Users\karth\Downloads\pestudio\pestudio\pestudio.exe`
- `C:\Users\karth\Downloads\Strings\strings.exe`

---

## Day-of checklist (morning of April 28)

- [ ] `ollama serve` is running (check with: `ollama list`)
- [ ] Python backend starts clean (`python server.py`)
- [ ] Frontend loads at http://localhost:5173
- [ ] Upload a test file and verify graph appears + AI chat responds
- [ ] Have a malware sample pre-staged and ready to upload
- [ ] Bring a hotspot in case venue WiFi is blocked on port 11434
- [ ] Browser zoom at 90% so everything fits on the projected screen
