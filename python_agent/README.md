# Aghora Malware Analysis Agent

Complete malware analysis system with AI-powered analysis, tool integration, and graph visualization.

## Features

- **Malware Analysis Tools**: Integration with Detect-it-Easy, PE-Studio, Strings, and more
- **AI-Powered Analysis**: OpenAI GPT-4-turbo for intelligent threat assessment
- **Chat Memory**: Ask questions about analyzed malware with full context
- **Logging System**: All tool outputs saved to log files
- **Graph Visualization**: Automatic graph creation from analysis results
- **REST API & WebSocket**: Real-time communication with frontend

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Set up environment variables:

Create a `.env` file in the `python_agent` directory:

```bash
# Copy the example file
cp env.example .env
```

Then edit `.env` and fill in your values:

```env
# Required: OpenAI API key
OPENAI_API_KEY=your-api-key-here

# Optional: Tool paths (if not in PATH)
DIE_PATH=C:\Users\karth\Downloads\die_win64_portable_3.10_x64\die.exe
PESTUDIO_PATH=C:\Users\karth\Downloads\pestudio\pestudio\pestudio.exe
STRINGS_PATH=C:\Users\karth\Downloads\Strings\strings.exe

# Optional: Server configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
LOGS_DIR=analysis_logs
CHART_AGENT_BASE_URL=http://localhost:8000
```

**Note:** The `.env` file is automatically loaded by all Python scripts. You can also set environment variables manually if preferred.

## Usage

### Starting the Server

```bash
python server.py
```

The server will run on `http://localhost:8000` by default.

### Analyzing a File

#### Via API

```python
from agent import ChartAgent
from malware_analyzer import MalwareAnalyzer

# Initialize
chart_agent = ChartAgent(session_id="my_session")
analyzer = MalwareAnalyzer(
    chart_agent=chart_agent,
    openai_api_key="your-key"
)

# Analyze file
results = analyzer.analyze_file(
    file_path="suspicious.exe",
    session_id="my_session",
    tools=["fileinfo", "strings", "die"],  # Optional: specify tools
    visualize=True
)
```

#### Via REST API

```bash
# Upload and analyze
curl -X POST "http://localhost:8000/api/analysis/upload" \
  -F "file=@suspicious.exe" \
  -F "sessionId=my_session"

# Or analyze existing file
curl -X POST "http://localhost:8000/api/analysis/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "filePath": "/path/to/file.exe",
    "sessionId": "my_session",
    "tools": ["fileinfo", "strings", "die"],
    "visualize": true
  }'
```

### Chat with AI

```python
# After analysis, chat about the results
response = analyzer.chat(
    session_id="my_session",
    message="What suspicious behaviors did you find?"
)
```

#### Via REST API

```bash
curl -X POST "http://localhost:8000/api/analysis/chat" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "What suspicious behaviors did you find?",
    "sessionId": "my_session"
  }'
```

## Supported Tools

### Detect-it-Easy (DiE)
- File type detection
- Packer identification
- Compiler detection

### PE-Studio
- PE file analysis
- Import/Export analysis
- Section analysis

### Strings
- String extraction
- Suspicious pattern detection
- IOC extraction (IPs, domains, URLs, registry keys)

### FileInfo
- Basic file information
- SHA256 hash calculation
- File metadata

## Analysis Workflow

1. **Tool Execution**: Run selected analysis tools on the file
2. **Logging**: Save all tool outputs to log files
3. **AI Analysis**: GPT-4-turbo analyzes results and provides insights
4. **Memory Storage**: Analysis added to chat memory for Q&A
5. **Visualization**: Graph created with nodes for IOCs and behaviors

## API Endpoints

### Analysis
- `POST /api/analysis/analyze` - Analyze a file
- `POST /api/analysis/upload` - Upload and analyze
- `POST /api/analysis/chat` - Chat with AI
- `GET /api/analysis/logs/{session_id}` - Get analysis logs
- `GET /api/analysis/summary/{session_id}` - Get analysis summary

### Graph
- `POST /api/graph/update` - Update entire graph
- `GET /api/graph/{session_id}` - Get current graph
- `POST /api/graph/node` - Add/update node
- `POST /api/graph/connection` - Add/update connection
- `DELETE /api/graph/node/{node_id}` - Delete node
- `DELETE /api/graph/connection/{connection_id}` - Delete connection

### WebSocket
- `WS /ws/{session_id}` - Real-time bidirectional communication

## Log Files

Analysis logs are stored in `analysis_logs/{session_id}/`:
- `analysis_YYYYMMDD_HHMMSS.log` - Human-readable log
- `complete_analysis.json` - Complete results in JSON
- Tool-specific output files (die_output.json, strings_output.txt, etc.)

## Chat Memory

The AI maintains conversation memory per session, including:
- Analysis results from all tools
- Previous chat messages
- Context about the analyzed file

This allows natural Q&A about the malware analysis.

## Graph Visualization

The analyzer automatically creates graph visualizations:
- **Main Node**: The analyzed file
- **Network Nodes**: IPs, domains, URLs found
- **Registry Nodes**: Registry keys modified
- **Threat Nodes**: Identified threats
- **Connections**: Relationships between entities

## Example

```python
from malware_analyzer import MalwareAnalyzer
from agent import ChartAgent

# Setup
chart_agent = ChartAgent(session_id="analysis_001")
analyzer = MalwareAnalyzer(
    chart_agent=chart_agent,
    openai_api_key=os.getenv("OPENAI_API_KEY")
)

# Analyze
results = analyzer.analyze_file(
    file_path="malware.exe",
    session_id="analysis_001"
)

# Chat
response = analyzer.chat(
    session_id="analysis_001",
    message="What is the threat level and why?"
)
print(response)
```

## Frontend Integration

The frontend can connect via:
- REST API for analysis and chat
- WebSocket for real-time updates
- React hooks: `useAIChat`, `useChartAgent`

See `src/hooks/useAIChat.ts` and `src/components/AiChat.tsx` for examples.

## Troubleshooting

### Tools Not Found
- Install tools or set environment variables with paths
- Tools will be skipped if not found (analysis continues)

### OpenAI API Errors
- Check API key is set correctly
- Verify API quota/credits
- Check network connectivity

### Graph Not Updating
- Ensure chart agent is initialized
- Check WebSocket connection
- Verify session IDs match

## Testing

### Quick Test

Run a quick test to verify everything is working:

```bash
python quick_test.py
```

### Comprehensive Test Suite

Run the full test suite:

```bash
python test_agent.py
```

Or test with a specific file:

```bash
python test_agent.py --file path/to/file.exe
```

See `TESTING.md` for detailed testing instructions.

## License

Part of the Aghora project.
