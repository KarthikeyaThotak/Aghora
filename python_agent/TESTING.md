# Testing Guide for Malware Analysis Agent

This guide explains how to test all components of the malware analysis agent.

## Prerequisites

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up environment variables:**
   
   Create a `.env` file in the `python_agent` directory:
   ```bash
   cp env.example .env
   ```
   
   Then edit `.env` and fill in your values:
   ```env
   OPENAI_API_KEY=your-api-key-here  # Required for AI chat
   DIE_PATH=/path/to/die.exe          # Optional: tool paths
   PESTUDIO_PATH=/path/to/pestudio.exe
   STRINGS_PATH=/path/to/strings.exe
   ```
   
   **Note:** All Python scripts automatically load the `.env` file.

3. **Start the server:**
   ```bash
   python server.py
   ```
   The server should start on `http://localhost:8000`

## Quick Test

Run the comprehensive test suite:

```bash
python test_agent.py
```

This will test:
- Server health
- Tool availability
- File analysis
- API endpoints
- WebSocket connection

## Manual Testing

### 1. Test Server Health

```bash
curl http://localhost:8000/
```

Expected response:
```json
{
  "status": "online",
  "service": "Aghora Chart Agent API",
  "version": "1.0.0"
}
```

### 2. Test Analysis Tools

```python
from malware_tools import MalwareAnalysisToolkit

toolkit = MalwareAnalysisToolkit()

# Check tool availability
for tool_name, tool in toolkit.tools.items():
    if hasattr(tool, 'find_tool'):
        path = tool.find_tool()
        print(f"{tool_name}: {path if path else 'Not found'}")
```

### 3. Test File Analysis

```python
from malware_tools import MalwareAnalysisToolkit

toolkit = MalwareAnalysisToolkit()
results = toolkit.analyze_file(
    "path/to/file.exe",
    "output_directory",
    tools=["fileinfo", "strings", "die"]
)

print(json.dumps(results, indent=2))
```

### 4. Test API - Upload and Analyze

```bash
curl -X POST "http://localhost:8000/api/analysis/upload" \
  -F "file=@test_file.exe" \
  -F "sessionId=test_session" \
  -F "visualize=true"
```

### 5. Test API - Chat

```bash
curl -X POST "http://localhost:8000/api/analysis/chat" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "What threats did you find?",
    "sessionId": "test_session"
  }'
```

### 6. Test Graph API

```bash
# Get graph
curl http://localhost:8000/api/graph/test_session

# Update graph
curl -X POST "http://localhost:8000/api/graph/update" \
  -H "Content-Type: application/json" \
  -d '{
    "nodes": [{"id": "1", "type": "file", "label": "test", "x": 100, "y": 100, "connections": [], "details": {}}],
    "connections": [],
    "sessionId": "test_session"
  }'
```

### 7. Test WebSocket

```python
import asyncio
import websockets
import json

async def test_ws():
    uri = "ws://localhost:8000/ws/test_session"
    async with websockets.connect(uri) as websocket:
        # Send ping
        await websocket.send(json.dumps({"type": "ping"}))
        response = await websocket.recv()
        print(f"Received: {response}")

asyncio.run(test_ws())
```

## Testing Individual Components

### Test Detect-it-Easy

```python
from malware_tools import DetectItEasyTool

tool = DetectItEasyTool()
result = tool.run("test_file.exe", "output_dir")
print(result)
```

### Test Strings Tool

```python
from malware_tools import StringsTool

tool = StringsTool()
result = tool.run("test_file.exe", "output_dir")
print(f"Total strings: {result['data']['total_strings']}")
print(f"Suspicious IPs: {result['data']['suspicious_patterns']['ips']}")
```

### Test AI Analyzer

```python
from ai_analyzer import AIAnalyzer
from malware_tools import MalwareAnalysisToolkit

# First, run analysis
toolkit = MalwareAnalysisToolkit()
results = toolkit.analyze_file("test_file.exe", "output_dir")

# Then analyze with AI
analyzer = AIAnalyzer(api_key="your-key")
ai_results = analyzer.analyze_with_ai(results, "test_session")

print(f"Threat Level: {ai_results['ai_analysis']['threat_level']}")
```

### Test Complete Workflow

```python
from malware_analyzer import MalwareAnalyzer
from agent import ChartAgent

# Initialize
chart_agent = ChartAgent(session_id="test_session")
analyzer = MalwareAnalyzer(
    chart_agent=chart_agent,
    openai_api_key=os.getenv("OPENAI_API_KEY")
)

# Analyze
results = analyzer.analyze_file(
    "test_file.exe",
    session_id="test_session",
    visualize=True
)

# Chat
response = analyzer.chat("test_session", "What did you find?")
print(response)
```

## Testing with Example Scripts

### Example Analysis Script

```bash
python example_analysis.py
```

This interactive script will:
1. Prompt for a file path
2. Run complete analysis
3. Display results
4. Allow interactive chat

### Example Usage Script

```bash
python example_usage.py
```

This demonstrates basic chart agent usage.

## Frontend Testing

### Test AI Chat Hook

1. Start the frontend:
   ```bash
   npm run dev
   ```

2. Open the AI chat sidebar
3. Send a message
4. Check browser console for WebSocket messages

### Test Chart Agent Hook

1. Use the `ChartAgentTest` component
2. Or use the hook directly:
   ```typescript
   import { useChartAgent } from '@/hooks/useChartAgent';
   
   const { updateGraph, connected } = useChartAgent({
     baseUrl: 'http://localhost:8000',
     sessionId: 'test_session'
   });
   ```

## Troubleshooting Tests

### Server Not Starting

- Check if port 8000 is available
- Check for Python errors in console
- Verify all dependencies are installed

### Tools Not Found

- Install missing tools
- Set environment variables with tool paths
- Tools will be skipped if not found (analysis continues)

### OpenAI API Errors

- Verify API key is set: `echo $OPENAI_API_KEY`
- Check API quota/credits
- Verify network connectivity

### WebSocket Connection Failed

- Ensure server is running
- Check CORS settings
- Verify WebSocket URL format: `ws://localhost:8000/ws/{session_id}`

## Test Coverage

The test suite covers:

- ✅ Server health and endpoints
- ✅ Tool availability and execution
- ✅ File analysis workflow
- ✅ API endpoints (upload, chat, graph)
- ✅ WebSocket communication
- ✅ Error handling
- ✅ Timeout handling

## Continuous Testing

For development, you can use:

```bash
# Watch mode (requires watchdog)
pip install watchdog
watchmedo auto-restart --pattern="*.py" --recursive -- python server.py
```

## Performance Testing

For large files, test timeout handling:

```python
# Test with large file
results = analyzer.analyze_file(
    "large_file.exe",
    session_id="test",
    tools=["fileinfo", "strings"]  # Skip slow tools
)
```

## Integration Testing

Test the complete flow:

1. Upload file via API
2. Wait for analysis
3. Query results
4. Chat with AI
5. Verify graph visualization
6. Check log files

```bash
# Complete integration test
python test_agent.py --file path/to/test_file.exe
```

