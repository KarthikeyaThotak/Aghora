"""
FastAPI server for communicating with the frontend chart interface.
Provides REST API and WebSocket endpoints for real-time graph data updates.
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import List, Dict, Optional, Set, Tuple
import json
import asyncio
import os
import tempfile
import zipfile
import shutil
from datetime import datetime
import uuid
from dotenv import load_dotenv
from pathlib import Path
from malware_analyzer import MalwareAnalyzer
from agent import ChartAgent
import database as db

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.resolve()
ENV_FILE = SCRIPT_DIR / ".env"

# Load environment variables from .env file
# Try loading from the script's directory first, then current directory
if ENV_FILE.exists():
    load_dotenv(dotenv_path=ENV_FILE, override=True)
    print(f"✓ Loaded .env file from: {ENV_FILE}")
else:
    # Try loading from current directory
    load_dotenv()
    if Path(".env").exists():
        print(f"✓ Loaded .env file from current directory")
    else:
        print(f"⚠ Warning: No .env file found at {ENV_FILE} or current directory")
        print(f"  Create a .env file based on env.example and add your OPENAI_API_KEY")

app = FastAPI(title="Aghora Chart Agent API", version="1.0.0")

# Initialise local SQLite database on startup
db.init_db()

# Initialize malware analyzer (lazy initialization)
malware_analyzer: Optional[MalwareAnalyzer] = None
chart_agent: Optional[ChartAgent] = None

# Log LLM provider so startup output is clear
_provider = os.getenv("LLM_PROVIDER", "ollama")
_model    = os.getenv("LLM_MODEL", "gemma4:e4b")
print(f"✓ LLM provider: {_provider}  model: {_model}")

def get_analyzer() -> MalwareAnalyzer:
    """Get or create malware analyzer instance"""
    global malware_analyzer, chart_agent
    if malware_analyzer is None:
        # Initialize chart agent
        chart_agent_base_url = os.getenv("CHART_AGENT_BASE_URL", "http://localhost:8000")
        chart_agent = ChartAgent(base_url=chart_agent_base_url, session_id="default")
        
        # Initialize malware analyzer
        openai_key = os.getenv("OPENAI_API_KEY")  # only used when LLM_PROVIDER=openai

        tools_config = {
            "die": os.getenv("DIE_PATH"),
            "pestudio": os.getenv("PESTUDIO_PATH"),
            "strings": os.getenv("STRINGS_PATH")
        }
        logs_dir = os.getenv("LOGS_DIR", "analysis_logs")
        
        # Create analyzer - it will handle missing API key gracefully
        malware_analyzer = MalwareAnalyzer(
            tools_config=tools_config,
            openai_api_key=openai_key,
            chart_agent=chart_agent,
            logs_dir=logs_dir
        )
        print(f"[get_analyzer] MalwareAnalyzer created, AI analyzer client: {'initialized' if malware_analyzer.ai_analyzer.client else 'NOT initialized'}")
    return malware_analyzer

# CORS middleware to allow frontend connections
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:8080",
        "http://localhost:8081",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models matching the frontend types
class GraphNode(BaseModel):
    id: str
    type: str  # "file" | "network" | "registry" | "process" | "threat" | "system" | "main"
    label: str
    x: float
    y: float
    connections: List[str] = []
    isMainNode: Optional[bool] = False
    sha256Hash: Optional[str] = None
    fileName: Optional[str] = None
    details: Dict = {
        "description": "",
        "riskLevel": "low",  # "low" | "medium" | "high" | "critical"
        "metadata": {}
    }

class GraphConnection(BaseModel):
    id: str
    sourceId: str
    targetId: str
    type: Optional[str] = "direct"  # "direct" | "bidirectional"
    weight: Optional[float] = None

class GraphUpdate(BaseModel):
    nodes: List[GraphNode]
    connections: List[GraphConnection]
    sessionId: Optional[str] = None

class NodeUpdate(BaseModel):
    node: GraphNode
    sessionId: Optional[str] = None

class ConnectionUpdate(BaseModel):
    connection: GraphConnection
    sessionId: Optional[str] = None

# Analysis models
class ChatMessage(BaseModel):
    message: str
    sessionId: str
    fileName: Optional[str] = None  # Optional file name from frontend
    fileHash: Optional[str] = None  # Optional file hash from frontend

class AnalysisRequest(BaseModel):
    filePath: str
    sessionId: str
    tools: Optional[List[str]] = None
    visualize: bool = True

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, session_id: str = "default"):
        await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = set()
        self.active_connections[session_id].add(websocket)
        print(f"Client connected to session {session_id}. Total connections: {len(self.active_connections[session_id])}")
    
    def disconnect(self, websocket: WebSocket, session_id: str = "default"):
        if session_id in self.active_connections:
            self.active_connections[session_id].discard(websocket)
            if not self.active_connections[session_id]:
                del self.active_connections[session_id]
        print(f"Client disconnected from session {session_id}")
    
    async def broadcast_to_session(self, message: dict, session_id: str = "default"):
        if session_id in self.active_connections:
            disconnected = set()
            for connection in self.active_connections[session_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    print(f"Error sending message: {e}")
                    disconnected.add(connection)
            
            # Remove disconnected clients
            for conn in disconnected:
                self.active_connections[session_id].discard(conn)

manager = ConnectionManager()

# In-memory storage for graph data (in production, use a database)
graph_storage: Dict[str, Dict] = {}

# REST API Endpoints

@app.get("/")
async def root():
    """Lightweight health check — does NOT call the LLM (keeps frontend check fast)."""
    return {
        "status": "online",
        "service": "Aghora Chart Agent API",
        "version": "1.0.0",
        "llm_provider": os.getenv("LLM_PROVIDER", "ollama"),
        "llm_model":    os.getenv("LLM_MODEL", "gemma4:e4b"),
    }

@app.get("/report/{session_id}")
async def get_report(session_id: str):
    """
    Generate and return a professional PDF malware analysis report for the given session.
    The PDF is assembled from the session's complete_analysis.json on disk.
    """
    try:
        from report_generator import generate_report
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"reportlab is not installed. Run: pip install reportlab  ({e})"
        )

    analyzer = get_analyzer()
    logs_dir = os.getenv("LOGS_DIR", "analysis_logs")
    results_path = Path(logs_dir) / session_id / "complete_analysis.json"

    if not results_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"No analysis found for session '{session_id}'. Run an analysis first."
        )

    with open(results_path, encoding="utf-8") as fh:
        analysis = json.load(fh)

    try:
        pdf_bytes = generate_report(analysis)
    except Exception as e:
        import traceback
        raise HTTPException(
            status_code=500,
            detail=f"Report generation failed: {e}\n{traceback.format_exc()}"
        )

    # Derive a clean filename
    file_info = (analysis.get("tool_results", {})
                 .get("tools", {})
                 .get("fileinfo", {})
                 .get("data", {}))
    raw_name = file_info.get("file_name", session_id)
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in raw_name)
    pdf_filename = f"aghora_report_{safe_name}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{pdf_filename}"',
            "Content-Length": str(len(pdf_bytes)),
        },
    )


@app.post("/api/graph/update")
async def update_graph(update: GraphUpdate):
    """
    Update the entire graph for a session.
    This will replace all nodes and connections for the session.
    """
    session_id = update.sessionId or "default"
    
    graph_storage[session_id] = {
        "nodes": [node.dict() for node in update.nodes],
        "connections": [conn.dict() for conn in update.connections],
        "updated_at": datetime.now().isoformat()
    }
    
    # Broadcast update to all connected clients
    await manager.broadcast_to_session({
        "type": "graph_update",
        "sessionId": session_id,
        "data": graph_storage[session_id]
    }, session_id)
    
    return {
        "status": "success",
        "sessionId": session_id,
        "nodes_count": len(update.nodes),
        "connections_count": len(update.connections)
    }

@app.get("/api/graph/{session_id}")
async def get_graph(session_id: str):
    """Get graph state — from in-memory cache or disk (handles server restarts)."""
    import json as _json
    if session_id in graph_storage and graph_storage[session_id].get("nodes"):
        return {"status": "success", "sessionId": session_id, "data": graph_storage[session_id]}

    # Fall back to complete_analysis.json saved by the analyzer
    logs_dir = os.getenv("LOGS_DIR", "analysis_logs")
    analysis_file = os.path.join(logs_dir, session_id, "complete_analysis.json")
    if os.path.exists(analysis_file):
        try:
            with open(analysis_file) as f:
                data = _json.load(f)
            graph_data = data.get("graph_data", {})
            if graph_data.get("nodes"):
                graph_storage[session_id] = {
                    "nodes": graph_data["nodes"],
                    "connections": graph_data["connections"],
                    "updated_at": data.get("timestamp", datetime.now().isoformat()),
                }
                return {"status": "success", "sessionId": session_id, "data": graph_storage[session_id]}
        except Exception as e:
            print(f"[GRAPH] Failed to load from disk: {e}")

    raise HTTPException(status_code=404, detail=f"Graph not found for session {session_id}")

@app.post("/api/graph/node")
async def add_node(update: NodeUpdate):
    """Add or update a single node"""
    session_id = update.sessionId or "default"
    
    if session_id not in graph_storage:
        graph_storage[session_id] = {
            "nodes": [],
            "connections": [],
            "updated_at": datetime.now().isoformat()
        }
    
    # Update or add node
    nodes = graph_storage[session_id]["nodes"]
    node_dict = update.node.dict()
    
    # Check if node exists
    node_index = next((i for i, n in enumerate(nodes) if n["id"] == node_dict["id"]), None)
    if node_index is not None:
        nodes[node_index] = node_dict
    else:
        nodes.append(node_dict)
    
    graph_storage[session_id]["updated_at"] = datetime.now().isoformat()
    
    # Broadcast update
    await manager.broadcast_to_session({
        "type": "node_update",
        "sessionId": session_id,
        "data": node_dict
    }, session_id)
    
    return {
        "status": "success",
        "sessionId": session_id,
        "node": node_dict
    }

@app.post("/api/graph/connection")
async def add_connection(update: ConnectionUpdate):
    """Add or update a single connection"""
    session_id = update.sessionId or "default"
    
    if session_id not in graph_storage:
        graph_storage[session_id] = {
            "nodes": [],
            "connections": [],
            "updated_at": datetime.now().isoformat()
        }
    
    # Update or add connection
    connections = graph_storage[session_id]["connections"]
    conn_dict = update.connection.dict()
    
    # Check if connection exists
    conn_index = next((i for i, c in enumerate(connections) if c["id"] == conn_dict["id"]), None)
    if conn_index is not None:
        connections[conn_index] = conn_dict
    else:
        connections.append(conn_dict)
    
    graph_storage[session_id]["updated_at"] = datetime.now().isoformat()
    
    # Broadcast update
    await manager.broadcast_to_session({
        "type": "connection_update",
        "sessionId": session_id,
        "data": conn_dict
    }, session_id)
    
    return {
        "status": "success",
        "sessionId": session_id,
        "connection": conn_dict
    }

@app.delete("/api/graph/node/{node_id}")
async def delete_node(node_id: str, session_id: str = "default"):
    """Delete a node from the graph"""
    if session_id not in graph_storage:
        raise HTTPException(status_code=404, detail=f"Graph not found for session {session_id}")
    
    nodes = graph_storage[session_id]["nodes"]
    connections = graph_storage[session_id]["connections"]
    
    # Remove node
    nodes[:] = [n for n in nodes if n["id"] != node_id]
    
    # Remove all connections involving this node
    connections[:] = [
        c for c in connections 
        if c["sourceId"] != node_id and c["targetId"] != node_id
    ]
    
    graph_storage[session_id]["updated_at"] = datetime.now().isoformat()
    
    # Broadcast update
    await manager.broadcast_to_session({
        "type": "node_deleted",
        "sessionId": session_id,
        "nodeId": node_id
    }, session_id)
    
    return {
        "status": "success",
        "sessionId": session_id,
        "deleted_node_id": node_id
    }

@app.delete("/api/graph/connection/{connection_id}")
async def delete_connection(connection_id: str, session_id: str = "default"):
    """Delete a connection from the graph"""
    if session_id not in graph_storage:
        raise HTTPException(status_code=404, detail=f"Graph not found for session {session_id}")
    
    connections = graph_storage[session_id]["connections"]
    connections[:] = [c for c in connections if c["id"] != connection_id]
    
    graph_storage[session_id]["updated_at"] = datetime.now().isoformat()
    
    # Broadcast update
    await manager.broadcast_to_session({
        "type": "connection_deleted",
        "sessionId": session_id,
        "connectionId": connection_id
    }, session_id)
    
    return {
        "status": "success",
        "sessionId": session_id,
        "deleted_connection_id": connection_id
    }

# WebSocket Endpoint

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for real-time bidirectional communication"""
    await manager.connect(websocket, session_id)
    
    try:
        # Send current graph state on connection
        if session_id in graph_storage:
            await websocket.send_json({
                "type": "graph_state",
                "sessionId": session_id,
                "data": graph_storage[session_id]
            })
        else:
            await websocket.send_json({
                "type": "graph_state",
                "sessionId": session_id,
                "data": {"nodes": [], "connections": []}
            })
        
        # Listen for messages from client
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")
            
            if message_type == "ping":
                await websocket.send_json({"type": "pong"})
            elif message_type == "get_graph":
                if session_id in graph_storage:
                    await websocket.send_json({
                        "type": "graph_state",
                        "sessionId": session_id,
                        "data": graph_storage[session_id]
                    })
            elif message_type == "update_graph":
                update_data = data.get("data", {})
                graph_storage[session_id] = {
                    "nodes": update_data.get("nodes", []),
                    "connections": update_data.get("connections", []),
                    "updated_at": datetime.now().isoformat()
                }
                await manager.broadcast_to_session({
                    "type": "graph_update",
                    "sessionId": session_id,
                    "data": graph_storage[session_id]
                }, session_id)
            else:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Unknown message type: {message_type}"
                })
                
    except WebSocketDisconnect:
        manager.disconnect(websocket, session_id)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket, session_id)

# Analysis Endpoints

@app.post("/api/analysis/analyze")
async def analyze_file(request: AnalysisRequest):
    """
    Analyze a malware file using analysis tools and AI
    Supports both local file paths and remote URLs (Firebase Storage)
    """
    try:
        analyzer = get_analyzer()
        
        # Update chart agent session
        if chart_agent:
            chart_agent.session_id = request.sessionId
        
        # Check if filePath is a URL (Firebase Storage) or local path
        file_path = request.filePath
        if file_path.startswith('http://') or file_path.startswith('https://'):
            # Download file from URL (Firebase Storage)
            print(f"Downloading file from URL: {file_path}")
            import requests
            import tempfile
            
            response = requests.get(file_path, stream=True)
            response.raise_for_status()
            
            # Create temp file
            temp_dir = tempfile.mkdtemp()
            # Extract filename from URL or use session ID
            filename = request.filePath.split('/')[-1].split('?')[0] or f"file_{request.sessionId}"
            file_path = os.path.join(temp_dir, filename)
            
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            print(f"File downloaded to: {file_path}")
        
        # Run analysis in a thread so the event loop stays alive for WebSocket/pings
        results = await asyncio.to_thread(
            analyzer.analyze_file,
            file_path=file_path,
            session_id=request.sessionId,
            tools=request.tools,
            visualize=request.visualize,
        )

        # --- Inject graph data directly into storage (no HTTP deadlock) ---
        graph_data = results.get("graph_data", {})
        if graph_data.get("nodes"):
            graph_storage[request.sessionId] = {
                "nodes": graph_data["nodes"],
                "connections": graph_data["connections"],
                "updated_at": datetime.now().isoformat()
            }
            # Push graph to any connected WebSocket clients
            await manager.broadcast_to_session({
                "type": "graph_update",
                "sessionId": request.sessionId,
                "data": graph_storage[request.sessionId]
            }, request.sessionId)
            print(f"[GRAPH] Pushed {len(graph_data['nodes'])} nodes to session {request.sessionId}")

        # Persist to local SQLite database
        try:
            db.save_session(request.sessionId, results)
        except Exception as db_err:
            print(f"[DB] Warning: could not save session: {db_err}")

        # Broadcast analysis complete
        await manager.broadcast_to_session({
            "type": "analysis_complete",
            "sessionId": request.sessionId,
            "data": {
                "threat_level": results.get("ai_analysis", {}).get("threat_level", "unknown"),
                "summary": results.get("ai_analysis", {}).get("threat_summary", ""),
                "log_directory": results.get("log_directory")
            }
        }, request.sessionId)

        return {
            "status": "success",
            "sessionId": request.sessionId,
            "results": results
        }
    except Exception as e:
        import traceback
        error_detail = str(e)
        error_traceback = traceback.format_exc()
        print(f"[ANALYSIS ERROR] Error in analyze_file endpoint:")
        print(f"  Error: {error_detail}")
        print(f"  Traceback:\n{error_traceback}")
        raise HTTPException(status_code=500, detail=f"Analysis error: {error_detail}")

# ── Executable extensions we're willing to analyse ───────────────────────────
_EXEC_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".ocx", ".com",
    ".drv", ".cpl", ".ax", ".acm", ".mui",
}
# Common PE-like but non-standard extensions worth picking up too
_BINARY_EXTS = _EXEC_EXTS | {".bin", ".dat", ".so", ".dylib"}

# Passwords tried (in order) when the ZIP is encrypted.
# 'infected' is the de-facto standard for malware sample sharing.
_ZIP_PASSWORDS = [
    b"infected", b"malware", b"virus", b"password",
    b"infected!", b"sandbox", b"sample", b"1234",
]


def _pick_best_target(names: List[str]) -> str:
    """
    Choose the most interesting file from a list of ZIP member names.
    Priority: known executable ext > largest name > first entry.
    """
    execs = [n for n in names if Path(n).suffix.lower() in _EXEC_EXTS]
    if execs:
        # Prefer files not in sub-directories (top-level first)
        top = [n for n in execs if "/" not in n and "\\" not in n]
        return (top or execs)[0]
    # Fall back to any binary-looking file
    bins = [n for n in names if Path(n).suffix.lower() in _BINARY_EXTS]
    if bins:
        return bins[0]
    # Last resort: the largest file by name length heuristic, or just first
    return names[0]


def _extract_zip(zip_path: str, extract_dir: str) -> Tuple[str, List[str], str | None]:
    """
    Extract a ZIP archive into extract_dir.
    Supports both ZipCrypto (standard zipfile) and AES-256 (pyzipper) encryption.
    MalwareBazaar and most malware-sharing sites use AES-256 with password 'infected'.

    Returns:
        (target_path, all_member_names, password_used_or_None)

    Raises:
        ValueError   if no extractable files are found.
        RuntimeError if the archive is encrypted and no password worked.
    """
    def _try_extract(zf, members, pwd_bytes, dest):
        """Try extractall, fall back to per-member extract. Returns True on success."""
        try:
            zf.extractall(dest, pwd=pwd_bytes)
        except Exception:
            # Per-member fallback — some members may extract even if others fail
            for m in members:
                try:
                    zf.extract(m, dest, pwd=pwd_bytes)
                except Exception:
                    pass
        target = _pick_best_target(members)
        return os.path.exists(os.path.join(dest, target))

    # Collect member list via standard zipfile first (works for both formats)
    with zipfile.ZipFile(zip_path, "r") as zf:
        all_members = [m for m in zf.namelist() if not m.endswith("/")]

    if not all_members:
        raise ValueError("ZIP archive is empty — no files to analyse.")

    target_name = _pick_best_target(all_members)

    # ── Pass 1: try standard ZipCrypto (built-in zipfile) ────────────────────
    with zipfile.ZipFile(zip_path, "r") as zf:
        encrypted = any(zf.getinfo(m).flag_bits & 0x1 for m in all_members)
        if not encrypted:
            zf.extractall(extract_dir)
            return os.path.join(extract_dir, target_name), all_members, None

        for pwd in _ZIP_PASSWORDS:
            shutil.rmtree(extract_dir, ignore_errors=True)
            os.makedirs(extract_dir, exist_ok=True)
            if _try_extract(zf, all_members, pwd, extract_dir):
                return os.path.join(extract_dir, target_name), all_members, pwd.decode()

    # ── Pass 2: try AES-256 via pyzipper (MalwareBazaar standard) ────────────
    try:
        import pyzipper
        for pwd in _ZIP_PASSWORDS:
            shutil.rmtree(extract_dir, ignore_errors=True)
            os.makedirs(extract_dir, exist_ok=True)
            try:
                with pyzipper.AESZipFile(zip_path, "r",
                                         compression=pyzipper.ZIP_DEFLATED,
                                         encryption=pyzipper.WZ_AES) as zf:
                    zf.extractall(extract_dir, pwd=pwd)
                if os.path.exists(os.path.join(extract_dir, target_name)):
                    return os.path.join(extract_dir, target_name), all_members, pwd.decode()
            except Exception:
                pass
    except ImportError:
        pass  # pyzipper not installed — AES-256 zips won't work

    raise RuntimeError(
        "ZIP is password-protected and none of the tried passwords worked. "
        "Passwords tried: " + ", ".join(p.decode() for p in _ZIP_PASSWORDS) + ". "
        "If the archive uses a custom password, extract it manually first."
    )


@app.post("/api/analysis/upload")
async def upload_and_analyze(
    file: UploadFile = File(...),
    sessionId: str = "default",
    tools: Optional[str] = None,
    visualize: bool = True
):
    """
    Upload a file and analyze it.
    Accepts any binary, PE executable, script, or a ZIP archive.
    If a ZIP is uploaded the server extracts it, picks the best executable
    inside (trying common malware-share passwords if encrypted), and analyses
    that file instead of the ZIP itself.
    """
    try:
        # Save uploaded file to temp directory
        temp_dir = tempfile.mkdtemp()
        original_filename = file.filename or "sample"
        file_path = os.path.join(temp_dir, original_filename)

        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        # ── ZIP detection & extraction ────────────────────────────────────────
        zip_info: Dict = {}
        is_zip = (
            original_filename.lower().endswith(".zip") or
            content[:2] == b"PK"          # ZIP magic bytes
        )

        if is_zip:
            print(f"[ZIP] Detected ZIP archive: {original_filename}")
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            try:
                target_path, members, pwd_used = _extract_zip(file_path, extract_dir)
                print(f"[ZIP] Extracted {len(members)} file(s). Target: {os.path.basename(target_path)}"
                      + (f" (password: '{pwd_used}')" if pwd_used else ""))
                zip_info = {
                    "original_zip": original_filename,
                    "members": members,
                    "target_file": os.path.basename(target_path),
                    "password_used": pwd_used,
                    "member_count": len(members),
                }
                file_path = target_path   # analyse the extracted file
            except (ValueError, RuntimeError) as ze:
                raise HTTPException(status_code=422, detail=str(ze))

        # Parse tools list
        tools_list = None
        if tools:
            tools_list = [t.strip() for t in tools.split(",")]

        analyzer = get_analyzer()

        # Update chart agent session
        if chart_agent:
            chart_agent.session_id = sessionId

        # Run analysis in a thread so the event loop stays alive for WebSocket/pings
        results = await asyncio.to_thread(
            analyzer.analyze_file,
            file_path=file_path,
            session_id=sessionId,
            tools=tools_list,
            visualize=visualize,
        )

        # Attach ZIP metadata to results so the frontend can show it
        if zip_info:
            results["zip_info"] = zip_info

        # --- Inject graph data directly into storage (no HTTP deadlock) ---
        graph_data = results.get("graph_data", {})
        if graph_data.get("nodes"):
            graph_storage[sessionId] = {
                "nodes": graph_data["nodes"],
                "connections": graph_data["connections"],
                "updated_at": datetime.now().isoformat()
            }
            await manager.broadcast_to_session({
                "type": "graph_update",
                "sessionId": sessionId,
                "data": graph_storage[sessionId]
            }, sessionId)
            print(f"[GRAPH] Pushed {len(graph_data['nodes'])} nodes to session {sessionId}")

        # Persist to local SQLite database
        try:
            db.save_session(sessionId, results)
        except Exception as db_err:
            print(f"[DB] Warning: could not save session: {db_err}")

        # Broadcast analysis complete
        await manager.broadcast_to_session({
            "type": "analysis_complete",
            "sessionId": sessionId,
            "data": {
                "threat_level": results.get("ai_analysis", {}).get("threat_level", "unknown"),
                "summary": results.get("ai_analysis", {}).get("threat_summary", ""),
                "log_directory": results.get("log_directory")
            }
        }, sessionId)

        return {
            "status": "success",
            "sessionId": sessionId,
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions")
async def list_sessions(limit: int = 100):
    """Return all analysis sessions newest-first (used by History tab)."""
    try:
        sessions = db.list_sessions(limit=limit)
        return {"status": "success", "sessions": sessions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    """Return a single session record."""
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "success", "session": session}


@app.patch("/api/sessions/{session_id}/rename")
async def rename_session(session_id: str, body: dict):
    """Rename the display name of a session."""
    new_name = (body.get("name") or "").strip()
    if not new_name:
        raise HTTPException(status_code=422, detail="name is required")
    found = db.rename_session(session_id, new_name)
    if not found:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "success", "sessionId": session_id, "name": new_name}


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a session and its chat history."""
    found = db.delete_session(session_id)
    if not found:
        raise HTTPException(status_code=404, detail="Session not found")
    # Also evict from in-memory graph cache
    graph_storage.pop(session_id, None)
    return {"status": "success", "sessionId": session_id}


@app.get("/api/analysis/status/{session_id}")
async def get_analysis_status(session_id: str):
    """
    Return live progress from the status.json written by MalwareAnalyzer._write_status().
    The frontend polls this every 2 s during upload to show a progress bar.
    """
    import json as _json
    logs_dir = os.getenv("LOGS_DIR", "analysis_logs")
    status_file = os.path.join(logs_dir, session_id, "status.json")
    if not os.path.exists(status_file):
        return {"step": 0, "total": 5, "message": "Waiting for analysis to start…", "done": False}
    try:
        with open(status_file) as f:
            return _json.load(f)
    except Exception:
        return {"step": 0, "total": 5, "message": "Reading status…", "done": False}


@app.get("/api/sessions/{session_id}/chat")
async def get_chat_history(session_id: str):
    """Return persisted chat messages for a session (used to reload history in the UI)."""
    try:
        messages = db.get_chat_history(session_id)
        return {"status": "success", "sessionId": session_id, "messages": messages}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sessions/{session_id}/functions")
async def get_function_list(session_id: str):
    """Return the full function list from the cached Ghidra analysis for a session."""
    import json as _json
    try:
        session = db.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        log_dir = session.get("log_directory")
        if not log_dir:
            raise HTTPException(status_code=404, detail="No log directory for this session")
        ghidra_file = os.path.join(log_dir, "ghidra_analysis.json")
        if not os.path.exists(ghidra_file):
            return {"status": "success", "sessionId": session_id, "functions": [], "total": 0}
        with open(ghidra_file, "r", encoding="utf-8") as f:
            gd = _json.load(f)
        funcs = gd.get("functions", [])
        return {
            "status": "success",
            "sessionId": session_id,
            "total": gd.get("function_count", len(funcs)),
            "functions": funcs,
            "decompiled": list(gd.get("decompiled", {}).keys()),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analysis/chat")
async def chat_with_ai(chat_request: ChatMessage):
    """
    Chat with AI about analyzed malware.
    Special command: messages matching 'decompile <function_name>' are handled
    directly by the Ghidra bridge without an LLM round-trip.
    """
    import re as _re, json as _json
    from malware_tools import GhidraTool

    # ── On-demand decompile intercept ────────────────────────────────────────
    _decompile_pat = _re.compile(
        r'(?:decompile|show\s+(?:me\s+)?(?:the\s+)?(?:code|pseudocode|source)\s+(?:for|of))\s+([A-Za-z0-9_:@$?]+)',
        _re.I,
    )
    _match = _decompile_pat.search(chat_request.message)
    if _match:
        func_name = _match.group(1).strip()
        session   = db.get_session(chat_request.sessionId)
        log_dir   = (session or {}).get("log_directory", "")
        code_text = None

        # 1. Check already-decompiled cache first
        if log_dir:
            ghidra_file = os.path.join(log_dir, "ghidra_analysis.json")
            if os.path.isfile(ghidra_file):
                try:
                    with open(ghidra_file, "r", encoding="utf-8") as _f:
                        _gd = _json.load(_f)
                    code_text = _gd.get("decompiled", {}).get(func_name)
                except Exception:
                    pass

        # 2. Run on-demand decompilation if not cached
        if not code_text and log_dir:
            ghidra_file  = os.path.join(log_dir, "ghidra_analysis.json")
            project_name = ""
            project_dir  = ""
            if os.path.isfile(ghidra_file):
                try:
                    with open(ghidra_file, "r", encoding="utf-8") as _f:
                        _gd = _json.load(_f)
                    project_name = _gd.get("project_name", "")
                    project_dir  = _gd.get("project_dir",  "")
                except Exception:
                    pass
            if not project_name:
                sha = (session or {}).get("sha256_hash", "")
                project_name = "aghora_" + sha[:16] if sha else "aghora"
            if not project_dir:
                project_dir = os.path.join(log_dir, "ghidra_project")

            print(f"[CHAT] On-demand decompile: {func_name}")
            _result = GhidraTool().decompile_function(func_name, project_name, project_dir)
            if _result["status"] == "success":
                code_text = _result["code"]
                # Cache it
                if os.path.isfile(ghidra_file):
                    try:
                        with open(ghidra_file, "r", encoding="utf-8") as _f:
                            _gd = _json.load(_f)
                        _gd.setdefault("decompiled", {})[func_name] = code_text
                        with open(ghidra_file, "w", encoding="utf-8") as _f:
                            _json.dump(_gd, _f, indent=2, ensure_ascii=False)
                    except Exception:
                        pass
            else:
                code_text = None

        if code_text:
            response = (
                f"Here is the decompiled C pseudocode for **`{func_name}`**:\n\n"
                f"```c\n{code_text}\n```\n\n"
                f"*Generated by Ghidra's Pcode decompiler. Variable names may be auto-generated.*"
            )
        else:
            response = (
                f"Could not decompile `{func_name}`. "
                "Check that the function name is exact and case-correct. "
                "Use 'list functions' in chat to see all available function names."
            )

        db.save_chat_message(chat_request.sessionId, "user", chat_request.message)
        db.save_chat_message(chat_request.sessionId, "ai", response)
        return {"status": "success", "sessionId": chat_request.sessionId, "response": response}

    # ── List functions intercept ──────────────────────────────────────────────
    if _re.search(r'\b(list|show|get)\s+(all\s+)?functions?\b', chat_request.message, _re.I):
        session = db.get_session(chat_request.sessionId)
        log_dir = (session or {}).get("log_directory", "")
        if log_dir:
            ghidra_file = os.path.join(log_dir, "ghidra_analysis.json")
            if os.path.isfile(ghidra_file):
                try:
                    with open(ghidra_file, "r", encoding="utf-8") as _f:
                        _gd = _json.load(_f)
                    funcs      = _gd.get("functions", [])
                    decompiled = list(_gd.get("decompiled", {}).keys())
                    total      = _gd.get("function_count", len(funcs))
                    lines = [
                        f"**{total} functions** found in this binary.",
                        f"Already decompiled: {', '.join(f'`{d}`' for d in decompiled) or 'none'}",
                        "",
                        "**Top functions by size:**",
                    ]
                    for fn in funcs[:50]:
                        if isinstance(fn, dict):
                            name = fn.get("name", "?")
                            size = fn.get("size", 0)
                            addr = fn.get("address", "")
                            tag  = " ✓" if name in decompiled else ""
                            lines.append(f"- `{name}` — {size} bytes @ {addr}{tag}")
                    lines.append("")
                    lines.append("*To decompile any function, type: `decompile <function_name>`*")
                    response = "\n".join(lines)
                    db.save_chat_message(chat_request.sessionId, "user", chat_request.message)
                    db.save_chat_message(chat_request.sessionId, "ai", response)
                    return {"status": "success", "sessionId": chat_request.sessionId, "response": response}
                except Exception:
                    pass

    # \u2500\u2500 Normal LLM chat path \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    try:
        print(f"[CHAT] Received chat request - Session: {chat_request.sessionId}, Message: {chat_request.message[:50]}...")
        if chat_request.fileName:
            print(f"[CHAT] File name from request: {chat_request.fileName}")
        if chat_request.fileHash:
            print(f"[CHAT] File hash from request: {chat_request.fileHash[:32]}...")
        
        analyzer = get_analyzer()
        print(f"[CHAT] Analyzer obtained successfully")
        response = analyzer.chat(
            chat_request.sessionId,
            chat_request.message,
            file_name=chat_request.fileName,
            file_hash=chat_request.fileHash
        )
        print(f"[CHAT] Got response from analyzer: {response[:100]}...")

        # Persist both sides of the conversation to SQLite
        try:
            db.save_chat_message(chat_request.sessionId, "user", chat_request.message)
            db.save_chat_message(chat_request.sessionId, "ai", response)
        except Exception as db_err:
            print(f"[CHAT] Warning: could not persist chat message: {db_err}")

        # Broadcast chat message (non-blocking)
        try:
            await manager.broadcast_to_session({
                "type": "chat_message",
                "sessionId": chat_request.sessionId,
                "data": {
                    "user_message": chat_request.message,
                    "ai_response": response
                }
            }, chat_request.sessionId)
        except Exception as broadcast_error:
            print(f"Warning: Failed to broadcast chat message: {broadcast_error}")

        return {
            "status": "success",
            "sessionId": chat_request.sessionId,
            "response": response
        }
    except Exception as e:
        print(f"[CHAT] Error in chat endpoint: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
