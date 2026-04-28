@echo off
REM Quick start script for the Chart Agent server (Windows)

echo Starting Aghora Chart Agent Server...
echo Server will be available at http://localhost:8000
echo WebSocket endpoint: ws://localhost:8000/ws/{session_id}
echo.
echo Press Ctrl+C to stop the server
echo.

python server.py


