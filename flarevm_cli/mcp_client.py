from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

from .config import get_flarevm_mcp_url
from . import __version__


class MCPClientError(RuntimeError):
    pass


@dataclass
class MCPTool:
    name: str
    description: Optional[str] = None
    input_schema: Optional[Dict[str, Any]] = None


class MCPClient:
    """
    Minimal HTTP MCP client for talking to the flarevm-mcp server.

    This assumes the server speaks the standard Model Context Protocol over HTTP
    with JSON-RPC style requests. If your server uses slightly different
    method names or payloads, you can adapt the helper methods below.
    """

    def __init__(self, base_url: Optional[str] = None, timeout: int = 60) -> None:
        self.base_url = base_url or get_flarevm_mcp_url()
        self.timeout = timeout
        self._session_id: Optional[str] = None

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }

        # Streamable HTTP MCP servers expect the client to accept both
        # JSON responses and text/event-stream for potential streaming.
        headers: Dict[str, str] = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }

        # For streamable-http MCP, most methods require a session.
        # We lazily initialize the session and then attach Mcp-Session-Id.
        if method != "initialize" and not self._session_id:
            self._initialize_session()

        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        try:
            response = requests.post(
                self.base_url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
        except Exception as exc:
            raise MCPClientError(f"Failed to contact MCP server at {self.base_url}: {exc}") from exc

        if not response.ok:
            raise MCPClientError(
                f"MCP server error {response.status_code}: {response.text[:500]}"
            )

        data = self._parse_response(response)

        if "error" in data and data["error"] is not None:
            raise MCPClientError(f"MCP error: {data['error']}")

        return data.get("result")

    def _initialize_session(self) -> None:
        """
        Perform the MCP 'initialize' call and capture the Mcp-Session-Id header.
        """
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "tools": {
                        "listChanged": False,
                    }
                },
                "clientInfo": {
                    "name": "flarevm-cli",
                    "version": __version__,
                },
            },
        }

        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }

        try:
            response = requests.post(
                self.base_url,
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
        except Exception as exc:
            raise MCPClientError(f"Failed to initialize MCP session at {self.base_url}: {exc}") from exc

        if not response.ok:
            raise MCPClientError(
                f"MCP initialize error {response.status_code}: {response.text[:500]}"
            )

        data = self._parse_response(response)

        # Session ID is returned in the Mcp-Session-Id header (case-insensitive)
        session_id = None
        for key, value in response.headers.items():
            if key.lower() == "mcp-session-id":
                session_id = value
                break

        if not session_id:
            raise MCPClientError(
                "MCP initialize did not return a Mcp-Session-Id header; "
                "cannot establish streamable-http session."
            )

        self._session_id = session_id

    def _parse_response(self, response: requests.Response) -> Dict[str, Any]:
        """
        Handle both JSON and text/event-stream (SSE) responses from a streamable-http MCP server.
        """
        content_type = response.headers.get("Content-Type", "")

        # SSE: event: message\n data: {...}\n\n
        if "text/event-stream" in content_type:
            text = response.text
            data_lines: List[str] = []
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("data:"):
                    data_lines.append(line[len("data:") :].strip())

            if not data_lines:
                raise MCPClientError(f"Invalid JSON from MCP server: {text[:500]}")

            last_data = data_lines[-1]
            try:
                return json.loads(last_data)
            except json.JSONDecodeError as exc:
                raise MCPClientError(
                    f"Invalid JSON from MCP server: {last_data[:500]}"
                ) from exc

        # Fallback: standard JSON response
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise MCPClientError(
                f"Invalid JSON from MCP server: {response.text[:500]}"
            ) from exc

    def list_tools(self) -> List[MCPTool]:
        """
        Fetch the list of tools from the MCP server.

        Expected MCP method: tools/list
        """
        result = self._request("tools/list")
        tools_raw = result.get("tools", []) if isinstance(result, dict) else result or []

        tools: List[MCPTool] = []
        for item in tools_raw:
            tools.append(
                MCPTool(
                    name=item.get("name"),
                    description=item.get("description"),
                    input_schema=item.get("inputSchema"),
                )
            )
        return tools

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """
        Call a specific tool by name with JSON-serializable arguments.

        Expected MCP method: tools/call
        """
        params = {"name": name, "arguments": arguments or {}}
        return self._request("tools/call", params=params)

