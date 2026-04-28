from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from anthropic import Anthropic

from .config import get_anthropic_api_key
from .mcp_client import MCPClient, MCPTool


def _get_client() -> Anthropic:
    return Anthropic(api_key=get_anthropic_api_key())


def summarize_tool_result(
    prompt: str,
    tool_name: str,
    tool_arguments: Dict[str, Any],
    tool_result: Any,
    model: str = "claude-sonnet-4-6",
    max_tokens: int = 1024,
) -> str:
    """
    Ask Anthropic to summarize and interpret a flarevm MCP tool result.
    """
    client = _get_client()

    system_prompt = (
        "You are a cybersecurity analyst working with a flarevm-powered MCP backend. "
        "Given the raw tool output and the user's question, provide a concise, "
        "actionable explanation. Focus on threat indicators, suspicious behavior, "
        "and recommended next steps. Keep answers technical and to the point."
    )

    content: List[Dict[str, Any]] = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"User question:\n{prompt}\n\n"
                        f"Tool name: {tool_name}\n"
                        f"Tool arguments (JSON): {tool_arguments}\n\n"
                        f"Raw tool result (truncated if large):\n{repr(tool_result)[:8000]}"
                    ),
                }
            ],
        }
    ]

    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system_prompt,
        messages=content,
    )

    text_parts: List[str] = []
    for block in response.content:
        if getattr(block, "type", None) == "text":
            text_parts.append(block.text)

    return "\n".join(text_parts).strip()


def _tools_for_anthropic(tools: Iterable[MCPTool]) -> List[Dict[str, Any]]:
    """
    Convert MCPTool objects to Anthropic tool definitions.
    """
    return [
        {
            "name": t.name,
            "description": t.description or "",
            "input_schema": t.input_schema or {"type": "object", "properties": {}},
        }
        for t in tools
    ]


def chat_with_mcp_tools(
    prompt: str,
    *,
    client: Optional[MCPClient] = None,
    model: str = "claude-sonnet-4-6",
    max_tokens: int = 1024,
    tool_name_prefix: Optional[str] = None,
) -> str:
    """
    Let the LLM decide which MCP tools to call (including windows-mcp).

    Example prompt:
        "On the FlareVM machine, open a browser and go to https://www.google.com,
         search for 'malware analysis', and tell me what you see."
    """
    mcp_client = client or MCPClient()
    all_tools = mcp_client.list_tools()

    if tool_name_prefix:
        tools = [t for t in all_tools if t.name.startswith(tool_name_prefix)]
    else:
        tools = list(all_tools)

    if not tools:
        raise RuntimeError("No MCP tools available for Anthropic tool-calling.")

    anthropic_client = _get_client()

    tools_spec = _tools_for_anthropic(tools)

    messages: List[Dict[str, Any]] = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "You are connected to a FlareVM environment via MCP tools. "
                        "You can call these tools to interact with the Windows machine "
                        "and then report back what happened.\n\n"
                        f"User request:\n{prompt}"
                    ),
                }
            ],
        }
    ]

    # Agentic loop: keep going until the model stops calling tools or we hit the limit.
    MAX_ITERATIONS = 20
    for _ in range(MAX_ITERATIONS):
        response = anthropic_client.messages.create(
            model=model,
            max_tokens=max_tokens,
            tools=tools_spec,
            messages=messages,
        )

        # Collect all tool_use blocks in this response
        tool_uses = [
            block
            for block in response.content
            if getattr(block, "type", None) == "tool_use"
        ]

        if not tool_uses:
            # No more tool calls — return the final text reply
            text_parts: List[str] = []
            for block in response.content:
                if getattr(block, "type", None) == "text":
                    text_parts.append(block.text)
            return "\n".join(text_parts).strip()

        # Append the assistant's response (may contain text + tool_use blocks)
        messages.append({"role": "assistant", "content": list(response.content)})

        # Execute every requested tool call and collect results
        tool_results: List[Dict[str, Any]] = []
        for tool_use in tool_uses:
            tool_input = tool_use.input or {}
            try:
                result = mcp_client.call_tool(tool_use.name, tool_input)
                result_content = repr(result)[:8000]
                is_error = False
            except Exception as exc:
                result_content = f"Tool call failed: {exc}"
                is_error = True

            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tool_use.id,
                    "content": result_content,
                    "is_error": is_error,
                }
            )

        messages.append({"role": "user", "content": tool_results})

    raise RuntimeError(f"Agentic loop exceeded {MAX_ITERATIONS} iterations without finishing.")

