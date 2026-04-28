from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Optional

# Ensure UTF-8 output on Windows so tool descriptions with Unicode chars print cleanly.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from .config import get_flarevm_mcp_url
from .mcp_client import MCPClient, MCPClientError
from .anthropic_client import summarize_tool_result, chat_with_mcp_tools
from . import __version__


def _parse_json(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON for arguments: {exc}") from exc


def cmd_info(args: argparse.Namespace) -> None:
    print(f"flarevm-cli version {__version__}")
    print(f"MCP server: {get_flarevm_mcp_url()}")


def cmd_list_tools(args: argparse.Namespace) -> None:
    client = MCPClient()
    try:
        tools = client.list_tools()
    except MCPClientError as exc:
        raise SystemExit(str(exc)) from exc

    if not tools:
        print("No tools reported by MCP server.")
        return

    for tool in tools:
        print(f"- {tool.name}")
        if tool.description:
            print(f"  description: {tool.description}")
        if tool.input_schema:
            print(f"  schema: {json.dumps(tool.input_schema, indent=2)}")
        print()


def cmd_run_tool(args: argparse.Namespace) -> None:
    client = MCPClient()
    arguments = _parse_json(args.arguments)

    try:
        result = client.call_tool(args.name, arguments)
    except MCPClientError as exc:
        raise SystemExit(str(exc)) from exc

    if args.raw:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        print(json.dumps(result, indent=2))


def cmd_analyze(args: argparse.Namespace) -> None:
    """
    Convenience command:
    1. Call a flarevm MCP tool
    2. Feed its output + your prompt into Anthropic for analysis
    """
    client = MCPClient()
    arguments = _parse_json(args.arguments)

    try:
        tool_result = client.call_tool(args.name, arguments)
    except MCPClientError as exc:
        raise SystemExit(str(exc)) from exc

    summary = summarize_tool_result(
        prompt=args.prompt,
        tool_name=args.name,
        tool_arguments=arguments,
        tool_result=tool_result,
        model=args.model,
        max_tokens=args.max_tokens,
    )

    if args.show_raw:
        print("=== RAW TOOL RESULT ===")
        print(json.dumps(tool_result, indent=2, default=str))
        print("\n=== LLM ANALYSIS ===")

    print(summary)


def cmd_chat(args: argparse.Namespace) -> None:
    """
    Free-form chat with the LLM where it can call MCP tools (e.g. windows-mcp)
    to act on the FlareVM machine.
    """
    try:
        reply = chat_with_mcp_tools(
            prompt=args.prompt,
            model=args.model,
            max_tokens=args.max_tokens,
            tool_name_prefix=args.tool_prefix,
        )
    except Exception as exc:
        raise SystemExit(str(exc)) from exc

    print(reply)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flarevm-cli",
        description="CLI for interacting with a flarevm MCP server and Anthropic LLM.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # info
    p_info = subparsers.add_parser("info", help="Show configuration information.")
    p_info.set_defaults(func=cmd_info)

    # tools
    p_list = subparsers.add_parser("tools", help="List tools exposed by the MCP server.")
    p_list.set_defaults(func=cmd_list_tools)

    # run
    p_run = subparsers.add_parser("run", help="Run a specific MCP tool and print raw result.")
    p_run.add_argument("name", help="Tool name")
    p_run.add_argument(
        "--arguments",
        "-a",
        help="JSON object with arguments to pass to the tool.",
    )
    p_run.add_argument(
        "--raw",
        action="store_true",
        help="Print raw JSON result without extra formatting.",
    )
    p_run.set_defaults(func=cmd_run_tool)

    # analyze (tool + Anthropic)
    p_analyze = subparsers.add_parser(
        "analyze",
        help="Run a MCP tool and summarize its output using Anthropic.",
    )
    p_analyze.add_argument("name", help="Tool name")
    p_analyze.add_argument(
        "--arguments",
        "-a",
        help="JSON object with arguments to pass to the tool.",
    )
    p_analyze.add_argument(
        "--prompt",
        "-p",
        required=True,
        help="Question or instruction for the LLM about the tool result.",
    )
    p_analyze.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Anthropic model name to use.",
    )
    p_analyze.add_argument(
        "--max-tokens",
        type=int,
        default=1024,
        help="Maximum tokens for the LLM response.",
    )
    p_analyze.add_argument(
        "--show-raw",
        action="store_true",
        help="Also print the raw tool result before the LLM analysis.",
    )
    p_analyze.set_defaults(func=cmd_analyze)

    # chat (LLM chooses MCP tools)
    p_chat = subparsers.add_parser(
        "chat",
        help="Talk to the LLM; it can call MCP tools like windows-mcp.",
    )
    p_chat.add_argument(
        "prompt",
        help="What you want the LLM to do (e.g. 'open a browser and search google.com').",
    )
    p_chat.add_argument(
        "--tool-prefix",
        help="Optional prefix to restrict tools (e.g. 'windows-mcp').",
    )
    p_chat.add_argument(
        "--model",
        default="claude-sonnet-4-6",
        help="Anthropic model name to use.",
    )
    p_chat.add_argument(
        "--max-tokens",
        type=int,
        default=1024,
        help="Maximum tokens for the LLM response.",
    )
    p_chat.set_defaults(func=cmd_chat)

    return parser


def main(argv: Optional[list[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

