# flarevm-cli backend

Command-line backend for interacting with your `flarevm-mcp` server and Anthropic LLM.

## Installation

From the project root:

```bash
cd flarevm_cli
pip install -r requirements.txt
```

## Configuration

Environment variables (can be placed in `python_agent/.env` so they are shared):

- `ANTHROPIC_API_KEY` **(required)**: your Anthropic API key.
- `FLAREVM_MCP_URL` *(optional)*: MCP endpoint. Defaults to `https://wincp.karthikeyathota.page/mcp`.

The CLI automatically loads:

1. `python_agent/.env` if present
2. project root `.env` if present
3. current-directory `.env`

## Usage

From the project root:

```bash
python -m flarevm_cli.cli info
python -m flarevm_cli.cli tools
python -m flarevm_cli.cli run <tool_name> --arguments '{"key": "value"}'
python -m flarevm_cli.cli analyze <tool_name> \
  --arguments '{"key": "value"}' \
  --prompt "Explain any security risks."
```

### Commands

- `info`: Show CLI version and configured MCP URL.
- `tools`: List tools exposed by the MCP server.
- `run`: Call a tool and print raw JSON result.
- `analyze`: Run a tool, then send its output plus your prompt to Anthropic for a concise analysis.

