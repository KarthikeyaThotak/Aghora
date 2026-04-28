import os
from pathlib import Path

from dotenv import load_dotenv


def _load_env() -> None:
    """
    Load environment variables for the CLI.

    Preference order:
    1. flarevm_cli/.env (this package's own config — highest priority)
    2. python_agent/.env (to reuse your existing config)
    3. Project root .env
    4. Process environment (already present)
    """
    project_root = Path(__file__).resolve().parents[1]

    # Load the package-local .env first so its values take priority
    package_env = Path(__file__).parent / ".env"
    if package_env.exists():
        load_dotenv(dotenv_path=package_env, override=False)

    python_agent_env = project_root / "python_agent" / ".env"
    if python_agent_env.exists():
        load_dotenv(dotenv_path=python_agent_env, override=False)

    # Also load from a root-level .env if present (non-fatal if missing)
    root_env = project_root / ".env"
    if root_env.exists():
        load_dotenv(dotenv_path=root_env, override=False)

    # Finally, call load_dotenv with defaults so a local .env near cwd is honored
    load_dotenv(override=False)


_load_env()


def get_anthropic_api_key() -> str:
    key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_KEY")
    if not key:
        raise RuntimeError(
            "Anthropic API key not found. "
            "Set ANTHROPIC_API_KEY (or ANTHROPIC_KEY) in your environment or .env."
        )
    return key


def get_flarevm_mcp_url() -> str:
    """
    Return the base URL for the flarevm MCP server.

    Default is your provided URL, but can be overridden via FLAREVM_MCP_URL.
    """
    return os.getenv(
        "FLAREVM_MCP_URL",
        "https://winmcp.karthikeyathota.page/mcp",
    )

