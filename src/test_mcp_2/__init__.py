"""MCP server package."""


def main() -> None:
    """Run the configured MCP HTTP server."""
    from .main import main as run_server

    run_server()
