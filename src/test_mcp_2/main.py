from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastmcp import FastMCP

from .mfa_auth import Config, cookie_auth_middleware, register_auth_routes
from .session_manager import MongoSessionStore

load_dotenv()

config = Config()
session_store = MongoSessionStore(
    uri=(
        config.mongodb_uri.get_secret_value()
        if config.mongodb_uri
        else None
    ),
    database=config.mongodb_database,
    collection=config.mongodb_collection,
    encryption_key=(
        config.session_encryption_key.get_secret_value()
        if config.session_encryption_key
        else None
    ),
)


@asynccontextmanager
async def app_lifespan(_server: FastMCP) -> AsyncGenerator[None, None]:
    await session_store.start()
    try:
        yield None
    finally:
        await session_store.close()


mcp = FastMCP(name="MCP Server", lifespan=app_lifespan)
register_auth_routes(mcp, config, session_store)


@mcp.tool()
async def hello_world():
    return "Hello, World!"

@mcp.tool()
def get_my_notes(_ctx)-> str:
    """Get all notes for a user."""
    return "Here are your notes!"

@mcp.tool()
def add_note(_ctx, note: str)-> str:
    """Add a new note for a user."""
    return f"Note added: {note}"

def main() -> None:
    mcp.run(
        transport="http",
        path=config.mcp_http_path,
        middleware=cookie_auth_middleware(config, session_store),
    )


if __name__ == "__main__":
    main()