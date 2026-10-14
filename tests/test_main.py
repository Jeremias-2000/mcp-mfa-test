import base64
import importlib
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

from test_mcp_2.mfa_auth import CookieSessionAuthMiddleware


class MainModuleTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.environment = patch.dict(
            os.environ,
            {
                "MONGODB_URI": "mongodb://127.0.0.1:27017",
                "AUTH_SESSION_ENCRYPTION_KEY": base64.urlsafe_b64encode(
                    bytes(32)
                ).decode("ascii"),
                "MONGODB_DATABASE": "unit_test",
                "MONGODB_COLLECTION": "sessions",
                "MCP_HTTP_PATH": "/test-mcp",
            },
        )
        cls.environment.start()
        sys.modules.pop("test_mcp_2.main", None)
        cls.main_module = importlib.import_module("test_mcp_2.main")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.environment.stop()
        sys.modules.pop("test_mcp_2.main", None)

    def test_entrypoint_runs_http_server_with_configured_path_and_middleware(self) -> None:
        with patch.object(self.main_module.mcp, "run") as run:
            self.main_module.main()

        arguments = run.call_args.kwargs
        self.assertEqual(arguments["transport"], "http")
        self.assertEqual(arguments["path"], "/test-mcp")
        middleware = arguments["middleware"]
        self.assertEqual(len(middleware), 1)
        self.assertIs(
            middleware[0].cls,
            CookieSessionAuthMiddleware,
        )
        self.assertEqual(
            middleware[0].kwargs["config"],
            self.main_module.config,
        )
        self.assertIs(
            middleware[0].kwargs["session_store"],
            self.main_module.session_store,
        )

    async def test_lifespan_starts_store_and_closes_it_after_shutdown(self) -> None:
        start = AsyncMock()
        close = AsyncMock()
        with (
            patch.object(self.main_module.session_store, "start", new=start),
            patch.object(self.main_module.session_store, "close", new=close),
        ):
            async with self.main_module.app_lifespan(self.main_module.mcp):
                start.assert_awaited_once()
                close.assert_not_awaited()

        close.assert_awaited_once()

    async def test_example_tools_return_documented_placeholder_values(self) -> None:
        self.assertEqual(await self.main_module.hello_world(), "Hello, World!")
        self.assertEqual(
            self.main_module.get_my_notes(None),
            "Here are your notes!",
        )
        self.assertEqual(
            self.main_module.add_note(None, "example"),
            "Note added: example",
        )

    async def asyncTearDown(self) -> None:
        await self.main_module.session_store.close()
