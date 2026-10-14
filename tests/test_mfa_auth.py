import asyncio
import json
import unittest
from typing import Any
from unittest.mock import AsyncMock, patch

from starlette.requests import Request

from test_mcp_2 import mfa_auth
from test_mcp_2.auth_errors import (
    ConfigurationError,
    InvalidCredentialsError,
    InvalidRequestError,
    InvalidUpstreamResponseError,
    PayloadTooLargeError,
    SessionValidationError,
    UpstreamServiceError,
)
from test_mcp_2.mfa_auth import (
    AuthenticatedPrincipal,
    Config,
    CookieSessionAuthMiddleware,
    LoginServiceResponse,
    MFAChallengeResponse,
    SessionValidationResponse,
    _ServiceResponse,
    _call_service,
    _cookie_values,
    _login_flow,
    _post_json,
    _read_limited,
    _read_request_body,
    _validate_session,
    register_auth_routes,
)
from test_mcp_2.session_manager import StoredSession


def make_config(**overrides: Any) -> Config:
    values: dict[str, Any] = {
        "auth_login_url": "https://login.example.test/auth",
        "session_validation_url": "https://login.example.test/session",
        "mfa_url": "https://login.example.test/mfa",
        "service_bearer_token": "test-service-token",
        "_env_file": None,
    }
    values.update(overrides)
    return Config(**values)


def make_request(
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    *,
    path: str = "/auth/login",
    method: str = "POST",
) -> Request:
    raw_headers = [
        (name.lower().encode("ascii"), value.encode("latin-1"))
        for name, value in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": raw_headers,
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
    }
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive() -> dict[str, Any]:
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    return Request(scope, receive)


def make_scope(
    *,
    path: str = "/mcp",
    method: str = "POST",
    headers: dict[str, str] | None = None,
    content_length: int | None = None,
) -> dict[str, Any]:
    request_headers = {
        name.lower().encode("ascii"): value.encode("latin-1")
        for name, value in (headers or {}).items()
    }
    if content_length is not None:
        request_headers[b"content-length"] = str(content_length).encode("ascii")
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": list(request_headers.items()),
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
    }


async def invoke_asgi(
    app: Any,
    scope: dict[str, Any],
    body: bytes = b"",
) -> list[dict[str, Any]]:
    pending = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if pending:
            return pending.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


class ConfigTests(unittest.TestCase):
    def test_defaults_and_bounded_configuration(self) -> None:
        config = Config(_env_file=None)
        self.assertEqual(config.mongodb_database, "mcp_auth")
        self.assertEqual(config.mongodb_collection, "sessions")
        self.assertEqual(config.session_ttl_seconds, 3600)
        self.assertEqual(config.mcp_http_path, "/mcp")
        self.assertEqual(
            make_config(
                auth_login_url="http://localhost:8001/login",
                session_validation_url="http://127.0.0.1/session",
            ).auth_login_url.host,
            "localhost",
        )
        for field in ("auth_login_url", "session_validation_url", "mfa_url"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                make_config(**{field: "http://auth.example.test"})
        for ttl in (0, 2_592_001):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                make_config(session_ttl_seconds=ttl)

    def test_authorization_header_contains_configured_bearer(self) -> None:
        self.assertEqual(
            make_config().authorization_headers(),
            {"Authorization": "Bearer test-service-token"},
        )

    def test_missing_required_configuration_is_reported(self) -> None:
        config = make_config(
            session_validation_url=None,
            service_bearer_token=None,
        )
        with self.assertRaises(ConfigurationError):
            config.require_url("session_validation_url", "MFA_SESSION_VALIDATION_URL")
        with self.assertRaises(ConfigurationError):
            config.authorization_headers()


class RequestAndServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_body_limits_and_invalid_length(self) -> None:
        request = make_request(b"1234", {"Content-Length": "4"})
        self.assertEqual(await _read_request_body(request, 4), b"1234")

        with self.assertRaises(InvalidRequestError):
            await _read_request_body(make_request(headers={"Content-Length": "x"}), 4)
        with self.assertRaises(PayloadTooLargeError):
            await _read_request_body(
                make_request(b"12345", {"Content-Length": "5"}),
                4,
            )
        with self.assertRaises(PayloadTooLargeError):
            await _read_request_body(make_request(b"12345"), 4)

    async def test_cookie_parser_reads_multiple_set_cookie_headers(self) -> None:
        self.assertEqual(
            _cookie_values(
                [
                    "csrf_token=csrf; Path=/; HttpOnly",
                    "session_id=upstream; Path=/; Secure",
                ]
            ),
            {"csrf_token": "csrf", "session_id": "upstream"},
        )

    async def test_post_json_sends_bearer_and_disables_redirects(self) -> None:
        response = FakeResponse(
            200,
            b'{"user_type":"regular"}',
            {"Set-Cookie": ["session_id=upstream"]},
        )
        client = FakeClientSession(response)
        with patch.object(mfa_auth.aiohttp, "ClientSession", return_value=client):
            result = await _post_json(
                make_config(),
                "https://service.example.test/login",
                {"username": "user"},
            )

        self.assertEqual(result.body, {"user_type": "regular"})
        self.assertEqual(result.cookies, ["session_id=upstream"])
        self.assertEqual(
            client.post_arguments["headers"]["Authorization"],
            "Bearer test-service-token",
        )
        self.assertFalse(client.post_arguments["allow_redirects"])

    async def test_post_json_rejects_oversized_and_invalid_json(self) -> None:
        oversized = FakeClientSession(FakeResponse(200, b"12345", {}, 5))
        with patch.object(mfa_auth.aiohttp, "ClientSession", return_value=oversized):
            with self.assertRaises(InvalidUpstreamResponseError):
                await _post_json(
                    make_config(max_service_response_bytes=4),
                    "https://service.example.test/login",
                    {},
                )

        invalid_json = FakeClientSession(FakeResponse(200, b"{", {}))
        with patch.object(
            mfa_auth.aiohttp,
            "ClientSession",
            return_value=invalid_json,
        ):
            with self.assertRaises(InvalidUpstreamResponseError):
                await _post_json(
                    make_config(),
                    "https://service.example.test/login",
                    {},
                )

    async def test_post_json_maps_network_errors_and_non_success_status(self) -> None:
        client = FakeClientSession(error=asyncio.TimeoutError())
        with patch.object(mfa_auth.aiohttp, "ClientSession", return_value=client):
            with self.assertRaises(UpstreamServiceError):
                await _post_json(
                    make_config(),
                    "https://service.example.test/login",
                    {},
                )

        client = FakeClientSession(FakeResponse(403, b"not-json", {}))
        with patch.object(mfa_auth.aiohttp, "ClientSession", return_value=client):
            response = await _post_json(
                make_config(),
                "https://service.example.test/login",
                {},
            )
        self.assertEqual(response.status, 403)
        self.assertIsNone(response.body)

    async def test_limited_stream_rejects_excess_bytes(self) -> None:
        with self.assertRaises(InvalidUpstreamResponseError):
            await _read_limited(FakeContent(b"12345"), 4)

    async def test_call_service_maps_auth_failures_and_unwraps_secrets(self) -> None:
        login = mfa_auth.LoginRequest(username="user", password="secret")
        with patch(
            "test_mcp_2.mfa_auth._post_json",
            new=AsyncMock(return_value=_ServiceResponse(401, None, [])),
        ):
            with self.assertRaises(InvalidCredentialsError):
                await _call_service(
                    make_config(),
                    "https://service.example.test/login",
                    login,
                    "Login service",
                    LoginServiceResponse,
                    InvalidCredentialsError,
                )

        post = AsyncMock(
            return_value=_ServiceResponse(200, {"user_type": "regular"}, [])
        )
        with patch("test_mcp_2.mfa_auth._post_json", new=post):
            result, _ = await _call_service(
                make_config(),
                "https://service.example.test/login",
                login,
                "Login service",
                LoginServiceResponse,
            )
        self.assertEqual(post.await_args.args[2]["password"], "secret")
        self.assertEqual(result.user_type, "regular")

        with patch(
            "test_mcp_2.mfa_auth._post_json",
            new=AsyncMock(return_value=_ServiceResponse(200, {}, [])),
        ):
            with self.assertRaises(InvalidUpstreamResponseError):
                await _call_service(
                    make_config(),
                    "https://service.example.test/login",
                    login,
                    "Login service",
                    LoginServiceResponse,
                )


class AuthenticationFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_session_validation_enforces_validity_and_mfa(self) -> None:
        master_without_mfa = SessionValidationResponse(
            valid=True,
            user_id="admin",
            user_type="master",
            mfa_verified=False,
        )
        with patch(
            "test_mcp_2.mfa_auth._call_service",
            new=AsyncMock(return_value=(master_without_mfa, [])),
        ):
            with self.assertRaises(SessionValidationError):
                await _validate_session(
                    make_config(),
                    "csrf",
                    "session",
                    require_mfa=True,
                )
            principal = await _validate_session(
                make_config(),
                "csrf",
                "session",
                require_mfa=False,
            )
        self.assertEqual(principal.user_type, "master")

        invalid = SessionValidationResponse(
            valid=False,
            user_id="user",
            user_type="regular",
        )
        with patch(
            "test_mcp_2.mfa_auth._call_service",
            new=AsyncMock(return_value=(invalid, [])),
        ):
            with self.assertRaises(SessionValidationError):
                await _validate_session(
                    make_config(),
                    "csrf",
                    "session",
                    require_mfa=False,
                )

    async def test_regular_login_creates_session_and_returns_no_store_response(self) -> None:
        store = AsyncMock()
        store.create_session.return_value = "opaque-handle"
        service_response = (
            LoginServiceResponse(user_type="regular"),
            ["csrf_token=csrf", "session_id=upstream"],
        )
        with (
            patch(
                "test_mcp_2.mfa_auth._call_service",
                new=AsyncMock(return_value=service_response),
            ) as call_service,
            patch(
                "test_mcp_2.mfa_auth._validate_session",
                new=AsyncMock(
                    return_value=AuthenticatedPrincipal(
                        user_id="user-1",
                        user_type="regular",
                        mfa_verified=False,
                    )
                ),
            ),
        ):
            response = await _login_flow(
                make_request(b'{"username":"user","password":"secret"}'),
                make_config(),
                store,
            )

        body = json.loads(response.body)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(body["authenticated"])
        self.assertFalse(body["mfa_required"])
        self.assertEqual(body["session_id"], "opaque-handle")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(call_service.await_count, 1)
        store.create_session.assert_awaited_once_with(
            cookies={"csrf_token": "csrf", "session_id": "upstream"},
            user_id="user-1",
            user_type="regular",
            ttl_seconds=3600,
        )

    async def test_master_login_starts_challenge_and_marks_session_pending(self) -> None:
        store = AsyncMock()
        store.create_session.return_value = "pending-handle"
        with (
            patch(
                "test_mcp_2.mfa_auth._call_service",
                new=AsyncMock(
                    side_effect=[
                        (
                            LoginServiceResponse(user_type="master"),
                            ["csrf_token=csrf", "session_id=upstream"],
                        ),
                        (MFAChallengeResponse(status="pending"), []),
                    ]
                ),
            ) as call_service,
            patch(
                "test_mcp_2.mfa_auth._validate_session",
                new=AsyncMock(
                    return_value=AuthenticatedPrincipal(
                        user_id="admin",
                        user_type="master",
                        mfa_verified=False,
                    )
                ),
            ),
        ):
            response = await _login_flow(
                make_request(b'{"username":"admin","password":"secret"}'),
                make_config(),
                store,
            )

        body = json.loads(response.body)
        self.assertFalse(body["authenticated"])
        self.assertTrue(body["mfa_required"])
        self.assertEqual(body["mfa_status"], "pending")
        self.assertEqual(call_service.await_count, 2)
        store.create_session.assert_awaited_once()

    async def test_login_rejects_invalid_payload_missing_cookies_or_identity_mismatch(self) -> None:
        store = AsyncMock()
        with self.assertRaises(InvalidRequestError):
            await _login_flow(
                make_request(b'{"username":" ","password":"secret"}'),
                make_config(),
                store,
            )

        with patch(
            "test_mcp_2.mfa_auth._call_service",
            new=AsyncMock(
                return_value=(LoginServiceResponse(user_type="regular"), [])
            ),
        ):
            with self.assertRaises(InvalidUpstreamResponseError):
                await _login_flow(
                    make_request(b'{"username":"user","password":"secret"}'),
                    make_config(),
                    store,
                )

        with (
            patch(
                "test_mcp_2.mfa_auth._call_service",
                new=AsyncMock(
                    return_value=(
                        LoginServiceResponse(user_type="regular"),
                        ["csrf_token=csrf", "session_id=upstream"],
                    )
                ),
            ),
            patch(
                "test_mcp_2.mfa_auth._validate_session",
                new=AsyncMock(
                    return_value=AuthenticatedPrincipal(
                        user_id="user-1",
                        user_type="different",
                        mfa_verified=False,
                    )
                ),
            ),
        ):
            with self.assertRaises(InvalidUpstreamResponseError):
                await _login_flow(
                    make_request(b'{"username":"user","password":"secret"}'),
                    make_config(),
                    store,
                )
        store.create_session.assert_not_awaited()


class MiddlewareTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.config = make_config(max_request_body_bytes=16)
        self.store = AsyncMock()
        self.store.get_session.return_value = StoredSession(
            cookies={"csrf_token": "csrf", "session_id": "upstream"},
            user_id="user-1",
            user_type="regular",
        )
        self.principal = AuthenticatedPrincipal(
            user_id="user-1",
            user_type="regular",
            mfa_verified=False,
        )
        self.validation = patch(
            "test_mcp_2.mfa_auth._validate_session",
            new=AsyncMock(return_value=self.principal),
        )
        self.validation_mock = self.validation.start()
        self.addCleanup(self.validation.stop)

    async def test_valid_session_adds_principal_and_replays_post_body(self) -> None:
        captured: dict[str, Any] = {}

        async def downstream(scope: dict[str, Any], receive: Any, send: Any) -> None:
            captured["state"] = scope["state"]
            captured["body"] = (await receive())["body"]
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        middleware = CookieSessionAuthMiddleware(
            downstream,
            self.config,
            self.store,
        )
        response = await invoke_asgi(
            middleware,
            make_scope(headers={"X-Auth-Session-ID": "opaque"}),
            b"{}",
        )

        self.assertEqual(response[0]["status"], 200)
        self.assertEqual(captured["body"], b"{}")
        self.assertEqual(
            captured["state"]["authenticated_principal"],
            self.principal.model_dump(),
        )
        self.assertEqual(
            captured["state"]["upstream_cookies"],
            {"csrf_token": "csrf", "session_id": "upstream"},
        )
        self.validation_mock.assert_awaited_once_with(
            self.config,
            "csrf",
            "upstream",
            require_mfa=True,
        )

    async def test_missing_handle_and_oversized_request_are_rejected(self) -> None:
        middleware = CookieSessionAuthMiddleware(
            AsyncMock(),
            self.config,
            self.store,
        )
        for headers in ({}, {"X-Auth-Session-ID": "x" * 129}):
            with self.subTest(length=len(headers.get("X-Auth-Session-ID", ""))):
                response = await invoke_asgi(middleware, make_scope(headers=headers))
                self.assertEqual(response[0]["status"], 401)
        response = await invoke_asgi(
            middleware,
            make_scope(
                headers={"X-Auth-Session-ID": "opaque"},
                content_length=17,
            ),
            b"x" * 17,
        )
        self.assertEqual(response[0]["status"], 413)
        self.store.get_session.assert_not_awaited()

    async def test_missing_cookies_and_identity_mismatch_are_rejected(self) -> None:
        middleware = CookieSessionAuthMiddleware(
            AsyncMock(),
            self.config,
            self.store,
        )
        request_scope = make_scope(headers={"X-Auth-Session-ID": "opaque"})
        self.store.get_session.return_value = StoredSession(
            cookies={"csrf_token": "csrf"},
            user_id="user-1",
            user_type="regular",
        )
        response = await invoke_asgi(middleware, request_scope, b"{}")
        self.assertEqual(response[0]["status"], 503)
        self.validation_mock.assert_not_awaited()

        self.store.get_session.return_value = StoredSession(
            cookies={"csrf_token": "csrf", "session_id": "upstream"},
            user_id="another-user",
            user_type="regular",
        )
        response = await invoke_asgi(
            middleware,
            make_scope(headers={"X-Auth-Session-ID": "opaque"}),
            b"{}",
        )
        self.assertEqual(response[0]["status"], 401)

    async def test_other_routes_pass_through_unauthenticated(self) -> None:
        downstream = AsyncMock()
        middleware = CookieSessionAuthMiddleware(
            downstream,
            self.config,
            self.store,
        )
        await invoke_asgi(middleware, make_scope(path="/health", method="GET"))

        downstream.assert_awaited_once()
        self.store.get_session.assert_not_awaited()


class AuthRoutesTests(unittest.IsolatedAsyncioTestCase):
    async def test_login_routes_register_and_login_page_has_security_headers(self) -> None:
        routes: dict[tuple[str, tuple[str, ...]], Any] = {}

        class FakeMCP:
            def custom_route(self, path: str, methods: list[str]) -> Any:
                def register(handler: Any) -> Any:
                    routes[(path, tuple(methods))] = handler
                    return handler

                return register

        register_auth_routes(FakeMCP(), make_config(), AsyncMock())
        response = await routes[("/auth/login", ("GET",))](
            make_request(method="GET")
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["referrer-policy"], "no-referrer")

        with patch(
            "test_mcp_2.mfa_auth._login_flow",
            new=AsyncMock(side_effect=InvalidCredentialsError("Invalid credentials.")),
        ):
            response = await routes[("/auth/login", ("POST",))](make_request())
        self.assertEqual(response.status_code, 401)
        self.assertEqual(json.loads(response.body), {"detail": "Invalid credentials."})


class FakeHeaders(dict[str, Any]):
    def getall(self, key: str, default: Any = None) -> Any:
        value = self.get(key, default)
        if value is default:
            return default
        return value if isinstance(value, list) else [value]


class FakeContent:
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def iter_chunked(self, chunk_size: int):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start : start + chunk_size]


class FakeResponse:
    def __init__(
        self,
        status: int,
        body: bytes,
        headers: dict[str, Any],
        content_length: int | None = None,
    ) -> None:
        self.status = status
        self.content = FakeContent(body)
        self.headers = FakeHeaders(headers)
        self.content_length = content_length

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None


class FakeClientSession:
    def __init__(
        self,
        response: FakeResponse | None = None,
        *,
        error: BaseException | None = None,
    ) -> None:
        self.response = response
        self.error = error
        self.post_arguments: dict[str, Any] = {}

    async def __aenter__(self) -> FakeClientSession:
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.post_arguments = {"url": url, **kwargs}
        if self.error is not None:
            raise self.error
        if self.response is None:
            raise AssertionError("A fake response is required.")
        return self.response


if __name__ == "__main__":
    unittest.main()
