"""Login routes and session validation for the MCP HTTP server."""

import asyncio
import json
from collections.abc import Mapping
from http.cookies import SimpleCookie
from typing import Any, TypeVar

import aiohttp
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_request
from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict
from starlette.middleware import Middleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .auth_errors import (
    AuthenticationError,
    AuthenticationExceptionHandler,
    ConfigurationError,
    InvalidCredentialsError,
    InvalidRequestError,
    InvalidUpstreamResponseError,
    PayloadTooLargeError,
    SessionNotFoundError,
    SessionStoreDataError,
    SessionValidationError,
    UpstreamServiceError,
)
from .session_manager import MongoSessionStore

ResponseModel = TypeVar("ResponseModel", bound=BaseModel)

LOGIN_PAGE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MCP session sign-in</title>
    <style>
      body { font: 16px system-ui, sans-serif; margin: 3rem auto; max-width: 34rem; padding: 0 1rem; }
      label { display: block; margin: 1rem 0 .35rem; }
      input { box-sizing: border-box; padding: .65rem; width: 100%; }
      button { margin-top: 1rem; padding: .65rem 1rem; }
      pre { overflow-wrap: anywhere; white-space: pre-wrap; }
    </style>
  </head>
  <body>
    <h1>Sign in to the MCP session</h1>
    <p>Credentials are sent to the configured authentication service.</p>
    <form id="login-form">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" required>
      <label for="password">Password</label>
      <input id="password" name="password" type="password"
             autocomplete="current-password" required>
      <button type="submit">Sign in</button>
    </form>
    <p id="message" role="status"></p>
    <section id="session-result" hidden>
      <h2>MCP session identifier</h2>
      <p>Copy this value to the MCP client's configured session header:</p>
      <pre id="session-id"></pre>
      <p id="session-header"></p>
      <p id="mfa-notice"></p>
    </section>
    <script>
      const form = document.querySelector("#login-form");
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const message = document.querySelector("#message");
        message.textContent = "Signing in...";
        try {
          const response = await fetch("/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: form.username.value,
              password: form.password.value
            })
          });
          const result = await response.json();
          if (!response.ok) {
            throw new Error(result.detail || "Sign-in failed.");
          }
          document.querySelector("#session-id").textContent = result.session_id;
          document.querySelector("#session-header").textContent =
            "Header name: " + result.session_header;
          document.querySelector("#mfa-notice").textContent =
            result.mfa_required
              ? "MFA is required. Complete the configured MFA challenge before using MCP."
              : "Sign-in complete. Configure the header above in your MCP client.";
          document.querySelector("#session-result").hidden = false;
          message.textContent = result.mfa_required
            ? "MFA challenge started; MCP access remains blocked until verified."
            : "Sign-in complete. Copy the session identifier now.";
          form.reset();
        } catch (error) {
          message.textContent = error.message;
        }
      });
    </script>
  </body>
</html>
"""


class Config(BaseSettings):
    """Authentication, session storage, and HTTP security settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    auth_login_url: AnyHttpUrl | None = None
    session_validation_url: AnyHttpUrl | None = Field(
        default=None,
        validation_alias="MFA_SESSION_VALIDATION_URL",
    )
    mfa_url: AnyHttpUrl | None = Field(
        default=None,
        validation_alias="MFA_ENDPOINT_URL",
    )
    service_bearer_token: SecretStr | None = Field(
        default=None,
        validation_alias="AUTH_SERVICE_BEARER_TOKEN",
    )
    mongodb_uri: SecretStr | None = None
    mongodb_database: str = "mcp_auth"
    mongodb_collection: str = "sessions"
    session_encryption_key: SecretStr | None = Field(
        default=None,
        validation_alias="AUTH_SESSION_ENCRYPTION_KEY",
    )
    session_ttl_seconds: int = Field(
        default=3600,
        gt=0,
        le=2_592_000,
        validation_alias="AUTH_SESSION_TTL_SECONDS",
    )
    csrf_cookie_name: str = Field(
        default="csrf_token",
        validation_alias="MFA_CSRF_COOKIE_NAME",
    )
    session_cookie_name: str = Field(
        default="session_id",
        validation_alias="MFA_SESSION_COOKIE_NAME",
    )
    mcp_session_id_header: str = Field(
        default="X-Auth-Session-ID",
        validation_alias="MCP_SESSION_ID_HEADER",
    )
    mcp_http_path: str = Field(
        default="/mcp",
        validation_alias="MCP_HTTP_PATH",
    )
    service_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    max_request_body_bytes: int = Field(default=16_384, gt=0, le=1_048_576)
    max_service_response_bytes: int = Field(
        default=1_048_576,
        gt=0,
        le=10_485_760,
    )

    @field_validator("auth_login_url", "session_validation_url", "mfa_url")
    @classmethod
    def require_https_outside_localhost(
        cls,
        value: AnyHttpUrl | None,
    ) -> AnyHttpUrl | None:
        if value is not None and value.scheme != "https":
            if value.host not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("Authentication service URLs must use HTTPS.")
        return value

    def require_url(self, attribute: str, env_name: str) -> str:
        value = getattr(self, attribute)
        if not value:
            raise ConfigurationError(
                f"Required environment variable {env_name} is not set."
            )
        return str(value)

    def authorization_headers(self) -> dict[str, str]:
        if not self.service_bearer_token:
            raise ConfigurationError(
                "Required environment variable AUTH_SERVICE_BEARER_TOKEN is not set."
            )
        return {
            "Authorization": (
                f"Bearer {self.service_bearer_token.get_secret_value()}"
            )
        }


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=256)
    password: SecretStr = Field(min_length=1, max_length=1024)


class LoginServiceResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    user_type: str = Field(min_length=1)


class SessionValidationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    csrf_token: SecretStr = Field(min_length=1)
    session_id: SecretStr = Field(min_length=1)


class SessionValidationResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    valid: bool
    user_id: str = Field(min_length=1)
    user_type: str = Field(min_length=1)
    mfa_verified: bool = False


class AuthenticatedPrincipal(BaseModel):
    user_id: str
    user_type: str
    mfa_verified: bool


class MFAChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    csrf_token: SecretStr = Field(min_length=1)
    session_id: SecretStr = Field(min_length=1)


class MFAChallengeResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    challenge_id: str | None = None
    status: str | None = None


class _ServiceResponse:
    def __init__(self, status: int, body: Any, cookies: list[str]) -> None:
        self.status = status
        self.body = body
        self.cookies = cookies


async def _read_limited(stream: aiohttp.StreamReader, max_bytes: int) -> bytes:
    body = bytearray()
    async for chunk in stream.iter_chunked(64 * 1024):
        body.extend(chunk)
        if len(body) > max_bytes:
            raise InvalidUpstreamResponseError(
                "Authentication service response is too large."
            )
    return bytes(body)


async def _post_json(
    config: Config,
    url: str,
    payload: Mapping[str, Any],
) -> _ServiceResponse:
    timeout = aiohttp.ClientTimeout(total=config.service_timeout_seconds)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as client:
            async with client.post(
                url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    **config.authorization_headers(),
                },
                allow_redirects=False,
            ) as response:
                if (
                    response.content_length is not None
                    and response.content_length > config.max_service_response_bytes
                ):
                    raise InvalidUpstreamResponseError(
                        "Authentication service response is too large."
                    )
                cookies = response.headers.getall("Set-Cookie", [])
                if response.status < 200 or response.status >= 300:
                    return _ServiceResponse(response.status, None, cookies)
                raw_body = await _read_limited(
                    response.content,
                    config.max_service_response_bytes,
                )
                try:
                    parsed_body = json.loads(raw_body)
                except (json.JSONDecodeError, UnicodeDecodeError) as error:
                    raise InvalidUpstreamResponseError(
                        "Authentication service returned invalid JSON."
                    ) from error
                return _ServiceResponse(response.status, parsed_body, cookies)
    except InvalidUpstreamResponseError:
        raise
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as error:
        raise UpstreamServiceError(
            "Authentication service is unavailable."
        ) from error


async def _call_service(
    config: Config,
    url: str,
    payload: BaseModel,
    service_name: str,
    response_model: type[ResponseModel],
    unauthorized_error: type[AuthenticationError] | None = None,
    unauthorized_detail: str | None = None,
) -> tuple[ResponseModel, list[str]]:
    request_payload = {
        key: (
            value.get_secret_value()
            if isinstance(value, SecretStr)
            else value
        )
        for key, value in payload.model_dump().items()
    }
    result = await _post_json(config, url, request_payload)
    if result.status in {401, 403} and unauthorized_error is not None:
        raise unauthorized_error(
            unauthorized_detail or f"{service_name} rejected the request."
        )
    if result.status < 200 or result.status >= 300:
        raise UpstreamServiceError(f"{service_name} returned an error.")
    try:
        parsed = response_model.model_validate(result.body)
    except ValidationError as error:
        raise InvalidUpstreamResponseError(
            f"{service_name} returned an invalid response."
        ) from error
    return parsed, result.cookies


def _cookie_values(set_cookie_headers: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for header in set_cookie_headers:
        cookies = SimpleCookie()
        cookies.load(header)
        values.update({name: morsel.value for name, morsel in cookies.items()})
    return values


async def _read_request_body(request: StarletteRequest, limit: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > limit:
                raise PayloadTooLargeError("Request body is too large.")
        except ValueError as error:
            raise InvalidRequestError("Invalid Content-Length header.") from error

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise PayloadTooLargeError("Request body is too large.")
    return bytes(body)


async def _validate_session(
    config: Config,
    csrf_token: str,
    session_id: str,
    *,
    require_mfa: bool,
) -> AuthenticatedPrincipal:
    validation_url = config.require_url(
        "session_validation_url",
        "MFA_SESSION_VALIDATION_URL",
    )
    response, _ = await _call_service(
        config,
        validation_url,
        SessionValidationRequest(
            csrf_token=csrf_token,
            session_id=session_id,
        ),
        "Session validation service",
        SessionValidationResponse,
        SessionValidationError,
        "Session validation failed.",
    )
    if not response.valid:
        raise SessionValidationError("Session validation failed.")
    if (
        require_mfa
        and response.user_type.casefold() == "master"
        and not response.mfa_verified
    ):
        raise SessionValidationError("MFA verification has not been completed.")
    return AuthenticatedPrincipal(
        user_id=response.user_id,
        user_type=response.user_type,
        mfa_verified=response.mfa_verified,
    )


async def _login_flow(
    request: StarletteRequest,
    config: Config,
    session_store: MongoSessionStore,
) -> Response:
    body = await _read_request_body(request, config.max_request_body_bytes)
    try:
        credentials = LoginRequest.model_validate_json(body)
    except ValidationError as error:
        raise InvalidRequestError(
            "Request must include a valid username and password."
        ) from error

    if not credentials.username.strip():
        raise InvalidRequestError("A username is required.")

    login_url = config.require_url("auth_login_url", "AUTH_LOGIN_URL")
    login_result, login_cookies = await _call_service(
        config,
        login_url,
        credentials,
        "Login service",
        LoginServiceResponse,
        InvalidCredentialsError,
        "Invalid username or password.",
    )
    cookies = _cookie_values(login_cookies)
    csrf_token = cookies.get(config.csrf_cookie_name)
    upstream_session_id = cookies.get(config.session_cookie_name)
    if not csrf_token or not upstream_session_id:
        raise InvalidUpstreamResponseError(
            "Login service did not set the required CSRF and session cookies."
        )

    principal = await _validate_session(
        config,
        csrf_token,
        upstream_session_id,
        require_mfa=False,
    )
    if principal.user_type.casefold() != login_result.user_type.casefold():
        raise InvalidUpstreamResponseError(
            "Login and session validation returned inconsistent user types."
        )

    mfa_required = principal.user_type.casefold() == "master"
    challenge: MFAChallengeResponse | None = None
    if mfa_required:
        mfa_url = config.require_url("mfa_url", "MFA_ENDPOINT_URL")
        challenge, _ = await _call_service(
            config,
            mfa_url,
            MFAChallengeRequest(
                csrf_token=csrf_token,
                session_id=upstream_session_id,
            ),
            "MFA service",
            MFAChallengeResponse,
        )

    session_handle = await session_store.create_session(
        cookies=cookies,
        user_id=principal.user_id,
        user_type=principal.user_type,
        ttl_seconds=config.session_ttl_seconds,
    )
    response = JSONResponse(
        {
            "authenticated": not mfa_required,
            "mfa_required": mfa_required,
            "mfa_status": challenge.status if challenge else None,
            "session_id": session_handle,
            "session_header": config.mcp_session_id_header,
            "expires_in": config.session_ttl_seconds,
        }
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


class CookieSessionAuthMiddleware:
    """Load the stored session and revalidate it before every MCP request."""

    def __init__(
        self,
        app: ASGIApp,
        config: Config,
        session_store: MongoSessionStore,
    ) -> None:
        self.app = app
        self.config = config
        self.session_store = session_store
        self.exception_handler = AuthenticationExceptionHandler()

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http" or scope.get("path") != self.config.mcp_http_path:
            await self.app(scope, receive, send)
            return

        request = StarletteRequest(scope, receive)
        session_handle = request.headers.get(self.config.mcp_session_id_header)
        if not session_handle or len(session_handle) > 128:
            await self._reject(
                scope,
                receive,
                send,
                SessionNotFoundError("A valid MCP session identifier is required."),
            )
            return

        downstream_receive = receive
        if scope.get("method") == "POST":
            try:
                body = await _read_request_body(
                    request,
                    self.config.max_request_body_bytes,
                )
            except AuthenticationError as error:
                await self._reject(scope, receive, send, error)
                return
            body_sent = False
            original_receive = receive

            async def replay_body() -> dict[str, Any]:
                nonlocal body_sent
                if not body_sent:
                    body_sent = True
                    return {
                        "type": "http.request",
                        "body": body,
                        "more_body": False,
                    }
                return await original_receive()

            downstream_receive = replay_body

        try:
            stored_session = await self.session_store.get_session(session_handle)
            csrf_token = stored_session.cookies.get(self.config.csrf_cookie_name)
            upstream_session_id = stored_session.cookies.get(
                self.config.session_cookie_name
            )
            if not csrf_token or not upstream_session_id:
                raise SessionStoreDataError(
                    "Stored session is missing required upstream cookies."
                )
            principal = await _validate_session(
                self.config,
                csrf_token,
                upstream_session_id,
                require_mfa=True,
            )
            if (
                principal.user_id != stored_session.user_id
                or principal.user_type.casefold()
                != stored_session.user_type.casefold()
            ):
                raise SessionValidationError(
                    "Session identity does not match the stored principal."
                )
        except AuthenticationError as error:
            await self._reject(scope, receive, send, error)
            return

        state = scope.setdefault("state", {})
        state["authenticated_principal"] = principal.model_dump()
        state["upstream_cookies"] = stored_session.cookies
        await self.app(scope, downstream_receive, send)

    async def _reject(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        error: AuthenticationError,
    ) -> None:
        response = self.exception_handler.handle(error)
        await response(scope, receive, send)


def get_authenticated_principal() -> AuthenticatedPrincipal:
    """Return the principal validated for the current tool call."""
    request = get_http_request()
    principal = request.scope.get("state", {}).get("authenticated_principal")
    if principal is None:
        raise SessionValidationError(
            "No authenticated session is attached to this request."
        )
    return AuthenticatedPrincipal.model_validate(principal)


def get_authenticated_session_cookies() -> dict[str, str]:
    """Return the upstream cookies for a validated tool call."""
    request = get_http_request()
    cookies = request.scope.get("state", {}).get("upstream_cookies")
    if not isinstance(cookies, dict) or not all(
        isinstance(name, str) and isinstance(value, str)
        for name, value in cookies.items()
    ):
        raise SessionValidationError(
            "No authenticated upstream session is attached to this request."
        )
    return cookies


def register_auth_routes(
    mcp: FastMCP,
    config: Config,
    session_store: MongoSessionStore,
) -> None:
    """Register the local login screen and credential submission endpoint."""
    exception_handler = AuthenticationExceptionHandler()

    @mcp.custom_route("/auth/login", methods=["GET"])
    async def login_page(_request: StarletteRequest) -> Response:
        return HTMLResponse(
            LOGIN_PAGE,
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )

    @mcp.custom_route("/auth/login", methods=["POST"])
    async def authenticate_user(request: StarletteRequest) -> Response:
        try:
            return await _login_flow(request, config, session_store)
        except AuthenticationError as error:
            return exception_handler.handle(error)


def cookie_auth_middleware(
    config: Config,
    session_store: MongoSessionStore,
) -> list[Middleware]:
    """Create middleware that protects MCP requests with stored sessions."""
    return [
        Middleware(
            CookieSessionAuthMiddleware,
            config=config,
            session_store=session_store,
        )
    ]
