"""Authentication-domain errors for the MCP server."""

from starlette.responses import JSONResponse


class AuthenticationError(Exception):
    """Base class for expected errors in the authentication flow."""

    status_code = 500

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class InvalidRequestError(AuthenticationError):
    status_code = 400


class PayloadTooLargeError(InvalidRequestError):
    status_code = 413


class InvalidCredentialsError(AuthenticationError):
    status_code = 401


class SessionValidationError(AuthenticationError):
    status_code = 401


class ConfigurationError(AuthenticationError):
    status_code = 503


class UpstreamServiceError(AuthenticationError):
    status_code = 502


class InvalidUpstreamResponseError(UpstreamServiceError):
    pass


class SessionStoreUnavailableError(AuthenticationError):
    status_code = 503


class SessionStoreDataError(AuthenticationError):
    status_code = 503


class SessionNotFoundError(SessionValidationError):
    pass


class AuthenticationExceptionHandler:
    """Convert expected authentication exceptions to HTTP JSON responses."""

    @staticmethod
    def handle(error: AuthenticationError) -> JSONResponse:
        return JSONResponse({"detail": error.detail}, status_code=error.status_code)
