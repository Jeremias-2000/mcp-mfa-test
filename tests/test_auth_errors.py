import unittest

from test_mcp_2.auth_errors import (
    AuthenticationError,
    AuthenticationExceptionHandler,
    ConfigurationError,
    InvalidCredentialsError,
    InvalidRequestError,
    InvalidUpstreamResponseError,
    PayloadTooLargeError,
    SessionNotFoundError,
    SessionStoreDataError,
    SessionStoreUnavailableError,
    SessionValidationError,
    UpstreamServiceError,
)


class AuthenticationErrorTests(unittest.TestCase):
    def test_error_hierarchy_and_status_codes(self) -> None:
        cases = [
            (AuthenticationError, 500),
            (InvalidRequestError, 400),
            (PayloadTooLargeError, 413),
            (InvalidCredentialsError, 401),
            (SessionValidationError, 401),
            (SessionNotFoundError, 401),
            (ConfigurationError, 503),
            (UpstreamServiceError, 502),
            (InvalidUpstreamResponseError, 502),
            (SessionStoreUnavailableError, 503),
            (SessionStoreDataError, 503),
        ]

        for error_type, status_code in cases:
            with self.subTest(error_type=error_type.__name__):
                error = error_type("expected detail")
                self.assertEqual(error.status_code, status_code)
                self.assertEqual(error.detail, "expected detail")
                self.assertEqual(str(error), "expected detail")

    def test_exception_handler_preserves_detail_and_status(self) -> None:
        response = AuthenticationExceptionHandler.handle(
            InvalidCredentialsError("Invalid username or password.")
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.body,
            b'{"detail":"Invalid username or password."}',
        )
