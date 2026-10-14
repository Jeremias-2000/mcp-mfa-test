# Cookie-backed MCP authentication

The MCP server uses a small browser sign-in page, stores upstream authentication
cookies in MongoDB, and gives the MCP client an opaque session handle. Regular
users can call tools after sign-in. `master` users must also complete MFA as
confirmed by the session-validation service.

This documentation and the architecture diagram use generic service names;
they do not reproduce company, product, or person names from the source image.

## Current source layout

```text
src/
`-- test_mcp_2/
    |-- __init__.py         # Package entry point
    |-- main.py             # Composes FastMCP, Mongo session store, and lifespan
    |-- auth_errors.py      # Authentication exceptions and HTTP error mapping
    |-- mfa_auth.py         # Login page/flow, service calls, middleware, helpers
    `-- session_manager.py  # Opaque handles and encrypted MongoDB cookie storage

tests/
`-- test_session_manager.py # Session persistence, encryption, expiry, and tampering

docs/
`-- architecture/
    `-- authentication-flow.excalidraw
```

`mfa_auth.py` still contains several authentication responsibilities. A
reasonable next refactor is to split it into `auth/config.py`,
`auth/schemas.py`, `auth/service_client.py`, `auth/login.py`, and
`auth/middleware.py`, keeping `main.py` as the composition root. That refactor
is separate from the current session-manager implementation.

## Flow, step by step

### Browser sign-in

1. The user opens `GET /auth/login`, a basic local HTML form served by the MCP
   application.
2. The form posts username and password to `POST /auth/login`. The credentials
   are sent to the configured login service and are not stored by this app.
3. The login service returns the user type and session/CSRF cookies.
4. The application calls the session-validation service with the cookie values
   to establish the validated user identity.
5. For a regular user, the application creates an opaque session handle.
6. For a `master` user, the application first initiates the MFA challenge,
   then creates a pending handle. The handle does not grant MCP access until
   the validation service reports `mfa_verified: true`.
7. The browser displays the handle and the HTTP header name to configure in the
   MCP client. Upstream cookies are never returned to the browser.

### MCP tool call

1. The MCP client sends its request to `/mcp` with the configured
   `X-Auth-Session-ID` header. The header name can be changed with
   `MCP_SESSION_ID_HEADER`.
2. The middleware hashes the handle and looks up its record in MongoDB.
3. The stored upstream cookies are decrypted in memory. MongoDB stores only
   the handle hash and AES-GCM-encrypted cookie values, with a TTL index.
4. The middleware calls the session-validation service on every MCP request.
   Invalid or expired sessions are rejected; `master` is rejected until MFA
   is confirmed.
5. The validated principal and upstream cookie values are attached to the
   request scope. Tool implementations can read them with
   `get_authenticated_principal()` and `get_authenticated_session_cookies()`
   from `test_mcp_2.mfa_auth`.
6. A tool that calls the business service can forward those upstream cookies.
   The example note tools remain placeholders; no business API has been wired
   into them yet.

The opaque handle is a bearer secret: do not paste it into logs, prompts,
source control, or shared screenshots. Use HTTPS outside local development.

## Configuration

Create a local `.env` with test/development values. Do not add real credentials
to source control.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `AUTH_LOGIN_URL` | Yes | — | Username/password login service |
| `MFA_SESSION_VALIDATION_URL` | Yes | — | Session validation service |
| `MFA_ENDPOINT_URL` | For `master` users | — | MFA challenge-initiation service |
| `AUTH_SERVICE_BEARER_TOKEN` | Yes | — | Bearer credential sent to auth services |
| `MONGODB_URI` | Yes | — | MongoDB connection string |
| `MONGODB_DATABASE` | No | `mcp_auth` | Database used for MCP sessions |
| `MONGODB_COLLECTION` | No | `sessions` | Session collection |
| `AUTH_SESSION_ENCRYPTION_KEY` | Yes | — | URL-safe base64 key that decodes to 32 bytes |
| `AUTH_SESSION_TTL_SECONDS` | No | `3600` | Opaque session-handle lifetime (maximum 30 days) |
| `MFA_CSRF_COOKIE_NAME` | No | `csrf_token` | CSRF cookie name from the auth service |
| `MFA_SESSION_COOKIE_NAME` | No | `session_id` | Session cookie name from the auth service |
| `MCP_SESSION_ID_HEADER` | No | `X-Auth-Session-ID` | Header carrying the opaque MCP session handle |
| `MCP_HTTP_PATH` | No | `/mcp` | HTTP MCP endpoint protected by the middleware |

Generate an encryption key for a local development environment:

```powershell
uv run python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Set the printed value as `AUTH_SESSION_ENCRYPTION_KEY`. Use a dedicated secret
manager and separate keys per environment outside local development. MongoDB
should use TLS when it is not on the local machine.

Authentication service URLs must use HTTPS except for localhost/loopback.
Upstream requests have a 10-second timeout, do not follow redirects, and limit
request/response sizes. The login route does not return upstream `Set-Cookie`
headers to the browser.

## Configure the VS Code MCP client

The workspace configuration is in `.vscode/mcp.json`. It connects to the
server's HTTP endpoint and prompts for the opaque session handle as a secret
input; it does not contain the user's login password or the server's service
credentials.

For local development, start the server first, then sign in at
`http://127.0.0.1:8000/auth/login` in a browser. Copy the displayed session
handle. In VS Code, start or enable the `test-mcp-2` MCP server from the MCP
Servers view/command and enter that handle when prompted for `mcpSessionId`.
The client sends it as `X-Auth-Session-ID` on MCP requests. If the handle
expires, sign in again and provide the new one.

When the server is deployed, change the `url` in `.vscode/mcp.json` to the
public HTTPS MCP endpoint, for example `https://mcp.example.com/mcp`, and
ensure the matching `/auth/login` page is reachable at that host. Do not put
`AUTH_SERVICE_BEARER_TOKEN`, `MONGODB_URI`, `AUTH_SESSION_ENCRYPTION_KEY`, or
other server-side secrets in `mcp.json`; configure them in the deployed
server's environment or secret manager. The user's login password is entered
only on the server's login page, not in VS Code's MCP configuration.

## Local test walkthrough

### Prerequisites and start

1. Ensure a local MongoDB instance is running and reachable using `MONGODB_URI`.
2. Configure the auth-service URLs and test credentials in `.env`.
3. Generate and set `AUTH_SESSION_ENCRYPTION_KEY` as shown above.
4. Synchronize dependencies and launch the server from the repository root:

   ```powershell
   uv sync
   uv run python -m test_mcp_2.main
   ```

5. Open `http://127.0.0.1:8000/auth/login` in a browser. The default MCP HTTP
   endpoint is `http://127.0.0.1:8000/mcp`. Then configure the VS Code MCP
   client as described above and enter the session handle shown by the login
   page when prompted.

### Verify a regular user

1. Sign in with a development account whose service response has a non-master
   `user_type`.
2. Confirm the page reports sign-in complete and shows a session handle.
3. Configure the MCP client to send
   `X-Auth-Session-ID: <displayed-handle>` on requests to the MCP endpoint.
4. Complete MCP initialization and call a tool. The session service should be
   called for that MCP request.

### Verify a master user

1. Sign in with a development `master` account.
2. Confirm the MFA challenge starts and the page reports that MCP access is
   still blocked.
3. Try an MCP tool before the service marks the session MFA-verified; expect
   an authentication rejection.
4. Complete MFA using the mechanism provided by the auth service. Once session
   validation returns `mfa_verified: true`, retry with the same handle; the
   middleware should allow the request.

**MFA integration limit:** this application starts the challenge but does not
currently collect or submit the user's MFA code. The service must provide the
code-verification step and update its session state. Agree that contract
before treating the master flow as production-ready.

### Negative cases

| Case | Expected result |
| --- | --- |
| Login with invalid credentials | HTTP 401; no handle is created |
| Login response lacks required upstream cookies | Explicit upstream-response error |
| MCP request omits or alters the session handle | HTTP 401 |
| Handle is expired or absent from MongoDB | HTTP 401 |
| Session-validation service rejects the upstream cookies | MCP request is rejected |
| Master session reports `mfa_verified: false` | MCP request is rejected |
| MongoDB cannot be reached | Explicit service-unavailable error |
| Request body exceeds configured limit | HTTP 413 |

For a low-level login check, PowerShell can post JSON without opening the page:

```powershell
$body = @{ username = "test-user"; password = "test-password" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/auth/login" `
  -ContentType "application/json" -Body $body
```

Treat the returned `session_id` as a secret and add it to the MCP client's
custom headers. Do not run this command with real credentials in shared shell
history.

### Automated tests

The unit tests use fake Mongo collections, mocked upstream HTTP responses, and
an in-process ASGI harness, so they do not require MongoDB or authentication
services to be running:

```powershell
uv run python -m unittest discover -s tests
```

The suite covers session encryption, expiry, tampering, and database-error
mapping; configuration and error responses; login and MFA branches; request
limits; upstream HTTP behavior; middleware authentication and request-body
replay; route security headers; and server startup/lifespan wiring.
Integration tests against real auth services and MongoDB are not included;
run the manual walkthrough with development endpoints before deployment.
