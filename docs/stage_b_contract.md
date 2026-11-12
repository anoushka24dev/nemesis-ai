Stage B contract
================
Purpose
-------
- Thin, local-only FastAPI service for the RealGmail reading pilot.
- Sits between the Chrome extension and the existing read-only Gmail flow in `gmail_auth.py`.
- Binds to `127.0.0.1:8123` only.
- Requires pairing with a per-install nonce before any Gmail operation.
- Uses only the read-only Gmail scope; never requests Gmail write scopes.

Port and bind
-------------
- Port: `8123`
- Bind: `127.0.0.1` only during this stage.
- `python -m backend.stage_b serve` binds loopback and refuses non-loopback hosts.
- App origin: `http://127.0.0.1:8123`
- Allowed extension origin scheme: `chrome-extension://`
  (pinned to a single ID via `STAGE_B_EXTENSION_ID` when set)
- No public or wildcard exposure.

Pairing model
-------------
- Backend has one per-install pairing nonce (generated in memory; never persisted to disk).
- Nonce delivery: `python -m backend.stage_b serve` prints the nonce once to the
  operator's terminal. The operator pastes it into the extension's pairing screen.
  The nonce is never served over HTTP and never placed in a frontend bundle.
- Extension presents that nonce, plus its own `extension_origin`, to complete pairing.
- Pairing is bound to the `extension_origin` supplied in the request body (an allowed
  `chrome-extension://` origin). The request `Origin` header is optional on `/pair`;
  when present it must also be an allowed extension origin.
- Identity hardening: if `STAGE_B_EXTENSION_ID` is set, every auth path requires the
  exact origin `chrome-extension://<pinned-id>`; otherwise any `chrome-extension://`
  origin is accepted (dev default).
- Once paired, protected endpoints require:
  - matching extension origin header
  - valid bearer token equal to the pairing nonce (constant-time comparison)
- Nonce must never be returned to the extension after pairing, and must not appear in
  frontend bundles/logs. It is never written to disk.

Lifecycle endpoints
-------------------
Mount prefix: `/api/v1/stage_b`

/ pair
  Method: POST
  Purpose: pair with the expected nonce and extension origin
  Request body:
    - presented_nonce: string, required
    - extension_origin: string, required (the bound origin)
  Responses:
    - 200 when pairing succeeds (state=paired, origin_validated=<extension_origin>)
    - 400 for missing/empty presented_nonce or extension_origin
    - 403 for disallowed extension origin, disallowed Origin header, or wrong nonce

/ ping
  Method: POST
  Purpose: heartbeat after pairing
  Required:
    - extension origin header matching the paired origin
    - Authorization: Bearer <pairing nonce>
  Responses:
    - 200 when valid and paired (state, last_ping, origin_validated, feed_name_prefix)
    - 400 for missing origin
    - 401 for missing/wrong bearer
    - 403 if not paired or origin changed after pairing

/ feed
  Method: POST
  Purpose: fetch demo emails using read-only Gmail flow
  Request body:
    - max_results: integer, optional, default 25, clamped to 1..25
  Required:
    - extension origin header matching paired origin
    - Authorization: Bearer <pairing nonce>
  Responses:
    - 200 with read-only email list
    - 400 for invalid max_results
    - 401 for missing/wrong bearer
    - 403 if not paired or origin changed
    - 403/500 for scope/read-only violations or backend errors

/ analyze
  Method: POST
  Purpose: run read-only analysis over demo emails
  Request body:
    - max_results: integer, optional, default 25, clamped to 1..25
  Required:
    - extension origin header matching paired origin
    - Authorization: Bearer <pairing nonce>
  Responses:
    - 200 with analysis payload
    - 400 for invalid max_results
    - 401 for missing/wrong bearer
    - 403 for not paired, origin change, scope/read-only violation
    - 502 for Gemini analysis error
    - 500 for unexpected backend error

/ attachments / {filename}
  Method: POST
  Purpose: get attachment metadata for a requested .bin file
  Path param:
    - filename: string
  Validation:
    - filename must be present and not blank
    - must end with `.bin`
    - must not contain `..` or start with `/` or `\`
    - normalized by stripping leading slashes/backslashes and converting backslashes to `/`
  Routing:
    - Mounted as both `/attachments/{filename}` and `/attachments/{filename:path}` so
      slash-containing inputs still reach the defensive validation (400) rather than 404.
  Required:
    - paired state
    - extension origin matching paired origin
    - Authorization: Bearer <pairing nonce>
  Responses:
    - 200 with readonly attachment metadata (nonce- and filename-bound)
    - 400 for invalid filename or non-.bin type
    - 401 for missing/wrong bearer
    - 403 for not paired, disallowed origin, or origin change

/ reset
  Method: POST
  Purpose: clear the paired flag so bearer tokens stop being accepted
  Required:
    - if an Origin header is present it must be an allowed extension origin and must
      match the bound origin (retained across resets); otherwise 403
    - a missing Origin header is allowed (reset only de-escalates access)
  Responses:
    - 200 with unpaired state (pairing_nonce_exposed=false, reset_at)
    - 403 for disallowed origin or origin that does not match the bound origin

Health
------
- GET /health
- Returns bind, origin, state, timestamp
- Does not require pairing

Authentication model
--------------------
- Extension origin must start with `chrome-extension://`.
- Origin matching is case-insensitive prefix match on the scheme root.
- Bearer token must equal the per-install pairing nonce.
- Bearer comparison must use constant-time comparison.
- Origin checks are applied before any Gmail operation.

Security invariants
-------------------
- Only `gmail_auth.GMAIL_READONLY_SCOPE` is acceptable.
- Backend asserts read-only scope before any Gmail call.
- OAuth tokens and token metadata are never returned to the extension.
- Nonce is never leaked in responses, frontend bundles, logs, or exception details,
  and is never persisted to disk.
- No Gmail mutation calls, no send/forward/delete/modify/archive/label/draft operations.
- Attachment access is gated by pairing + origin + bearer; network exposure is
  prevented by binding the server to 127.0.0.1.
- Attachment filenames are validated defensively (reject blank, `..`, leading `/` or
  `\`, and non-`.bin` types before any state or auth work).
- Simulated actions never invoke Gmail write operations.

Mocked test contract
--------------------
- Unit tests use in-memory mocks for credentials/service/Gemini paths where needed.
- Tests do not require real Gmail access, network calls, or live credentials.
- Tests may rely on deterministic nonce and origin checks.

CLI contract
------------
- Package exposes a CLI via `python -m backend.stage_b`.
- `info` command prints backend identity, port, bind/loopback, read-only pairing model,
  and mounted endpoint information. Does not require credentials.
- `serve` command starts the backend on loopback and prints the pairing nonce once to
  the operator's terminal; refuses non-loopback hosts.
- CLI output should not mention public/staging/webhook/noisy deployment concepts.
