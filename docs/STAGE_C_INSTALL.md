# Stage C — install and startup

The pilot is two parts: a **local read-only backend** (Python/FastAPI) and an
**unpacked Chrome extension** (Manifest V3) that pairs with it. All proposed
actions are simulation-only; the backend cannot send, modify, or delete anything
in Gmail.

## Prerequisites

- Python 3.10+ with the repo's dependencies installed
  (`pip install -r requirements.txt` or `pip install -e .[dev]`).
- Google OAuth `credentials.json` in the repo root and a completed one-time
  authorization that produces `token.json` (scope: `gmail.readonly` only).
- Google Chrome 114+.
- The `NEMESIS_DEMO` label must exist in the Gmail account, with the demo
  messages labeled.

## Step 1 — Start the read-only backend

From the repository root:

```
python -m backend.stage_b serve
```

This binds the server to `127.0.0.1:8123` only (it refuses any other host) and
prints a **pairing nonce** once to your terminal:

```
stage_b read-only backend on http://127.0.0.1:8123
Pairing nonce (operator only — paste into the extension pairing screen):
<64-hex-char nonce>
```

Keep this terminal open. The nonce is shown only here — it is never served over
HTTP and never written to disk. Copy it; you will paste it into the extension.

To pin a single extension ID (recommended), set it before starting:

```
# Windows PowerShell
$env:STAGE_B_EXTENSION_ID="<your-extension-id>"
python -m backend.stage_b serve

# macOS/Linux
STAGE_B_EXTENSION_ID="<your-extension-id>" python -m backend.stage_b serve
```

When pinned, the backend only accepts requests whose origin is exactly
`chrome-extension://<your-extension-id>`. You can leave it unset for development
(any `chrome-extension://` origin is accepted).

To find your extension ID, load the extension first (Step 2) then read it from
`chrome://extensions`.

## Step 2 — Load the unpacked extension

1. Open `chrome://extensions` in Chrome.
2. Enable **Developer mode** (toggle, top-right).
3. Click **Load unpacked** and select the `extension/` folder of this repo
   (the folder that contains `manifest.json`).
4. Note the **ID** shown on the card. If you pin `STAGE_B_EXTENSION_ID`, use this
   value and restart the backend (Step 1).

## Step 3 — Open the sidebar in Gmail

1. Go to `https://mail.google.com` and open any email (or the inbox).
2. Click the extension's toolbar icon (puzzle piece → pin the
   "RealGmail Reading Pilot" icon). Clicking it opens the side panel.
   - The side panel may also appear automatically on Gmail tabs.
3. In the sidebar, under **"1. Pair with local backend"**, paste the nonce from
   your backend terminal and click **Pair**.
   - Status should turn green: "Paired. Feed prefix: stage_b_…".
   - The nonce is stored only in the extension's `chrome.storage.local` and is
     never displayed again.

## Step 4 — Use the read-only features

- **"Read open email (read-only)"** — reads the subject/sender/body of the email
  currently open in Gmail, straight from the page DOM. Nothing is sent to Gmail.
- **"Fetch demo emails (/feed)"** — asks the backend to list only the
  `NEMESIS_DEMO`-labeled emails via the read-only Gmail API. The real inbox is
  never returned.
- **"Analyze (/analyze)"** — sends the demo-feed email bodies to the provider
  selected above the button:
  - **Local Ollama (llama3.1:8b, default)** — the backend calls Ollama on
    `http://127.0.0.1:11434`; email content never leaves this machine, and
    local mode never calls Gemini or any external AI. If the local model is
    unavailable, the result is clearly labeled `fallback` and shows the
    deterministic ruleset verdicts only.
  - **Gemini (external API)** — the pre-existing integration, chosen only by
    explicit selection.
- **"Attachment info (/attachments)"** — returns read-only metadata for a `.bin`
  attachment name (id, sha256, size). No file content is ever served.
- **"Proposed actions (simulation only)"** — inert previews of what an operator
  *could* do. Nothing here is executed or sent anywhere.

## Step 5 — Unpair / stop

- Click **"Unpair (/reset)"** in the sidebar to clear pairing on the backend.
- Stop the backend with `Ctrl+C` in its terminal.

## Security notes

- The backend binds to `127.0.0.1` only; it is never exposed on the network.
- Gmail access is read-only (`gmail.readonly`); the backend refuses to run if the
  OAuth token requests any other scope.
- The pairing nonce is operator-only (terminal), constant-time compared, never
  logged, never returned in any response, and never written to disk.
- The extension requests no Gmail API permissions; it only reads the open tab's
  DOM and talks to the loopback backend.

## What is NOT verified

- The sidebar's rendering inside a live Gmail tab was not exercised in an
  automated browser here; loading/error/selected-email-change handling is
  implemented and unit-tested at the static level, but confirm visually.
- `/analyze` in **Gemini mode** depends on live Gemini availability. A
  transient upstream 503 is returned as an error when Gemini is under load;
  retry later — or switch the provider selector to local Ollama.
- The backend→Ollama leg for **local mode** is exercised by an automated
  integration test that runs against a real local `llama3.1:8b` when Ollama
  is running (`pytest tests/test_local_analysis.py -q`); the sidebar's
  in-browser rendering is still confirmed visually, as above.
