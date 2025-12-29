# Cloud Deployment Notes (Render / similar)

ChatMock’s built-in `login` command uses an OAuth callback on `localhost` (by design).
That works on your own computer, but it **does not work inside a typical cloud container**.

For cloud deployments, the recommended flow is:
1) Run `login` locally once to generate `auth.json`
2) Upload `auth.json` to the cloud instance via the web admin panel (`/admin/auth`)
3) Use the admin panel (`/admin`) to configure server settings (persisted to `server_settings.json`)

## Render (Docker) – recommended setup

### 1) Repository layout
- Render must see a `Dockerfile` at the **repo root**.
- If you pushed a parent folder that contains `ChatMock/` as a subfolder, either:
  - set Render’s “Root Directory” to `ChatMock`, **or**
  - move/copy `Dockerfile` to the repo root.

### 2) Create a Web Service
- Environment: Docker
- Render provides `PORT` automatically; ChatMock’s Docker entrypoint will bind to it.

### 3) Add a persistent disk (important)
Mount a persistent disk to:
- `/data`

This keeps:
- `/data/auth.json` (your login tokens)
- `/data/server_settings.json` (admin-panel settings)

### 4) Set environment variables
Minimum:
- `CHATMOCK_ADMIN_PASSWORD` = a strong password (enables `/admin`)
- `CHATMOCK_SECRET_KEY` = a long random string (keeps sessions stable across restarts)

Recommended:
- `CHATGPT_LOCAL_HOME` = `/data` (explicit)

Optional (same as local flags):
- `CHATGPT_LOCAL_REASONING_EFFORT` = `minimal|low|medium|high|xhigh`
- `CHATGPT_LOCAL_REASONING_SUMMARY` = `auto|concise|detailed|none`
- `CHATGPT_LOCAL_REASONING_COMPAT` = `legacy|o3|think-tags|current`
- `CHATGPT_LOCAL_EXPOSE_REASONING_MODELS` = `true|false`
- `CHATGPT_LOCAL_ENABLE_WEB_SEARCH` = `true|false`

### 5) First-time auth (cloud)
1) Open `https://<your-render-domain>/admin`
2) Go to `https://<your-render-domain>/admin/auth`
3) Upload your locally-generated `auth.json`

Local `auth.json` location (default):
- Windows: `%USERPROFILE%\\.chatgpt-local\\auth.json`
- macOS/Linux: `~/.chatgpt-local/auth.json`

### 6) Use from Cherry Studio / Chatbox
Use OpenAI Compatible mode:
- Base URL: `https://<your-render-domain>/v1`
- API key: any non-empty string (ignored by ChatMock)

## Troubleshooting

- **Render shows “Dockerfile not found”**
  - Repo root is wrong; see “Repository layout” above.

- **502 / service unavailable**
  - Container is not listening on the expected `PORT` (or crashed). Check Render logs.

- **`login` doesn’t work in cloud**
  - Expected. Upload `auth.json` via `/admin/auth` instead.

- **Want CLI flags to win over saved settings**
  - Set `CHATMOCK_DISABLE_SETTINGS=true` (ignores `/data/server_settings.json`).

- **Disable the admin panel after setup**
  - Set `CHATMOCK_DISABLE_ADMIN=true` (keeps the server running, removes `/admin`).
