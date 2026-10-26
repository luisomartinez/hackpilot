---
name: run-hackpilot
description: Build, run, and drive HackPilot Enterprise's web dashboard (advance_hackpilot.py --web) via Docker Compose. Use when asked to start HackPilot, bring up its Docker stack, launch a pentest from the dashboard, take a screenshot of its UI, or interact with the running app.
---

HackPilot Enterprise is a Flask dashboard (`advance_hackpilot.py --web`,
served on `:8080`) fronting a 6-phase pentest engine, run via Docker
Compose alongside Postgres/Redis/Celery. There is no dev server outside
Docker - the app is driven by building the `hackpilot-web` image,
starting the compose stack, and navigating a headless Chromium against
`http://localhost:8080`. Drive it with
`.claude/skills/run-hackpilot/driver.mjs` (a small Playwright REPL - the
`chromium-cli` skill this template normally points at isn't available in
this environment).

All paths below are relative to the repo root (`hackpilot/`).

## Prerequisites

Verified on **Windows with Docker Desktop** (not the Linux container this
template assumes - there's no `apt-get` step here, Docker Desktop is the
real requirement). Node.js is needed for the driver only:

```bash
node --version   # v18+ - this session used v26.7.0, already present
docker --version
docker-compose --version
```

## Setup

`.env` does not exist until you create it - `docker-compose.yml` reads
required vars from it via `${VAR:?...}` and refuses to start without
them:

```bash
cp .env.example .env
```

Fill in at minimum: `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `SECRET_KEY`,
and one AI provider key (e.g. `ANTHROPIC_API_KEY` + `HACKPILOT_PROVIDER=anthropic`
+ `HACKPILOT_MODEL=<model id>`). Everything else has safe defaults.

**To actually reach the dashboard from outside the container**, also set
dashboard Basic Auth - without it the process binds to `127.0.0.1`
*inside* the container only, and the published `8080:8080` port forwards
to nothing (see Gotchas):

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_PASSWORD', bcrypt.gensalt()).decode())"
```

Put the result in `.env` as `CONSOLE_AUTH_USER=admin` /
`CONSOLE_AUTH_PASS_HASH=<hash, with every literal $ doubled to $$>` - see
Gotchas for why the doubling matters.

Driver dependencies (installed once, local to the skill dir - does not
touch the project's own Python/pip world):

```bash
cd .claude/skills/run-hackpilot
npm install                      # playwright, from this dir's package.json
npx playwright install chromium  # downloads the browser binary (~120MB)
```

## Build

```bash
docker-compose build hackpilot-web
```

Takes **10-20 minutes**, even for a code-only change with no dependency
bumps - budget for it, don't assume a quick rebuild. Most of that is
`install.sh` running inside the image (apt packages including
metasploit-framework, plus a `git clone` of the full nuclei-templates
repo - see Gotchas).

## Run (agent path)

First time on a clean machine, bring up the whole stack (Postgres/Redis
need to be healthy before `hackpilot-web` will start):

```bash
docker-compose up -d
```

After a code-only rebuild, it's enough to recreate just the one
container:

```bash
docker-compose build hackpilot-web && docker-compose up -d hackpilot-web
```

Wait for it to actually serve before driving it (`health: starting` for
the first ~15-20s is normal - the app does heavy startup init):

```bash
timeout 40 bash -c 'until curl -sf -u "$CONSOLE_AUTH_USER:$CONSOLE_AUTH_PASS" http://localhost:8080/healthz >/dev/null; do sleep 2; done'
```

Then drive it with the Playwright REPL driver - pipe a script to stdin,
same shape as the `chromium-cli` convention this template normally uses:

```bash
cd .claude/skills/run-hackpilot
BASIC_AUTH_USER=admin BASIC_AUTH_PASS='<password>' node driver.mjs <<'EOF'
nav http://localhost:8080/
wait-for text=Dashboard Overview
screenshot home
console
quit
EOF
```

Screenshots land in `.claude/skills/run-hackpilot/screenshots/`.

| command | what it does |
|---|---|
| `nav <url>` | Navigate. Auth comes from `BASIC_AUTH_USER`/`BASIC_AUTH_PASS` env vars (context-level), never put credentials in the URL - see Gotchas. |
| `wait-for text=<substring>` | Wait for visible text. |
| `wait-for sel=<css>` / `wait-for <css>` | Wait for a selector. |
| `click <css>` | Click the first match. |
| `fill <css> <text...>` | Fill an input. |
| `press <key>` | Keyboard key (e.g. `Enter`). |
| `screenshot [name]` | Full-page PNG → `screenshots/<name>.png`. |
| `screenshot-visible [name]` | Viewport-only PNG - use for a centered modal on a page that scrolls for miles (see Gotchas). |
| `eval <js>` | Evaluate in page context; useful as a crude `sleep` via `eval new Promise(r => setTimeout(r, 500))` (see Gotchas). |
| `console` | Print captured console/page errors since launch. |
| `quit` | Close the browser and exit. |

## Run (human path)

Open `http://localhost:8080` in a real browser, Basic Auth prompt asks
for `CONSOLE_AUTH_USER`/the plaintext password. `docker-compose logs -f
hackpilot-web` to watch it; `docker-compose stop hackpilot-web` to stop.

## Test

```bash
python -m pytest tests/ -q
```

245 pass, 3 skip, 4 fail - the 4 failures are environment-specific on
this Windows host (no `openai` package installed; no WSL/bash for two
`install.sh` contract tests) and unrelated to the dashboard.

---

## Gotchas

- **Dashboard unreachable from the host even though the container is
  "healthy."** Without `CONSOLE_AUTH_USER` set, `security/dashboard_auth.py`
  binds the Flask process to `127.0.0.1` *inside* the container as a
  safe-by-default fallback. Docker's healthcheck passes (it curls from
  inside the container, where `127.0.0.1` is real), but the published
  `8080:8080` port forwards to the container's external interface, which
  nothing is listening on - `curl`/browser from the host gets connection
  refused. Fix: set `CONSOLE_AUTH_USER`/`CONSOLE_AUTH_PASS_HASH` and
  recreate the container.
- **`docker-compose up` silently drops env vars.** Setting a var in
  `.env` does nothing unless `docker-compose.yml`'s service also lists
  it under `environment:` as `- VAR=${VAR:-default}`. Confirmed missing
  for `ENABLE_AUTO_EXPLOIT`/`ENABLE_ADVANCED_EXPLOITATION`/
  `ALLOWED_TARGETS`/`USE_AI`/`LOCAL_LLM_*` until fixed - `printenv VAR`
  inside the container is the way to actually verify a var landed, don't
  trust `.env` alone.
- **Literal `$` in `.env` values gets misinterpreted by Compose.** A
  bcrypt hash (`$2b$12$...`) in `CONSOLE_AUTH_PASS_HASH` makes Compose
  try to substitute `$2b`/`$12`/etc. as variable references, silently
  defaulting them to empty (`docker-compose up` prints a `variable is
  not set` warning per `$...` chunk). Fix: double every literal `$` to
  `$$` in `.env`.
- **Docker's port-publish NAT rewrites the source IP.** A request from
  the host to `localhost:8080` arrives at the Flask app with
  `remote_addr` set to the bridge network's gateway (confirmed
  `172.20.0.1` on this project's `172.20.0.0/16` subnet - get yours with
  `docker network inspect <project>_hackpilot-network --format
  '{{(index .IPAM.Config 0).Subnet}}'`), not `127.0.0.1`. If
  `CONSOLE_ALLOWED_IPS` only has `127.0.0.1`, every host-published
  request gets 403'd even with correct credentials.
- **A long-lived Postgres volume won't have new columns.** This app
  creates its schema via SQLAlchemy `create_all()`, which only adds
  missing tables, never missing columns on an existing one. A Postgres
  volume older than a migration needs it applied by hand once:
  `docker exec hackpilot-web python3 -m alembic stamp <baseline-revision>
  && docker exec hackpilot-web python3 -m alembic upgrade head`. Symptom
  if you skip this: `psycopg2.errors.UndefinedColumn` on the first write
  that touches the new column, mid-pentest.
- **`nav`ing to `http://user:pass@host/` aborts.** Chromium refuses
  credential-in-URL navigation for Basic Auth (`net::ERR_ABORTED`). Use
  `context.httpCredentials` instead (this driver reads
  `BASIC_AUTH_USER`/`BASIC_AUTH_PASS` env vars for exactly this reason).
- **Piping a whole heredoc to the driver can abort the first command.**
  Node's `readline` fires `line` events without waiting for an async
  handler to finish; with a multi-line heredoc, the `close` (EOF) event
  can fire - and close the browser - while the first `nav` is still
  in-flight, producing `net::ERR_ABORTED` / "Target page, context or
  browser has been closed." The driver queues commands and runs them
  strictly one at a time; if you fork this driver, keep that queue.
- **Full-page screenshot of the Findings view is ~9600px tall** (100+
  consolidated findings from one real scan) and unreadable as a single
  image. Use `screenshot-visible` for anything centered in the viewport
  (like the inspect modal) instead of `screenshot`.
- **A screenshot taken immediately after `wait-for` can catch the
  modal's 150ms fade-in mid-transition**, rendering as a translucent
  ghost over the table behind it - looks like a real transparency bug
  but isn't one (computed `background-color` and `opacity` are correct;
  it's a timing artifact). Add a short pause - `eval new Promise(r =>
  setTimeout(r, 500))` - after opening a just-animated modal/panel and
  before screenshotting it.
- **Rebuilding `hackpilot-web` is slow even for a one-line Python
  change** (observed 10-20 min across several rebuilds in this session)
  - the Dockerfile's `COPY` of source happens before some slow layers
  finish, so changing any tracked file invalidates more of the cache
  than you'd expect. Don't `docker cp` a file into the running
  container as a substitute for committing + rebuilding - it's fine for
  a 30-second visual check, but the change won't survive the next
  `docker-compose up -d` recreate.
