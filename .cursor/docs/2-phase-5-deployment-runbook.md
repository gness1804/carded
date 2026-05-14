---
name: phase-5-deployment-runbook
description: Step-by-step runbook for deploying Carded to Render with a Cloudflare DNS cutover to carded.io. Manual steps that require Graham's Render and Cloudflare accounts.
type: runbook
---

# Phase 5 — Render + Cloudflare Deployment Runbook

**Status (2026-05-13):** Live on `*.onrender.com`. Custom domain (`carded.io`) cutover **deferred** — tracked in `.cursor/features/1-custom-domain-carded-io-cutover.md`. Steps 1, 2, and 4 below were completed; Step 3 (Cloudflare DNS) is the deferred work and remains documented here as the operator reference for when Graham picks it up.

The Dockerfile, `.dockerignore`, and `render.yaml` have been built and locally smoke-tested. This runbook covers the operator steps that require Graham's account access.

## Artifacts already on disk

- `Dockerfile` — `python:3.11-slim`, non-root `appuser`, stdlib `urllib` healthcheck against `/health`, uvicorn on `0.0.0.0:8000`. Final image ~440 MB. `pillow-heif` manylinux wheel bundles libheif — no apt packages needed.
- `.dockerignore` — excludes `.git/`, `.cursor/`, `tests/`, `test-cards/`, `data/`, `.env*`, build artifacts.
- `render.yaml` — Render Blueprint: `web` service, `docker` env, `starter` plan, `healthCheckPath: /health`. Three secrets marked `sync: false` (operator sets them in the dashboard). Four non-secret defaults inline.
- `requirements.txt` now pins `starlette>=0.40,<1.0` — Starlette 1.0 removed the deprecated `TemplateResponse(name, context)` API used by `app.py`. See "Phase 6 follow-up" below.

## Local smoke test (verified)

```bash
docker build -t carded:phase5 .
SESSION_SECRET=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
DOWNLOAD_TOKEN_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
docker run -d --rm --name carded-smoke -p 8000:8000 \
  -e SESSION_SECRET="$SESSION_SECRET" \
  -e DOWNLOAD_TOKEN_SECRET="$DOWNLOAD_TOKEN_SECRET" \
  -e COOKIE_SECURE=false \
  carded:phase5
sleep 5
curl -fsS http://localhost:8000/health    # → {"status":"ok"}
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/    # → 200
docker inspect --format='{{.State.Health.Status}}' carded-smoke    # → healthy
docker stop carded-smoke
```

All checks: green.

## Step 1 — Create the Render Web Service

**Option A: Blueprint (recommended).** From the Render dashboard:

1. **New → Blueprint** → connect this repo (`feat/carded-mvp-scaffold` for the initial deploy; switch to `main` after merge).
2. Render reads `render.yaml`, prompts you for the three secrets:
   - `SESSION_SECRET` — generate fresh: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
   - `DOWNLOAD_TOKEN_SECRET` — generate fresh: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`
   - `OWNER_ANTHROPIC_API_KEY` — your real `sk-ant-...` key
3. The four non-secret defaults (`COOKIE_SECURE=true`, `MAX_FILE_SIZE_MB=10`, `EXTRACTION_TIMEOUT_SECONDS=60`, `DOWNLOAD_TOKEN_TTL_SECONDS=900`) are baked into `render.yaml` — no action needed.
4. Click **Apply**.

**Option B: Dashboard config (if you'd rather not use a Blueprint).** New → Web Service → connect repo → Environment: `Docker` → Plan: `Starter ($7/mo)` → Health Check Path: `/health` → set all seven env vars from the list above by hand.

## Step 2 — Verify the deploy

Render will give you a `*.onrender.com` URL. Before touching DNS, smoke-test there:

```bash
URL="https://<your-service>.onrender.com"
curl -fsS "$URL/health"                           # → {"status":"ok"}
curl -s -o /dev/null -w "%{http_code}\n" "$URL/"  # → 200
```

Then in a browser at `$URL`:
1. Paste a real `sk-ant-...` key. Confirm the "key set ✓" indicator appears.
2. Upload a real card image (JPG or HEIC). Confirm extracted fields render.
3. Download the `.vcf`. Confirm it imports into Contacts.
4. Download the Google CSV. Confirm fields look right.

If anything fails, check **Logs** in the Render dashboard. The image runs as `appuser` (non-root) — no `sudo` available; if you need to shell in, use Render's built-in shell.

## Step 3 — Cloudflare DNS cutover (DEFERRED)

> **Deferred 2026-05-13.** Carded is live on `*.onrender.com`. The DNS cutover is tracked as a separate feature in `.cursor/features/1-custom-domain-carded-io-cutover.md`. Steps below remain authoritative for when Graham picks this up.

Assuming you've already registered `carded.io` and it's on Cloudflare:

1. In Render → your service → **Settings → Custom Domains** → **Add Custom Domain** → enter `carded.io` (and `www.carded.io` if you want both). Render shows you a target — either a CNAME target like `<service>.onrender.com` or a set of A records.
2. In Cloudflare DNS for `carded.io`:
   - Apex (`@`): **CNAME flattening** (Cloudflare supports apex CNAMEs via flattening) → target: `<service>.onrender.com`. Proxy status: **DNS only** (gray cloud) for the initial cert issuance.
   - `www`: CNAME → `<service>.onrender.com`. Proxy: DNS only.
3. Wait for Render to show the domain as **Verified** and the cert as **Issued** (usually 1–5 min).
4. Once green, you can flip Cloudflare's proxy back to **Proxied** (orange cloud) if you want CF in front of it — but note Render already does TLS termination, so the orange-cloud flip is purely a CDN/WAF preference, not a requirement.

If `carded.io` isn't owned yet, fallback domains in priority order: `carded.app`, `getcarded.io`, or a `*.onrender.com` for launch and revisit later.

## Step 4 — Live smoke test on the real domain

Once DNS resolves:

```bash
URL="https://carded.io"
curl -fsS "$URL/health"                           # → {"status":"ok"}
curl -sI "$URL/" | head -20                       # check headers, TLS
```

Repeat the browser test from Step 2 against `https://carded.io`. Also test from an iPhone Safari (HEIC upload from the camera roll) and an Android Chrome (JPG).

## Env-var checklist (Render dashboard final state)

| Var | Source | Notes |
|---|---|---|
| `SESSION_SECRET` | `cryptography.fernet.Fernet.generate_key()` | Secret. 32-byte url-safe base64. |
| `DOWNLOAD_TOKEN_SECRET` | `secrets.token_urlsafe(32)` | Secret. Do NOT reuse `SESSION_SECRET`. |
| `OWNER_ANTHROPIC_API_KEY` | Your real Anthropic key | Secret. Used only by `is_owner()`. |
| `COOKIE_SECURE` | `"true"` | Inline in `render.yaml`. Render serves HTTPS-only, so `true` is correct. |
| `MAX_FILE_SIZE_MB` | `"10"` | Inline. |
| `EXTRACTION_TIMEOUT_SECONDS` | `"60"` | Inline. |
| `DOWNLOAD_TOKEN_TTL_SECONDS` | `"900"` | Inline. |

## Cost expectations

- Render Starter: **$7/mo** for the web service. No sleep — always-on. Sufficient for the MVP.
- Cloudflare DNS: **$0** (DNS is free on any plan; the domain registration itself is the cost).
- `carded.io` domain: typical `.io` is ~$30–60/yr.
- Anthropic API: pay-per-request via the user's BYOK; the owner key is only invoked when *you* use the app.

## Phase 6 follow-up (flagged for the next phase, not blocking deploy)

- **Starlette pin.** `requirements.txt` now pins `starlette<1.0` because `app.py:205` and any other `templates.TemplateResponse(name, context)` calls use the deprecated form. To lift the pin, migrate to `TemplateResponse(request=request, name="index.html", context={...})` (or pass `request` as the first positional arg in newer Starlette). Mike (QA) can take this as a small refactor; all template-rendering tests will catch regressions.

## Rollback

If the live deploy misbehaves:

- **Quick:** in Render dashboard → **Manual Deploy** → pick a previous successful deploy → **Deploy**.
- **DNS:** switch the Cloudflare CNAME back to a maintenance page or remove the record entirely. TTL is 5 min by default on Cloudflare.

## What's NOT in this runbook

- CI/CD beyond Render's built-in auto-deploy from Git. If you want PR-preview environments or staging, that's a follow-on.
- Observability / Sentry / metrics. Render gives you basic logs + per-deploy metrics; anything richer is out of scope for MVP.
- Backups — there's no persistent state in this app (BYOK lives in user cookies; download tokens are in-process). Nothing to back up.
