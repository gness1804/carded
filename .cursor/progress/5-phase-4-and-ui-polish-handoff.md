---
name: Phase 4 + UI Polish Complete — Handoff to Phase 5/6
description: Captures Phase 4 (FastAPI app + UI) completion, the post-build UI/UX polish (key indicator, change-key flow, upload reset, preview robustness), the Opus security review verdict, and exact pickup points for Phases 5 + 6.
type: handoff
---

# Phase 4 + UI Polish Complete — Handoff for Next Session

**Date:** 2026-05-12
**Branch:** `feat/carded-mvp-scaffold` (2 commits ahead of `origin`; never pushed)
**Latest commits:**
- `0d419b5` — `fix: post-MVP UI/UX polish — key indicator, change-key flow, upload reset, preview robustness`
- `860d189` — `feat: implement Phase 4 FastAPI app, templates, and route tests`

**Open Todoist tasks (both due 2026-05-13, both High priority, both in `carded` project):**
- `6gf2WJ29J766XpRq` — Pick up Carded Phase 5 (Deployment — G)
- `6gf2WJ4hP82h9hwH` — Pick up Carded Phase 6 (Tests + Security Review — Mike + Alex)

**Phases 5 and 6 are independent — they can run in parallel.**

---

## What's done

### Phase 4 — FastAPI app + frontend (commit `860d189`)

- `app.py` (442 lines) — all 7 routes per the interface contract: `GET /`, `POST /session/key`, `POST /process`, `GET /download/vcf`, `GET /download/csv`, `GET /health`. Plus a thread-safe in-memory `TokenStore` with TTL eviction, `is_owner()` helper, `_sanitize_detail()` for the LLM-derived 422 `detail` field.
- `templates/base.html`, `templates/index.html` — Jinja2; default autoescape; no `| safe` anywhere.
- `static/css/style.css`, `static/js/app.js` — mobile-first card UI; all server-derived strings render via `.textContent` (zero `innerHTML`). `safeLink()` enforces `http`/`https`-only on URL fields.
- `tests/test_app.py` (49 tests) + `tests/test_session.py` (12 tests) — FastAPI TestClient, mocks `extract_card_from_bytes` at unit level only.
- Cookie: `HttpOnly + Secure + SameSite=Lax + Max-Age=86400`. `Secure` controllable via `COOKIE_SECURE` env (default `true`).

**Opus security review (Alex):** No CRITICAL or HIGH. One MEDIUM (M1, hardcoded default for `DOWNLOAD_TOKEN_SECRET`) was fixed in the same commit by switching to a per-process random secret via `secrets.token_urlsafe(32)`. L1–L5 deferred to Phase 6 — see "Open security items" below.

### Post-MVP UI/UX polish (commit `0d419b5`)

Four bugs Graham hit while testing locally:

1. **Blank tile after first key save.** Indicator block was server-conditionally rendered → JS refs were null on first visit → `revealKeyIndicator()` silently no-op'd. Fix: always render the indicator block; toggle visibility via `.key-indicator--hidden` class.
2. **Change Key didn't clear server state.** Added `DELETE /session/key` (clears the cookie via `delete_cookie`). JS Change handler calls it, then resets the UI. Tooltip added per Graham's request: *"Change your API key. This will erase the encrypted key stored on the server."*
3. **Silent failure on Extract Card.** Submit handler read `refs.fileInput.files[0]`, but a drag-dropped file is never written to a file input's `FileList` (browser security). The `if (file)` guard fell through silently. Fix: track `selectedFile` in a closure variable (set by both picker `change` and drop handlers); replace silent guard with a visible error.
4. **Mangled preview when uploading a second card after extract.** Two issues: (a) nothing reset the upload form after extract, leaving stale `selectedFile` / blob URL; (b) browsers can't render HEIC inline (Chrome/Firefox/Edge) so the `<img>` showed broken-image icon + alt text. Fix: auto-reset upload form via `clearFile()` after a successful extract; revoke prior blob URLs; new `previewImg.onerror` handler swaps to a fallback view (card icon + filename) so HEIC and corrupted files degrade gracefully. Preview area also got `min-height: 88px` so the absolutely-positioned Remove button always has room.

**Tests:** added 1 (DELETE /session/key). **123/123 unit tests passing in ~5s, no skips, no live BAML calls.**

---

## Non-obvious decisions worth knowing

- **`DOWNLOAD_TOKEN_SECRET` falls back to a per-process random secret if unset** (not a hardcoded string). This is per Alex's M1 fix. Production must set `DOWNLOAD_TOKEN_SECRET` in env so tokens survive process restarts; without it, a server restart invalidates all outstanding download tokens. Mirrors the pattern `session.py` uses for `SESSION_SECRET`.
- **`selectedFile` is the source of truth for what gets uploaded**, not `fileInput.files[0]`. Drag-drop and picker both write to `selectedFile`; the submit handler reads only from it. Keep this invariant if you touch the upload flow.
- **Preview gracefully degrades for HEIC.** The `<img onerror>` handler adds `.preview-area--no-image` which hides the img and shows the filename badge instead. Don't reintroduce a path that assumes the preview always renders — a HEIC card from an iPhone will hit the fallback every time on desktop browsers.
- **After successful extract, the upload form stays visible but resets to a clean state** (no stale file/preview, button disabled). Graham confirmed this UX. The result section appears below; user can scan another card without refreshing.
- **`POST /process` returns the card via `card.model_dump()`** — a raw dict, exactly what `vcard_builder.py` and `google_csv_builder.py` accept. No Pydantic round-trip in the handler.

---

## Open security items (deferred to Phase 6)

These are the L1–L5 from Alex's Phase 4 Opus review. All low-priority but worth addressing in the Phase 6 sweep:

- **L1** — `_sanitize_detail` strips ASCII control chars but not Unicode C1 (U+0080–U+009F) or bidi-overrides (U+202A–U+202E, U+2066–U+2069). Cosmetic-spoofing surface only; no XSS path. Optional: also filter `unicodedata.category(c) == "Cc"` and the bidi codepoints.
- **L2** — `is_owner` boolean round-trips to the client (`/session/key` response) — minor oracle for owner-key membership. No rate limiting on `POST /session/key` or `POST /process`. Add basic rate limiting (or rely on a reverse proxy / Render's built-in).
- **L3** — `TokenStore` has no per-session ownership check. Anyone with a valid signed token can redeem the corresponding card. Bind tokens to an HMAC of the session value and verify on redeem.
- **L4** — No CSP / `X-Content-Type-Options` / `Referrer-Policy` / `Permissions-Policy` headers. Add `SecurityHeadersMiddleware` (suggested CSP: `default-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'`).
- **L5** — `previewImg.src` blob-URL revocation leak. **ALREADY FIXED in commit `0d419b5`** — `currentPreviewUrl` is tracked and `URL.revokeObjectURL()` called before each new selection. Verify the test suite covers this path.

Other Phase 6 items per the plan: prompt-injection re-assessment, libheif CVE check, polyglot file handling, Pillow `MAX_IMAGE_PIXELS` decompression-bomb guard (`main.py:_convert_heic_to_jpeg`), `pip-audit` dependency scan, logging hygiene (no API keys, no card content in logs), full integration tests against fixture cards (gated by `RUN_INTEGRATION_TESTS=1`), manual mobile E2E.

---

## How to run / test locally

```bash
cd ~/Desktop/carded && SESSION_SECRET=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") DOWNLOAD_TOKEN_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))") COOKIE_SECURE=false python -m uvicorn app:app --reload --port 8000
```

Open http://127.0.0.1:8000, paste a real `sk-ant-...` key, upload a card. Hard-refresh (Cmd-Shift-R) after CSS/JS edits — uvicorn reloads Python automatically. Tests: `pytest -q` (123 should pass).

---

## Sub-agent stalls this session

Two stalls, same Sonnet pattern documented in handoff #4:

- **First Prudvi (Sonnet)** for Phase 4 backend: API internal-server-error mid-run. Files were sound on disk; only the report didn't return.
- **Second Prudvi (Sonnet)** for Phase 4 backend: completed successfully, wrote 1133 lines and tests, but truncated mid-thought after the work was on disk. 56/61 of the new tests passed on first run; 5 failures were small bugs (TTL boundary `>` vs `>=`, TestClient cookie persistence) that the main agent (Opus) fixed in <5 minutes.

Pattern across all six Carded stalls so far is the same: real work lands on disk, the closing report clips. All Sonnet-backed. The `~/CLAUDE.md` mitigations (cap reports at ~200 words, verify files-on-disk before reporting) continue to hold up.

---

## Where to pick up next session

**Phase 5 — Deployment (G):**
- Pick up Todoist task `6gf2WJ29J766XpRq`.
- Read `.cursor/progress/2-carded-mvp-plan-final.md` § "Phase 5 — Deployment" (lines ~558–575).
- Deliverables: Dockerfile (`python:3.11-slim`, uvicorn), HEALTHCHECK against `/health`, `render.yaml` or dashboard config, local docker smoke test, Render Web Service ($7/mo Starter), Cloudflare DNS for `carded.io`, all env vars in dashboard, live smoke test.
- Sub-agent: `g-infrastructure-docs` (Sonnet).
- Budget: ~3–5% weekly all-models.

**Phase 6 — Tests + Security Review (Mike + Alex):**
- Pick up Todoist task `6gf2WJ4hP82h9hwH`.
- Read `.cursor/progress/2-carded-mvp-plan-final.md` § "Phase 6 — Tests + Security Review" (lines ~576–600).
- Mike (QA, Sonnet): coverage review, integration tests behind `RUN_INTEGRATION_TESTS=1`, manual mobile E2E.
- Alex (security, **Opus** per global rule): full surface review + L1–L4 above, `pip-audit`, libheif CVEs, logging hygiene, rate limiting.
- Budget: ~7–10% weekly all-models.

Both phases are independent — can run in parallel sessions.

---

## Key documents to load on resume

1. `.cursor/progress/2-carded-mvp-plan-final.md` — full signed-off plan
2. `.cursor/docs/1-interface-contract.md` — Phase 4 contract (still authoritative; do not change without Graham approval)
3. `.cursor/progress/5-phase-4-and-ui-polish-handoff.md` — this file
4. `app.py`, `templates/`, `static/` — Phase 4 surface; Phase 5 packages it; Phase 6 reviews it
5. `~/CLAUDE.md` § Sub-Agents and Routing — three new bullets from the previous session still apply

---

*End of handoff. Resume Phases 5 and 6 from the Todoist tasks listed above. Project is in a good state — Graham confirmed the local app works end-to-end after the polish session.*
