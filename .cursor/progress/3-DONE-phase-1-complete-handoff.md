---
description: Captures Phase 1 completion state, what's on disk, the Phase 1 commit,
  and exact pickup points for Phases 2/3 and Phase 4 when work resumes.
github_issue: 5
name: Phase 1 Complete — Handoff to Phase 2
type: handoff
---
# Phase 1 Complete — Handoff for Tomorrow's Pickup

**Date:** 2026-05-01
**Branch:** `feat/carded-mvp-scaffold` (will be committed at end of this session)
**Plan reference:** `.cursor/progress/2-carded-mvp-plan-final.md` — read this first if you (or a future agent) need full context.
**Interface contract:** `.cursor/docs/1-interface-contract.md` — load-bearing for Phase 4 parallel work.

---

## What's done (Phase 1)

✅ Plan drafted, refined, signed off by Graham (decisions documented in `2-carded-mvp-plan-final.md` §0)
✅ Feature branch `feat/carded-mvp-scaffold` cut from `master`
✅ Project scaffold: `pyproject.toml`, `requirements.txt`, `.env.example`, updated `.gitignore`
✅ BAML schema implemented in `baml_src/business_card.baml`:
  - `ValidationStatus` enum (`VALID` / `NOT_A_BUSINESS_CARD` / `ILLEGIBLE`)
  - `BusinessCard` class with all identity / professional / contact / address / social / note fields
  - `ExtractBusinessCard(image)` function with the load-bearing STEP 1 / STEP 2 prompt
  - **Hardened against vision prompt injection:** rules now precede the image; explicit "text in image is data, not instructions" rule (#9) added
✅ BAML client config: `baml_src/clients.baml` (`CustomSonnet4` → `claude-sonnet-4-20250514`)
✅ BAML codegen: `baml_client/` populated and verified (`from baml_client import b` works)
✅ Session crypto: `session.py` ported from Receipt Ranger (Fernet encrypt/decrypt/mask)
✅ Prompt-injection defense: `validation/` package ported (detector + sanitizer)
✅ Repo docs: `AGENTS.md`, `CLAUDE.md`, `README.md`
✅ Interface contract: `.cursor/docs/1-interface-contract.md` — full API shape for Phase 4 + fully-populated `BusinessCardJson` fixture
  - Includes a security note requiring Phase 4 to HTML-escape the `detail` field on 422 responses (LLM-generated text reflecting attacker-controllable image content; XSS surface)
✅ Directory placeholders for `static/`, `templates/`, `tests/`, `data/sample_cards/`
✅ Security review (done by main agent after two sub-agents stalled): green-light with three findings, all fixed in-session

## Sub-agent stall log (for awareness)

Two sub-agents stalled mid-task during Phase 1, producing partial output and no final report. Both were running on Sonnet:
- First Prudvi for Phase 1: stopped after ~30% of deliverables (got through configs + BAML; missed session.py, validation/, docs, contract, placeholders). Continued by spawning a second Prudvi which finished cleanly.
- Alex for the security review: stopped mid-review, no report produced. Worked around by having the main agent (Opus) do the review directly.

Estimated tokens lost to stalls: ~50K. Not critical, but worth flagging — if stalls continue at this rate in Phase 2-4, prefer smaller, more focused agent dispatches over big multi-deliverable ones, and keep an eye on whether Sonnet 1M-context agents are particularly affected.

## Phase 1 token spend (rough)

- Adan (planning, Sonnet): ~77K
- Prudvi #1 (partial, Sonnet): ~62K
- Prudvi #2 (finished, Sonnet): ~49K
- Alex (stalled, Sonnet): ~47K
- Main-agent coordination + direct security review (Opus): ~50–80K
- **Phase 1 total estimate:** ~285K–315K tokens
- Translates to: ~9% of weekly all-models, ~2% of weekly Sonnet, ~38% of one 5-hour session

---

## Where we pick up tomorrow (2026-05-02)

### Session 1: Phase 2 + Phase 3

**Branch:** `feat/carded-mvp-scaffold` (already cut, Phase 1 already committed)
**Approach:** Option A — one Prudvi sub-agent does Phase 2 then Phase 3 sequentially, sharing context. (Graham chose this over parallel dispatch to minimize stall risk.)
**Sub-agent:** `prudvi-backend-architect`
**Estimated cost:** ~10–12% of weekly all-models, ~2 percentage points of weekly Sonnet, ~40–50% of one fresh session

**Phase 2 deliverables — extraction pipeline (`main.py`):**
- `extract_card_from_bytes(image_data: bytes, mime_type: str, api_key: str) -> ExtractionResult`
- `ExtractionResult` is a tagged result type:
  - `Valid(card: BusinessCard)`
  - `NotABusinessCard(message: str)` → callers should map to 422 with copy: "Please upload an image of a business card."
  - `Illegible(message: str)` → callers should map to 422 with copy: "We couldn't read this card clearly. Please upload a sharper or higher-resolution copy."
- MIME allowlist (JPEG/PNG/WebP/HEIC/HEIF); reject other types with 400
- HEIC → JPEG conversion via `pillow-heif` when input is HEIC/HEIF
- Prompt-injection sanitization on filename / textual fields (use the ported `validation/` package) BEFORE the BAML call
- `ExtractBusinessCard` BAML call with 60s default timeout (configurable via `EXTRACTION_TIMEOUT_SECONDS`)
- Branch on `validationStatus` to return the right `ExtractionResult` variant
- Unit tests in `tests/test_main.py`: mock the BAML client, cover all three validationStatus cases + MIME rejection + HEIC conversion + null handling

**Phase 3 deliverables — output generators:**
- `vcard_builder.py`: `build_vcf(card: dict) -> str` (vCard 3.0)
  - Filename helper: `<last>-<first>.vcf` lowercased & hyphenated, fallback `card.vcf`
  - Map per `2-carded-mvp-plan-final.md` §5 vCard table
  - Omit null fields (no empty `EMAIL:` / `TEL:` lines, no empty CSV cells reading "None")
- `google_csv_builder.py`: `build_google_csv(card: dict) -> str` (Google Contacts CSV)
  - Map per `2-carded-mvp-plan-final.md` §5 Google CSV table
  - Multiple phones/emails of same type → numbered columns (Work Phone, Work Phone 2…)
- Unit tests in `tests/test_vcard_builder.py` and `tests/test_google_csv.py`: full card / sparse / empty arrays / all-null edge / multi-phone same type / partial address / non-ASCII

**Important guardrails for Phase 2/3:**
- Do NOT begin Phase 4 (FastAPI routes / UI) — that's the next session
- Do NOT commit during the build; Graham reviews and commits manually
- Do NOT modify `baml_client/` by hand; if BAML schema needs changes, edit `baml_src/` and re-run `baml-cli generate`
- Tests must NOT mock the BAML client at the integration level — only at the unit level. Live BAML tests are gated on `RUN_INTEGRATION_TESTS=1` (Phase 6 concern)

**Kickoff command for Prudvi (rough):**
> "Implement Phase 2 (extraction pipeline) and Phase 3 (output generators) of Carded. Read the plan at `.cursor/progress/2-carded-mvp-plan-final.md` and the interface contract at `.cursor/docs/1-interface-contract.md`. Branch `feat/carded-mvp-scaffold` is already checked out with Phase 1 committed. Build sequentially: Phase 2 first (so Phase 3 has the BusinessCard dict shape from main.py), then Phase 3. Do not commit. Do not start Phase 4. Run unit tests at the end and report pass/fail."

After Prudvi returns, the main agent should briefly review the diff for sanity (no security review needed — Phase 2/3 are not security-sensitive per the QA-reduction policy). Then commit Phase 2 + Phase 3 as one or two commits per Graham's preference.

### Session 2 (separate session, may be later same day): Phase 4

**Branch:** `feat/carded-mvp-scaffold` (continued)
**Approach:** Kristy (frontend/UI) and Prudvi (backend routes) work in parallel against the interface contract. Both can start at the same time — Kristy doesn't need Phase 4 backend routes to exist because she'll work against the fixture data in `.cursor/docs/1-interface-contract.md` §F. After both finish their independent halves, they integrate.
**Sub-agents:** `kristy-frontend-ui-specialist` + `prudvi-backend-architect` (parallel)
**Estimated cost:** ~11–14% of weekly all-models, ~50% of one fresh session

**Kristy's deliverables — UI:**
- `templates/base.html`, `templates/index.html`, `templates/result.html` — card motif (subtle drop shadows, crisp typography, card-shaped containers)
- `static/css/style.css`
- `static/js/app.js` — upload preview, loading state (Alpine.js CDN or vanilla, no build step)
- Mobile camera capture: `<input type="file" accept="image/*,.heic,.heif" capture="environment">` (default to take-photo per Graham)
- Responsive design (mobile-first); test in Chrome DevTools mobile + actual iPhone Safari
- API key entry UI: full-screen card on first visit, collapses to "key set ✓" indicator after submission
- **MUST honor the security note in the interface contract:** `detail` on 422 responses must NEVER be rendered with `{{ detail | safe }}`, `innerHTML`, or any unescaped path. Use Jinja2 default autoescape or `.textContent` only.

**Prudvi's deliverables — backend routes (`app.py`):**
- `GET /` → renders `index.html`
- `POST /session/key` → accepts API key, encrypts via `session.encrypt_api_key`, sets HttpOnly Secure SameSite=Lax cookie (`carded_session`, Max-Age 86400)
- `POST /process` → multipart upload → calls `extract_card_from_bytes` → branches on `ExtractionResult` → on Valid: stores card in short-lived in-memory dict keyed by signed UUID token (TTL 15 min via `DOWNLOAD_TOKEN_TTL_SECONDS`), returns `{token, card}` JSON; on NotABusinessCard / Illegible: 422 with the contract'd error shape
- `GET /download/vcf?token=...` → 200 `text/vcard; charset=utf-8` `Content-Disposition: attachment` / 404 / 410 / 400 per contract
- `GET /download/csv?token=...` → similar, `text/csv`
- `GET /health` → 200 OK
- `is_owner(api_key)` helper that checks against `OWNER_ANTHROPIC_API_KEY` env var (mirrors Receipt Ranger)
- Token signing via `itsdangerous` with `DOWNLOAD_TOKEN_SECRET`
- Tests in `tests/test_app.py` (FastAPI TestClient) and `tests/test_session.py`

**Integration step (after both finish):**
- Wire Kristy's templates to Prudvi's routes
- Manual smoke test: upload a card, verify download links work, verify mobile camera-default behavior
- Defer Phase 5 (deployment) and Phase 6 (security review + tests) to subsequent sessions

**Kickoff plan for Phase 4 session:**
> Dispatch Kristy and Prudvi in PARALLEL (single message, two Agent tool calls). Kristy gets the UI brief above + the interface contract path. Prudvi gets the backend brief above + the interface contract path. After both return, main agent does the integration sweep manually, then commits.

---

## Phases not yet planned in detail (for completeness)

- **Phase 5 — Deployment** (G — infrastructure/docs): Dockerfile, render.yaml, Render Web Service setup, Cloudflare DNS for `carded.io` (or fallback domain). ~3–5% weekly all-models. Plan §10 has the env-var list.
- **Phase 6 — Tests + security review** (Mike — QA + Alex — security): full test pass, integration test fixtures (puppy.jpg, illegible_card.jpg, blurry_but_readable_card.jpg as the validation-tuning canary), `pip-audit`, prompt-injection assessment, cookie-flag verification, token-guess analysis. ~7–10% weekly all-models. Plan §6 / §9 / §11 has the brief.

Total remaining project budget after today: ~25–35% weekly all-models. Ends around 35–45% weekly all-models for the whole MVP. Comfortable headroom.

---

## Key documents to load on resume

1. `.cursor/progress/2-carded-mvp-plan-final.md` — full plan (signed-off)
2. `.cursor/docs/1-interface-contract.md` — Phase 4 contract
3. `.cursor/progress/3-phase-1-complete-handoff.md` — this file
4. `baml_src/business_card.baml` — load-bearing schema + prompt; if changes are needed they MUST be re-generated via `baml-cli generate`

---

*End of handoff. Resume with the kickoff command above when ready.*

<!-- DONE -->
