---
name: Phase 2 + Phase 3 Complete — Handoff to Phase 4
description: Captures Phase 2/3 completion state, what's on disk, the commit, this session's sub-agent stall, the new global CLAUDE.md rules added in this session, and exact pickup points for the Phase 4 session.
type: handoff
---

# Phase 2 + Phase 3 Complete — Handoff for Next Session

**Date:** 2026-05-11
**Branch:** `feat/carded-mvp-scaffold`
**Commit:** `44e7b25` — `feat: implement Phase 2 extraction pipeline and Phase 3 output generators`
**Plan reference:** `.cursor/progress/2-carded-mvp-plan-final.md`
**Prior handoff:** `.cursor/progress/3-phase-1-complete-handoff.md` — Phase 4 brief is in §"Session 2" of that doc; it remains accurate and is the load-bearing reference for the next session.
**Interface contract:** `.cursor/docs/1-interface-contract.md` — still authoritative for Phase 4.

---

## What's done (Phase 2 + Phase 3)

Phase 2 (extraction pipeline):
- ✅ `main.py` — `extract_card_from_bytes(image_data, mime_type, api_key, filename=None) -> ExtractionResult`
- ✅ Tagged result types: `Valid(card)`, `NotABusinessCard(message)`, `Illegible(message)`
- ✅ Exception types: `UnsupportedMimeType` (→ 400), `ExtractionTimeout` (→ 502), `ExtractionError` (→ 502)
- ✅ MIME allowlist: JPEG, PNG, WebP, HEIC, HEIF (case-insensitive)
- ✅ HEIC/HEIF → JPEG via `pillow-heif` + PIL (RGB convert to drop alpha)
- ✅ Filename sanitization via `InputSanitizer` as defense-in-depth (not currently sent to BAML — comment in `main.py` explains why)
- ✅ BYOK enforced: `api_key` param passed via `b.with_options(env={"ANTHROPIC_API_KEY": ...})`. No owner-key fallback in this module — that's the route layer's job.
- ✅ 60s timeout via `ThreadPoolExecutor` + `future.result(timeout=...)`. Configurable via `EXTRACTION_TIMEOUT_SECONDS` env.
- ✅ `tests/test_main.py` — 15 tests, all green. BAML mocked at unit level only.

Phase 3 (output generators):
- ✅ `vcard_builder.py` — `build_vcf(card) -> str`, `vcf_filename(card) -> str`. vCard 3.0 with `\r\n` line endings, RFC 2426 escaping (commas/semicolons/backslashes), social X-properties, ADR sub-field handling, FN fallback to organization when no name.
- ✅ `google_csv_builder.py` — `build_google_csv(card) -> str`, `csv_filename(card) -> str`. Google Contacts CSV using the **modern structured column variant** (`Phone 1 - Type`, `Address 1 - Street`, etc.) rather than plan §5's older `Business Street`-style columns. Documented in module header.
- ✅ Overflow handling: phones beyond 4 / emails beyond 2 / urls beyond 2 are silently dropped with `logger.warning(...)`.
- ✅ `tests/test_vcard_builder.py` — 24 tests, all green.
- ✅ `tests/test_google_csv.py` — 22 tests, all green.
- ✅ `tests/fixtures_data.py` — shared Jamie Park / Chris Okafor / ALL_NULL fixtures matching interface contract §F.

**Total: 61 unit tests passing in ~5s. No tests skipped. No live BAML calls in the suite.**

## Non-obvious decisions worth knowing

- **Google CSV column variant.** Used modern structured columns (`Organization 1 - Name`, `Phone N - Type/Value`, `Address 1 - Street`) rather than plan §5's `Business Street`-style. More reliable for re-import into current Google Contacts UI. Plan §5 is the floor; this is the ceiling.
- **`_safe_filename` is duplicated** in `vcard_builder.py` and `google_csv_builder.py` rather than factored into a shared helper. Both modules have a one-line comment explaining why (10-line helper, avoid cross-module import for trivial reuse).
- **Phone/email/URL overflow drops silently** with a logger warning at WARNING level via the `google_csv_builder` logger. Phase 4 should configure logging so these surface in Render logs.
- **HEIC conversion** routes through PIL after `pillow_heif.register_heif_opener()` (called once at module import), not via direct pillow-heif APIs. Keeps the in-memory bytes→bytes flow clean.
- **`Address 1 - Formatted`** column is intentionally left empty — Google Contacts populates it from the structured sub-fields on import, so pre-populating risks duplication.
- **Builders accept raw `dict`** (not Pydantic models). Phase 4's `/process` handler can pass `card.model_dump()` or the JSON-decoded card dict from the response directly to either builder.

## Sub-agent stall log (this session)

One stall, consistent with the Phase 1 pattern:
- **First Prudvi (Sonnet):** completed Phase 2 (15/15 green) and wrote `vcard_builder.py`, but truncated its final report mid-sentence (`"Now Phase 3 — vcard_builder.py:"`) without writing the vCard tests, `google_csv_builder.py`, or its tests. Files on disk were sound; only the closing report was clipped.
- **Second Prudvi (Sonnet, fresh dispatch):** picked up cleanly with an explicit "what's done / what's left" context. Wrote the remaining three files, ran the full suite, returned a clean structured report under 200 words. 61/61 total green.

The pattern across all four Carded stalls so far (two in Phase 1, one Alex security review in Phase 1, one this session) is the same: real work landed on disk, the closing summary message clipped. All four were Sonnet-backed.

## Mitigations added to global CLAUDE.md this session

Added three bullets to `~/CLAUDE.md` § Sub-Agents and Routing:

1. **Cap sub-agent final reports at ~200 words by default**, unless the task genuinely requires a longer report (e.g., a full security review with findings).
2. **Files-on-disk + test results are the success criterion**, not the agent's summary message. Verify state from the filesystem before reporting completion. A truncated report does not mean the work failed.
3. **Model selection:** prefer Sonnet for lower-stakes work (most implementation, exploration, routine review). Prefer Opus for high-stakes single-shot dispatches: security reviews, QA of security-sensitive code, final-pass reviews before merging significant features.

These will apply to Phase 4 and beyond.

## Token spend (rough)

- First Prudvi (Sonnet, partial): ~74K tokens
- Second Prudvi (Sonnet, finished): ~69K tokens
- Main-agent coordination + verification (Opus): ~80–120K
- **Session total estimate:** ~225K–265K tokens
- Roughly: ~7–9% weekly all-models, ~30–40% of one fresh session. Came in slightly under the ~10–12% / ~40–50% budget on the Todoist task.

---

## Where to pick up next session: Phase 4

Phase 4 is fully briefed in `.cursor/progress/3-phase-1-complete-handoff.md` § "Session 2 (separate session, may be later same day): Phase 4" — read that section (lines 99–133) when starting the next session. It still applies. Notable details from that brief:

- **Branch:** `feat/carded-mvp-scaffold` (continued)
- **Approach:** Kristy (UI) + Prudvi (backend routes) work in parallel against the interface contract. Both can start at the same time — Kristy uses the contract §F fixtures.
- **Sub-agents:** `kristy-frontend-ui-specialist` + `prudvi-backend-architect` (parallel)
- **Budget:** ~11–14% weekly all-models, ~50% of one fresh session (the largest single-session budget in the remaining build)
- **Open Todoist task:** ID `6gWJcJ4HVXM2m8gq` — "Pick up Carded Phase 4 (FastAPI app + UI — Kristy + Prudvi parallel)"

### Additional reminders for the Phase 4 dispatcher (new this session)

- **Cap both sub-agent final reports at ~200 words.** This was the single biggest lever that turned the second-Prudvi dispatch into a clean return after the first-Prudvi truncation.
- **After both agents return, verify state from the filesystem before reporting.** Don't trust the summary message alone — check that the expected files exist, run the test suite, run a smoke test against the dev server.
- **Phase 4 is security-sensitive** (auth/session flow, file upload handling, public HTTP surface — per plan §0 row 9). After Kristy and Prudvi finish, consider running a focused QA / security review pass with **Opus**, not Sonnet, given the Phase 1 stall pattern on Sonnet for security-sensitive review work.
- **Specific Phase 4 security touchpoint:** the `detail` field on 422 responses is LLM-generated text reflecting attacker-controllable image content. It MUST be HTML-escaped on render (Jinja2 default autoescape is fine; never `{{ detail | safe }}` or `innerHTML`). See interface contract §B security note for full details.

### Phases after Phase 4 (unchanged)

- **Phase 5 — Deployment** (G): ~3–5% weekly. Dockerfile, render.yaml, Cloudflare DNS, env vars.
- **Phase 6 — Tests + security review** (Mike + Alex): ~7–10% weekly. Full integration tests with fixture cards, manual mobile E2E, dependency CVE scan, prompt-injection assessment, cookie-flag verification, token-guess analysis. **Use Opus for Alex per the new global CLAUDE.md rule.**

Remaining project budget after this session: ~21–29% weekly all-models. Comfortable headroom.

---

## Key documents to load on resume

1. `.cursor/progress/2-carded-mvp-plan-final.md` — full signed-off plan
2. `.cursor/docs/1-interface-contract.md` — Phase 4 contract (authoritative)
3. `.cursor/progress/3-phase-1-complete-handoff.md` — Phase 4 brief in § "Session 2"
4. `.cursor/progress/4-phase-2-and-3-complete-handoff.md` — this file
5. `main.py`, `vcard_builder.py`, `google_csv_builder.py` — Phase 4 will call these
6. `~/CLAUDE.md` § Sub-Agents and Routing — three new bullets apply to Phase 4 dispatch

---

*End of handoff. Resume Phase 4 from the brief in `3-phase-1-complete-handoff.md`.*
