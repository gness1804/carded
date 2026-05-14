---
description: Final, signed-off-pending plan for Carded MVP. Incorporates Graham's
  decisions on domain, BYOK, HEIC, camera default, parallel build, and feature branch.
github_issue: 4
name: Carded MVP Plan (Final)
type: handoff
---
# Carded MVP Plan (Final)

**Status:** Final draft — awaiting Graham's green-light on Phase 1 kickoff.
**Date:** 2026-05-01
**Supersedes:** `.cursor/progress/1-carded-mvp-plan.md` (kept for history)
**Feature branch (proposed):** `feat/carded-mvp-scaffold` — to be cut from `master` before any code lands.

---

## 0. Decisions Confirmed by Graham (2026-05-01)

| # | Question | Decision |
|---|---|---|
| 1 | Domain | `carded.io` preferred. Fallback to a comparably premium TLD (e.g., `.app`, `.com`) if `.io` is taken or pricing is unreasonable. Carded will register the domain and point Cloudflare DNS at Render, mirroring Receipt Ranger. |
| 2 | API key model | **Bring-Your-Own-Key (BYOK)**, mirroring Receipt Ranger. Graham does not want his key spammed. The owner key (`OWNER_ANTHROPIC_API_KEY`) is recognized so Graham bypasses the BYOK prompt for his own use. |
| 3 | HEIC support | **Yes** — add `pillow-heif` so iPhone photos work natively without an explicit conversion step on the user's end. |
| 4 | Mobile camera default | Default to **"take photo"** (`<input type="file" accept="image/*" capture="environment">`). User can still choose from library via the OS picker. |
| 5 | Build parallelism | Kristy (frontend/UI) and Prudvi (backend) work **in parallel**. This requires an upfront interface contract (see §8) so the two streams can integrate cleanly at Phase 4. |
| 6 | Vision model | `claude-sonnet-4-20250514` via BAML, matching Receipt Ranger's `CustomSonnet4` client. |
| 7 | Feature branch | `feat/carded-mvp-scaffold`. |
| 8 | Card-validity gate | After prompt-injection defense and before downstream output generation, an LLM judges whether the image is a valid, legible business card. Three states: `VALID` (proceed), `NOT_A_BUSINESS_CARD` (error: "Please upload an image of a business card"), `ILLEGIBLE` (error: "We couldn't read this card — please upload a sharper / higher-resolution copy"). The LLM must try hard to read blurry or low-quality cards before declaring them illegible — only truly unrecoverable text should yield `ILLEGIBLE`. **Implementation: single BAML call** (the validation status is part of the same `BusinessCard` response — see §4). Two-call alternative was considered but rejected because BYOK doubles user cost. If single-call validation reliability proves insufficient during Phase 6 testing, we'll revisit. |
| 9 | QA sub-agent scope | To save tokens, QA sub-agent reviews now run **only on security-sensitive phases (1, 4, 6)** instead of every phase. Phases 2, 3, and 5 ship without a dedicated QA pass; their unit tests (written by the implementing agent) and Phase 6's full security/QA review provide coverage. Phase 1 covers the BAML schema strictness, the `validation/` prompt-injection port, and the `session.py` Fernet crypto port — all security-sensitive. Phase 4 covers the auth/session flow, file upload handling, and the public HTTP surface. Phase 6 is the dedicated end-of-build security + QA review. |

---

## 1. Summary

Carded is a web application (mobile + desktop) that accepts a photo or screenshot of a business card and uses a vision-capable LLM — wrapped in a BAML schema — to extract structured contact fields **strictly as they appear on the card**. It then generates a downloadable vCard (`.vcf`) for Apple/iOS contacts and a Google Contacts–compatible CSV. On mobile, the `.vcf` is served with the right MIME and disposition headers so iOS triggers its native "Add Contact" flow and Android opens the file with Google/Samsung Contacts.

Carded follows the Receipt Ranger architecture (Python backend, BAML for deterministic AI extraction, Docker on Render, BYOK API keys with Fernet-encrypted session storage) but is materially simpler: no persistent storage, no accounts, no Google Sheets integration. Frontend uses **FastAPI + Jinja2 + vanilla CSS + Alpine.js (CDN)** instead of Streamlit, because Streamlit can't cleanly serve a `.vcf` with custom headers and its UI ceiling is too low for the modern card-motif look Carded needs.

The cardinal rule for the AI: **never infer, never supplement with outside knowledge, null = "not on card."** BAML enforces this via strict schema typing with explicit `null` semantics and prompt-level instructions.

---

## 2. Architecture Overview

```
User (mobile or desktop browser)
        |
        | (1) Enters Anthropic API key (or owner key)
        | (2) uploads image (JPEG/PNG/WEBP/HEIC)
        v
+------------------------------------------+
|  FastAPI backend  (Python 3.11)           |
|                                          |
|  - Validate session (encrypted API key)  |
|  - Validate image (MIME, size)           |
|  - HEIC -> JPEG conversion (pillow-heif) |
|  - Prompt-injection guard (text fields)  |
|  - Call BAML ExtractBusinessCard()       |
|  - Inspect validationStatus:             |
|      VALID -> proceed                    |
|      NOT_A_BUSINESS_CARD -> 422 error    |
|      ILLEGIBLE -> 422 error              |
|  - Build vCard + Google CSV              |
|  - Issue short-lived download tokens     |
+------------------------------------------+
        |
        |  BAML function call
        v
+----------------------------------------------+
|  BAML ExtractBusinessCard()                  |
|  -> claude-sonnet-4-20250514 (vision)        |
|  -> First classifies image:                  |
|      VALID / NOT_A_BUSINESS_CARD / ILLEGIBLE |
|  -> If VALID, extracts fields literally      |
|     (no inference, null = not on card)       |
|  -> Returns typed BusinessCard (Pydantic)    |
+----------------------------------------------+
        |
        v
+----------------------------+
|  Output generators         |
|  vcard_builder.py          |
|  google_csv_builder.py     |
+----------------------------+
        |
        v
Downloads served:
  - GET /download/vcf?token=...   Content-Type: text/vcard
  - GET /download/csv?token=...   Content-Type: text/csv

On mobile iOS/Android:
  - .vcf served with proper headers ->
    iOS Safari opens native "Add Contact" sheet,
    Android Chrome offers "Open with Contacts."
```

---

## 3. Tech Stack Recommendation

### Frontend Framework: FastAPI + Jinja2 (NOT Streamlit) — confirmed

**Recommendation:** FastAPI with server-rendered Jinja2 templates, vanilla CSS for the card motif, and Alpine.js (CDN) for upload preview / loading state. No build step, no JS bundler.

Why not Streamlit:
- Streamlit cannot ergonomically serve a file with custom headers (`Content-Type: text/vcard`, `Content-Disposition: attachment; filename="contact.vcf"`). The iOS native "Add Contact" handoff requires a direct GET to a URL that returns `text/vcard` — clean in FastAPI, awkward-to-impossible in Streamlit.
- Streamlit's default aesthetic doesn't meet the "modern, attractive, card motif" bar without heavy `unsafe_allow_html` hacks. Receipt Ranger already does this and still looks like Streamlit.
- Mobile camera capture works through `<input capture>` attributes — Streamlit doesn't expose those without HTML injection.

Why not React/Next, HTMX, Reflex, Gradio:
- React/Next: build step + node toolchain is overkill for a single-page upload→download tool.
- HTMX: would work, but Jinja2 + a few lines of vanilla JS / Alpine.js is simpler.
- Reflex / Gradio: same UI ceiling problem as Streamlit.

### Hosting: Render (confirmed)

Same workflow as Receipt Ranger: Render Web Service, Docker runtime, auto-deploy from `main`, custom domain via Cloudflare DNS-only (grey cloud), Render handles SSL via Let's Encrypt. Render Starter plan ($7/month) is sufficient for an MVP.

### Vision Model: Claude Sonnet 4 via BAML — confirmed

- Primary client: `CustomSonnet4` → `claude-sonnet-4-20250514` (matches Receipt Ranger `baml_src/clients.baml`).
- Optional fallback (Phase 5 stretch): `claude-opus-4-1-20250805` for difficult/degraded images.
- Anthropic-only — no second provider in MVP.

### BYOK Session Pattern — confirmed (mirrors Receipt Ranger)

- Frontend prompts the user for their `ANTHROPIC_API_KEY` on first visit. Submitted via POST to `/session/key`.
- Server **Fernet-encrypts** the key with `SESSION_SECRET` (a Fernet key from env) and returns an opaque token, stored in an HTTP-only cookie. Plaintext API keys are never persisted to disk and never logged.
- On each subsequent request, the cookie is decrypted server-side and the plaintext key is set on `os.environ["ANTHROPIC_API_KEY"]` for the duration of the BAML call (or passed via BAML's per-call client override if supported in our version).
- `OWNER_ANTHROPIC_API_KEY` env var holds Graham's key — the app recognizes it and skips any "you've used the owner key" indicator (matches Receipt Ranger's `is_owner()`).
- Helpers: `encrypt_api_key`, `decrypt_api_key`, `mask_api_key` — port directly from `receipt-ranger/session.py`.

### BAML

Same version and pattern as Receipt Ranger: `baml-py>=0.218.0`, `generators.baml` targeting `python/pydantic`, sync client mode. Never edit `baml_client/` by hand — it's generated.

### HEIC Support — confirmed

- Add `pillow-heif` to `requirements.txt`.
- On upload, if MIME is `image/heic` or `image/heif`, convert to JPEG in-memory before passing bytes to BAML. (Anthropic's vision API does not accept HEIC directly.)
- Allowed upload MIME types: `image/jpeg`, `image/png`, `image/webp`, `image/heic`, `image/heif`.

---

## 4. Data Model / BAML Schema

### Design Principles
- Every scalar field is either populated literally from the card or `null` (Python `None`).
- **No field defaults to an inferred value.** If it's not on the card, it's `null`.
- Arrays (phones, emails, urls) are `[]` when nothing is present, never `null`.
- The model does NOT augment with external knowledge (no LinkedIn lookups, no inferring email from name+domain, no completing partial info).

### Proposed BAML Schema (`baml_src/business_card.baml`)

```
enum PhoneType {
    MOBILE     @alias("Mobile")
    WORK       @alias("Work")
    HOME       @alias("Home")
    FAX        @alias("Fax")
    OTHER      @alias("Other")
}

enum EmailType {
    WORK       @alias("Work")
    PERSONAL   @alias("Personal")
    OTHER      @alias("Other")
}

enum ValidationStatus {
    VALID                @alias("Valid")
    NOT_A_BUSINESS_CARD  @alias("Not a business card")
    ILLEGIBLE            @alias("Illegible")
}

class PhoneEntry {
    number string  @description("Phone number exactly as printed on the card. Preserve formatting (dashes, parens, country codes).")
    type PhoneType @description("Type of phone. If labeled (M:, Cell:, Fax:, F:, Work:), use the matching type. If unlabeled on a business card, default to WORK.")
}

class EmailEntry {
    address string @description("Email address exactly as printed on the card.")
    type EmailType @description("Type of email. If unlabeled on a business card, default to WORK.")
}

class AddressEntry {
    street string?      @description("Street address line 1. Null if not on card.")
    street2 string?     @description("Suite, unit, floor, etc. Null if not on card.")
    city string?        @description("City. Null if not on card.")
    state string?       @description("State or province. Null if not on card.")
    postal_code string? @description("ZIP or postal code. Null if not on card.")
    country string?     @description("Country. Null if not on card.")
}

class BusinessCard {
    validationStatus ValidationStatus @description("VALID = image is a business card AND text is readable (with effort, blur, low light, etc.). NOT_A_BUSINESS_CARD = image is not a business card (puppy, landscape, receipt, generic document, etc.). ILLEGIBLE = image is or appears to be a business card BUT text cannot be recovered even with best vision effort.")
    validationMessage string          @description("If validationStatus is NOT_A_BUSINESS_CARD: brief description of what the image actually is (e.g., 'a photo of a dog', 'a restaurant receipt'). If ILLEGIBLE: brief reason (e.g., 'image is too blurry to read', 'glare obscures most text', 'resolution is too low'). If VALID: empty string.")

    // Identity
    full_name string?      @description("Full name as printed. Null if absent.")
    first_name string?     @description("First name only if unambiguously separable. Null otherwise.")
    last_name string?      @description("Last name only if unambiguously separable. Null otherwise.")
    prefix string?         @description("Name prefix (Dr., Prof.). Null if absent.")
    suffix string?         @description("Name suffix (Jr., MD, PhD). Null if absent.")

    // Professional
    title string?          @description("Job title exactly as printed. Null if absent.")
    organization string?   @description("Company or organization exactly as printed. Null if absent.")
    department string?     @description("Department or division. Null if absent.")

    // Contact arrays
    phones PhoneEntry[]    @description("All phones on the card. Empty array if none.")
    emails EmailEntry[]    @description("All emails on the card. Empty array if none.")
    urls string[]          @description("All website URLs on the card, exactly as printed. Empty array if none.")

    // Address
    address AddressEntry?  @description("Mailing/business address if printed. Null if no address present.")

    // Social
    linkedin string?       @description("LinkedIn URL or handle if printed. Null if absent.")
    twitter string?        @description("Twitter/X handle or URL if printed. Null if absent.")
    instagram string?      @description("Instagram handle or URL if printed. Null if absent.")

    // Catch-all
    note string?           @description("Any other text on the card not covered above. Null if nothing extra.")
}
```

### Prompt Instructions (in the BAML template)

```
STEP 1 — VALIDATE THE IMAGE BEFORE EXTRACTING:

Set validationStatus to one of three values:

- VALID: the image clearly shows a business card or contact card AND
  enough text is recoverable to populate at least one identifying field
  (name, organization, phone, email, etc.). Mild blur, glare, or low
  contrast is OK if you can still read most text.

- NOT_A_BUSINESS_CARD: the image is something else entirely — a photo of
  a person/animal/landscape, a receipt, a screenshot of an unrelated
  document, a logo or product shot with no contact context, a blank page,
  or random text that is not a business/contact card. Set
  validationMessage to a brief description of what the image actually is.

- ILLEGIBLE: the image IS or appears to be a business card, BUT text
  cannot be recovered even with best vision effort (e.g., extreme blur,
  total glare, severely cropped, resolution too low to resolve any
  characters). Set validationMessage to a brief reason.

LEGIBILITY GUIDANCE — be permissive, not pedantic:
- Try hard to read text. Use context, partial letterforms, common name
  patterns, and standard contact-card layouts to recover characters from
  blurry or low-quality images.
- If you can read SOME text but not all, set validationStatus = VALID and
  populate only the fields you can read with reasonable confidence;
  unreadable fields = null. Do not mark the whole card ILLEGIBLE just
  because one field is hard to read.
- Reserve ILLEGIBLE for cards where essentially no text is recoverable.

STEP 2 — IF AND ONLY IF validationStatus IS VALID, EXTRACT FIELDS:

If validationStatus is NOT_A_BUSINESS_CARD or ILLEGIBLE, set every other
field to its empty/null default (scalars = null, arrays = []). Do not
attempt to extract from a non-card or illegible image.

STRICT EXTRACTION RULES (apply only when VALID) — READ CAREFULLY:
1. Only extract information literally printed or displayed on the card.
2. Do NOT infer, guess, or supplement any field with outside knowledge.
3. Do NOT derive an email address from a name and domain unless explicitly written.
4. Do NOT look up or add phone numbers, addresses, titles, or social handles not shown.
5. Do NOT "complete" partial info (e.g., if only "John" appears, first_name="John", last_name=null).
6. Preserve exact formatting for phone numbers and URLs as they appear on the card.
7. If a SPECIFIC field is unclear due to image quality, use null for THAT field rather than guessing.
   (This is different from marking the whole card ILLEGIBLE — see Step 1 guidance.)
8. PhoneType: respect labels (M:, Cell:, Fax:, F:, Work:); default unlabeled → WORK on a business card.
```

### Missing-Field Behavior

| Situation | Behavior |
|---|---|
| Scalar field absent | `null` |
| Phone/email/url arrays empty | `[]` |
| Address present, some sub-fields missing | `AddressEntry` with missing sub-fields = `null` |
| No address at all | `address: null` |
| Image too poor to read a field | `null` |
| Ambiguous label (phone vs fax) | Use best-readable type; otherwise OTHER |

---

## 5. Output Formats

### vCard 3.0 Mapping

vCard 3.0 (not 4.0) — broader compatibility, fully supported by iOS Contacts.

| BusinessCard field | vCard 3.0 property | Notes |
|---|---|---|
| `full_name` | `FN:` | If null, construct from first_name + last_name |
| `first_name`, `last_name`, `prefix`, `suffix` | `N:last;first;;;prefix;suffix` | vCard `N` order: Last;First;Middle;Prefix;Suffix |
| `title` | `TITLE:` | |
| `organization` + `department` | `ORG:Organization;Department` | Department in second `ORG` field |
| `phones[i]` (MOBILE) | `TEL;TYPE=CELL,VOICE:number` | |
| `phones[i]` (WORK) | `TEL;TYPE=WORK,VOICE:number` | |
| `phones[i]` (HOME) | `TEL;TYPE=HOME,VOICE:number` | |
| `phones[i]` (FAX) | `TEL;TYPE=FAX:number` | |
| `phones[i]` (OTHER) | `TEL;TYPE=VOICE:number` | |
| `emails[i]` (WORK) | `EMAIL;TYPE=WORK,INTERNET:addr` | |
| `emails[i]` (PERSONAL) | `EMAIL;TYPE=HOME,INTERNET:addr` | |
| `emails[i]` (OTHER) | `EMAIL;TYPE=INTERNET:addr` | |
| `urls[i]` | `URL:url` | One per URL |
| `address` | `ADR;TYPE=WORK:;;street;city;state;postal;country` | |
| `linkedin` | `X-SOCIALPROFILE;TYPE=linkedin:value` | Extended property |
| `twitter` | `X-SOCIALPROFILE;TYPE=twitter:value` | |
| `instagram` | `X-SOCIALPROFILE;TYPE=instagram:value` | |
| `note` | `NOTE:` | |

Boilerplate:
```
BEGIN:VCARD
VERSION:3.0
...fields...
END:VCARD
```

Filename: `{last_name}_{first_name}.vcf`, fallback `contact.vcf`.
Served with `Content-Type: text/vcard; charset=utf-8` and `Content-Disposition: attachment; filename="..."`.

### Google Contacts CSV Mapping

Reference: https://support.google.com/contacts/answer/1069522

| BusinessCard field | Google CSV column |
|---|---|
| `first_name` | `First Name` |
| `last_name` | `Last Name` |
| `prefix` | `Title` (honorific prefix) |
| `suffix` | `Suffix` |
| `organization` | `Company` |
| `title` | `Job Title` |
| `department` | `Department` |
| `phones[i]` (MOBILE) | `Mobile Phone` |
| `phones[i]` (WORK) | `Work Phone` |
| `phones[i]` (FAX) | `Work Fax` |
| `emails[0]` | `E-mail Address` |
| `emails[1]` | `E-mail 2 Address` |
| `urls[0]` | `Web Page` |
| `address.street` | `Business Street` |
| `address.city` | `Business City` |
| `address.state` | `Business State` |
| `address.postal_code` | `Business Postal Code` |
| `address.country` | `Business Country/Region` |
| `note` | `Notes` |

Multiple phones of same type → `Work Phone`, `Work Phone 2`, etc.
Filename: `contacts.csv`, served as `text/csv; charset=utf-8`.

---

## 6. Mobile Contact Handoff

### Feasible from a Web App

**iOS Safari (iPhone/iPad):** Serving a `.vcf` with `Content-Type: text/vcard` + `Content-Disposition: attachment; filename="contact.vcf"` causes iOS to open Contacts and present the "New Contact / Add to Existing" sheet. Works without a native app. Implementation: a plain anchor `<a href="/download/vcf?token=...">Add to Contacts</a>` — must be a direct GET, not a JS Blob download.

**Android Chrome:** Same headers work; behavior depends on the contacts app. Chrome typically downloads the `.vcf` and surfaces an "Open with Contacts" notification action. Less seamless than iOS but reliable.

**Camera capture (mobile):** `<input type="file" accept="image/*" capture="environment">` — opens the rear camera by default on iOS Safari and Android Chrome. **Confirmed default per Graham's decision.** Users can still tap "Photo Library" / "Files" in the picker if they prefer an existing image.

### Out of Scope for MVP (deferred to future native app)

- Direct write to the device contacts DB from a web app — no Web standard supports it. The `navigator.contacts.select` API is read-only.
- Future React Native phase will use `react-native-contacts` / `expo-contacts`.

### Practical UI

After extraction, the result page shows two prominent buttons:
- **"Add to Contacts"** → `/download/vcf?token=...` (iOS triggers native add flow; Android downloads + opens with Contacts; desktop opens system contacts app)
- **"Download for Google"** → `/download/csv?token=...`

Plus a tertiary "Download vCard file" link for desktop users who want to save the file rather than auto-import.

---

## 7. Project Layout

Mirroring Receipt Ranger where sensible, simplified for Carded:

```
carded/
├── app.py                      # FastAPI app: routes, upload, downloads, session/key
├── main.py                     # Core pipeline: extraction orchestration
├── vcard_builder.py            # Builds vCard (.vcf) from BusinessCard
├── google_csv_builder.py       # Builds Google Contacts CSV from BusinessCard
├── session.py                  # Fernet encrypt/decrypt for BYOK API key (port from RR)
├── pyproject.toml
├── requirements.txt            # fastapi, uvicorn, jinja2, baml-py, cryptography,
│                               # pillow, pillow-heif, python-multipart
├── Dockerfile
├── render.yaml                 # Render service config (or dashboard-only)
├── .bumpversion.cfg
├── README.md
├── AGENTS.md
├── CLAUDE.md
├── .env.example
│
├── baml_src/                   # BAML source (DO NOT auto-edit baml_client/)
│   ├── business_card.baml      # BusinessCard schema + ExtractBusinessCard function
│   ├── clients.baml            # CustomSonnet4 client (claude-sonnet-4-20250514)
│   └── generators.baml         # python/pydantic, sync
│
├── baml_client/                # Auto-generated; never edit by hand
│   └── ...
│
├── validation/                 # Prompt-injection detection (port from Receipt Ranger)
│   ├── __init__.py
│   ├── detector.py
│   └── sanitizer.py
│
├── static/
│   ├── css/
│   │   └── style.css           # Card motif styles
│   ├── js/
│   │   └── app.js              # Upload preview, loading state (Alpine.js or vanilla)
│   └── img/
│       └── logo.svg            # Carded logo
│
├── templates/
│   ├── base.html               # Card-motif base layout
│   ├── index.html              # Upload page (+ inline API key prompt if not in session)
│   └── result.html             # Extracted contact + Add-to-Contacts / Download buttons
│
├── tests/
│   ├── __init__.py
│   ├── test_main.py
│   ├── test_vcard_builder.py
│   ├── test_google_csv.py
│   ├── test_session.py
│   ├── test_app.py             # FastAPI TestClient
│   └── fixtures/
│       └── expected/           # JSON fixtures: expected BusinessCard outputs
│
├── data/
│   └── sample_cards/           # JPEGs/PNGs/HEIC for integration tests
│
├── output/                     # Runtime artifacts (gitignored)
│
└── .cursor/
    ├── init.md
    ├── features/
    ├── bugs/
    ├── progress/
    ├── qa/
    ├── security/
    └── tmp/
```

---

## 8. Build Phases

### Phase 1 — Scaffolding + BAML Schema (foundation, blocking all others)

**Deliverables:**
- Repo structure, `pyproject.toml`, `requirements.txt`
- `AGENTS.md`, `CLAUDE.md`
- `baml_src/business_card.baml` — BusinessCard schema + ExtractBusinessCard function (image input)
- `baml_src/clients.baml` — `CustomSonnet4` (`claude-sonnet-4-20250514`)
- `baml_src/generators.baml` — Python/Pydantic sync
- `baml-cli generate` run, `baml_client/` populated and committed
- `session.py` ported from Receipt Ranger (Fernet encrypt/decrypt/mask)
- `validation/` ported from Receipt Ranger
- `.env.example` with all required vars
- **Interface contract document** (`.cursor/docs/N-interface-contract.md`) defining the JSON shape returned by `/process` and the `BusinessCard` Python type — so Phase 2/3/4 can work in parallel.

**Sub-agent:** Prudvi (backend architect)
**Dependencies:** None
**Parallel with:** Nothing — must finish first.

---

### Phase 2 — Extraction Pipeline (parallel with Phase 3)

**Deliverables:**
- `main.py`:
  - `extract_card_from_bytes(image_data: bytes, mime_type: str, api_key: str) -> ExtractionResult`
  - `ExtractionResult` is a tagged result type with three variants:
    - `Valid(card: BusinessCard)` — proceed to output generation
    - `NotABusinessCard(message: str)` — surface a 422 to the user with copy: "Please upload an image of a business card."
    - `Illegible(message: str)` — surface a 422 to the user with copy: "We couldn't read this card clearly. Please upload a sharper or higher-resolution copy."
- Image validation (MIME allowlist; reject unknown types with 400)
- HEIC → JPEG conversion via `pillow-heif` when input is HEIC/HEIF
- Prompt-injection sanitization on any user-supplied text (port from Receipt Ranger) — runs **before** the BAML call
- BAML `ExtractBusinessCard` call (single call returns validationStatus + populated fields)
- Branch on `validationStatus`:
  - `VALID` → return `Valid(card)`
  - `NOT_A_BUSINESS_CARD` → return `NotABusinessCard(validationMessage)`
  - `ILLEGIBLE` → return `Illegible(validationMessage)`
- BAML call timeout (60s default, configurable via env)
- BusinessCard normalization (None → omitted, types coerced) — only on the VALID path
- Unit tests in `tests/test_main.py` (mock BAML client to return each of the three states)

**Sub-agent:** Prudvi (backend architect)
**Dependencies:** Phase 1 (BAML client must exist + interface contract)
**Parallel with:** Phase 3, and parts of Phase 4 (Kristy can build templates + CSS against the contracted JSON shape with mock data)

---

### Phase 3 — Output Generators (parallel with Phase 2)

**Deliverables:**
- `vcard_builder.py`: `build_vcf(card: dict) -> str`
- `google_csv_builder.py`: `build_google_csv(card: dict) -> str`
- Both gracefully omit null fields (no empty `EMAIL:` lines, no empty CSV cells reading "None")
- Filename helpers for both formats
- Unit tests covering: full card, sparse card, empty arrays, all-null edge case, multiple phones/emails of same type, address with partial sub-fields, non-ASCII names

**Sub-agent:** Prudvi
**Dependencies:** Phase 1 (BusinessCard type)
**Parallel with:** Phase 2

---

### Phase 4 — FastAPI App + UI (parallel between Kristy and Prudvi)

**Deliverables (Prudvi side — backend routes):**
- `app.py` routes:
  - `GET /` → renders `index.html`
  - `POST /session/key` → accept user-submitted API key, encrypt, set HTTP-only secure cookie
  - `POST /process` → multipart upload, run pipeline, store result in short-lived in-memory dict keyed by signed UUID token, return JSON `{ token, card }`
  - `GET /download/vcf?token=...` → `text/vcard` `FileResponse`
  - `GET /download/csv?token=...` → `text/csv` `FileResponse`
  - `GET /health` → 200 OK
- Token TTL: 15 minutes (config); auto-evict expired entries
- `tests/test_app.py` (FastAPI TestClient) and `tests/test_session.py`

**Deliverables (Kristy side — UI):**
- `templates/base.html`, `index.html`, `result.html` — card-motif layout (subtle drop shadows, crisp typography, card-shaped containers)
- `static/css/style.css`
- Upload form: `<input type="file" accept="image/*,.heic,.heif" capture="environment">` (camera-default on mobile per Graham's decision)
- Upload preview thumbnail (Alpine.js)
- Loading state during extraction (skeleton or spinner inside a card)
- Result page: extracted fields displayed in a "card preview" component + two prominent buttons (Add to Contacts, Download for Google)
- API key entry UI (initially full-screen card on first visit; collapses to a small "key set ✓" indicator after submission)
- Responsive design (mobile-first); test in Chrome DevTools mobile emulation + actual iPhone Safari before handoff

**Coordination:**
- Both work against the interface contract from Phase 1.
- Kristy can mock the `/process` response with a static JSON fixture while building UI.
- Prudvi can ship routes returning real data; integration happens at end of Phase 4.

**Sub-agents:** Kristy + Prudvi (parallel)
**Dependencies:** Phase 1 (interface contract); Phase 2 + 3 must be complete before final integration.

---

### Phase 5 — Deployment

**Deliverables:**
- `Dockerfile` (`python:3.11-slim`, `uvicorn app:app --host 0.0.0.0 --port 8000`)
- `render.yaml` (or dashboard config notes)
- `HEALTHCHECK` in Dockerfile against `/health`
- Local `docker build && docker run` smoke test
- Render Web Service created (Starter, $7/mo)
- Cloudflare DNS for `carded.io` (or chosen domain) → Render
- All env vars set in Render dashboard (see §10)
- Deploy and smoke-test on the live URL

**Sub-agent:** G (infrastructure/docs)
**Dependencies:** Phase 4 complete
**Parallel with:** Phase 6 (tests/security review can run on the codebase while G handles deployment)

---

### Phase 6 — Tests + Security Review

**Deliverables:**
- Full unit test suite green (`pytest`)
- Integration tests against fixture cards (gated by `RUN_INTEGRATION_TESTS=1`)
- Manual mobile E2E (iOS Safari, Android Chrome) — record screenshots/notes
- Mike (QA) test review: coverage gaps, test integrity, parametrization opportunities
- Alex (security) full review:
  - Prompt-injection surface (image content + any text fields)
  - File upload validation (MIME, size, polyglot files)
  - HEIC processing safety (libheif CVEs)
  - Token guessability for download URLs (must be cryptographically random + signed)
  - Cookie flags (Secure, HttpOnly, SameSite=Lax)
  - Fernet key handling
  - Dependency CVE scan (`pip-audit`)
  - Logging hygiene (no API keys, no card content in logs)
  - Rate limiting / abuse considerations

**Sub-agents:** Mike (QA) + Alex (security)
**Dependencies:** Phase 4 complete
**Parallel with:** Phase 5

---

## 9. Testing Plan

### Unit Tests (deterministic, no LLM)

**`tests/test_vcard_builder.py`**
- `test_full_card_produces_valid_vcf`
- `test_sparse_card_omits_null_fields`
- `test_multiple_phones_with_types`
- `test_phone_type_mapping` (MOBILE→CELL,VOICE; WORK→WORK,VOICE; FAX→FAX)
- `test_address_partial_subfields`
- `test_non_ascii_name_encoding`
- `test_filename_generation` (named card vs nameless fallback)
- `test_social_profile_x_properties`

**`tests/test_google_csv.py`**
- `test_full_card_csv_headers_complete`
- `test_null_fields_become_empty_cells_not_None`
- `test_multiple_emails_overflow_to_numbered_columns`
- `test_phone_type_routing_to_correct_column`
- `test_csv_quoting_for_commas_and_quotes_in_fields`

**`tests/test_main.py`**
- `test_extract_calls_baml_with_image_bytes`
- `test_validation_status_VALID_returns_Valid_result`
- `test_validation_status_NOT_A_BUSINESS_CARD_returns_NotABusinessCard_result`
- `test_validation_status_ILLEGIBLE_returns_Illegible_result`
- `test_non_card_image_skips_field_extraction` (mock BAML returning `NOT_A_BUSINESS_CARD`; confirm vCard/CSV builders are not called)
- `test_image_mime_validation_rejects_pdf`
- `test_heic_converted_to_jpeg_before_baml_call`
- `test_null_handling_through_pipeline`

**`tests/test_session.py`**
- `test_encrypt_decrypt_round_trip`
- `test_decrypt_invalid_token_returns_None`
- `test_mask_api_key_format`
- `test_owner_key_recognized`

**`tests/test_app.py`** (FastAPI TestClient)
- `test_health_endpoint_returns_200`
- `test_index_renders`
- `test_session_key_set_returns_cookie`
- `test_upload_without_key_redirects_to_key_prompt`
- `test_upload_valid_image_returns_token_and_card_json`
- `test_upload_non_card_image_returns_422_with_user_friendly_copy` ("Please upload an image of a business card.")
- `test_upload_illegible_card_returns_422_with_user_friendly_copy` ("We couldn't read this card clearly...")
- `test_upload_invalid_filetype_returns_400`
- `test_upload_oversize_returns_413`
- `test_download_vcf_correct_content_type_and_disposition`
- `test_download_csv_correct_content_type`
- `test_download_invalid_token_returns_404`
- `test_download_expired_token_returns_410`

### Integration Tests (real BAML/LLM, gated)

Fixture set in `data/sample_cards/`:
1. `dense_english_card.jpg` — full data → expect `validationStatus=VALID`, all fields populated
2. `sparse_card.jpg` — name + one phone only → expect `VALID`, most fields null
3. `non_english_card.jpg` — Japanese or Spanish (encoding sanity) → expect `VALID`
4. `heic_card.heic` — iPhone-format card → expect `VALID` (after HEIC pipeline)
5. `blurry_but_readable_card.jpg` — moderately blurry but text recoverable → expect `VALID` (verifies the "be permissive" prompt instruction works in practice; this is the most important regression fixture for the validation tuning)
6. `not_a_card.jpg` — landscape photo → expect `validationStatus=NOT_A_BUSINESS_CARD`
7. `puppy.jpg` — dog photo → expect `NOT_A_BUSINESS_CARD` (per Graham's example)
8. `receipt.jpg` — restaurant receipt → expect `NOT_A_BUSINESS_CARD`
9. `illegible_card.jpg` — extreme blur / total glare on what looks like a card → expect `validationStatus=ILLEGIBLE`

Each fixture has a paired JSON file in `tests/fixtures/expected/` asserting `validationStatus` and key fields. The blurry-but-readable case is the validation-tuning canary: if it ever flips to `ILLEGIBLE`, the prompt has gotten too strict and needs adjustment.

### Manual E2E (MVP)

- Desktop Safari → upload card → download vCard → import into macOS Contacts
- iOS Safari → upload via take-photo → tap "Add to Contacts" → verify native sheet shows correct fields
- Android Chrome → upload card → download → open in Google Contacts

---

## 10. Deployment Plan

### Platform: Render Web Service

| Setting | Value |
|---|---|
| Runtime | Docker |
| Start command | `uvicorn app:app --host 0.0.0.0 --port 8000` |
| Port | 8000 |
| Plan | Starter ($7/mo, always-on) |
| Auto-deploy | From `main` branch |
| Custom domain | `carded.io` (or fallback if unavailable) via Cloudflare DNS-only (grey cloud) |
| SSL | Let's Encrypt via Render |

### Environment Variables (Render dashboard)

| Variable | Purpose | Required |
|---|---|---|
| `OWNER_ANTHROPIC_API_KEY` | Graham's Anthropic key — recognized by `is_owner()` so he bypasses BYOK prompts; not used as a fallback for other users | Yes |
| `SESSION_SECRET` | Fernet key (32-byte url-safe base64) used to encrypt user-submitted API keys at rest in cookies | Yes |
| `DOWNLOAD_TOKEN_SECRET` | Secret used to sign short-lived download tokens (`itsdangerous` or HMAC) | Yes |
| `MAX_FILE_SIZE_MB` | Upload cap (default 10) | No |
| `EXTRACTION_TIMEOUT_SECONDS` | BAML call timeout (default 60) | No |
| `DOWNLOAD_TOKEN_TTL_SECONDS` | Download URL expiry (default 900 = 15 min) | No |

User API keys are **never** stored as env vars on Render — they live encrypted-only inside short-lived cookies.

### Dockerfile (sketch)

```dockerfile
FROM python:3.11-slim
WORKDIR /app

# System deps for pillow-heif (libheif) and curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    libheif-dev curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py main.py vcard_builder.py google_csv_builder.py session.py ./
COPY baml_client/ baml_client/
COPY validation/ validation/
COPY templates/ templates/
COPY static/ static/

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl --fail http://localhost:8000/health || exit 1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### DNS

- Register `carded.io` (or fallback). Manual step Graham will handle outside the build.
- In Cloudflare: `A` record for `carded.io` → Render IP (or `CNAME` for `www.carded.io` → `carded.onrender.com`), DNS-only (grey cloud).
- Render auto-provisions SSL.

### CI

- No GitHub Actions for MVP. Auto-deploy from `main` is sufficient.
- Post-MVP: add a `pytest` workflow on PR.

---

## 11. Build Kickoff Checklist

When Graham gives the green light:

1. Cut feature branch: `git checkout -b feat/carded-mvp-scaffold` from `master`.
2. Phase 1 — Prudvi scaffolds repo, defines BAML schema, ports session.py + validation, writes interface contract doc.
3. Once Phase 1 lands, fan out: Prudvi takes Phase 2 + Phase 3 in sequence (or interleaved), Kristy takes Phase 4 UI in parallel against the contract.
4. Phase 4 integration when Phase 2 + 3 are merged.
5. Phase 5 (G — deployment) and Phase 6 (Mike + Alex — QA + security) in parallel.
6. Final pre-merge checks: full test suite green, security review clean, manual E2E on iOS/Android passed.
7. Offer Graham a version bump (minor) and a commit message before any merge.

---

*End of plan. Awaiting Graham's green-light to begin Phase 1.*
