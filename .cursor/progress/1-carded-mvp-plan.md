# Carded MVP Plan

**Status:** Draft — awaiting Graham's sign-off before any code is written.  
**Date:** 2026-05-01  
**Author:** Adan (planning sub-agent)

---

## 1. Summary

Carded is a web application (mobile + desktop) that accepts a photo or screenshot of a business card and uses a vision-capable LLM — wrapped in a BAML schema — to extract structured contact fields strictly as they appear on the card. It then generates a downloadable vCard (.vcf) for Apple/iOS contacts and a Google Contacts–compatible CSV, and on mobile it serves the .vcf in a way that triggers the native "Add Contact" flow. The app follows the Receipt Ranger pattern (Python backend, BAML for deterministic AI extraction, Docker + Render deployment) but is simpler: no persistent storage, no accounts, no Google Sheets integration.

The key design constraint is that the AI **never infers missing data** — it reports only what is literally printed on the card. BAML enforces this via a strict schema with explicit `null`/omit semantics and targeted prompt instructions.

---

## 2. Architecture Overview

```
User (mobile or desktop browser)
        |
        | uploads image (JPEG/PNG/WEBP/HEIC)
        v
+------------------------+
|  FastAPI backend        |
|  (Python 3.11)         |
|                        |
|  1. Validate image     |
|  2. Prompt-injection   |
|     check (text fields)|
|  3. Call BAML layer    |
|     (vision LLM)       |
|  4. Build vCard + CSV  |
|  5. Return downloads   |
+------------------------+
        |
        |  BAML function call
        v
+-------------------------------+
|  BAML ExtractBusinessCard()   |
|  → claude-sonnet-4 (vision)   |
|  → returns typed BusinessCard |
+-------------------------------+
        |
        v
+---------------------------+
|  Output generators        |
|  vcard_builder.py         |
|  google_csv_builder.py    |
+---------------------------+
        |
        v
Downloads served to browser:
  - contact.vcf  (Content-Type: text/vcard)
  - contacts.csv (Content-Type: text/csv)

On mobile iOS/Android:
  - vcf served with correct headers → browser/OS
    opens native "Add Contact" sheet
```

---

## 3. Tech Stack Recommendation

### Frontend Framework: FastAPI + Jinja2 templates (NOT Streamlit)

**Recommendation: FastAPI with server-rendered Jinja2 templates + a small amount of vanilla JS / Alpine.js for interactivity.**

Streamlit is not the right call here. The reasons:
- Streamlit's default aesthetic is functional but not "modern and attractive." Even with CSS overrides (which Receipt Ranger already does with `st.markdown(unsafe_allow_html=True)` hacks), achieving a polished card-motif UI requires fighting the framework. See Receipt Ranger's `app.py`: it hides file list elements, injects custom CSS, and still looks like a Streamlit app.
- Streamlit has no ergonomic way to serve a file with custom headers (`Content-Type: text/vcard`, `Content-Disposition: attachment; filename="contact.vcf"`). The download button component sets its own content-type. Triggering the iOS native "Add Contact" flow requires serving a `.vcf` at a URL the browser navigates to — not a Streamlit download button.
- Mobile experience: Streamlit's responsive design is limited. Camera capture (`<input type="file" accept="image/*" capture="camera">`) works in mobile browsers but requires custom HTML in Streamlit — another `st.markdown(unsafe_allow_html=True)` hack.
- The vCard handoff on iOS works best as a direct GET request to a URL that returns `text/vcard` — clean to implement in FastAPI, awkward in Streamlit.

**FastAPI + Jinja2** gives us:
- Full control over HTML/CSS — we can build the card motif exactly
- Native `FileResponse` / `StreamingResponse` with any Content-Type headers
- A clean `/process` POST endpoint that takes the image, returns JSON with download links
- Direct route for `/download/vcf` and `/download/csv` with proper headers
- Works identically on Render via Docker (same as Receipt Ranger)

**What about React/Next or HTMX?**
- React/Next adds a build step, node dependency, and separate frontend service — overkill for a single-page tool with no client-side state beyond the current card session.
- HTMX would work but adds another dependency; Jinja2 + a few lines of vanilla JS/Alpine.js for the upload preview is cleaner.
- Reflex and Gradio both constrain the UI similarly to Streamlit.

**Verdict:** FastAPI + Jinja2 + vanilla CSS (or Tailwind CDN for the card motif styling). Alpine.js (CDN) for reactive upload preview and loading state — no build step required.

---

### Hosting: Render (confirmed)

Render is the right call. Reasons:
- Receipt Ranger is already on Render via Docker — Graham knows the workflow
- Render supports Docker deployments, custom domains, auto-deploy from `main`
- The FastAPI app is a simple HTTP server (port 8000), no WebSocket dependency (which caused Receipt Ranger's failed App Runner migration)
- Render Starter plan ($7/month) is sufficient for this stateless, low-traffic MVP
- Render handles SSL via Let's Encrypt + Cloudflare DNS setup is already known

No changes from Receipt Ranger's Render setup. Same Docker + `render.yaml` approach.

---

### Vision Model: Claude Sonnet 4 via Anthropic (confirmed)

Receipt Ranger uses `claude-sonnet-4-20250514` as the primary model in BAML (`CustomSonnet4`). This is the correct choice for Carded too:
- Business card OCR requires reading small, dense text at unusual angles — Claude Sonnet 4's vision capability is strong here
- BAML's Anthropic provider is well-tested in Receipt Ranger
- GPT-4o/5 vision is comparable but adds OpenAI as a second required API key; keeping Anthropic-only simplifies secrets management
- Gemini Pro vision is an option but less battle-tested in this BAML setup

**Primary:** `claude-sonnet-4-20250514` via BAML `CustomSonnet4` client  
**Fallback (optional, Phase 5 decision):** `claude-opus-4` for difficult/degraded images

The app will use Graham's ANTHROPIC_API_KEY on the server — no "bring your own key" model needed for MVP (Carded is simpler than Receipt Ranger). This is a deliberate simplification.

---

### BAML: Same version and pattern as Receipt Ranger

`baml-py>=0.218.0`, `generators.baml` targeting `python/pydantic`, sync client mode. Do not edit `baml_client/` directly.

---

## 4. Data Model / BAML Schema

### Design Principles
- Every field is either populated from what's literally on the card or `null` (Python `None` / BAML `null`).
- **No field defaults to an inferred value.** If the field isn't on the card, it's `null`.
- Arrays (phones, emails, urls) are empty lists `[]` when nothing is present — not `null`.
- The model does NOT augment with external knowledge (no LinkedIn lookups, no inferring email from name+domain, etc.).

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

class PhoneEntry {
    number string       @description("Phone number exactly as printed on the card. Preserve formatting (dashes, parens, country codes).")
    type PhoneType      @description("Type of phone number. If ambiguous, use WORK for a business card. If labeled (e.g., 'M:', 'Cell:', 'F:'), use the appropriate type.")
}

class EmailEntry {
    address string      @description("Email address exactly as printed on the card.")
    type EmailType      @description("Type of email. If ambiguous, use WORK for a business card.")
}

class AddressEntry {
    street string?      @description("Street address line 1 (e.g., '123 Main St'). Null if not on card.")
    street2 string?     @description("Suite, unit, floor, etc. Null if not on card.")
    city string?        @description("City. Null if not on card.")
    state string?       @description("State or province. Null if not on card.")
    postal_code string? @description("ZIP or postal code. Null if not on card.")
    country string?     @description("Country. Null if not on card.")
}

class BusinessCard {
    isValidCard bool            @description("True only if this image clearly shows a business card or contact card. False for other images (photos, receipts, documents, etc.).")
    validationError string      @description("If isValidCard is false, brief explanation. If isValidCard is true, empty string.")

    // Identity
    full_name string?           @description("Full name as printed. Null if not present.")
    first_name string?          @description("First name only if it can be unambiguously separated from the full name. Null otherwise.")
    last_name string?           @description("Last name only if it can be unambiguously separated from the full name. Null otherwise.")
    prefix string?              @description("Name prefix (e.g., 'Dr.', 'Prof.'). Null if not present.")
    suffix string?              @description("Name suffix (e.g., 'Jr.', 'MD', 'PhD'). Null if not present.")

    // Professional
    title string?               @description("Job title exactly as printed (e.g., 'Senior Software Engineer'). Null if not on card.")
    organization string?        @description("Company or organization name exactly as printed. Null if not on card.")
    department string?          @description("Department or division if printed. Null if not on card.")

    // Contact arrays
    phones PhoneEntry[]         @description("All phone numbers on the card. Empty array if none.")
    emails EmailEntry[]         @description("All email addresses on the card. Empty array if none.")
    urls string[]               @description("All website URLs on the card, exactly as printed. Empty array if none.")

    // Address
    address AddressEntry?       @description("Mailing/business address if printed on the card. Null if no address present.")

    // Social / other
    linkedin string?            @description("LinkedIn profile URL or handle if printed on card. Null if not present.")
    twitter string?             @description("Twitter/X handle or URL if printed on card. Null if not present.")
    instagram string?           @description("Instagram handle or URL if printed on card. Null if not present.")

    // Catch-all
    note string?                @description("Any other text on the card that doesn't fit the above fields (taglines, QR code description, etc.). Null if nothing extra.")
}
```

### Critical Prompt Instructions (in the BAML template string)

```
STRICT EXTRACTION RULES — READ CAREFULLY:
1. Only extract information that is literally printed or displayed on this business card.
2. Do NOT infer, guess, or supplement any field with outside knowledge.
3. Do NOT derive an email address from a name and domain if it is not explicitly written.
4. Do NOT look up or add phone numbers, addresses, titles, or social handles not shown.
5. Do NOT "complete" partial information (e.g., if only "John" appears with no last name, first_name="John", last_name=null).
6. Preserve exact formatting for phone numbers and URLs as they appear on the card.
7. If a field's value is ambiguous or unclear due to image quality, set it to null rather than guessing.
8. For PhoneType: if a phone is labeled (M:, Cell:, Mobile:, Fax:, F:, Work:, etc.) use that type. If unlabeled on a business card, default to WORK.
9. Do NOT set isValidCard to true for images that are not business cards.
```

### Handling Missing Fields

| Situation | Behavior |
|---|---|
| Single scalar field not on card | `null` |
| Phone/email/url arrays empty | `[]` (not null) |
| Address present but some sub-fields missing | `AddressEntry` with missing sub-fields as `null` |
| No address at all | `address: null` |
| Image quality too poor to read a field | `null` |
| Text present but ambiguous (e.g., unclear if phone or fax) | Use best-readable type; note in BAML description |

---

## 5. Output Formats

### vCard 3.0 Mapping

vCard 3.0 is the right choice (not 4.0) — iOS Contacts fully supports 3.0 and it has broader compatibility. We can serve as 4.0 optionally but 3.0 is the default.

| BusinessCard field | vCard 3.0 property | Notes |
|---|---|---|
| `full_name` | `FN:` | If null, construct from first_name + last_name |
| `first_name`, `last_name`, `prefix`, `suffix` | `N:last;first;;;prefix;suffix` | vCard N field order: Last;First;Middle;Prefix;Suffix |
| `title` | `TITLE:` | |
| `organization` + `department` | `ORG:Organization;Department` | Department in second field of ORG |
| `phones[i].number` (MOBILE) | `TEL;TYPE=CELL,VOICE:number` | |
| `phones[i].number` (WORK) | `TEL;TYPE=WORK,VOICE:number` | |
| `phones[i].number` (HOME) | `TEL;TYPE=HOME,VOICE:number` | |
| `phones[i].number` (FAX) | `TEL;TYPE=FAX:number` | |
| `emails[i].address` (WORK) | `EMAIL;TYPE=WORK,INTERNET:addr` | |
| `emails[i].address` (PERSONAL) | `EMAIL;TYPE=HOME,INTERNET:addr` | |
| `urls[i]` | `URL:url` | Multiple URL lines |
| `address` | `ADR;TYPE=WORK:;;street;city;state;postal;country` | |
| `linkedin` | `X-SOCIALPROFILE;TYPE=linkedin:value` | Extended property |
| `twitter` | `X-SOCIALPROFILE;TYPE=twitter:value` | |
| `note` | `NOTE:` | |

**Boilerplate:**
```
BEGIN:VCARD
VERSION:3.0
...fields...
END:VCARD
```

**Filename:** `{last_name}_{first_name}.vcf` or `contact.vcf` if name unknown.

**MIME type for serving:** `text/vcard` with `Content-Disposition: attachment; filename="contact.vcf"`

---

### Google Contacts CSV Mapping

Google Contacts CSV uses specific column headers. Reference: https://support.google.com/contacts/answer/1069522

| BusinessCard field | Google CSV column |
|---|---|
| `first_name` | `First Name` |
| `last_name` | `Last Name` |
| `prefix` | `Title` (honorific prefix) |
| `suffix` | `Suffix` |
| `organization` | `Company` |
| `title` | `Job Title` |
| `department` | `Department` |
| `phones[0]` (MOBILE) | `Mobile Phone` |
| `phones[0]` (WORK) | `Work Phone` |
| `phones[0]` (FAX) | `Work Fax` |
| `emails[0]` (WORK) | `E-mail Address` |
| `emails[1]` | `E-mail 2 Address` |
| `urls[0]` | `Web Page` |
| `address.street` | `Business Street` |
| `address.city` | `Business City` |
| `address.state` | `Business State` |
| `address.postal_code` | `Business Postal Code` |
| `address.country` | `Business Country/Region` |
| `note` | `Notes` |

Multiple phones of same type: use `Work Phone`, `Work Phone 2`, etc.
Filename: `contacts.csv`

---

## 6. Mobile Contact Handoff

### What is Feasible from a Web App

**iOS (Safari on iPhone/iPad):**
- Serving a `.vcf` file with `Content-Type: text/vcard` and `Content-Disposition: attachment; filename="contact.vcf"` causes iOS Safari to automatically open the Contacts app and present the "New Contact" / "Add to Existing Contact" sheet.
- This works reliably without any native app. It is the same mechanism used by email clients and websites to share contacts.
- Implementation: a FastAPI route `/download/vcf` returns `FileResponse` (or `StreamingResponse`) with the correct headers.
- **Critically:** the link must be a direct browser navigation (GET request), not a JavaScript blob download. FastAPI can serve this as a normal anchor link `<a href="/download/vcf">Add to Contacts</a>`. On mobile, tapping this link will trigger the iOS share/add-contact flow.

**Android (Chrome):**
- Android also handles `.vcf` files, but behavior varies by launcher/contacts app. Chrome on Android will typically download the file and then show a "Open with Contacts" option in the notification bar.
- The same `text/vcard` + `Content-Disposition: attachment` approach works. It is not as seamless as iOS but functional.
- Android contacts apps (Google Contacts, Samsung Contacts) all import `.vcf` natively.

**What Requires a Native App (out of scope for MVP):**
- Directly writing to the device contacts database via a JavaScript API — there is no web standard for this. The Web Contacts API (`navigator.contacts.select`) is read-only (for autofill use cases) and does not support writing new contacts.
- A future React Native app could use the `expo-contacts` or `react-native-contacts` library to write directly to the contacts database. This is the Phase 2 path.
- Custom "Add to iPhone contacts" share extension — requires native iOS development.

**Practical Implementation (MVP):**
1. After extraction, show two prominent buttons:
   - "Add to Contacts" — links to `/download/vcf` (triggers iOS native flow, Android download+open)
   - "Download for Google" — links to `/download/csv`
2. A "Download vCard" link (same as Add to Contacts) for desktop users who want the file.
3. On desktop, the `.vcf` will open in the system contacts app (macOS Contacts) or download depending on browser settings.

**No JavaScript tricks required.** Simple `<a href>` links with proper server-side headers are sufficient.

---

## 7. Project Layout

Mirroring Receipt Ranger's structure, adapted for Carded:

```
carded/
├── app.py                      # FastAPI app: routes, file upload, download endpoints
├── main.py                     # Core pipeline: extraction, vcard/csv generation
├── vcard_builder.py            # Builds vCard (.vcf) string from BusinessCard dict
├── google_csv_builder.py       # Builds Google Contacts CSV from BusinessCard dict
├── pyproject.toml              # Project metadata, dependencies (Python 3.11+)
├── requirements.txt            # Pinned production dependencies
├── Dockerfile                  # Same pattern as Receipt Ranger (python:3.11-slim)
├── .bumpversion.cfg            # bump2version config
├── README.md                   # User-facing docs
├── AGENTS.md                   # AI agent instructions (like Receipt Ranger)
├── CLAUDE.md                   # Project-specific Claude instructions
│
├── baml_src/                   # BAML source definitions (DO NOT auto-edit)
│   ├── business_card.baml      # BusinessCard model + ExtractBusinessCard function
│   ├── clients.baml            # LLM provider config (Anthropic Sonnet 4)
│   └── generators.baml         # Python/Pydantic output, sync mode
│
├── baml_client/                # Auto-generated (DO NOT edit manually)
│   └── ...
│
├── validation/                 # Prompt injection detection (port from Receipt Ranger)
│   ├── __init__.py
│   ├── detector.py
│   └── sanitizer.py
│
├── static/                     # Frontend assets
│   ├── css/
│   │   └── style.css           # Card motif styles
│   ├── js/
│   │   └── app.js              # Upload preview, loading states (Alpine.js or vanilla)
│   └── img/
│       └── logo.svg            # Carded logo/icon
│
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Base layout with card motif
│   ├── index.html              # Upload page
│   └── result.html             # Extracted contact + download buttons
│
├── tests/
│   ├── __init__.py
│   ├── test_main.py            # Unit tests: extraction pipeline logic
│   ├── test_vcard_builder.py   # Unit tests: vCard generation
│   ├── test_google_csv.py      # Unit tests: Google CSV generation
│   └── test_app.py             # FastAPI route tests (TestClient)
│
├── data/
│   └── sample_cards/           # Sample card images for integration tests
│
├── output/                     # Generated at runtime (gitignored)
│
├── .env.example                # Template for required env vars
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

### Phase 1 — Project Scaffolding + BAML Schema
**Deliverables:**
- Repo structure, `pyproject.toml`, `requirements.txt`
- `AGENTS.md`, `CLAUDE.md` with project rules
- `baml_src/business_card.baml` — complete BusinessCard schema + ExtractBusinessCard function
- `baml_src/clients.baml` — Anthropic Sonnet 4 client
- `baml_src/generators.baml` — Python/Pydantic sync
- `baml-cli generate` run → `baml_client/` populated
- `.env.example`
- `validation/` ported from Receipt Ranger

**Sub-agent:** Prudvi (backend architect) — schema design, project setup  
**Dependencies:** None  
**Parallel with:** Nothing (must be first; BAML client must exist for everything else)

---

### Phase 2 — Extraction Pipeline
**Deliverables:**
- `main.py`: `extract_card_from_bytes(image_data, mime_type) -> dict`
- Image validation (MIME type check)
- Prompt injection validation for any text inputs (port from Receipt Ranger)
- `BusinessCard` dict normalization (None handling, field coercion)
- Timeout handling (60s, same pattern as Receipt Ranger)
- Unit tests: `tests/test_main.py` — mock BAML client, test extraction logic

**Sub-agent:** Prudvi (backend architect)  
**Dependencies:** Phase 1 (BAML client must exist)  
**Parallel with:** Phase 3 can start in parallel once Phase 1 is done

---

### Phase 3 — Output Generators (vCard + Google CSV)
**Deliverables:**
- `vcard_builder.py`: `build_vcf(card: dict) -> str` — produces vCard 3.0 string
- `google_csv_builder.py`: `build_google_csv(card: dict) -> str` — produces Google Contacts CSV
- Both handle `null` fields gracefully (omit from output, don't write empty properties)
- Unit tests: `tests/test_vcard_builder.py`, `tests/test_google_csv.py`
  - Test with fully-populated card
  - Test with sparse card (only name + one phone)
  - Test with empty arrays
  - Test with all-null card (edge case)

**Sub-agent:** Prudvi (backend architect)  
**Dependencies:** Phase 1 (BusinessCard type from baml_client)  
**Parallel with:** Phase 2

---

### Phase 4 — FastAPI App + UI
**Deliverables:**
- `app.py`: FastAPI app with routes:
  - `GET /` — renders `index.html` (upload form)
  - `POST /process` — accepts image, calls extraction pipeline, stores result in session/temp, returns JSON with card data and download tokens
  - `GET /download/vcf?token=...` — serves vCard with `text/vcard` header
  - `GET /download/csv?token=...` — serves Google CSV
  - `GET /health` — health check endpoint
- Session handling: use a short-lived in-memory dict (keyed by UUID token) to hold the processed card data between `/process` and `/download`. No persistent storage needed.
- `templates/`: `base.html`, `index.html`, `result.html`
- `static/css/style.css`: card motif design — clean, modern (think business card aesthetic: crisp typography, subtle drop shadows, card-shaped containers)
- Mobile camera capture: `<input type="file" accept="image/*" capture="environment">` on mobile
- Upload preview (show thumbnail before processing)
- Loading state during AI extraction
- FastAPI `TestClient` tests: `tests/test_app.py`

**Sub-agent:** Kristy (frontend/UI specialist) for templates + CSS; Prudvi for FastAPI routes  
**Dependencies:** Phases 2 + 3  
**Parallel with:** Nothing — needs pipeline complete

---

### Phase 5 — Deployment
**Deliverables:**
- `Dockerfile` (python:3.11-slim, FastAPI on port 8000, `uvicorn app:app`)
- `render.yaml` or Render dashboard setup notes
- Env var documentation
- Health check route verified
- Local `docker build && docker run` smoke test

**Sub-agent:** G (infrastructure/docs)  
**Dependencies:** Phase 4  
**Parallel with:** Nothing

---

### Phase 6 — Tests + Security Review
**Deliverables:**
- Complete test suite with all tests passing (`pytest`)
- Integration tests with sample card images (at least 3 fixture cards: dense card, sparse card, non-English card)
- Mike (QA) runs test review
- Alex (security) runs security review: prompt injection surface, file upload validation, MIME spoofing, token guessing for download URLs

**Sub-agent:** Mike (QA expert) for test coverage review; Alex (security expert) for security review  
**Dependencies:** Phase 4  
**Parallel with:** Phase 5 (deployment can happen concurrently with test completion)

---

## 9. Testing Plan

### Unit Tests (deterministic, no LLM calls)

**`tests/test_vcard_builder.py`**
- `test_full_card_produces_valid_vcf()` — all fields populated, check FN, N, TEL, EMAIL, ADR, ORG, TITLE, URL
- `test_sparse_card_omits_null_fields()` — name + one phone only; verify no empty `EMAIL:` lines
- `test_multiple_phones()` — two phones with different types → two TEL lines with correct TYPE params
- `test_phone_type_mapping()` — MOBILE → `TYPE=CELL,VOICE`, WORK → `TYPE=WORK,VOICE`, FAX → `TYPE=FAX`
- `test_address_partial()` — address with only city+state, no street → correct ADR formatting
- `test_vcf_encoding()` — non-ASCII characters in name (e.g., accented chars) handled correctly
- `test_filename_generation()` — last_name + first_name → correct filename; null names → `contact.vcf`

**`tests/test_google_csv.py`**
- `test_full_card_csv_headers()` — verify all expected Google CSV column headers present
- `test_null_fields_produce_empty_cells()` — null fields → empty string in CSV, not "None"
- `test_multiple_emails_overflow()` — 3 emails → E-mail Address, E-mail 2 Address, E-mail 3 Address
- `test_phone_type_routing()` — Mobile → Mobile Phone column, Work → Work Phone column

**`tests/test_main.py`**
- `test_extract_calls_baml()` — mock `b.ExtractBusinessCard`, verify correct mapping
- `test_invalid_card_returns_error()` — `isValidCard=False` → correct error dict returned
- `test_image_validation()` — reject unsupported MIME types
- `test_null_handling()` — BAML returns null fields → Python dict has `None` values correctly

**`tests/test_app.py`** (FastAPI TestClient)
- `test_health_endpoint()` — GET /health returns 200
- `test_upload_valid_image()` — POST /process with valid image → 200 + JSON with card data
- `test_upload_invalid_filetype()` — POST /process with .pdf → 400 error
- `test_download_vcf()` — GET /download/vcf?token=... → 200, Content-Type: text/vcard
- `test_download_csv()` — GET /download/csv?token=... → 200, Content-Type: text/csv
- `test_download_invalid_token()` — GET /download/vcf?token=bogus → 404

### Integration Tests (with real BAML/LLM — optional, gated by env var `RUN_INTEGRATION_TESTS=1`)

**Fixture cards** (store in `data/sample_cards/`):
1. `dense_english_card.jpg` — full name, title, org, 2 phones, email, website, address
2. `sparse_card.jpg` — name + phone only
3. `non_english_card.jpg` — Japanese or Spanish card (test encoding)
4. `not_a_card.jpg` — photo of a landscape (must return `isValidCard=False`)

For each fixture, store expected output in a JSON fixture file and assert key fields match.

### E2E Tests (manual for MVP)

- Upload card on desktop Safari → download vCard → import into macOS Contacts
- Upload card on iOS Safari → tap "Add to Contacts" → verify native sheet appears with correct data
- Upload card on Android Chrome → download vCard → open with Google Contacts

---

## 10. Deployment Plan

### Platform: Render Web Service

**Configuration:**
- Runtime: Docker
- Build command: `docker build`
- Start command: `uvicorn app:app --host 0.0.0.0 --port 8000`
- Port: 8000
- Plan: Starter ($7/month), always-on
- Auto-deploy from `main` branch

**Environment Variables (set in Render dashboard):**

| Variable | Purpose | Required |
|---|---|---|
| `ANTHROPIC_API_KEY` | Anthropic API key for vision model | Yes |
| `SESSION_SECRET` | Secret key for generating/validating download tokens (use `secrets.token_hex(32)`) | Yes |
| `MAX_FILE_SIZE_MB` | Max upload size in MB (default: 10) | No |
| `EXTRACTION_TIMEOUT_SECONDS` | LLM call timeout (default: 60) | No |

**No** `SESSION_SECRET` encryption of user API keys is needed — unlike Receipt Ranger, Carded uses Graham's server-side key only. The `SESSION_SECRET` here is for signing download tokens.

**Dockerfile (sketch):**
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py main.py vcard_builder.py google_csv_builder.py ./
COPY baml_client/ baml_client/
COPY validation/ validation/
COPY templates/ templates/
COPY static/ static/
EXPOSE 8000
HEALTHCHECK CMD curl --fail http://localhost:8000/health || exit 1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
```

**DNS:** Same Cloudflare setup as Receipt Ranger — DNS-only (grey cloud), Render handles SSL.

**CI:** For MVP, no CI pipeline required. Auto-deploy from `main` on Render is sufficient. A GitHub Actions workflow for `pytest` on PR can be added post-MVP.

---

## 11. Open Questions for Graham

1. **Domain name:** Do you have a domain for Carded, or should the plan assume the default Render URL (`carded.onrender.com`) for MVP? This affects the deployment plan but not the build.

2. **API key model:** The plan assumes Graham's `ANTHROPIC_API_KEY` lives on the server (no user-supplied keys). This is simpler but means all AI costs come from Graham's account. Is this the right model for MVP, or should it support "bring your own key" like Receipt Ranger?

3. **HEIC support:** iPhones shoot in HEIC format. HEIC business card photos taken directly in-app would fail without a HEIC→JPEG conversion step (the `pillow-heif` library handles this). Should HEIC be supported in MVP? It adds one dependency and a conversion step.

4. **Card scan via camera on the upload page:** Should the primary mobile UI prompt the user to take a photo (using `capture="environment"` on the file input), or should it default to "choose from library"? This is a UX copy/default decision, not a technical one.

5. **Sub-agent for build:** Kristy (frontend) + Prudvi (backend) will likely do most of the work. Do you want one agent to own the whole build (simpler coordination), or is true parallel work (Kristy on templates while Prudvi does the pipeline) the preference? Parallel requires careful interface contracts upfront.

---

*End of plan. Awaiting Graham's review and sign-off.*
