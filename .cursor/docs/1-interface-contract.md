---
github_issue: 8
---
# Interface Contract — Carded Phase 4

This document is the authoritative contract for the Phase 4 parallel build (Kristy on templates/frontend, Prudvi on `app.py`). Do not change endpoint shapes, error payloads, or cookie behavior without updating this document and getting approval from Graham.

---

## A. `POST /process` — Success Response

**Status:** 200 OK  
**Content-Type:** `application/json`

```json
{
  "token": "string (signed UUID, 15-minute TTL)",
  "card": {
    "validationStatus": "VALID",
    "validationMessage": "",
    "full_name": "string | null",
    "first_name": "string | null",
    "last_name": "string | null",
    "prefix": "string | null",
    "suffix": "string | null",
    "title": "string | null",
    "organization": "string | null",
    "department": "string | null",
    "phones": [
      {
        "number": "string",
        "type": "MOBILE | WORK | HOME | FAX | OTHER"
      }
    ],
    "emails": [
      {
        "address": "string",
        "type": "WORK | PERSONAL | OTHER"
      }
    ],
    "urls": ["string"],
    "address": {
      "street": "string | null",
      "street2": "string | null",
      "city": "string | null",
      "state": "string | null",
      "postal_code": "string | null",
      "country": "string | null"
    },
    "linkedin": "string | null",
    "twitter": "string | null",
    "instagram": "string | null",
    "note": "string | null"
  }
}
```

### `BusinessCardJson` Field Reference

All fields map directly to the Pydantic model in `baml_client/types.py`.

| Field | JSON type | Notes |
|---|---|---|
| `validationStatus` | string enum | `"VALID"`, `"NOT_A_BUSINESS_CARD"`, or `"ILLEGIBLE"` |
| `validationMessage` | string | Empty string when VALID; populated for the other two statuses |
| `full_name` | string \| null | Full name as printed |
| `first_name` | string \| null | First name, only if unambiguously separable |
| `last_name` | string \| null | Last name, only if unambiguously separable |
| `prefix` | string \| null | Name prefix (Dr., Prof.) |
| `suffix` | string \| null | Name suffix (Jr., MD, PhD) |
| `title` | string \| null | Job title exactly as printed |
| `organization` | string \| null | Company or org exactly as printed |
| `department` | string \| null | Department or division |
| `phones` | array of PhoneEntry | Empty array `[]` if none |
| `phones[].number` | string | Phone number exactly as printed (preserves formatting) |
| `phones[].type` | string enum | `"MOBILE"`, `"WORK"`, `"HOME"`, `"FAX"`, `"OTHER"` |
| `emails` | array of EmailEntry | Empty array `[]` if none |
| `emails[].address` | string | Email address exactly as printed |
| `emails[].type` | string enum | `"WORK"`, `"PERSONAL"`, `"OTHER"` |
| `urls` | array of string | Website URLs exactly as printed; empty array `[]` if none |
| `address` | AddressEntry \| null | Null if no address on card |
| `address.street` | string \| null | Street line 1 |
| `address.street2` | string \| null | Suite, unit, floor |
| `address.city` | string \| null | City |
| `address.state` | string \| null | State or province |
| `address.postal_code` | string \| null | ZIP or postal code |
| `address.country` | string \| null | Country |
| `linkedin` | string \| null | LinkedIn URL or handle as printed |
| `twitter` | string \| null | Twitter/X handle or URL as printed |
| `instagram` | string \| null | Instagram handle or URL as printed |
| `note` | string \| null | Any other text not covered above |

---

## B. `POST /process` — Error Responses

All error responses use `application/json`. The `detail` field is present only on errors where BAML provides a message.

### 422 NOT_A_BUSINESS_CARD

```json
{
  "error": "not_a_business_card",
  "message": "Please upload an image of a business card.",
  "detail": "a photo of a dog"
}
```

`detail` is the `validationMessage` returned by BAML (e.g., `"a restaurant receipt"`, `"a photo of a cat"`).

### 422 ILLEGIBLE

```json
{
  "error": "illegible",
  "message": "We couldn't read this card clearly. Please upload a sharper or higher-resolution copy.",
  "detail": "image is too blurry to read"
}
```

`detail` is the `validationMessage` returned by BAML.

> **SECURITY NOTE — Phase 4 implementation requirement.**
> The `detail` field on the two 422 responses (`not_a_business_card` and `illegible`) is **LLM-generated text** that reflects attacker-controlled image content. A crafted image could cause BAML to return a `validationMessage` containing HTML, JavaScript, or other markup. Phase 4 MUST treat `detail` as untrusted user content:
>
> 1. **When rendered server-side via Jinja2:** rely on Jinja's default autoescape (do NOT use `{{ detail | safe }}`, `{% autoescape false %}`, or `Markup(detail)`).
> 2. **When rendered client-side via JavaScript:** assign with `.textContent` or equivalent — **never** `.innerHTML`, `document.write`, `dangerouslySetInnerHTML`, or template literals interpolated into HTML strings.
> 3. **Optional defense in depth:** strip control characters and ASCII < 0x20 (except `\n`/`\t`) from `detail` server-side before responding, and cap its length (e.g., 200 chars).
>
> The same applies to any other field that carries LLM output back to the client (e.g., the `card.note` field, `card.organization`, etc.) — but those at least correspond to literal card content, while `detail` reflects the model's free-form classification message and is the highest-leverage XSS surface.

### 400 INVALID_FILE_TYPE

```json
{
  "error": "invalid_file_type",
  "message": "Unsupported file type. Please upload a JPEG, PNG, WebP, or HEIC image."
}
```

### 413 FILE_TOO_LARGE

```json
{
  "error": "file_too_large",
  "message": "File exceeds the 10 MB limit."
}
```

### 401 MISSING_API_KEY

```json
{
  "error": "missing_api_key",
  "message": "Please enter your Anthropic API key to continue."
}
```

Sent when the `carded_session` cookie is absent or cannot be decrypted.

### 502 EXTRACTION_FAILED

```json
{
  "error": "extraction_failed",
  "message": "AI extraction failed. Please try again."
}
```

Wraps BAML client errors, network timeouts, and unexpected exceptions from the extraction pipeline. Internal error details are never surfaced to the client.

### 429 RATE_LIMITED

```json
{
  "error": "rate_limited",
  "message": "Too many requests. Please wait a moment and try again."
}
```

> **Added in Phase 6 (L2).** `POST /process` and `POST /session/key` are protected by an in-process, per-client-IP sliding-window rate limiter (defense-in-depth abuse mitigation). When the per-client allowance is exceeded the endpoint returns 429 before any other processing. Limits are configurable via `RATE_LIMIT_PROCESS`, `RATE_LIMIT_SESSION_KEY`, and `RATE_LIMIT_WINDOW_SECONDS`. This is the only error code added since the Phase 4 contract was signed off.

---

## C. Download Endpoints

### `GET /download/vcf?token=<token>`

**Success — 200 OK**

```
Content-Type: text/vcard; charset=utf-8
Content-Disposition: attachment; filename="jamie-park.vcf"
```

Body is a valid vCard 3.0 string derived from the stored `BusinessCardJson`.

**Filename derivation:** `<last_name>-<first_name>.vcf` lowercased and hyphenated, falling back to `<full_name>.vcf`, then `card.vcf` if no name is available.

### `GET /download/csv?token=<token>`

**Success — 200 OK**

```
Content-Type: text/csv; charset=utf-8
Content-Disposition: attachment; filename="jamie-park.csv"
```

Body is a Google Contacts-compatible CSV string.

### Shared Error Responses

| Status | Condition |
|---|---|
| 404 Not Found | Token is unknown (was never issued) |
| 410 Gone | Token is known but has expired (>15 min TTL) |
| 400 Bad Request | Token signature is invalid (tampered or wrong secret), or the token was issued to a different session (binding mismatch — see below) |

> **Session binding added in Phase 6 (L3).** The signed token payload is a `[token_id, session_binding]` pair, where `session_binding` is an HMAC of the issuing request's `carded_session` cookie value. The download endpoints re-derive the binding from the request cookie and compare it in constant time, so a leaked or shared token cannot be redeemed from a different session. The endpoint shape, success responses, and the 404/410/400 status set are unchanged; only the 400 condition is broadened. Legacy single-string token payloads (pre-L3) are rejected with 400.

---

## D. `POST /session/key` — Set BYOK API Key

**Request body:**

```json
{
  "api_key": "sk-ant-api03-..."
}
```

**Success — 200 OK**

Sets cookie and returns empty body (or `{"ok": true}`).

```
Set-Cookie: carded_session=<fernet-token>; HttpOnly; Secure; SameSite=Lax; Max-Age=86400; Path=/
```

**400 Bad Request — invalid key format**

```json
{
  "error": "invalid_api_key_format",
  "message": "API key must begin with 'sk-ant-'."
}
```

---

## E. Session Cookie

| Property | Value |
|---|---|
| Name | `carded_session` |
| Value | Fernet-encrypted plaintext API key (output of `session.encrypt_api_key()`) |
| HttpOnly | Yes — not accessible to JavaScript |
| Secure | Yes — HTTPS only |
| SameSite | `Lax` |
| Max-Age | 86400 (24 hours) |
| Path | `/` |

The cookie value is opaque to the client. `session.decrypt_api_key()` recovers the plaintext key server-side. If decryption fails (tampered, expired Fernet TTL), treat as missing and return 401.

---

## F. Fixture Data

### Fully-Populated `BusinessCardJson` Example

Use this as a fixture for template development. All field types are present so no branch of the template goes untested.

```json
{
  "validationStatus": "VALID",
  "validationMessage": "",
  "full_name": "Jamie Park",
  "first_name": "Jamie",
  "last_name": "Park",
  "prefix": null,
  "suffix": null,
  "title": "Senior Designer",
  "organization": "Helio Studio",
  "department": "Brand & Experience",
  "phones": [
    { "number": "(415) 555-0182", "type": "WORK" },
    { "number": "+1-415-555-0199", "type": "MOBILE" }
  ],
  "emails": [
    { "address": "jamie@heliostudio.co", "type": "WORK" },
    { "address": "jamie.park@gmail.com", "type": "PERSONAL" }
  ],
  "urls": [
    "https://heliostudio.co",
    "https://jamiepark.design"
  ],
  "address": {
    "street": "340 Pine Street",
    "street2": "Suite 800",
    "city": "San Francisco",
    "state": "CA",
    "postal_code": "94104",
    "country": "USA"
  },
  "linkedin": "linkedin.com/in/jamiepark",
  "twitter": "@jamiepark",
  "instagram": "@heliostudio",
  "note": "Pronouns: they/them"
}
```

### Minimal Card (name + phone only)

```json
{
  "validationStatus": "VALID",
  "validationMessage": "",
  "full_name": "Chris Okafor",
  "first_name": "Chris",
  "last_name": "Okafor",
  "prefix": null,
  "suffix": null,
  "title": null,
  "organization": null,
  "department": null,
  "phones": [
    { "number": "212-555-0147", "type": "WORK" }
  ],
  "emails": [],
  "urls": [],
  "address": null,
  "linkedin": null,
  "twitter": null,
  "instagram": null,
  "note": null
}
```

### Error Response Examples

**NOT_A_BUSINESS_CARD (422)**

```json
{
  "error": "not_a_business_card",
  "message": "Please upload an image of a business card.",
  "detail": "a photo of a golden retriever"
}
```

**ILLEGIBLE (422)**

```json
{
  "error": "illegible",
  "message": "We couldn't read this card clearly. Please upload a sharper or higher-resolution copy.",
  "detail": "image is too blurry to read"
}
```

**INVALID_FILE_TYPE (400)**

```json
{
  "error": "invalid_file_type",
  "message": "Unsupported file type. Please upload a JPEG, PNG, WebP, or HEIC image."
}
```

**FILE_TOO_LARGE (413)**

```json
{
  "error": "file_too_large",
  "message": "File exceeds the 10 MB limit."
}
```

**MISSING_API_KEY (401)**

```json
{
  "error": "missing_api_key",
  "message": "Please enter your Anthropic API key to continue."
}
```

**EXTRACTION_FAILED (502)**

```json
{
  "error": "extraction_failed",
  "message": "AI extraction failed. Please try again."
}
```
