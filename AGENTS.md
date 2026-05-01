Carded

Project-specific instructions for AI agents working on this codebase.

## Project Overview

Carded is a FastAPI web application that scans business card images through an LLM (via BAML) to extract structured contact information. Users supply their own Anthropic API key (BYOK model); the key is Fernet-encrypted and stored in an HttpOnly session cookie. Extracted data can be downloaded as a vCard (.vcf) or Google Contacts CSV.

Current status: **in development** — Phase 1 scaffolding complete.

## Cardinal Rule

**The AI never infers — it only reports literal card content.**

The validation gate in `baml_src/business_card.baml` is load-bearing. Every field must be populated exactly as printed on the card or set to null/[]. Do not relax, paraphrase, or work around the extraction rules without explicit approval from Graham.

## Tech Stack

- **FastAPI** — web framework and API layer
- **Jinja2** — server-side HTML templates
- **BAML** — structured LLM output (function definitions in `baml_src/`)
- **Anthropic Claude Sonnet 4** (`claude-sonnet-4-20250514`) — vision model for card extraction
- **Fernet (cryptography)** — BYOK session encryption in `session.py`

## Where the Plan Lives

Full MVP plan: `.cursor/progress/2-carded-mvp-plan-final.md`

## BAML Rules

- **Do not edit `baml_client/` by hand.** It is auto-generated.
- After editing any `.baml` file in `baml_src/`, regenerate with:

```bash
baml-cli generate
```

Run this from the repo root.

## Project Structure

```
carded/
├── app.py                      # FastAPI application (Phase 4)
├── session.py                  # Fernet BYOK encryption
├── validation/                 # Prompt injection defense
├── baml_src/                   # BAML source definitions
│   ├── business_card.baml      # BusinessCard model + ExtractBusinessCard function
│   ├── clients.baml            # LLM client config (CustomSonnet4)
│   └── generators.baml         # Code generation config
├── baml_client/                # Auto-generated Python client (DO NOT edit manually)
├── static/                     # CSS, JS, images (Phase 4 — Kristy)
├── templates/                  # Jinja2 HTML templates (Phase 4 — Kristy)
├── tests/                      # Test suite (Phases 2/3)
└── .cursor/
    ├── docs/                   # Interface contracts and design docs
    ├── features/               # Feature specs (CFS)
    ├── progress/               # Handoff documents for agent continuity
    └── tmp/                    # Temporary/debug files (gitignored)
```

## Rules

- Do not edit anything in `baml_client/`. It is auto-generated.
- Follow PEP 8 for all Python code.
- Output files and runtime data go in `data/` or gitignored paths.
- Debug/temp files go in `.cursor/tmp/`.
- The interface contract at `.cursor/docs/1-interface-contract.md` is the source of truth for Phase 4 parallelization.
