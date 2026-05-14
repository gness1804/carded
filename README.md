# Carded

Carded scans a business card image and extracts structured contact information using Claude's vision model (via BAML). Extracted data can be downloaded as a vCard (.vcf) for import into Apple Contacts, Google Contacts, or any vCard-compatible app, or as a Google Contacts CSV.

**Status: live on Render (`*.onrender.com`).** Custom domain cutover to `carded.io` deferred — see `.cursor/features/1-custom-domain-carded-io-cutover.md`.

## Quickstart

### Run locally

```bash
git clone <repo-url> && cd carded
cp .env.example .env          # fill in SESSION_SECRET (see .env.example for how to generate one)
pip install -r requirements.txt
baml-cli generate             # regenerate baml_client/ from baml_src/
uvicorn app:app --reload
```

Then open `http://localhost:8000` in your browser. You'll be prompted to enter your Anthropic API key before uploading a card.

### Run in Docker

```bash
docker build -t carded .
SESSION_SECRET=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
DOWNLOAD_TOKEN_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
docker run --rm -p 8000:8000 \
  -e SESSION_SECRET="$SESSION_SECRET" \
  -e DOWNLOAD_TOKEN_SECRET="$DOWNLOAD_TOKEN_SECRET" \
  -e COOKIE_SECURE=false \
  carded
```

### Deploy

See `.cursor/docs/2-phase-5-deployment-runbook.md` for the Render + Cloudflare runbook.

## Requirements

- Python 3.11+
- An Anthropic API key (BYOK — Carded never stores your key in plaintext)

## License

TBD
