# Carded

Carded scans a business card image and extracts structured contact information using Claude's vision model (via BAML). Extracted data can be downloaded as a vCard (.vcf) for import into Apple Contacts, Google Contacts, or any vCard-compatible app, or as a Google Contacts CSV.

**Status: in development**

## Quickstart

```bash
git clone <repo-url> && cd carded
cp .env.example .env          # fill in SESSION_SECRET (see .env.example for how to generate one)
pip install -r requirements.txt
baml-cli generate             # regenerate baml_client/ from baml_src/
uvicorn app:app --reload
```

Then open `http://localhost:8000` in your browser. You'll be prompted to enter your Anthropic API key before uploading a card.

## Requirements

- Python 3.11+
- An Anthropic API key (BYOK — Carded never stores your key in plaintext)

## License

TBD
