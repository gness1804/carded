---
github_issue: 1
---
# Extraction errors on real-world card: hallucinated email local-part, wrong phone digits, OCR misread of title

## Working directory

`~/Desktop/carded`

## Contents

## Summary

Extraction returned incorrect contact data for a real-world business card on the deployed app (version `0.1.1`). Three field errors, one of which appears to violate the cardinal rule in `baml_src/business_card.baml` — the model output text that is not literally present on the card.

> Personal contact details from the card are redacted from this issue body to keep them out of public indexing. The error patterns below are detailed enough to investigate; the card photo + output screenshot can be attached privately later if needed.

## Errors

1. **Email — hallucinated local-part (worst).** The actual local-part has the form `<short_prefix>.<role_word>3058@gmail.com`. The output replaced `<role_word>` with a substring matching the **city name** appearing in a different region of the card (the organization tagline), and dropped the `.` separator. The `3058` numeric suffix was preserved. The substituted substring does **not** appear anywhere in the email region of the card — this is inference, not transcription.

2. **Phone — two wrong digits.** Both errors fall in the area-code / exchange portion of a 10-digit US number. Pattern smells like OCR ambiguity on a dense numeric run (e.g. `5↔0`, `8↔3`).

3. **Title — OCR misread + punctuation.** A 2-syllable word starting with "P" was misread as a 3-syllable, visually similar "P—" word. A spurious period was also inserted after the abbreviated "Pct".

4. **Address — borderline.** The "City, State" line on the card is the organization's tagline beneath the org name, not a postal mailing address. The extractor populated the `address` field with it. Arguably a bug, arguably a reasonable interpretation — flagging for evaluation.

## Severity

**High.** A user importing this extracted contact gets the *wrong* phone and the *wrong* email — worse than no contact at all. The email hallucination in particular is the exact failure mode that the STEP 1 validation block in `baml_src/business_card.baml` was designed to prevent.

## Suggested investigation

- **Reproducibility.** Re-upload the same card 3–5 times. Deterministic errors point to OCR / prompt; stochastic errors point to sampling.
- **Other cards.** Sweep the fixtures in `test-cards/` for similar failures.
- **Prompt audit.** Review the STEP 1 validation block in `baml_src/business_card.baml` for anything that might allow region-mixing inference (combining text from disparate areas of the card).
- **Image quality.** Worth checking whether resolution / contrast preprocessing in `main.py:_convert_heic_to_jpeg` (or the upstream image) is contributing to the digit errors.
- **Wire accuracy regression tests into Phase 6.** The QA half of the Phase 6 Todoist task (`6gf2WJ4hP82h9hwH`) should include real-card extraction accuracy tests behind `RUN_INTEGRATION_TESTS=1`. This bug is exactly the kind those tests would catch.

## Environment

- `carded.onrender.com`, version `0.1.1` (verified via `GET /health`)
- iOS Safari on iPhone
- Real card photograph under typical mobile-capture conditions (no special lighting or framing)

## Acceptance criteria

<!-- DONE -->
