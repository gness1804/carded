Carded

Claude-specific instructions for this project.

## Global Rules

Graham's global rules in `~/CLAUDE.md` apply in full. Read them if you haven't.

## Carded-Specific Rules

### Never invent card fields

The cardinal rule is enforced by the extraction prompt: only report what is literally printed on the card. Do not infer, supplement, or complete partial information. `null` means "not on card" — not "I couldn't find it."

### Validation prompt is load-bearing

The wording in `baml_src/business_card.baml` — the `STEP 1` validation block, the legibility guidance, and the strict extraction rules — must not be paraphrased, loosened, or modified without explicit approval from Graham. This prompt is the correctness gate for the entire pipeline.

### BYOK is the API key model

Users supply their own Anthropic API key. There is no owner-key fallback for non-owner users. Do not introduce any code path that silently falls back to an owner/server key for users who haven't provided their own. If a key is missing, return 401 MISSING_API_KEY.

### BAML client

Do not edit `baml_client/` by hand. After modifying `baml_src/*.baml`, regenerate with:

```bash
baml-cli generate
```

### Testing

- Do not mock the BAML client at the integration test level.
- Gate any test that makes a live BAML/LLM call behind `RUN_INTEGRATION_TESTS=1`.
- Unit tests may mock the BAML client at the unit level (testing logic around the call, not the call itself).

```python
import os
import pytest

integration = pytest.mark.skipif(
    not os.getenv("RUN_INTEGRATION_TESTS"),
    reason="Set RUN_INTEGRATION_TESTS=1 to run live LLM tests",
)
```

### Interface contract

`.cursor/docs/1-interface-contract.md` is the authoritative contract for the Phase 4 parallel build. Do not change endpoint shapes, error codes, or cookie behavior without updating this document and flagging Graham.
