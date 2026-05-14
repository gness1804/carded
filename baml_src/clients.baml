// Learn more about clients at https://docs.boundaryml.com/docs/snippets/clients/overview

// Primary client for Carded — Claude Sonnet 4 via Anthropic.
// ANTHROPIC_API_KEY is set at runtime from the user's session-decrypted key
// (or from OWNER_ANTHROPIC_API_KEY for the owner bypass flow).
client<llm> CustomSonnet4 {
  provider anthropic
  options {
    model "claude-sonnet-4-20250514"
    api_key env.ANTHROPIC_API_KEY
  }
}

// Optional fallback client for Phase 5 stretch goal: use Opus 4 for difficult or
// degraded images where Sonnet 4 struggles. Commented out — not used in MVP.
// Uncomment and wire into business_card.baml if needed post-MVP.
//
// client<llm> CustomOpus4 {
//   provider anthropic
//   options {
//     model "claude-opus-4-1-20250805"
//     api_key env.ANTHROPIC_API_KEY
//   }
// }

// https://docs.boundaryml.com/docs/snippets/clients/retry
retry_policy Constant {
  max_retries 2
  strategy {
    type constant_delay
    delay_ms 500
  }
}
