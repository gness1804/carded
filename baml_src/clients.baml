// Learn more about clients at https://docs.boundaryml.com/docs/snippets/clients/overview

// Primary client for Carded — Claude Sonnet 5 via Anthropic.
// ANTHROPIC_API_KEY is set at runtime from the user's session-decrypted key
// (or from OWNER_ANTHROPIC_API_KEY for the owner bypass flow).
//
// Thinking is disabled: Sonnet 5 turns adaptive thinking on by default, which
// adds latency and cost and puts thinking blocks ahead of the text block.
// Literal transcription of a card does not benefit from it.
client<llm> CustomSonnet5 {
  provider anthropic
  options {
    model "claude-sonnet-5"
    api_key env.ANTHROPIC_API_KEY
    thinking {
      type "disabled"
    }
  }
}

// Optional fallback client for Phase 5 stretch goal: use Opus for difficult or
// degraded images where Sonnet struggles. Commented out — not used in MVP.
// Uncomment and wire into business_card.baml if needed post-MVP.
// Note: claude-opus-4-1-20250805 may be retired; check the model list first.
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
