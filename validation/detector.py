"""Prompt injection detection via regex patterns, encoding analysis,
and typoglycemia detection."""

import base64
import logging
import re

logger = logging.getLogger(__name__)


class PromptInjectionDetector:
    """Detects common prompt injection patterns using regex, encoding analysis,
    and typoglycemia detection."""

    INJECTION_PATTERNS = [
        # Direct instruction override attempts
        r"ignore\s+(all\s+)?previous\s+instructions?",
        r"disregard\s+(all\s+)?(previous\s+)?(instructions?|prompts?)",
        r"disregard\s+(your\s+)?system\s+prompt",
        r"forget\s+(all\s+)?previous\s+(instructions?|context)",
        r"you\s+are\s+now\s+(in\s+)?(developer|admin|debug)\s+mode",
        r"your\s+new\s+(role|instructions?)\s+(is|are)",
        r"system\s*:\s*new\s+instructions?",
        r"override\s+(all\s+)?(previous\s+)?(instructions?|rules?|settings?)",
        r"from\s+now\s+on\s+(you\s+)?(will|must|should)\s+",
        r"act\s+as\s+(if\s+)?(you\s+)?(are|were)\s+",
        # Information extraction attempts
        r"(show|reveal|display|output|print)\s+(me\s+)?(your\s+)?(system\s+)?(prompt|instructions?)",
        r"what\s+(is|are)\s+your\s+(initial|system|original)\s+(prompt|instructions?)",
        r"repeat\s+(your\s+)?instructions?",
        r"(dump|list|echo)\s+(your\s+)?(full\s+)?(system\s+)?(prompt|instructions?|config)",
        # Privilege escalation
        r"enable\s+(admin|root|debug|developer)\s+mode",
        r"(sudo|admin|root)\s+access",
        r"bypass\s+(security|restrictions?|filters?|safety)",
        r"jailbreak",
        r"DAN\s+mode",
        # Data exfiltration
        r"send\s+.+\s+to\s+https?://",
        r"POST\s+.+\s+to\s+https?://",
        r"(upload|transmit|forward)\s+.+\s+to\s+",
        r"(curl|wget|fetch)\s+https?://",
        # Roleplay / identity manipulation
        r"pretend\s+(you\s+)?(have\s+no|there\s+are\s+no)\s+(rules|restrictions|guidelines)",
        r"roleplay\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored)",
        r"you\s+are\s+(no\s+longer|not)\s+(bound|restricted|limited)\s+by",
        r"respond\s+(as|like)\s+(an?\s+)?(unrestricted|unfiltered)",
        # Impersonation / fake authority
        r"(the\s+)?(developer|creator|admin|Graham)\s+(said|told|wants|asks)\s+(you\s+)?to",
        r"(this\s+is\s+)?(an?\s+)?(official|authorized|urgent)\s+(update|instruction|command)",
        r"(maintenance|system|security)\s+(mode|update|override)",
        # Delimiter / formatting attacks
        r"<\|?(system|im_start|endoftext)\|?>",
        r"\[SYSTEM\]",
        r"###\s*(system|instruction|prompt)",
        r"---\s*BEGIN\s+(SYSTEM|ADMIN)\s+MESSAGE\s*---",
        # Indirect extraction
        r"(translate|convert|encode)\s+your\s+(system\s+)?(prompt|instructions)",
        r"(summarize|paraphrase)\s+your\s+(initial\s+)?(instructions|rules)",
        r"(what|how)\s+(were|are)\s+you\s+(programmed|configured|instructed)\s+to",
        # Multi-step / chain attacks
        r"(first|step\s+1)\s*[.:]\s*(ignore|disregard|forget)",
        r"do\s+not\s+filter\s+(your\s+)?(output|response)",
        # Encoding / obfuscation indicators
        r"base64\s+decode",
        r"0x[0-9a-fA-F]{8,}",
        r"\\u[0-9a-fA-F]{4}",
    ]

    SENSITIVE_KEYWORDS = [
        "api_key",
        "password",
        "secret",
        "token",
        "credential",
        "admin",
        "root",
        "sudo",
        "system_prompt",
        "instructions",
    ]

    # Phrases to check for typoglycemia (scrambled middle letters)
    INJECTION_PHRASES = [
        "ignore previous instructions",
        "developer mode",
        "system prompt",
        "disregard instructions",
        "bypass security",
        "admin mode",
        "override instructions",
        "reveal instructions",
        "maintenance override",
        "unrestricted mode",
    ]

    def __init__(self):
        self.patterns = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]

    def check_direct_patterns(self, text: str) -> tuple[bool, list[str]]:
        """Check for direct injection patterns via regex."""
        detected = []
        for pattern in self.patterns:
            if pattern.search(text):
                detected.append(pattern.pattern)
        return len(detected) > 0, detected

    def check_encoding_attacks(self, text: str) -> tuple[bool, str]:
        """Detect encoded injection attempts (Base64, hex, Unicode escapes)."""
        # Check for Base64-encoded payloads
        base64_chunks = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
        for chunk in base64_chunks:
            try:
                decoded = base64.b64decode(chunk).decode("utf-8", errors="ignore")
                is_injection, patterns = self.check_direct_patterns(decoded)
                if is_injection:
                    return True, f"Base64 encoded injection: {patterns}"
            except Exception:
                continue

        # Check for excessive Unicode escapes
        if re.search(r"(\\u[0-9a-fA-F]{4}){5,}", text):
            return True, "Suspicious Unicode escape sequence"

        # Check for excessive hex escapes
        if re.search(r"(\\x[0-9a-fA-F]{2}){5,}", text):
            return True, "Suspicious hex escape sequence"

        return False, ""

    def check_typoglycemia(self, text: str) -> bool:
        """Detect scrambled-word attacks where first/last letters are kept
        but middle letters are rearranged."""
        words = text.lower().split()
        for phrase in self.INJECTION_PHRASES:
            phrase_words = phrase.split()
            if self._fuzzy_phrase_match(words, phrase_words):
                return True
        return False

    def _fuzzy_phrase_match(
        self, text_words: list[str], phrase_words: list[str]
    ) -> bool:
        """Check if a phrase appears in a word list with scrambled middle letters."""
        if len(text_words) < len(phrase_words):
            return False

        for i in range(len(text_words) - len(phrase_words) + 1):
            window = text_words[i : i + len(phrase_words)]
            if all(
                self._fuzzy_word_match(w1, w2) for w1, w2 in zip(window, phrase_words)
            ):
                return True
        return False

    def _fuzzy_word_match(self, word1: str, word2: str) -> bool:
        """Check if word1 is a scrambled version of word2
        (same first/last letter, same sorted middle)."""
        if len(word1) != len(word2):
            return False
        if len(word1) <= 3:
            return word1 == word2
        return (
            word1[0] == word2[0]
            and word1[-1] == word2[-1]
            and sorted(word1[1:-1]) == sorted(word2[1:-1])
        )

    def calculate_risk_score(self, text: str, block_score: int = 10) -> dict:
        """Calculate overall risk score for the input text.

        Args:
            text: The input text to analyze.
            block_score: Score threshold at which to block the input (default: 10).

        Returns:
            Dict with score, risk_level, reasons, and should_block.
        """
        score = 0
        reasons = []

        # Direct pattern matching (+10)
        has_injection, patterns = self.check_direct_patterns(text)
        if has_injection:
            score += 10
            reasons.append(f"Direct injection patterns: {patterns}")

        # Encoding attacks (+8)
        has_encoding, encoding_type = self.check_encoding_attacks(text)
        if has_encoding:
            score += 8
            reasons.append(encoding_type)

        # Typoglycemia (+7)
        if self.check_typoglycemia(text):
            score += 7
            reasons.append("Typoglycemia attack detected")

        # Sensitive keyword density (+2 per keyword)
        text_lower = text.lower()
        sensitive_count = sum(1 for kw in self.SENSITIVE_KEYWORDS if kw in text_lower)
        if sensitive_count > 0:
            score += sensitive_count * 2
            reasons.append(f"Sensitive keywords found: {sensitive_count}")

        result = {
            "score": score,
            "risk_level": self._score_to_level(score),
            "reasons": reasons,
            "should_block": score >= block_score,
        }

        if score >= 10:
            logger.warning(
                "Prompt injection detected: score=%d level=%s reasons=%s",
                score,
                result["risk_level"],
                reasons,
            )
        elif score >= 5:
            logger.info(
                "Medium risk input: score=%d reasons=%s",
                score,
                reasons,
            )

        return result

    @staticmethod
    def _score_to_level(score: int) -> str:
        if score >= 15:
            return "CRITICAL"
        elif score >= 10:
            return "HIGH"
        elif score >= 5:
            return "MEDIUM"
        else:
            return "LOW"
