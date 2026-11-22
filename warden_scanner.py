"""
Warden scanner (Layer 2)
========================
Looks for prompt-injection attacks inside content that tools return to the AI
(emails, files, web pages) BEFORE the AI reads it.

Checks:
  1. Hidden characters  - invisible "tag" characters, direction tricks,
                          zero-width characters used to hide text.
  2. Injection phrases  - "ignore previous instructions" and friends in
                          English, Arabic, Arabizi, Hindi and Urdu.
  3. Talking to the AI  - text that gives orders to "the AI / assistant".
  4. LLM Guard (optional) - Protect AI's open-source PromptInjection model,
                          if installed and switched on in warden_config.json.

The phrase lists are a STARTER set. The Attack Lab (Stage 4) will show which
attacks get through, and new patterns get added here.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass

log = logging.getLogger("warden")


@dataclass
class Finding:
    kind: str      # "hidden_text", "injection_phrase", "addresses_ai", "llm_guard"
    detail: str    # plain-language description
    snippet: str   # the text that triggered it (shortened)

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "detail": self.detail, "snippet": self.snippet}


# ---------------------------------------------------------------------------
# 1. Hidden characters
# ---------------------------------------------------------------------------

TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")            # invisible "tag" letters
BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩]")     # reverse/redirect text direction
ZERO_WIDTH = re.compile("[​⁠᠎]|(?<=.)﻿")    # zero-width space, word joiner...
# ZWNJ/ZWJ (200C/200D) are NORMAL in Arabic, Persian, Hindi and emoji, so a single
# one is fine. Only long runs of them are suspicious.
JOINER_RUN = re.compile("[‌‍]{3,}")

HIDDEN_PATTERNS = [
    (TAG_CHARS, "invisible tag characters (a known way to hide instructions)"),
    (BIDI_CONTROLS, "text-direction control characters (can disguise what text says)"),
    (ZERO_WIDTH, "zero-width characters"),
    (JOINER_RUN, "long run of invisible joiner characters"),
]


def decode_tag_chars(text: str) -> str:
    """Tag characters map 1:1 onto ASCII, so the hidden message can be revealed."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def strip_hidden(text: str) -> str:
    """Remove hidden characters so the AI never sees the invisible part."""
    for pattern, _ in HIDDEN_PATTERNS:
        text = pattern.sub("", text)
    return text


# ---------------------------------------------------------------------------
# 2. Normalising text so tricks don't dodge the phrase checks
# ---------------------------------------------------------------------------

ARABIC_DIACRITICS = re.compile("[ً-ْٰـ]")   # tashkeel + tatweel


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", strip_hidden(text))     # fancy/look-alike forms -> plain
    text = ARABIC_DIACRITICS.sub("", text)
    text = re.sub("[أإآ]", "ا", text).replace("ى", "ي")
    text = text.lower()
    return re.sub(r"\s+", " ", text)


# ---------------------------------------------------------------------------
# 3. Injection phrases (starter set)
# ---------------------------------------------------------------------------

PHRASES: list[tuple[str, str]] = [
    # English
    (r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,20}\b(instructions?|rules|prompts?|guidelines)",
     "English: tells the AI to ignore its instructions"),
    (r"\b(new|updated|real) (instructions|task|system prompt)\b", "English: claims to give the AI new instructions"),
    (r"\bdo not (tell|inform|alert|mention).{0,20}\b(the )?(user|human|owner)\b", "English: tells the AI to hide something from the user"),
    (r"\b(forward|send|upload|email|share|copy)\b.{0,40}\b(all|every|entire|the user'?s)\b.{0,30}\b(files?|emails?|documents?|data|contacts|passwords?|credentials)",
     "English: asks to move the user's data somewhere"),
    # Arabic
    (r"تجاهل.{0,20}(التعليمات|الاوامر|الأوامر|القواعد)", "Arabic: tells the AI to ignore its instructions"),
    (r"(انس|انسي|تخط).{0,20}(التعليمات|الاوامر|القواعد)", "Arabic: tells the AI to forget its instructions"),
    (r"(ارسل|حول|انقل|شارك).{0,30}(جميع|كل).{0,20}(الملفات|الرسائل|البيانات|المستندات|كلمات المرور)",
     "Arabic: asks to send all the user's files or data"),
    (r"لا (تخبر|تبلغ).{0,20}المستخدم", "Arabic: tells the AI to hide something from the user"),
    # Arabizi (Arabic written in Latin letters and numbers)
    (r"\b(tjahal|t[ae]jahal|itjahal)\b.{0,25}\b(el|al|l)?[ -]?(ta3limat|t3limat|awamer|awamir)", "Arabizi: tells the AI to ignore its instructions"),
    (r"\b(ersel|irsil|arsil|ib3at|eb3at|ab3at)\b.{0,25}\b(kol|kul|kel)\b.{0,20}\b(el|al|l)?[ -]?(malafat|milafat|rasayel|data)", "Arabizi: asks to send all the user's files"),
    # Hindi
    (r"(पिछले|पहले के|सभी).{0,20}निर्देश.{0,20}(अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)", "Hindi: tells the AI to ignore its instructions"),
    # Urdu
    (r"(پچھلی|پچھلے|تمام).{0,20}ہدایات.{0,20}(نظر انداز|بھول)", "Urdu: tells the AI to ignore its instructions"),
]
PHRASE_PATTERNS = [(re.compile(p, re.IGNORECASE | re.DOTALL), d) for p, d in PHRASES]

ADDRESSES_AI = re.compile(
    r"(\b(ai|assistant|agent|chatbot|claude|chatgpt|copilot|gpt)\b\s*[:,!-]\s*(please\s+)?(you must|now|immediately|send|forward|delete|run|ignore|open))"
    r"|(ايها (المساعد|الذكاء الاصطناعي))",
    re.IGNORECASE,
)


def _snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    s = text[max(0, start - pad): end + pad].strip()
    return s if len(s) <= 160 else s[:160] + "..."


# ---------------------------------------------------------------------------
# 4. Optional: LLM Guard (pip install llm-guard)
# ---------------------------------------------------------------------------

class LLMGuardAdapter:
    def __init__(self, threshold: float = 0.5) -> None:
        from llm_guard.input_scanners import PromptInjection  # imported only if switched on
        self._scanner = PromptInjection(threshold=threshold)

    def scan(self, text: str) -> Finding | None:
        _, is_valid, risk = self._scanner.scan(text)
        if is_valid:
            return None
        return Finding("llm_guard", f"LLM Guard flagged prompt injection (risk {risk:.2f})", text[:160])


# ---------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self, use_llm_guard: bool = False) -> None:
        self.llm_guard: LLMGuardAdapter | None = None
        if use_llm_guard:
            try:
                self.llm_guard = LLMGuardAdapter()
                log.info("LLM Guard scanner enabled")
            except Exception as exc:
                log.warning("LLM Guard is switched on but could not load (%s); using built-in checks only", exc)

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        if not text:
            return findings

        for pattern, detail in HIDDEN_PATTERNS:
            m = pattern.search(text)
            if m:
                hidden = decode_tag_chars(text) if pattern is TAG_CHARS else ""
                findings.append(Finding("hidden_text", detail, f"hidden message: {hidden[:120]}" if hidden else ""))

        # Scan both the visible text and any message hidden in tag characters.
        clean = normalize(text + " " + decode_tag_chars(text))
        for pattern, detail in PHRASE_PATTERNS:
            m = pattern.search(clean)
            if m:
                findings.append(Finding("injection_phrase", detail, _snippet(clean, m.start(), m.end())))

        m = ADDRESSES_AI.search(clean)
        if m:
            findings.append(Finding("addresses_ai", "Text gives orders directly to the AI", _snippet(clean, m.start(), m.end())))

        if self.llm_guard is not None:
            try:
                f = self.llm_guard.scan(strip_hidden(text))
                if f:
                    findings.append(f)
            except Exception as exc:
                log.warning("LLM Guard scan failed: %s", exc)

        return findings
