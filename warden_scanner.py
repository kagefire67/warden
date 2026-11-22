"""
Warden scanner (Layer 2)
========================
Looks for prompt-injection attacks inside content that tools return to the AI
(emails, files, web pages) BEFORE the AI reads it.

Checks:
  1. Hidden characters   - invisible "tag" characters, direction tricks,
                           zero-width characters used to hide text.
  2. Look-alike letters  - Cyrillic/Greek letters mixed into Latin words
                           (e.g. a Russian "о" inside "ignоre").
  3. Injection phrases   - "ignore previous instructions" and friends in English,
                           Arabic (incl. Egyptian dialect), Arabizi, Hindi, Urdu,
                           and Hindi/Urdu written in Latin letters (Hinglish, Roman Urdu).
     ...also after undoing disguises: l33tspeak (1gn0re) and s p a c e d letters.
  4. Talking to the AI   - text that gives orders to "the AI / assistant".
  5. Fake system tags    - text pretending to be a system message (<|im_start|>system, [SYSTEM]...).
  6. LLM Guard (optional) - Protect AI's open-source PromptInjection model.

Severity:
  "high" - an attack: the session gets tainted (see warden_gateway.py)
  "info" - a known attack phrase that is only QUOTED in a discussion
           (a security newsletter). Logged, but does not lock anything.

The phrase lists are still a starter set. The Attack Lab shows what gets through.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass

log = logging.getLogger("warden")


@dataclass
class Finding:
    kind: str      # "hidden_text", "lookalike", "injection_phrase", "addresses_ai", "fake_system", "llm_guard"
    detail: str    # plain-language description
    snippet: str   # the text that triggered it (shortened)
    severity: str = "high"   # "high" = attack, "info" = only mentioned/quoted

    def as_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "detail": self.detail, "snippet": self.snippet, "severity": self.severity}


# ---------------------------------------------------------------------------
# 1. Hidden characters
# ---------------------------------------------------------------------------

TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")            # invisible "tag" letters
BIDI_CONTROLS = re.compile("[‪-‮⁦-⁩]")   # reverse/redirect text direction
ZERO_WIDTH = re.compile("[​⁠᠎]|(?<=.)﻿")  # zero-width space, word joiner...
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
# 2. Look-alike letters (homoglyphs)
# ---------------------------------------------------------------------------
# Cyrillic and Greek letters that look exactly like Latin ones. A word that mixes
# Latin letters with these is almost always a trick - real Russian or Greek text
# uses whole words in its own alphabet, so it is NOT flagged.

CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "ε": "e",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})
LATIN = re.compile("[A-Za-z]")
CONFUSABLE_CHARS = re.compile("[" + "".join(chr(k) for k in CONFUSABLES) + "]")
WORD = re.compile(r"\w+")


def _is_mixed(word: str) -> bool:
    return bool(LATIN.search(word) and CONFUSABLE_CHARS.search(word))


def mixed_script_words(text: str) -> list[str]:
    """Words that mix Latin letters with Cyrillic/Greek look-alikes."""
    return [w for w in WORD.findall(text) if _is_mixed(w)]


def fix_lookalikes(text: str) -> str:
    """Replace look-alike letters with Latin ones, but only inside mixed words."""
    return WORD.sub(lambda m: m.group().translate(CONFUSABLES) if _is_mixed(m.group()) else m.group(), text)


# ---------------------------------------------------------------------------
# 3. Normalising text so tricks don't dodge the phrase checks
# ---------------------------------------------------------------------------

ARABIC_DIACRITICS = re.compile("[ً-ْٰـ]")   # tashkeel + tatweel


def normalize(text: str) -> str:
    text = fix_lookalikes(strip_hidden(text))
    text = unicodedata.normalize("NFKC", text)           # fancy/full-width forms -> plain
    text = ARABIC_DIACRITICS.sub("", text)
    text = re.sub("[أإآ]", "ا", text).replace("ى", "ي")
    text = text.lower()
    return re.sub(r"\s+", " ", text)


# l33tspeak: only used for the English/Latin patterns (Arabizi uses digits for real letters).
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# "I g n o r e  a l l" -> runs of single letters separated by spaces/dots/dashes.
SPACED_RUN = re.compile(r"(?:\b\w\b[\s.\-_*]+){5,}\b\w\b")


# ---------------------------------------------------------------------------
# 4. Injection phrases
# ---------------------------------------------------------------------------
# Each entry: (regex, plain-language description, latin?)  latin=True -> also checked on the l33t copy.

PHRASES: list[tuple[str, str, bool]] = [
    # --- English ---
    (r"\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,20}\b(instructions?|rules|prompts?|guidelines)",
     "English: tells the AI to ignore its instructions", True),
    (r"\b(new|updated|real) (instructions|task|system prompt)\b", "English: claims to give the AI new instructions", True),
    (r"\bdo not (tell|inform|alert|mention).{0,20}\b(the )?(user|human|owner)\b", "English: tells the AI to hide something from the user", True),
    (r"\b(forward|send|upload|email|share|copy)\b.{0,40}\b(all|every|entire|the user'?s)\b.{0,30}\b(files?|emails?|documents?|data|contacts|passwords?|credentials|contracts?|invoices?)",
     "English: asks to move the user's data somewhere", True),
    # --- Arabic (Modern Standard + Egyptian/Levantine dialect) ---
    (r"تجاهل.{0,20}(التعليمات|الاوامر|القواعد)", "Arabic: tells the AI to ignore its instructions", False),
    (r"(انس|انسي|تخط).{0,20}(التعليمات|الاوامر|القواعد)", "Arabic: tells the AI to forget its instructions", False),
    (r"(ارسل|ابعت|ابعث|حول|انقل|شارك).{0,30}(جميع|كل).{0,20}(الملفات|الرسائل|البيانات|المستندات|كلمات المرور|الفواتير)",
     "Arabic: asks to send all the user's files or data", False),
    (r"(لا (تخبر|تبلغ|تقول)|متقولش|ماتقولش|ما تقولش).{0,20}(المستخدم|للمستخدم)", "Arabic: tells the AI to hide something from the user", False),
    # --- Arabizi (Arabic in Latin letters and numbers) ---
    (r"\b(tjahal|t[ae]jahal|itjahal)\b.{0,25}\b(el|al|l)?[ -]?(ta3limat|t3limat|awamer|awamir)", "Arabizi: tells the AI to ignore its instructions", False),
    (r"\b(ersel|irsil|arsil|ib3at|eb3at|ab3at)\b.{0,25}\b(kol|kul|kel)\b.{0,20}\b(el|al|l)?[ -]?(malafat|milafat|rasayel|data|files)", "Arabizi: asks to send all the user's files", False),
    # --- Hindi (Devanagari) ---
    (r"(पिछले|पहले के|सभी).{0,20}निर्देश.{0,20}(अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)", "Hindi: tells the AI to ignore its instructions", False),
    (r"(सभी|सारी|सारे).{0,15}(फ़ाइल|फाइल|ईमेल|डेटा|पासवर्ड).{0,50}भेज", "Hindi: asks to send all the user's files", False),
    (r"(उपयोगकर्ता|यूज़र|यूजर).{0,10}को.{0,10}(मत|न) बता", "Hindi: tells the AI to hide something from the user", False),
    # --- Urdu (Arabic script) ---
    (r"(پچھلی|پچھلے|تمام).{0,20}ہدایات.{0,20}(نظر انداز|بھول)", "Urdu: tells the AI to ignore its instructions", False),
    (r"(تمام|ساری|سارے).{0,15}(فائلیں|فائلز|فائل|ای میل|ڈیٹا).{0,50}بھیج", "Urdu: asks to send all the user's files", False),
    (r"(صارف|یوزر).{0,10}کو.{0,10}(مت|نہ) بتا", "Urdu: tells the AI to hide something from the user", False),
    # --- Hinglish / Roman Urdu (Hindi/Urdu in Latin letters) ---
    (r"\b(pichle|pichhle|pichli|purane|saare|sare|sab|tamam)\b.{0,30}\b(instructions?|nirdesh|hidayat|hidaayat|hidayaat|rules)\b.{0,20}\b(ignore|bhool|bhul|nazarandaaz|nazar ?andaz)",
     "Hinglish/Roman Urdu: tells the AI to ignore its instructions", False),
    (r"\b(saari|sari|saare|sare|sab|sabhi|tamam)\b.{0,15}\b(files?|emails?|data|passwords?|documents?)\b.{0,50}\b(bhej|bhejo|bhejdo|send kar)",
     "Hinglish/Roman Urdu: asks to send all the user's files", False),
    (r"\buser\s+ko\s+(mat|na|nahi|nahin)\s+(batana|batao|bataye|bataen)", "Hinglish/Roman Urdu: tells the AI to hide something from the user", False),
]
# Patterns are NFKC-normalised like the text, so letters such as "फ़" match either way they are typed.
PHRASE_PATTERNS = [(re.compile(unicodedata.normalize("NFKC", p), re.IGNORECASE | re.DOTALL), d, latin)
                   for p, d, latin in PHRASES]

# The same English attacks with all spaces removed, for "s p a c e d" text.
SQUASHED = re.compile(
    r"(ignore|disregard|forget|override)(all|any)?(the|your)?(previous|prior|above|earlier)?(instructions?|rules|prompts?)"
    r"|(forward|send|email|upload)(all|every)(the)?(files?|emails?|invoices?|documents?|data|passwords?)"
)

ADDRESSES_AI = re.compile(
    r"(\b(ai|assistant|agent|chatbot|claude|chatgpt|copilot|gpt)\b\s*[:,!-]\s*(please\s+)?(you must|now|immediately|send|forward|delete|run|ignore|open))"
    r"|(ايها (المساعد|الذكاء الاصطناعي))",
    re.IGNORECASE,
)

# Text pretending to be a system/developer message (chat-template tokens and fake headers).
FAKE_SYSTEM = re.compile(
    r"<\|im_start\|>\s*(system|developer)|<\|(system|developer)\|>|\[/?inst\]|\[system\]|<<sys>>"
    r"|(^|\n)\s*#{2,}\s*(system|developer|instructions?)\b|(^|\n)\s*(system|developer)( prompt| message)?\s*:",
    re.IGNORECASE,
)

# --- Quoted in a discussion? (to avoid false alarms on security newsletters) ---
QUOTES = "\"'“”‘’«»„"
DISCUSSION_CUES = re.compile(
    r"\b(like|such as|e\.g\.|for example|called|known as|phrases?|attackers?|hackers?|scammers?|scam|phishing|"
    r"prompt injection|watch out|beware)\b", re.IGNORECASE)


def quoted_in_discussion(text: str, start: int, end: int) -> bool:
    """True if a matched phrase sits inside quotes AND the sentence is clearly discussing attacks.

    An attacker could wrap a real order in quotes too, so this only applies to short
    quotes with no email address or link inside them.
    """
    before, after = text[max(0, start - 3):start], text[end:end + 3]
    if not (any(q in before for q in QUOTES) and any(q in after for q in QUOTES)):
        return False
    quoted = text[start:end]
    if "@" in quoted or "http" in quoted or len(quoted) > 80:
        return False
    return bool(DISCUSSION_CUES.search(text[max(0, start - 120):start]))


def _snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    s = text[max(0, start - pad): end + pad].strip()
    return s if len(s) <= 160 else s[:160] + "..."


# ---------------------------------------------------------------------------
# 5. Optional: LLM Guard (pip install llm-guard)
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

        # 1. Hidden characters
        for pattern, detail in HIDDEN_PATTERNS:
            if pattern.search(text):
                hidden = decode_tag_chars(text) if pattern is TAG_CHARS else ""
                findings.append(Finding("hidden_text", detail, f"hidden message: {hidden[:120]}" if hidden else ""))

        # 2. Look-alike letters
        mixed = mixed_script_words(strip_hidden(text))
        if mixed:
            findings.append(Finding("lookalike", "look-alike letters from another alphabet hidden inside words",
                                    "disguised words: " + ", ".join(fix_lookalikes(w) for w in mixed[:6])))

        # 3. Phrases - on the visible text plus any message hidden in tag characters,
        #    and (for Latin patterns) also on a l33tspeak-decoded copy.
        clean = normalize(text + " " + decode_tag_chars(text))
        leet = clean.translate(LEET)
        for pattern, detail, latin in PHRASE_PATTERNS:
            m, source = pattern.search(clean), clean
            if not m and latin:
                m, source = pattern.search(leet), leet
            if not m:
                continue
            if source is clean and quoted_in_discussion(clean, m.start(), m.end()):
                findings.append(Finding("injection_phrase", detail + " (quoted in a discussion, not an order)",
                                        _snippet(clean, m.start(), m.end()), severity="info"))
            else:
                findings.append(Finding("injection_phrase", detail + (" (written in l33tspeak)" if source is leet else ""),
                                        _snippet(source, m.start(), m.end())))

        for run in SPACED_RUN.finditer(clean):
            squashed = re.sub(r"\W", "", run.group()).translate(LEET)
            m = SQUASHED.search(squashed)
            if m:
                findings.append(Finding("injection_phrase", "English: hidden instruction with s p a c e d letters",
                                        f"un-spaced: {m.group()}"))
                break

        # 4. Orders addressed to the AI
        m = ADDRESSES_AI.search(clean) or ADDRESSES_AI.search(leet)
        if m:
            findings.append(Finding("addresses_ai", "Text gives orders directly to the AI", _snippet(clean, m.start(), m.end())))

        # 5. Fake system messages (needs the line breaks, so not the squashed text)
        lines = fix_lookalikes(strip_hidden(text + "\n" + decode_tag_chars(text)))
        m = FAKE_SYSTEM.search(lines)
        if m:
            findings.append(Finding("fake_system", "Text pretends to be a system message for the AI",
                                    _snippet(lines, m.start(), m.end())))

        # 6. Optional LLM Guard
        if self.llm_guard is not None:
            try:
                f = self.llm_guard.scan(strip_hidden(text))
                if f:
                    findings.append(f)
            except Exception as exc:
                log.warning("LLM Guard scan failed: %s", exc)

        return findings


def serious(findings: list[Finding]) -> list[Finding]:
    """Only the findings that should lock the session (severity "high")."""
    return [f for f in findings if f.severity == "high"]
