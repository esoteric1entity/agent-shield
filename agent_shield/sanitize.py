"""agent-shield Layer 2 — Input Sanitization.

Heuristic sanitization of UNTRUSTED incoming content (web fetches, tool/MCP
output, user input, agent-to-agent handoffs) before it reaches the model.
Four sub-layers, in pipeline order:

  1. encoding  — NFKC-normalize FIRST (so disguised full-width/compatibility
                 glyphs are reconstituted to ASCII before anything is scanned),
                 then DETECT (never decode) long base64/base64url blobs and
                 mixed-script (Latin + Cyrillic/Greek) homoglyph tokens.
  2. structural — STRIP (destructive, safe) invisible/zero-width chars (ZWSP,
                 BOM, WORD JOINER, invisible math operators, interlinear
                 anchors), BIDI overrides/isolates + directional marks
                 (Trojan-Source family), Unicode tag chars, C0/C1 control chars
                 (except tab/newline/CR), and lone surrogates. ZWJ/ZWNJ are
                 preserved (legitimate in emoji and Indic/Persian-Arabic text).
  3. content   — DETECT-AND-FLAG (non-destructive by default) instruction-
                 injection / jailbreak markers; opt-in ``strict=True`` neutralizes
                 the markers it matched with an inert placeholder.
  4. context   — wrap content in NONCE-delimited typed tags so it cannot break
                 out of or forge its wrapper (the random per-wrap nonce is the
                 mechanism). wrap_web / wrap_user_input / wrap_agent_output /
                 wrap_tool_output.

This is a heuristic regex/Unicode layer that RAISES ATTACKER COST and SURFACES
suspicious content for the model/caller to judge. It does NOT "block" prompt
injection — novel phrasings and creative encodings are unbounded, and a wrapper
only helps if the consuming prompt is instructed to honor the delimiters.
See docs/SANITIZATION.md for the threat model, the nonce-delimiter contract,
and the bypasses & limitations.

Stdlib-only; never-crash on any input (incl. invalid Unicode / lone surrogates
/ multi-MB); deterministic; the cleaned text is idempotent. License: Apache-2.0
"""

from __future__ import annotations

import hashlib
import re
import secrets
import unicodedata
from dataclasses import dataclass
from typing import Callable, Literal

#: The four sub-layer identifiers (README reading order). The runtime PIPELINE
#: runs encoding(NFKC)→structural→content→context — see the module docstring.
SUBLAYER_IDS = ("structural", "content", "encoding", "context")

Source = Literal["web", "user", "agent", "tool"]
_SOURCE_TAG = {"web": "web_content", "user": "user_input",
               "agent": "agent_output", "tool": "tool_output"}

#: Closed Finding-kind taxonomies (pinned to docs; the raw marker COUNT is NOT
#: pinned — phrasings are heuristic and churn, the kind taxonomy is stable).
_STRIP_KINDS = ("zero_width", "bidi_override", "tag_char", "control", "surrogate")
_MARKER_KINDS = ("ignore_previous", "fake_system_prefix", "role_override",
                 "tool_call_mimicry", "wrapper_mimicry", "harness_tag_spoof")
_ENCODING_KINDS = ("encoded_blob", "mixed_script")
ALL_KINDS = _STRIP_KINDS + _MARKER_KINDS + _ENCODING_KINDS + ("oversize_unscanned",)

#: Budget (chars) shared by NFKC normalization AND the marker/encoding deep-scan.
#: NFKC runs in combining-safe chunks (see ``_bounded_nfkc``) and accumulates
#: output up to this bound; if an expansion-heavy input would exceed it,
#: normalization stops at a safe boundary, one ``oversize_unscanned`` Finding is
#: emitted, and the deep-scan is skipped. Because the NFKC budget and the scan
#: budget are the SAME value, any in-budget input is FULLY folded before it is
#: scanned — there is no partial-fold gap a full-width payload could hide in.
#: This makes the time bound real (never a hidden CPU/memory cliff) even on a
#: pathological ~18x compatibility expander. Documented in docs/SANITIZATION.md.
MAX_DEEP_SCAN = 1_000_000

#: Input chars per NFKC call. Bounds per-chunk cost so a single ``normalize()``
#: can't stall on a huge expander run.
_NFKC_CHUNK = 65_536

#: NFKC output/input ratio above which (once output also exceeds MAX_DEEP_SCAN) a
#: large input is treated as a pathological compatibility expander and normalization
#: is circuit-broken. Legitimate compatibility chars expand ~1-3x (ﬁ→fi, Ⅸ→IX);
#: the abusive ones (e.g. U+FDFA → 18x) sit far above 4. Benign text (~1x) at any
#: size never trips it.
_MAX_EXPANSION = 4

#: Longest consecutive combining-mark run we will normalize. NFKC canonical
#: reordering is O(M^2) in a run of M marks on one base, so a long run is a DoS
#: independent of expansion. No legitimate text has a run
#: anywhere near this (Unicode Stream-Safe Format caps at 30); a longer run is
#: treated as pathological and bailed to oversize_unscanned without normalizing.
_MAX_COMBINING_RUN = 256

#: Chars with raw canonical combining class 0 (so unicodedata.combining() == 0)
#: whose NFD/NFKC decomposition BEGINS with a combining mark. They must be treated
#: as unsafe split points (and counted toward a combining run) — splitting a chunk
#: immediately before one yields a non-NFKC result. This is the
#: complete set in Unicode: the three Tibetan vowel signs that decompose to a
#: leading U+0F71. Splitting before any other cc=0 char is safe (UAX #15).
_NFD_LEADING_MARK = frozenset(("ཱི", "ཱུ", "ཱྀ"))

#: strict-mode replacement. Inert by construction: matches no marker pattern,
#: is <40 chars (no blob), single-script (no mixed_script) — so neutralization
#: is idempotent and never re-triggers a finding.
_PLACEHOLDER = "[agent-shield:neutralized]"

_NONCE_BYTES = 16  # secrets.token_hex(16) -> 32 hex chars, 128-bit CSPRNG


# --------------------------------------------------------------- data shapes
@dataclass(frozen=True)
class SanitizeFinding:
    """One sanitization signal.

    sublayer: one of SUBLAYER_IDS.
    kind:     a member of ALL_KINDS.
    span:     half-open [start, end) char offsets into the FINAL cleaned text
              (SanitizeReport.text), or None for content that was REMOVED
              (structural strips / strict-mode neutralizations) and therefore
              has no offset in the cleaned text. snippet is the authoritative
              human-readable evidence; span is a best-effort pointer.
    snippet:  ASCII-safe, escaped (backslashreplace / \\uXXXX), <=80 chars — so
              it can be printed/logged on any console (incl. Windows cp1252)
              without raising. Raw matched bytes never enter the snippet.
    why:      one-line rationale.
    """

    sublayer: str
    kind: str
    span: tuple[int, int] | None
    snippet: str
    why: str

    def to_dict(self) -> dict:
        return {
            "sublayer": self.sublayer,
            "kind": self.kind,
            "span": list(self.span) if self.span is not None else None,
            "snippet": self.snippet,
            "why": self.why,
        }


@dataclass(frozen=True)
class SanitizeReport:
    """Result of sanitize().

    text:           the cleaned output (the single source of truth — there is
                    no separate return value). Idempotent + deterministic.
    findings:       tuple of SanitizeFinding.
    stripped_count: number of code points REMOVED by the structural sub-layer
                    (not a net length delta; NFKC folds do not count).
    wrapped:        always False from sanitize(); wrapping is done by the
                    wrap_*() functions (which clean first, then wrap).
    """

    text: str
    findings: tuple[SanitizeFinding, ...]
    stripped_count: int
    wrapped: bool = False

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "findings": [f.to_dict() for f in self.findings],
            "stripped_count": self.stripped_count,
            "wrapped": self.wrapped,
        }


# ------------------------------------------------------------------ helpers
def _coerce(text: object) -> str:
    """Total str coercion: None->'', bytes->utf-8(replace), else str(x)."""
    if text is None:
        return ""
    if isinstance(text, str):
        return text
    if isinstance(text, (bytes, bytearray)):
        return bytes(text).decode("utf-8", errors="replace")
    return str(text)


def _ascii_safe(s: str, limit: int = 80) -> str:
    """ASCII-only escaped rendering (never raises on exotic/surrogate input)."""
    out = s.encode("ascii", "backslashreplace").decode("ascii")
    return out if len(out) <= limit else out[: limit - 3] + "..."


# ----- structural strip table (explicit deny-set; NEVER by raw Unicode category)
def _build_delete_table() -> dict[int, None]:
    cps: set[int] = set()
    cps |= {0x200B, 0xFEFF, 0x2060}         # zero-width space + BOM/ZWNBSP + WORD JOINER
    cps |= set(range(0x2061, 0x2065))       # invisible math operators (FUNCTION APPLICATION..PLUS)
    cps |= {0xFFF9, 0xFFFA, 0xFFFB}         # interlinear annotation anchors
    cps |= {0x200E, 0x200F, 0x061C}         # LRM / RLM / ALM directional marks (Trojan-Source family)
    cps |= set(range(0x202A, 0x202F))       # BIDI embeds/overrides LRE..RLO (Trojan-Source)
    cps |= set(range(0x2066, 0x206A))       # BIDI isolates LRI/RLI/FSI/PDI
    cps |= set(range(0xE0000, 0xE0080))     # Unicode tag chars
    # NOTE: ZWJ (U+200D) and ZWNJ (U+200C) are deliberately NOT stripped —
    # they are load-bearing in emoji sequences and Indic/Persian-Arabic text.
    cps |= {c for c in range(0x00, 0x20) if c not in (0x09, 0x0A, 0x0D)}  # C0 except \t\n\r
    cps.add(0x7F)                           # DEL
    cps |= set(range(0x80, 0xA0))           # C1 controls
    cps |= set(range(0xD800, 0xE000))       # lone surrogates
    return {c: None for c in cps}


_DELETE_TABLE = _build_delete_table()

# Detect WHICH strip kinds occurred (only runs when something was stripped).
# Surrogates are handled separately to avoid a surrogate range inside a pattern.
_STRUCT_DETECT = {
    "zero_width": re.compile("[​⁠-⁤﻿￹-￻]"),
    "bidi_override": re.compile("[؜‎‏‪-‮⁦-⁩]"),
    "tag_char": re.compile("[\U000e0000-\U000e007f]"),
    "control": re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"),
}
_STRUCT_WHY = {
    "zero_width": "zero-width / invisible character (obfuscation; no legitimate place in prompt text)",
    "bidi_override": "BIDI override/isolate (Trojan-Source visual-reordering attack)",
    "tag_char": "Unicode tag character (invisible tagging / smuggling)",
    "control": "C0/C1 control character (non-printing; not tab/newline/CR)",
    "surrogate": "lone surrogate (invalid Unicode; cannot be UTF-8 encoded safely)",
}


def _has_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


# ----- content markers (FLAT, bounded patterns only — no nested quantifiers;
#       a nested form like ignore([\s]+)*previous catastrophically backtracks).
_MARKER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore_previous",
     re.compile(r"(?i)(?:ignore|disregard|forget).{0,30}?(?:previous|prior|above|earlier)")),
    ("fake_system_prefix",
     re.compile(r"(?im)^[\s>\]\[*#\-]{0,8}system\s*[:：]")),
    ("role_override",
     re.compile(r"(?i)(?:you\W{0,4}are\W{0,4}now|from\W{0,4}now\W{0,4}on|"
                r"new\W{0,6}instructions?|developer\W{0,4}mode|jailbreak)")),
    ("tool_call_mimicry",
     re.compile(r"(?i)(?:<\s*/?\s*(?:tool_call|function_calls?|invoke)\b|"
                r"\"function\"\s*:\s*\{|\"arguments\"\s*:\s*\{|\"tool_call\")")),
    ("wrapper_mimicry",
     re.compile(r"(?i)<\s*/?\s*(?:web_content|user_input|agent_output|tool_output)\b")),
    ("harness_tag_spoof",
     re.compile(r"(?i)<\s*/?\s*(?:system-reminder|system|assistant|user|instructions)\b")),
]
_MARKER_WHY = {
    "ignore_previous": "instruction-override phrasing ('ignore/disregard ... previous')",
    "fake_system_prefix": "forged system/role prefix at line start",
    "role_override": "role/persona-override or jailbreak phrasing",
    "tool_call_mimicry": "content imitating a tool/function call",
    "wrapper_mimicry": "content embeds a reserved agent-shield wrapper tag name",
    "harness_tag_spoof": "content forges a harness framing tag (system/assistant/user/instructions)",
}

# ----- encoding detection (DETECTION ONLY — never decoded)
_BLOB_RE = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")  # base64 + base64url superset
_TOKEN_RE = re.compile(r"\w+", re.UNICODE)
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
#: A real data: URI base64 prefix ending immediately before the blob — bounded,
#: linear. Requires the data: scheme, not just a bare "base64," substring (which
#: an attacker can place in prose to suppress detection).
_DATA_URI_B64 = re.compile(r"data:[^\s,]{0,128};base64,\Z")
_ENC_WHY = {
    "encoded_blob": "long base64/base64url-shaped blob (possible hidden payload; never decoded — a flag is not a verdict)",
    "mixed_script": "token mixes Latin with Cyrillic/Greek (possible homoglyph; best-effort, no confusables DB)",
}


def _is_benign_blob(blob: str, text: str, start: int) -> bool:
    core = blob.rstrip("=")
    if _HEX_RE.fullmatch(core) and len(core) in (32, 40, 64, 128):
        return True                                   # md5/sha1/sha256/sha512 hex digest
    if not any(c.isdigit() or c in "+/_-" for c in core):
        return True                                   # all-letters: a long word, not a payload
    if _DATA_URI_B64.search(text[max(0, start - 160):start]):
        return True                                   # genuine data: URL base64 payload
    return False


def _is_mixed_script(token: str) -> bool:
    """True iff the token mixes Latin with Cyrillic or Greek (the homoglyph case).

    A cheap ``ord(ch) < 0x370`` fast-path classifies the ASCII/Latin majority
    without an ``unicodedata.name()`` lookup (Cyrillic/Greek start at 0x400/0x370,
    so nothing below 0x370 can be a confusable). The number of non-ASCII letters
    examined is budget-capped to bound cost on a long single-script token. Honest
    limit (best-effort, not airtight): because the scan stops once the letter
    budget is spent, a homoglyph placed AFTER more than the budget's worth of
    non-ASCII letters can evade detection — this raises the attacker's cost, it
    does not guarantee catching every mixed-script token (there is also no
    confusables/TR39 database). Other multi-script combinations (CJK + kana,
    Arabic) are NOT flagged, to avoid false positives on legitimately
    multilingual text."""
    has_latin = has_confusable = False
    checked = 0
    for ch in token:
        if ord(ch) < 0x370:                  # ASCII / Latin-1 / Latin-Ext: Latin only
            if ch.isalpha():
                has_latin = True
        elif ch.isalpha():
            fam = unicodedata.name(ch, "").split(" ", 1)[0]
            if fam == "LATIN":
                has_latin = True
            elif fam in ("CYRILLIC", "GREEK"):
                has_confusable = True
            checked += 1
            if checked >= 256:               # enough to catch a homoglyph word; bounds cost
                break
        if has_latin and has_confusable:
            return True
    return False


def _iter_compiled_patterns():
    """Every compiled pattern (for the 'precompiled at import' guarantee)."""
    for _, pat in _MARKER_PATTERNS:
        yield pat
    yield from _STRUCT_DETECT.values()
    yield _BLOB_RE
    yield _TOKEN_RE
    yield _HEX_RE


# ------------------------------------------------------------- scan internals
def _scan_content(s: str, strict: bool) -> tuple[str, list[SanitizeFinding]]:
    findings: list[SanitizeFinding] = []
    for kind, pat in _MARKER_PATTERNS:
        for m in pat.finditer(s):
            span = None if strict else (m.start(), m.end())
            findings.append(SanitizeFinding("content", kind, span,
                                            _ascii_safe(m.group()), _MARKER_WHY[kind]))
    if strict and findings:
        for _, pat in _MARKER_PATTERNS:
            s = pat.sub(_PLACEHOLDER, s)
    return s, findings


def _scan_encoding(s: str) -> list[SanitizeFinding]:
    findings: list[SanitizeFinding] = []
    for m in _BLOB_RE.finditer(s):
        blob = m.group()
        if _is_benign_blob(blob, s, m.start()):
            continue
        findings.append(SanitizeFinding("encoding", "encoded_blob", (m.start(), m.end()),
                                        _ascii_safe(blob), _ENC_WHY["encoded_blob"]))
    for m in _TOKEN_RE.finditer(s):
        tok = m.group()
        if _is_mixed_script(tok):
            findings.append(SanitizeFinding("encoding", "mixed_script", (m.start(), m.end()),
                                            _ascii_safe(tok), _ENC_WHY["mixed_script"]))
    return findings


def _bounded_nfkc(s: str) -> tuple[str, bool]:
    """NFKC-normalize ``s`` with a bounded cost. Returns ``(text, fully_normalized)``.

    NFKC on the full raw input is unbounded: a single ~18x compatibility expander
    (e.g. U+FDFA) blows a sub-MB input up into tens of millions of chars and
    stalls for minutes. The cost comes from *expansion*, not size — benign text
    (output ≈ input) normalizes in milliseconds at any length. So we normalize in
    chunks and trip a **circuit breaker** only when the output has both grown past
    MAX_DEEP_SCAN *and* is expanding faster than ``_MAX_EXPANSION`` (the signature
    of a pathological expander). On trip, the un-normalized remainder is passed
    through raw (the cheap, linear structural strip downstream still cleans it) and
    ``fully_normalized=False`` is returned, so the caller emits ``oversize_unscanned``
    and skips the deep-scan — an un-folded tail is never silently marker-scanned.
    Benign input of any size is normalized in full (no coverage regression).

    Chunks are split only BEFORE a starter (canonical combining class 0): a
    combining sequence (starter + its marks) is never split across a
    ``normalize()`` call, which would change the result. Splitting before a
    starter is the standard incremental-normalization boundary (UAX #15).
    """
    # Fast path: small input — one normalize; even worst-case 18x expansion of a
    # single 64K chunk measures well under the test budget.
    if len(s) <= _NFKC_CHUNK:
        return unicodedata.normalize("NFKC", s), True
    # Pathological combining-mark run guard: NFKC reorders a run of
    # M consecutive combining marks in O(M^2), so a single long run stalls a chunk
    # even though it barely expands (the expansion breaker can't catch it). One
    # cheap O(n) pass: if any run exceeds _MAX_COMBINING_RUN the input is hostile —
    # bail to oversize_unscanned (raw, un-normalized) instead of normalizing it.
    # When no run exceeds the cap, every chunk's normalize() is bounded, and the
    # combining-extension loop below extends by at most _MAX_COMBINING_RUN.
    run = 0
    for ch in s:
        if unicodedata.combining(ch) or ch in _NFD_LEADING_MARK:
            run += 1
            if run > _MAX_COMBINING_RUN:
                return s, False
        else:
            run = 0
    parts: list[str] = []
    out_total = 0
    i, n = 0, len(s)
    while i < n:
        end = min(i + _NFKC_CHUNK, n)
        # Extend to a safe split point: never cut inside a combining sequence, and
        # never split immediately before a cc=0 char whose NFD starts with a mark
        # (the _NFD_LEADING_MARK Tibetan vowels) — that would change the NFKC result.
        while end < n and (unicodedata.combining(s[end]) or s[end] in _NFD_LEADING_MARK):
            end += 1
        chunk = unicodedata.normalize("NFKC", s[i:end])
        parts.append(chunk)
        out_total += len(chunk)
        i = end
        # Pathological-expansion circuit breaker: large output AND high expansion.
        if out_total > MAX_DEEP_SCAN and out_total > i * _MAX_EXPANSION:
            parts.append(s[i:])           # raw, un-normalized remainder
            return "".join(parts), False
    return "".join(parts), True


# --------------------------------------------------------------- public API
def sanitize(text: object, source: str = "web", *, strict: bool = False) -> SanitizeReport:
    """Sanitize untrusted content. Returns a SanitizeReport (its .text is the
    cleaned output). Never raises on any input. ``source`` is a label only in
    v0.1 (it does not change which sub-layers run); an unknown source does not
    raise. ``strict=True`` neutralizes matched injection markers (off by default
    because neutralization changes meaning)."""
    findings: list[SanitizeFinding] = []

    s = _coerce(text)
    s, fully_normalized = _bounded_nfkc(s)            # 1. encoding: NFKC FIRST (bounded)

    before = s
    s = before.translate(_DELETE_TABLE)               # 2. structural strip
    stripped_count = len(before) - len(s)
    if stripped_count:
        for kind, rx in _STRUCT_DETECT.items():
            m = rx.search(before)
            if m:
                findings.append(SanitizeFinding("structural", kind, None,
                                                _ascii_safe(m.group()), _STRUCT_WHY[kind]))
        if _has_surrogate(before):
            ch = next(c for c in before if 0xD800 <= ord(c) <= 0xDFFF)
            findings.append(SanitizeFinding("structural", "surrogate", None,
                                            _ascii_safe(ch), _STRUCT_WHY["surrogate"]))

    if not fully_normalized or len(s) > MAX_DEEP_SCAN:
        findings.append(SanitizeFinding(
            "content", "oversize_unscanned", None, "",
            f"input exceeds the {MAX_DEEP_SCAN}-char NFKC/scan budget; "
            f"normalization and marker/encoding deep-scan stopped at the bound"))
    else:
        s, content_findings = _scan_content(s, strict)  # 3. content markers
        findings.extend(content_findings)
        findings.extend(_scan_encoding(s))               # encoding detection

    return SanitizeReport(text=s, findings=tuple(findings),
                          stripped_count=stripped_count, wrapped=False)


def clean(text: object, source: str = "web", *, strict: bool = False) -> str:
    """Convenience: return just the cleaned text (== sanitize(...).text)."""
    return sanitize(text, source, strict=strict).text


# ---------------------------------------------------------------- wrappers
def _esc_body(s: str) -> str:
    # '&' MUST be escaped first, else an incoming '&lt;' would not be re-escaped
    # and a consumer that HTML-unescapes the body could resurrect a live tag.
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _esc_attr(s: str) -> str:
    return (_esc_body(s).replace('"', "&quot;")
            .replace("\n", " ").replace("\r", " "))


def _resolve_nonce(cleaned: str, _nonce: str | None,
                   _nonce_factory: Callable[[], str] | None) -> str:
    if _nonce is not None:
        return _nonce                                  # injected (test seam); used verbatim
    factory = _nonce_factory or (lambda: secrets.token_hex(_NONCE_BYTES))
    nonce = factory()
    tries = 0
    while nonce in cleaned and tries < 8:              # astronomically rare echo guard
        nonce = factory()
        tries += 1
    return nonce


def wrap_web(content: object, *, url: str = "",
             _nonce: str | None = None,
             _nonce_factory: Callable[[], str] | None = None) -> str:
    """Clean ``content`` then wrap it in a nonce-delimited <web_content> tag.
    The random per-wrap nonce (in BOTH the open and close tag) is the breakout
    defense: embedded close-tags/forged nonces in the content cannot terminate
    the wrapper. ``url`` (often itself untrusted) is escaped like the body."""
    cleaned = clean(content, "web")
    nonce = _resolve_nonce(cleaned, _nonce, _nonce_factory)
    return (f'<web_content nonce="{nonce}" url="{_esc_attr(url)}">'
            f'{_esc_body(cleaned)}</web_content nonce="{nonce}">')


def wrap_user_input(content: object, *,
                    _nonce: str | None = None,
                    _nonce_factory: Callable[[], str] | None = None) -> str:
    """Clean ``content`` then wrap it in a nonce-delimited <user_input> tag."""
    cleaned = clean(content, "user")
    nonce = _resolve_nonce(cleaned, _nonce, _nonce_factory)
    return (f'<user_input nonce="{nonce}">'
            f'{_esc_body(cleaned)}</user_input nonce="{nonce}">')


def wrap_agent_output(content: object, *, agent: str = "",
                      _nonce: str | None = None,
                      _nonce_factory: Callable[[], str] | None = None) -> str:
    """Clean ``content`` then wrap it in a nonce-delimited <agent_output> tag.
    ``sha256`` is the hex digest of the ORIGINAL (pre-clean) UTF-8 content — a
    content-IDENTITY fingerprint for audit/dedup, NOT an authenticity guarantee
    (it is unkeyed; whoever controls the content controls the hash)."""
    original = _coerce(content)
    cleaned = clean(content, "agent")
    nonce = _resolve_nonce(cleaned, _nonce, _nonce_factory)
    sha = hashlib.sha256(original.encode("utf-8", errors="surrogatepass")).hexdigest()
    return (f'<agent_output nonce="{nonce}" agent="{_esc_attr(agent)}" sha256="{sha}">'
            f'{_esc_body(cleaned)}</agent_output nonce="{nonce}">')


def wrap_tool_output(content: object, *, tool: str = "",
                     _nonce: str | None = None,
                     _nonce_factory: Callable[[], str] | None = None) -> str:
    """Clean ``content`` then wrap it in a nonce-delimited <tool_output> tag."""
    cleaned = clean(content, "tool")
    nonce = _resolve_nonce(cleaned, _nonce, _nonce_factory)
    return (f'<tool_output nonce="{nonce}" tool="{_esc_attr(tool)}">'
            f'{_esc_body(cleaned)}</tool_output nonce="{nonce}">')
