"""skill_vetting — Layer 1 of agent-shield: static, read-only supply-chain vetting.

Scans a skill / MCP server / hook / package BEFORE you install it and returns a
3-tier verdict — **approved / review / rejected** — with structured findings.

  from agent_shield import skill_vetting
  result = skill_vetting.vet_path("/path/to/some-skill")
  result.tier      # "approved" | "review" | "rejected"
  result.score     # 0..10 (severity-weighted, capped)
  result.findings  # list[Finding]

CLI (exit code maps to the tier: 0 approved · 1 review · 2 rejected):

  python -m agent_shield.skill_vetting /path/to/some-skill [--format md|json]

Security contract:
- **Read-only.** Never executes, imports, writes, or network-fetches the
  target — it only reads files and pattern-matches. (No subprocess, no eval.)
- **Zero runtime dependencies** — Python standard library only.
- **Never crashes** on missing / binary / malformed input, and never silently
  approves something it could not scan.

It is a static heuristic layer, not a sandbox: it raises the cost of installing
something malicious; it does not guarantee safety. See docs/VETTING_ESCALATION.md.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

# =============================================================================
# Tiers + severity model
# =============================================================================
_SEVERITY_WEIGHT: Final[dict[str, int]] = {"critical": 10, "high": 4, "medium": 2, "low": 1}

# score < REVIEW_AT -> approved ; REVIEW_AT <= score < REJECT_AT -> review ; >= REJECT_AT -> rejected
_REVIEW_AT: Final[int] = 3
_REJECT_AT: Final[int] = 8

_CODE_EXTS: Final[frozenset[str]] = frozenset(
    {".py", ".js", ".ts", ".mjs", ".cjs", ".sh", ".bash", ".zsh", ".rb", ".go", ".rs", ".ps1"}
)
_INSTRUCTION_EXTS: Final[frozenset[str]] = frozenset({".md", ".markdown"})
_INSTRUCTION_NAMES: Final[frozenset[str]] = frozenset(
    {"skill.md", "readme.md", "claude.md", "agents.md", "hooks.json", "settings.json", "mcp.json"}
)
_MAX_BYTES: Final[int] = 2_000_000  # skip pathologically large files (operational guard)


# =============================================================================
# Threat categories — each scans CODE files line-by-line.
# (id, severity, compiled patterns, why). Threat signatures are domain
# knowledge; the verdicts they produce are pinned by tests/test_skill_vetting.py.
# =============================================================================
def _c(*pats: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in pats)


_CODE_CATEGORIES: Final[tuple[dict, ...]] = (
    {
        "id": "ENV_BULK", "severity": "high",
        "patterns": _c(r"dict\s*\(\s*os\.environ", r"os\.environ\.copy\s*\(",
                        r"for\s+\w+\s+in\s+os\.environ", r"json\.stringify\s*\(\s*process\.env",
                        r"object\.keys\s*\(\s*process\.env", r"process\.env\b\s*\)"),
        "why": "Enumerates ALL environment variables (credential-harvesting risk).",
    },
    {
        "id": "ENV_SCRAPE", "severity": "medium",
        "patterns": _c(r"os\.getenv\b", r"os\.environ\s*\[", r"os\.environ\.get",
                        r"process\.env\.\w+", r"\bdotenv\b"),
        "why": "Reads individual environment variables (possible credential access).",
    },
    {
        "id": "CRED_PATH", "severity": "critical",
        "patterns": _c(r"\.ssh/", r"\.aws/", r"\.gnupg", r"\.kube/", r"\.config/gcloud",
                        r"\bid_rsa\b", r"\bid_ed25519\b", r"\bid_ecdsa\b", r"\.netrc\b",
                        r"credentials\.json", r"\btoken\.json\b", r"\.npmrc\b"),
        "why": "Accesses a known credential-storage location.",
    },
    {
        "id": "FS_DANGER", "severity": "critical",
        "patterns": _c(r"rm\s+-[rf]{1,2}\s+/", r"shutil\.rmtree\s*\(\s*['\"]/",
                        r"chmod\s+-R\s+777\s+/", r"rmdir\s+/[sq]"),
        "why": "Destructive recursive delete or broad permission change on a root path.",
    },
    {
        "id": "PIPE_TO_SHELL", "severity": "critical",
        "patterns": _c(r"(curl|wget|fetch)\b[^\n|]*\|\s*(bash|sh|zsh|powershell|pwsh)",
                        r"(base64\s+-d|--decode)[^\n|]*\|\s*(bash|sh)"),
        "why": "Downloads and pipes remote/encoded content straight into a shell.",
    },
    {
        "id": "PERSIST", "severity": "high",
        "patterns": _c(r"\bcrontab\b", r"systemctl\s+enable", r"\blaunchd\b", r"\bschtasks\b",
                        r"register-scheduledtask", r"currentversion\\\\?run",
                        # append-redirect INTO a shell rc/profile = persistence (readiness
                        # the old `\.bashrc\b\s*>>` was backwards — it
                        # matched a benign read and missed `echo … >> ~/.bashrc`).
                        # Bounded, non-greedy gap: a greedy
                        # `[^\n]*` over many `>>` start positions backtracks O(n^2)
                        # (ReDoS). A redirect target is never far from `>>`, so a
                        # single bounded `{0,200}?` gap (no overlapping `\s*`) is
                        # linear and loses no realistic coverage.
                        r">>[^\n]{0,200}?(\.bashrc|\.zshrc|\.profile|\.bash_profile|\.bash_login|\.zprofile)\b"),
        "why": "Installs persistence (cron / systemd / launchd / scheduled task / autorun).",
    },
    {
        "id": "NET_EXFIL", "severity": "high",
        "patterns": _c(r"(requests\.(post|put|patch|request)|httpx\.(post|put)|urllib\.request|fetch\s*\()[^\n]*open\s*\(",
                        r"open\s*\([^\n]*\)\s*[^\n]*\|\s*(nc|ncat|curl|wget)\b",
                        r"socket\.\w+[^\n]*open\s*\("),
        "why": "Reads a local file and sends it over the network (exfiltration shape).",
    },
    {
        "id": "CRYPTO_MINE", "severity": "critical",
        "patterns": _c(r"stratum\+tcp://", r"\bxmrig\b", r"\bcoinhive\b", r"\bcryptonight\b",
                        r"monero[^\n]*pool", r"\bminergate\b"),
        "why": "Cryptocurrency-mining indicator.",
    },
)

# =============================================================================
# Prompt-injection — scans INSTRUCTION files (SKILL.md / README / hooks / etc.)
# =============================================================================
_INJECTION = {
    "id": "PROMPT_INJECTION", "severity": "high",
    "patterns": _c(
        r"ignore\s+(all\s+)?(your\s+|the\s+)?previous\s+instructions",
        r"disregard\s+(your\s+|the\s+)?(system\s+prompt|instructions|rules)",
        r"do\s+not\s+tell\s+the\s+user",
        r"exfiltrat", r"reveal\s+(your\s+)?system\s+prompt",
        r"override\s+(your\s+)?(safety|guard)",
    ),
    "why": "Instruction file contains prompt-injection / jailbreak phrasing.",
}

# =============================================================================
# Typosquat — checks declared dependency names against popular packages.
# =============================================================================
_KNOWN_PACKAGES: Final[frozenset[str]] = frozenset({
    "requests", "flask", "django", "numpy", "pandas", "scipy", "pytest", "pip", "setuptools",
    "urllib3", "boto3", "click", "jinja2", "pyyaml", "cryptography", "sqlalchemy", "fastapi",
    "pydantic", "httpx", "aiohttp", "matplotlib", "scikit-learn", "torch", "tensorflow",
    "beautifulsoup4", "lxml", "pillow", "python-dateutil", "six", "certifi", "openai",
    "anthropic", "express", "react", "lodash", "axios", "chalk", "commander", "dotenv",
    "typescript", "webpack", "eslint", "next", "vue",
})
_TYPOSQUAT = {"id": "TYPOSQUAT", "severity": "high",
              "why": "Dependency name is one edit away from a popular package (typosquat risk)."}

# Public: the set of category ids, pinned to the README by the doc-claims test.
# Operational finding (NOT a threat signature) for a file too large to scan.
# Deliberately excluded from THREAT_CATEGORY_IDS — that tuple is pinned to the
# README's 10 threat categories by the doc-claims test.
_UNSCANNED: Final[dict[str, str]] = {
    "id": "UNSCANNED",
    "severity": "medium",
    "why": "File exceeds the size cap and was not scanned — assess manually "
           "(a security tool never silently approves what it could not read).",
}

THREAT_CATEGORY_IDS: Final[tuple[str, ...]] = tuple(
    [c["id"] for c in _CODE_CATEGORIES] + [_INJECTION["id"], _TYPOSQUAT["id"]]
)


# =============================================================================
# Result types
# =============================================================================
@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    file: str
    line: int
    snippet: str
    why: str

    def to_dict(self) -> dict:
        return {
            "category": self.category, "severity": self.severity, "file": self.file,
            "line": self.line, "snippet": self.snippet, "why": self.why,
        }


@dataclass(frozen=True)
class VetResult:
    score: int
    tier: str
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "score": self.score, "tier": self.tier, "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


# =============================================================================
# Internals
# =============================================================================
def _read_text(p: Path) -> str:
    try:
        if p.stat().st_size > _MAX_BYTES:
            return ""
        return p.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _scan_code(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for lineno, line in enumerate(text.split("\n"), start=1):
        for cat in _CODE_CATEGORIES:
            key = (cat["id"], lineno)
            if key in seen:
                continue
            if any(p.search(line) for p in cat["patterns"]):
                out.append(Finding(cat["id"], cat["severity"], rel, lineno, line.strip()[:200], cat["why"]))
                seen.add(key)
    return out


def _scan_injection(rel: str, text: str) -> list[Finding]:
    for lineno, line in enumerate(text.split("\n"), start=1):
        if any(p.search(line) for p in _INJECTION["patterns"]):
            return [Finding(_INJECTION["id"], _INJECTION["severity"], rel, lineno,
                            line.strip()[:200], _INJECTION["why"])]
    return []


def _edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance.

    Counts an adjacent-character transposition as a single edit — important for
    typosquat detection, where swaps (``reqeusts`` vs ``requests``) are a common
    attack form, not just insertions/deletions/substitutions.
    """
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return 2  # we only care whether distance == 1
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)  # transposition
    return d[la][lb]


def _dep_names(rel: str, text: str) -> list[str]:
    names: list[str] = []
    base = rel.rsplit("/", 1)[-1].lower()
    if base == "requirements.txt":
        for line in text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            names.append(re.split(r"[=<>!~\[ ]", line, maxsplit=1)[0].strip().lower())
    elif base == "package.json":
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return names
        if not isinstance(data, dict):
            return names            # a non-dict manifest has no dependency map
        for keyset in ("dependencies", "devDependencies"):
            dep = data.get(keyset)
            if isinstance(dep, dict):
                names.extend(str(k).lower() for k in dep)
    return [n for n in names if n]


def _scan_typosquat(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for name in _dep_names(rel, text):
        if name in _KNOWN_PACKAGES or len(name) < 4:
            continue
        if any(_edit_distance(name, known) == 1 for known in _KNOWN_PACKAGES):
            out.append(Finding(_TYPOSQUAT["id"], _TYPOSQUAT["severity"], rel, 1, name, _TYPOSQUAT["why"]))
    return out


def _is_instruction(p: Path) -> bool:
    return p.suffix.lower() in _INSTRUCTION_EXTS or p.name.lower() in _INSTRUCTION_NAMES


def _tier_for(score: int) -> str:
    if score >= _REJECT_AT:
        return "rejected"
    if score >= _REVIEW_AT:
        return "review"
    return "approved"


# =============================================================================
# Public API
# =============================================================================
def vet_path(path: str | Path) -> VetResult:
    """Statically vet a skill/tool path and return a VetResult. Read-only; never raises."""
    root = Path(path)
    if not root.exists():
        # Can't assess what isn't there — never silently approve.
        return VetResult(0, "review", [], "target not found — cannot vet")

    if root.is_file():
        files = [root]
        base = root.parent
    else:
        files = sorted(p for p in root.rglob("*") if p.is_file())
        base = root

    findings: list[Finding] = []
    for p in files:
        try:
            rel = p.relative_to(base).as_posix()
        except ValueError:
            rel = p.name
        try:
            oversize = p.stat().st_size > _MAX_BYTES
        except OSError:
            oversize = False
        if oversize:
            # Never silently approve what we couldn't read — emit a finding.
            findings.append(Finding(_UNSCANNED["id"], _UNSCANNED["severity"],
                                    rel, 0, "", _UNSCANNED["why"]))
            continue
        text = _read_text(p)
        if not text:
            continue
        if p.suffix.lower() in _CODE_EXTS:
            findings.extend(_scan_code(rel, text))
        if _is_instruction(p):
            findings.extend(_scan_injection(rel, text))
        if p.name.lower() in ("requirements.txt", "package.json"):
            findings.extend(_scan_typosquat(rel, text))

    score = min(10, sum(_SEVERITY_WEIGHT.get(f.severity, 0) for f in findings))
    tier = _tier_for(score)
    if tier == "approved" and any(f.category == _UNSCANNED["id"] for f in findings):
        tier = "review"   # can't assess what we couldn't scan
    summary = f"{tier.upper()} (score {score}/10) — {len(findings)} finding(s)"
    return VetResult(score, tier, findings, summary)


def _render_md(result: VetResult) -> str:
    lines = [f"# agent-shield vetting report", "", f"**Verdict:** {result.summary}", ""]
    if not result.findings:
        lines.append("No findings.")
    else:
        lines.append("| Severity | Category | Location | Detail |")
        lines.append("|---|---|---|---|")
        for f in result.findings:
            lines.append(f"| {f.severity} | {f.category} | {f.file}:{f.line} | {f.why} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="agent_shield.skill_vetting",
        description="Statically vet a skill/tool/package; exit 0=approved, 1=review, 2=rejected.",
    )
    parser.add_argument("path", help="path to a skill / tool / package (file or directory)")
    parser.add_argument("--format", choices=["md", "json"], default="md")
    try:
        args = parser.parse_args(argv)
        result = vet_path(args.path)
        if args.format == "json":
            sys.stdout.write(json.dumps(result.to_dict()))
        else:
            sys.stdout.write(_render_md(result))
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001 — vetter must never crash; can't-assess -> review
        sys.stderr.write("skill-vetting: scan error\n")
        return 1
    return {"approved": 0, "review": 1, "rejected": 2}[result.tier]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
