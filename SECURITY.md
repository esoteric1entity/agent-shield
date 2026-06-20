# Security Policy

`agent-shield` is a defensive security tool. We take security in the tool itself seriously.

## Supported versions

Until v1.0.0, the **latest minor release** is the only version that receives security fixes. Pre-release tags (`aN`, `bN`, `rcN`) are not eligible for security backports — upgrade to the latest release on the same minor line.

| Version | Status | Security fixes |
|---|---|---|
| `0.1.x` | ✅ active alpha | Yes (latest pre-release only) |
| `< 0.1` | — | None — not a released line |

Once `1.0.0` ships, the policy will be revised to support the most recent two minor versions for the security window stated in the release notes.

## Reporting a vulnerability

**Please do NOT open a public issue for security vulnerabilities.** Doing so puts the entire user base at risk while a fix is in flight.

Instead, use **one** of the following private channels (in order of preference):

1. **GitHub Security Advisory** — Open a private vulnerability report through the repository's "Security" tab → "Report a vulnerability." This is the preferred channel because it keeps the entire fix lifecycle (reproduction, triage, fix, disclosure, CVE issuance if applicable) in one place and auto-issues a CVE if the fix qualifies.
2. **No email channel yet** — GitHub private vulnerability reporting is currently the only confidential channel; a direct maintainer contact (with PGP fingerprint) will be published in a future release. Please do **not** disclose vulnerabilities through the public issue tracker.

Please include:

- A description of the issue
- The version of `agent-shield` affected
- Steps to reproduce (or a minimal proof of concept)
- The impact (what an attacker can do; severity estimate is helpful but not required)
- Your preferred attribution: name + URL, anonymous, or "see GHSA credit"

## What we'll do

| Step | Target | Notes |
|---|---|---|
| Acknowledge receipt | within **48 hours** | A human will reply confirming we got it |
| Initial triage + reproduction | within **5 business days** | We'll tell you whether we can reproduce, our severity estimate, and the proposed fix window |
| Fix development | depends on severity | Critical: aim for 7 days; High: 14 days; Medium: 30 days; Low: next regular release |
| Coordinated disclosure | per agreement | We aim for **90 days from acknowledgement to public disclosure**, or sooner if a patch is available + accepted. We extend if you need it; we don't shorten without your agreement. |
| Credit | at your discretion | Reporter is credited in the security advisory and `CHANGELOG.md` unless they request anonymity |

If we cannot reproduce a reported issue, we'll tell you why and ask for more information. If we conclude the report is not a security vulnerability (e.g. expected behavior, out of scope), we'll explain our reasoning and offer to convert the report to a public issue if you'd like.

## Threat model — what `agent-shield` defends against

This shapes which reports we consider "security vulnerabilities" vs "usability or correctness issues."

**In scope:**
- A malicious or confused agent attempts to issue a dangerous command (e.g. `rm -rf /`, `mkfs.ext4`, `curl … | bash`, credential exfiltration) and `agent-shield` allows it through (decision `allow` or `ask` instead of `deny`)
- A pattern intended to be RED-tier is bypassable via a quoting / escaping / encoding trick the regex did not anticipate
- A malicious crafted input to the CLI / library API causes `agent-shield` itself to crash, hang, or behave unsafely
- `agent_shield/*.py` (the canonical guard module) is writable by an agent under the shield's protection (the self-protection contract is broken)
- Audit-log integrity is compromised by an under-shield action

**Out of scope (interesting but not security):**
- An agent issues a YELLOW-tier command (`ask`) and the user approves it — the user is the authority; their approval is the contract
- The shield blocks a legitimate command in error (false positive) — this is a usability bug; please open a public issue
- The shield does not detect a class of attack the README/threat-model never claimed to detect (e.g. semantic prompt injection without an obvious shell-command vector)
- The agent harness itself (Claude Code, OpenClaw) has a vulnerability — please report to the harness's security channel, not here
- The host OS, Python interpreter, or third-party libraries have CVEs — please report upstream

**Adversary assumption.** `agent-shield` assumes the **agent is the adversary** — misled by an adversarial prompt, an injected payload, or a confused-deputy attack via the harness. We do NOT assume the host or the user is the adversary; we assume the user is the authority and `agent-shield` is enforcing their pre-committed policy.

## Disclosed vector: harness-tag spoofing (F-001, detected as of this release)

On 2026-05-12, a class of injection was observed where attacker-controlled content
attempted to spoof harness-level structural framing by forging tag boundaries
(tags characteristic of agent harness context). This class of attack aims to make
injected content appear to the model as if it originates from the harness itself,
rather than from untrusted external input.

**Status:** Detected as of this release — Layer 2 (`sanitize`) flags this class of
harness-tag spoofing (F-001). Detection raises attacker cost and produces audit
evidence; see the threat model note on the limits of detection vs. prevention.

No specific bypass payload is published here. If you believe you have found a novel
variant not covered by the current detection, please report it via the responsible
disclosure process above (GitHub Security Advisory).

## Known limitations (v0.1.0 — alpha)

`agent-shield` is **defense-in-depth, not an airtight guarantee.** It raises the cost of a dangerous action and makes tampering evident; it does not make either impossible. The API is **not yet stable** (`0.x`) — breaking changes may land between `0.x` releases, including to close a security gap. Maturity is also signalled by the PyPI `Development Status :: 3 - Alpha` classifier. Known, accepted limits in this release:

- **Coverage: 6 of 8 layers ship.** Layer 0 (operational/automation hygiene) and **Layer 5 (network egress)** are not built. There is **no outbound-egress enforcement** in v0.1 — a `deny` on `curl … | bash` is pattern-based at Layer 4, not a network control.
- **Detection is heuristic, not semantic.** Layers 1–4 are pattern/static heuristics. A novel phrasing, an unmodeled quoting/encoding trick, or semantic prompt injection without an obvious shell vector can pass. A flag is "look here," not a verdict.
- **L1 `skill_vetting`** is a static read-only scan, not a sandbox; typosquat detection covers a small known-package set over `requirements.txt`/`package.json`; homoglyph detection is best-effort (no confusables database). Files over the size cap are reported `UNSCANNED` and cannot resolve to `approved` — they are not scanned.
- **L2 `sanitize`** is detection, not prevention — it strips invisible/control characters and *flags* markers/encodings; it does not block injection. NFKC is bounded: input that expands past the budget (a pathological compatibility expander) is reported `oversize_unscanned` rather than deep-scanned.
- **L4 guards** are a regex tier model. Full path-normalization (`..` resolution) in the **bash** port requires a Python interpreter to be present; without one it degrades to collapsing `//` and `/./` only (still strictly better than no normalization, and documented). The Python and bash ports are verified decision-equivalent on the tested configuration.
- **L6 `audit` is tamper-*evident*, not tamper-*resistant*** on its own: `verify()` proves internal chain consistency but cannot detect a from-genesis rewrite. Tamper-resistance requires an **independent external anchor**, and even then the **unanchored tail** (everything since the last anchor) is forgeable — keep anchor cadences small. The anchor shipper runs synchronously, in-process.
- **L7 `config` is not a trust boundary.** It carries policy/paths, never secrets, and cannot weaken a built-in guard.

These are disclosed so the protection is neither over- nor under-claimed; see the linked layer docs for the per-layer detail.

## Uninstalling (remove the hooks, too)

`pip uninstall agent-shield` removes the package but **not** the harness hook wiring. If
you wired the guards into a `PreToolUse` hook, you must also remove those two entries from
your `settings.json` (the `Bash` → `agent_shield.bash_guard` and `Write|Edit|MultiEdit` →
`agent_shield.write_guard` entries) and restart the harness. A hook that points at a removed
guard makes every tool call fail with `ModuleNotFoundError` until the entry is cleared — see
`INSTALL_AGENT.md` Step 6 for the exact procedure.

## Coordinated disclosure principles

- We will not publicly disclose a vulnerability before a fix is available, unless: (a) the issue is already being exploited in the wild, or (b) the reporter requests immediate disclosure and we've assessed it is appropriate.
- We will not issue legal threats against good-faith security researchers.
- Researchers who follow this policy will not face legal action under the CFAA or analogous statutes for their work on `agent-shield`.
- We aim for **transparency in the fix lifecycle**: the GitHub Security Advisory captures triage, fix, and disclosure; the corresponding CHANGELOG entry describes the user-facing impact and the upgrade path.

## CVE issuance

For vulnerabilities with a clear technical impact (CVSS ≥ 4.0), we will request a CVE via GitHub Security Advisories. Lower-severity issues may be addressed via a CHANGELOG entry only.

## Hall of credit

Researchers who responsibly disclose vulnerabilities to `agent-shield` will be credited in:

- The corresponding security advisory (GHSA-####)
- `CHANGELOG.md` under the patched version
- This `SECURITY.md` "Hall of credit" section (forthcoming after the first acknowledgement)

Thank you for keeping `agent-shield` and its downstream users safe.

---

*Maintained by `esoteric1entity`. A PDuk Brainworks project. Apache-2.0.*
