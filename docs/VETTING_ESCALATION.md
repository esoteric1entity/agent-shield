# Skill / Tool Vetting — Manual Escalation Rubric

> Companion to **Layer 1** (`agent_shield/skill_vetting.py`). The automated
> scanner gives a 3-tier verdict — **approved / review / rejected**. This doc is
> the human review path for the **review** tier (and a sanity check before
> trusting an **approved** verdict on anything high-value).

## When to use this

- **approved** → install is reasonable; skim Layer 1 below if the source is unfamiliar.
- **review** → **do not install yet.** Walk the five layers below before deciding.
- **rejected** → do not install. If you believe it's a false positive, treat it as a
  *review* and document why each flagged finding is benign before overriding.

The scanner is a static heuristic gate, not a sandbox. A clean automated verdict
means "no known-bad signatures matched," not "proven safe." High-value or
high-privilege tools deserve the manual pass regardless of score.

## The five layers

Work top to bottom. Any layer can halt the install on its own.

### Layer 1 — Provenance
- Who publishes it? Is the author/org identifiable and reputable?
- Where did the link come from? (A README link, a search result, and a DM are
  not equal trust.)
- How old is it, how many maintainers, recent activity, open security issues?
- Does the install source match the claimed project (no look-alike repo/namespace)?

### Layer 2 — Permissions & blast radius
- What does it ask to touch — filesystem paths, network, credentials, shell, the
  agent's own settings/hooks?
- Least privilege: does it need everything it requests, or can you scope it down?
- What's the worst case if it (or a future update) turns hostile? Is that
  acceptable on this machine / account?

### Layer 3 — Code read (the findings)
- Read every finding the scanner reported, in context — not just the count.
- For each: is it genuinely benign (e.g. a documented, scoped env read) or a real
  risk (bulk env harvest, credential-path access, exfiltration shape, persistence)?
- Look for what the scanner can't see: runtime-assembled commands, dynamic
  imports/`eval` of fetched data, obfuscation, logic that only activates later.

### Layer 4 — Behavior & supply chain
- Dependencies: are they real, pinned, and themselves trustworthy? Any typosquats
  or unexpected transitive pulls?
- Does it phone home, auto-update, or fetch+execute remote code at runtime?
- If feasible, observe it in an isolated/throwaway environment before the real one.

### Layer 5 — Decision & record
- Decide: install / install-scoped-down / reject.
- **Write it down** — what you reviewed, what you found, why you decided as you did.
  Keep a personal vetting log for your own reference and to support re-vetting on
  future version bumps; agent-shield's Layer 6 audit log can capture install events too.
- Re-vet on major version bumps — trust is per-version, not forever.

## Default deny

When the layers leave you uncertain, **don't install.** A skipped tool costs you a
feature; a hostile one costs you the machine, the credentials, or the data the
agent can reach. Uncertainty resolves toward "no."
