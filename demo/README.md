# Demo

A 30-second, runnable demonstration of agent-shield's Layer 4 `bash_guard` — the
real guard, not a mock-up.

## Run it

```bash
bash demo/demo.sh
```

You'll watch the live guard:

| Command | Decision | Why |
|---|---|---|
| `rm -rf /` | 🔴 **deny** | destructive — blocked outright |
| `git push --force origin main` | 🟡 **ask** | risky but legitimate — surfaced for your decision |
| `ls -la` | 🟢 **allow** | safe — passes silently, exit 0 |

Requires agent-shield installed (`pip install agent-shield`, or `pip install -e .`
from a checkout). Pure Python — no other dependencies. Point the demo at a
specific interpreter with `PYTHON=/path/to/python bash demo/demo.sh`.

## The static card in the README

[`../docs/assets/demo-bash-guard.svg`](../docs/assets/demo-bash-guard.svg) is a
committed, version-controlled snapshot of this same output, so the README renders
a visual everywhere with no binary blob. It reflects the guard's actual decisions
and reasons; regenerate it by hand if those change.

## Recording an animated GIF / asciinema (optional)

The script is written to record cleanly. With
[asciinema](https://asciinema.org/) and [agg](https://github.com/asciinema/agg):

```bash
asciinema rec demo.cast --overwrite -c "bash demo/demo.sh"
agg demo.cast docs/assets/demo-bash-guard.gif          # animated GIF
# or, for a scalable SVG cast:
#   npm i -g svg-term-cli
#   svg-term --in demo.cast --out docs/assets/demo-bash-guard-cast.svg
```

Then reference the recording from the README alongside (or in place of) the
static card.
