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

## The card in the README

The README's "See it in action" section embeds an animated card,
[`../docs/assets/demo-bash-guard.gif`](../docs/assets/demo-bash-guard.gif), that
reveals the three decisions in sequence. A static twin,
[`../docs/assets/demo-bash-guard.svg`](../docs/assets/demo-bash-guard.svg), is kept
for contexts where a GIF isn't wanted. Both show the guard's actual decisions and
reason strings.

## Regenerating the card

The animated GIF is rendered by [`render_card.py`](render_card.py) — a dev tool
(needs `pip install Pillow` and a monospace font: Consolas on Windows, DejaVu Sans
Mono on Linux). It is **not** part of the shipped package, which stays stdlib-only.

```bash
python demo/render_card.py        # writes docs/assets/demo-bash-guard.gif
```

`render_card.py` and the `.svg` are stylized cards, **not** screen recordings. For
an authentic live capture of an actual run, record `demo.sh` with
[asciinema](https://asciinema.org/) + [agg](https://github.com/asciinema/agg):

```bash
asciinema rec demo.cast --overwrite -c "bash demo/demo.sh"
agg demo.cast docs/assets/demo-bash-guard.gif
```
