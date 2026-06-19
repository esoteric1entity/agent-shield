#!/usr/bin/env python3
"""Render the animated demo card (docs/assets/demo-bash-guard.gif).

A dev/demo tool — NOT part of the shipped `agent_shield` package (which stays
stdlib-only). It draws the three decisions shown in `demo/demo.sh` as a
line-by-line presentation reveal and loops. The decisions and reason strings
are the guard's real output; this renders them as a styled card (the static
twin is docs/assets/demo-bash-guard.svg). It is not a screen recording — for an
authentic live capture, use the asciinema recipe in demo/README.md.

Requires Pillow (`pip install Pillow`) and a monospace font (Consolas on
Windows or DejaVu Sans Mono on Linux). Run from anywhere:

    python demo/render_card.py
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent
OUT_GIF = REPO / "docs" / "assets" / "demo-bash-guard.gif"

SCALE = 2
W, H = 880, 300
CW, CH = W * SCALE, H * SCALE

BG, BORDER = (13, 17, 23), (48, 54, 61)
DOTS = ((255, 95, 86), (254, 188, 46), (39, 201, 63))
TITLE = (139, 148, 158)
PROMPT, CMD, DIM = (86, 211, 100), (201, 209, 217), (139, 148, 158)
DENY, ASK, ALLOW, GREY = (255, 123, 114), (227, 179, 65), (86, 211, 100), (110, 118, 129)

_REGULAR = [r"C:\Windows\Fonts\consola.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", "DejaVuSansMono.ttf"]
_BOLD = [r"C:\Windows\Fonts\consolab.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", "DejaVuSansMono-Bold.ttf"]


def _font(paths, size):
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return ImageFont.load_default()


f_body = _font(_REGULAR, 14 * SCALE)
f_bold = _font(_BOLD, 14 * SCALE)
f_title = _font(_REGULAR, 14 * SCALE)
f_foot = _font(_REGULAR, 12 * SCALE)

CMD1 = "$ echo '{\"tool_input\":{\"command\":\"rm -rf /\"}}' | python -m agent_shield.bash_guard"
CMD2 = "$ echo '{\"tool_input\":{\"command\":\"git push --force origin main\"}}' | python -m agent_shield.bash_guard"
CMD3 = "$ echo '{\"tool_input\":{\"command\":\"ls -la\"}}' | python -m agent_shield.bash_guard"
TITLE_TXT = "agent-shield · Layer 4 · bash_guard (PreToolUse hook)"
FOOT_TXT = ("Real decisions · a safe command prints nothing (exit 0) · "
            "only ask / deny emit JSON · zero runtime dependencies")

Y_C1, Y_O1, Y_C2, Y_O2, Y_C3, Y_O3, Y_FOOT = 62, 86, 124, 148, 186, 210, 262


def _seg(draw, x, y, parts):
    for text, color, font in parts:
        draw.text((x, y), text, font=font, fill=color)
        x += draw.textlength(text, font=font)


def _cmd(cmd):
    return [("$ ", PROMPT, f_body), (cmd[2:], CMD, f_body)]


def render(state):
    """state 0..7 = number of content lines revealed (chrome always drawn)."""
    img = Image.new("RGB", (CW, CH), BG)
    d = ImageDraw.Draw(img)
    s = SCALE
    d.rounded_rectangle([2 * s, 2 * s, (W - 2) * s, (H - 2) * s], radius=12 * s,
                        outline=BORDER, width=max(1, int(1.5 * s)))
    for cx, col in zip((26, 44, 62), DOTS):
        r = 5 * s
        d.ellipse([cx * s - r, 24 * s - r, cx * s + r, 24 * s + r], fill=col)
    d.text((92 * s, 16 * s), TITLE_TXT, font=f_title, fill=TITLE)
    d.line([0, 44 * s, CW, 44 * s], fill=BORDER, width=1)

    if state >= 1:
        _seg(d, 24 * s, Y_C1 * s, _cmd(CMD1))
    if state >= 2:
        _seg(d, 40 * s, Y_O1 * s, [("permissionDecision: ", DIM, f_body), ("deny", DENY, f_bold),
            ("  —  ", DIM, f_body), ('"Destructive rm -rf targeting root directory"', CMD, f_body)])
    if state >= 3:
        _seg(d, 24 * s, Y_C2 * s, _cmd(CMD2))
    if state >= 4:
        _seg(d, 40 * s, Y_O2 * s, [("permissionDecision: ", DIM, f_body), ("ask", ASK, f_bold),
            ("  —  ", DIM, f_body),
            ('"Destructive git operation — may lose commit history or untracked files"', CMD, f_body)])
    if state >= 5:
        _seg(d, 24 * s, Y_C3 * s, _cmd(CMD3))
    if state >= 6:
        _seg(d, 40 * s, Y_O3 * s, [("(no output — ", GREY, f_body), ("allowed", ALLOW, f_bold),
            (", exit 0)", GREY, f_body)])
    if state >= 7:
        d.line([0, 246 * s, CW, 246 * s], fill=BORDER, width=1)
        d.text((24 * s, Y_FOOT * s), FOOT_TXT, font=f_foot, fill=GREY)

    return img.resize((W, H), Image.LANCZOS)


def main():
    durations = [500, 450, 750, 450, 800, 450, 650, 2400]
    frames = [render(i) for i in range(8)]
    base = frames[-1].convert("RGB").quantize(colors=128, method=Image.MEDIANCUT)
    pframes = [f.quantize(palette=base, dither=Image.NONE) for f in frames]
    OUT_GIF.parent.mkdir(parents=True, exist_ok=True)
    pframes[0].save(OUT_GIF, save_all=True, append_images=pframes[1:],
                    duration=durations, loop=0, optimize=True, disposal=2)
    print(f"wrote {OUT_GIF} ({OUT_GIF.stat().st_size} bytes, {len(pframes)} frames)")


if __name__ == "__main__":
    main()
