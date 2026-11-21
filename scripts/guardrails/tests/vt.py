"""A tiny terminal emulator for the installer's rich display tests.

It understands what scripts/lib/ui.sh writes: printable text, CR, LF, cursor up (ESC [ n A),
erase to the end of the screen (ESC [ J), erase the line (ESC [ 2 K), SGR colours (ignored) and
cursor show/hide (ESC [ ? 25 h/l). Anything else raises, so a new escape sequence in the display
is noticed by the tests.
"""

import re

_CSI = re.compile(r"\x1b\[(\??)([0-9;]*)([A-Za-z])")


class Screen:
    def __init__(self, cols: int) -> None:
        self.cols = cols
        self.lines: list[str] = [""]
        self.row = 0
        self.col = 0
        self.cursor_visible = True
        self.overflow = False

    def _put(self, ch: str) -> None:
        line = self.lines[self.row]
        if self.col >= self.cols:
            self.overflow = True
        if len(line) < self.col:
            line += " " * (self.col - len(line))
        self.lines[self.row] = line[: self.col] + ch + line[self.col + 1 :]
        self.col += 1

    def feed(self, data: str) -> None:
        i = 0
        while i < len(data):
            ch = data[i]
            if ch == "\x1b":
                m = _CSI.match(data, i)
                if not m:
                    raise ValueError(f"unknown escape at {i}: {data[i : i + 10]!r}")
                private, arg, cmd = m.groups()
                n = int(arg) if arg.isdigit() else 1
                if private == "?" and arg == "25" and cmd in "hl":
                    self.cursor_visible = cmd == "h"
                elif private:
                    raise ValueError(f"unknown private sequence {m.group(0)!r}")
                elif cmd == "m":
                    pass
                elif cmd == "A":
                    self.row = max(0, self.row - n)
                elif cmd == "J":
                    self.lines[self.row] = self.lines[self.row][: self.col]
                    del self.lines[self.row + 1 :]
                elif cmd == "K" and arg == "2":
                    self.lines[self.row] = ""
                else:
                    raise ValueError(f"unknown sequence {m.group(0)!r}")
                i = m.end()
                continue
            if ch == "\r":
                self.col = 0
            elif ch == "\n":
                self.row += 1
                self.col = 0
                if self.row >= len(self.lines):
                    self.lines.append("")
            else:
                self._put(ch)
            i += 1

    def text(self) -> str:
        return "\n".join(line.rstrip() for line in self.lines).rstrip("\n") + "\n"
