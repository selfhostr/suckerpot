"""Shell arithmetic (``$(( ))``): a small hand-written integer expression evaluator.

Tokenizer plus a precedence-climbing parser over ``+ - * / % ( )``, unary ``+``/``-``,
decimal integers and variable names. It never uses Python's ``eval``/``exec``: the input is
attacker text and is only ever looked at character by character. Length, nesting depth and
the number of tokens are bounded, and results wrap to a signed 64-bit integer like bash's.
"""

from __future__ import annotations

from collections.abc import Callable

MAX_EXPR_CHARS = 256
MAX_DEPTH = 24
MAX_TOKENS = 128
MAX_DIGITS = 19
_INT64 = 1 << 63


class ArithError(Exception):
    """Syntax error, division by zero or a bound exceeded."""


def _wrap(value: int) -> int:
    return (value + _INT64) % (1 << 64) - _INT64


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\n":
            i += 1
        elif ch in "+-*/%()":
            tokens.append(("op", ch))
            i += 1
        elif "0" <= ch <= "9":
            j = i
            while j < n and "0" <= text[j] <= "9":
                j += 1
            if j - i > MAX_DIGITS:
                raise ArithError("value too great")
            tokens.append(("num", text[i:j]))
            i = j
        elif ch == "_" or ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
            j = i
            while j < n and (
                text[j] == "_"
                or "a" <= text[j] <= "z"
                or "A" <= text[j] <= "Z"
                or "0" <= text[j] <= "9"
            ):
                j += 1
            tokens.append(("name", text[i:j]))
            i = j
        else:
            raise ArithError(f"syntax error: operand expected (error token is {text[i:]!r})")
        if len(tokens) > MAX_TOKENS:
            raise ArithError("expression too long")
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]], lookup: Callable[[str], str]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.lookup = lookup

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def parse(self) -> int:
        if not self.tokens:
            return 0
        value = self._expr(0)
        if self._peek() is not None:
            raise ArithError("syntax error in expression")
        return value

    def _expr(self, depth: int) -> int:
        if depth > MAX_DEPTH:
            raise ArithError("expression nested too deeply")
        value = self._term(depth)
        while (tok := self._peek()) is not None and tok[1] in "+-" and tok[0] == "op":
            self.pos += 1
            rhs = self._term(depth)
            value = _wrap(value + rhs if tok[1] == "+" else value - rhs)
        return value

    def _term(self, depth: int) -> int:
        value = self._unary(depth)
        while (tok := self._peek()) is not None and tok[1] in "*/%" and tok[0] == "op":
            self.pos += 1
            rhs = self._unary(depth)
            if tok[1] == "*":
                value = _wrap(value * rhs)
                continue
            if rhs == 0:
                raise ArithError("division by 0")
            quotient = abs(value) // abs(rhs)  # C semantics: truncate toward zero
            if (value < 0) != (rhs < 0):
                quotient = -quotient
            value = _wrap(quotient if tok[1] == "/" else value - quotient * rhs)
        return value

    def _unary(self, depth: int) -> int:
        if depth > MAX_DEPTH:
            raise ArithError("expression nested too deeply")
        tok = self._peek()
        if tok is None:
            raise ArithError("syntax error: operand expected")
        if tok[0] == "op" and tok[1] in "+-":
            self.pos += 1
            value = self._unary(depth + 1)
            return _wrap(-value) if tok[1] == "-" else value
        return self._primary(depth)

    def _primary(self, depth: int) -> int:
        tok = self._peek()
        if tok is None:
            raise ArithError("syntax error: operand expected")
        self.pos += 1
        kind, text = tok
        if kind == "num":
            return _wrap(int(text))
        if kind == "name":
            return _variable(self.lookup(text))
        if text == "(":
            value = self._expr(depth + 1)
            close = self._peek()
            if close is None or close[1] != ")":
                raise ArithError("missing `)'")
            self.pos += 1
            return value
        raise ArithError(f"syntax error: operand expected (error token is {text!r})")


def _variable(raw: str) -> int:
    """A variable's value: a decimal integer, else 0 (unset) like bash; names are not recursed."""
    raw = raw.strip()
    if not raw:
        return 0
    sign = -1 if raw.startswith("-") else 1
    digits = raw.lstrip("+-")
    if digits.isascii() and digits.isdigit() and len(digits) <= MAX_DIGITS:
        return _wrap(sign * int(digits))
    return 0


def evaluate(expr: str, lookup: Callable[[str], str]) -> int:
    """Value of the arithmetic expression ``expr``. Raises :class:`ArithError`."""
    if len(expr) > MAX_EXPR_CHARS:
        raise ArithError("expression too long")
    return _Parser(_tokenize(expr), lookup).parse()
