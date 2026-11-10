"""Shell arithmetic (``$(( ))``): a small hand-written integer expression evaluator.

Tokenizer plus a precedence parser over ``** * / % + - << >>``, parentheses, unary ``+``/``-``,
integer literals (decimal, ``0x`` hex, ``0`` octal, ``base#digits``) and variable names. It
never uses Python's ``eval``/``exec``: the input is attacker text and is only ever looked at
character by character. Length, nesting depth and the number of tokens are bounded, results
wrap to a signed 64-bit integer like bash's, ``**`` uses at most 64 wrapping multiplications
and shift counts are masked to 0-63, so no step can build a large number.
"""

from __future__ import annotations

from collections.abc import Callable

MAX_EXPR_CHARS = 256
MAX_DEPTH = 24
MAX_TOKENS = 128
MAX_LITERAL = 24
_INT64 = 1 << 63
_DIGITS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@_"
_ALNUM = frozenset(_DIGITS) | {"#"}

Token = tuple[str, str, int]  # kind ("op", "num", "name"), text, offset in the source


class ArithError(Exception):
    """Syntax error, division by zero or a bound exceeded."""

    def __init__(self, message: str, token: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.token = token

    def __str__(self) -> str:
        suffix = f' (error token is "{self.token}")' if self.token else ""
        return self.message + suffix


def _wrap(value: int) -> int:
    return (value + _INT64) % (1 << 64) - _INT64


def _literal(text: str) -> int:
    """Value of a numeric literal as bash reads it."""
    bad = ArithError("value too great for base", text)
    if "#" in text:
        base_text, _, digits = text.partition("#")
        if not (base_text.isascii() and base_text.isdigit()) or not 2 <= int(base_text) <= 64:
            raise ArithError("invalid arithmetic base", text)
        base = int(base_text)
        if not digits:
            raise bad
        value = 0
        for ch in digits:
            # up to base 36 letters are case-insensitive, beyond that a-z < A-Z < @ < _
            pos = _DIGITS.find(ch.lower() if base <= 36 else ch)
            if pos < 0 or pos >= base:
                raise bad
            value = _wrap(value * base + pos)
        return value
    if text[:2] in ("0x", "0X"):
        digits, base = text[2:], 16
    elif len(text) > 1 and text[0] == "0":
        digits, base = text[1:], 8
    else:
        digits, base = text, 10
    try:
        return _wrap(int(digits, base)) if digits else _raise(bad)
    except ValueError:
        raise bad from None


def _raise(exc: ArithError) -> int:
    raise exc


def _tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        two = text[i : i + 2]
        if ch in " \t\n":
            i += 1
            continue
        if two in ("**", "<<", ">>"):
            tokens.append(("op", two, i))
            i += 2
        elif ch in "+-*/%()":
            tokens.append(("op", ch, i))
            i += 1
        elif ch in _ALNUM and ch != "#":
            j = i
            while j < n and text[j] in _ALNUM:
                j += 1
            word = text[i:j]
            if j - i > MAX_LITERAL:
                raise ArithError("value too great for base", word[:MAX_LITERAL])
            if "0" <= ch <= "9":
                tokens.append(("num", word, i))
            elif ch == "_" or ch.isalpha():
                tokens.append(("name", word, i))
            else:
                raise ArithError("syntax error: operand expected", text[i:])
            i = j
        else:
            raise ArithError("syntax error: operand expected", text[i:])
        if len(tokens) > MAX_TOKENS:
            raise ArithError("expression too long")
    return tokens


def _power(base: int, exp: int) -> int:
    """``base ** exp`` by square-and-multiply with wrapping: at most 64 iterations."""
    result = 1
    for _ in range(64):
        if exp & 1:
            result = _wrap(result * base)
        exp >>= 1
        if not exp:
            break
        base = _wrap(base * base)
    return result


class _Parser:
    def __init__(self, source: str, tokens: list[Token], lookup: Callable[[str], str]) -> None:
        self.source = source
        self.tokens = tokens
        self.pos = 0
        self.lookup = lookup

    def _peek(self) -> Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _is_op(self, *ops: str) -> bool:
        tok = self._peek()
        return tok is not None and tok[0] == "op" and tok[1] in ops

    def _operand_expected(self) -> ArithError:
        tok = self._peek()
        if tok is not None:
            return ArithError("syntax error: operand expected", self.source[tok[2] :])
        last = self.tokens[-1][1] if self.tokens else ""
        return ArithError("syntax error: operand expected", last)

    def parse(self) -> int:
        if not self.tokens:
            return 0
        value = self._shift(0)
        tok = self._peek()
        if tok is not None:
            raise ArithError("syntax error in expression", self.source[tok[2] :])
        return value

    def _shift(self, depth: int) -> int:
        if depth > MAX_DEPTH:
            raise ArithError("expression nested too deeply")
        value = self._sum(depth)
        while self._is_op("<<", ">>"):
            op = self.tokens[self.pos][1]
            self.pos += 1
            count = self._sum(depth) & 63
            value = _wrap(value << count) if op == "<<" else value >> count
        return value

    def _sum(self, depth: int) -> int:
        value = self._term(depth)
        while self._is_op("+", "-"):
            op = self.tokens[self.pos][1]
            self.pos += 1
            rhs = self._term(depth)
            value = _wrap(value + rhs if op == "+" else value - rhs)
        return value

    def _term(self, depth: int) -> int:
        value = self._power(depth)
        while self._is_op("*", "/", "%"):
            op = self.tokens[self.pos][1]
            self.pos += 1
            rhs = self._power(depth)
            if op == "*":
                value = _wrap(value * rhs)
                continue
            if rhs == 0:
                raise ArithError("division by 0", self.tokens[self.pos - 1][1])
            quotient = abs(value) // abs(rhs)  # C semantics: truncate toward zero
            if (value < 0) != (rhs < 0):
                quotient = -quotient
            value = _wrap(quotient if op == "/" else value - quotient * rhs)
        return value

    def _power(self, depth: int) -> int:
        base = self._unary(depth)
        if self._is_op("**"):
            self.pos += 1
            start = self.pos
            exp = self._power(depth + 1)  # right associative
            if exp < 0:
                token = self.source[self.tokens[start][2] :] if start < len(self.tokens) else ""
                raise ArithError("exponent less than 0", token)
            return _power(base, exp)
        return base

    def _unary(self, depth: int) -> int:
        if depth > MAX_DEPTH:
            raise ArithError("expression nested too deeply")
        if self._is_op("+", "-"):
            op = self.tokens[self.pos][1]
            self.pos += 1
            value = self._unary(depth + 1)
            return _wrap(-value) if op == "-" else value
        return self._primary(depth)

    def _primary(self, depth: int) -> int:
        tok = self._peek()
        if tok is None or (tok[0] == "op" and tok[1] != "("):
            raise self._operand_expected()
        self.pos += 1
        kind, text, _ = tok
        if kind == "num":
            return _literal(text)
        if kind == "name":
            return _variable(self.lookup(text))
        value = self._shift(depth + 1)
        if not self._is_op(")"):
            raise ArithError("missing `)'", ")")
        self.pos += 1
        return value


def _variable(raw: str) -> int:
    """A variable's value: an integer, else 0 (unset) like bash; names are not recursed."""
    raw = raw.strip()
    sign = -1 if raw.startswith("-") else 1
    digits = raw.lstrip("+-")
    if digits.isascii() and digits.isdigit() and len(digits) <= MAX_LITERAL:
        return _wrap(sign * int(digits))
    return 0


def evaluate(expr: str, lookup: Callable[[str], str]) -> int:
    """Value of the arithmetic expression ``expr``. Raises :class:`ArithError`."""
    if len(expr) > MAX_EXPR_CHARS:
        raise ArithError("expression too long")
    return _Parser(expr, _tokenize(expr), lookup).parse()
