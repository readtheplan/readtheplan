from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


class PuppetHoconError(ValueError):
    """Raised when a Puppet Server HOCON file is ambiguous or malformed."""


@dataclass(frozen=True)
class HoconDocument:
    values: dict[str, Any]
    include_count: int
    substitution_count: int


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    line: int


_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$")
_DYNAMIC = "<unresolved-hocon-substitution>"
_MAX_NESTING = 100


def parse_puppet_hocon(source: str) -> HoconDocument:
    """Parse the static HOCON subset used by Puppet Server without resolving includes."""
    parser = _Parser(_tokenize(source))
    values = parser.parse()
    return HoconDocument(
        values=values,
        include_count=parser.include_count,
        substitution_count=parser.substitution_count,
    )


def _tokenize(source: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    line = 1
    length = len(source)
    punctuation = {
        "{": "LBRACE",
        "}": "RBRACE",
        "[": "LBRACKET",
        "]": "RBRACKET",
        ":": "COLON",
        "=": "EQUALS",
        ",": "COMMA",
    }

    while index < length:
        char = source[index]
        if char in " \t\r":
            index += 1
            continue
        if char == "\n":
            tokens.append(_Token("NEWLINE", "", line))
            line += 1
            index += 1
            continue
        if char == "#" or source.startswith("//", index):
            newline = source.find("\n", index)
            index = length if newline < 0 else newline
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise PuppetHoconError(f"unterminated block comment on line {line}")
            block = source[index : end + 2]
            line += block.count("\n")
            index = end + 2
            continue
        if char in punctuation:
            tokens.append(_Token(punctuation[char], char, line))
            index += 1
            continue
        if source.startswith('"""', index):
            end = source.find('"""', index + 3)
            if end < 0:
                raise PuppetHoconError(f"unterminated triple-quoted string on line {line}")
            value = source[index + 3 : end]
            tokens.append(_Token("STRING", value, line))
            line += value.count("\n")
            index = end + 3
            continue
        if char == '"':
            start = index
            start_line = line
            index += 1
            escaped = False
            while index < length:
                current = source[index]
                if current == "\n":
                    raise PuppetHoconError(
                        f"quoted string crosses a newline on line {start_line}"
                    )
                if current == '"' and not escaped:
                    index += 1
                    break
                if current == "\\" and not escaped:
                    escaped = True
                else:
                    escaped = False
                index += 1
            else:
                raise PuppetHoconError(f"unterminated quoted string on line {start_line}")
            try:
                value = json.loads(source[start:index])
            except json.JSONDecodeError as exc:
                raise PuppetHoconError(f"invalid quoted string on line {start_line}") from exc
            tokens.append(_Token("STRING", value, start_line))
            continue
        if source.startswith("${", index):
            start_line = line
            end = source.find("}", index + 2)
            if end < 0:
                raise PuppetHoconError(f"unterminated substitution on line {start_line}")
            expression = source[index + 2 : end].strip()
            if not expression or "{" in expression:
                raise PuppetHoconError(f"invalid substitution on line {start_line}")
            tokens.append(_Token("SUBSTITUTION", _DYNAMIC, start_line))
            index = end + 1
            continue

        start = index
        while index < length:
            current = source[index]
            if current.isspace() or current in '{}[]:=,#"':
                break
            if source.startswith("//", index) or source.startswith("/*", index):
                break
            index += 1
        if start == index:
            raise PuppetHoconError(f"unsupported HOCON token on line {line}")
        tokens.append(_Token("BARE", source[start:index], line))

    tokens.append(_Token("EOF", "", line))
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.position = 0
        self.include_count = 0
        self.substitution_count = 0

    @property
    def current(self) -> _Token:
        return self.tokens[self.position]

    def advance(self) -> _Token:
        token = self.current
        self.position += 1
        return token

    def skip_layout(self) -> None:
        while self.current.kind in {"NEWLINE", "COMMA"}:
            self.advance()

    def parse(self) -> dict[str, Any]:
        self.skip_layout()
        if self.current.kind == "LBRACE":
            self.advance()
            values = self.parse_object("RBRACE", depth=1)
            self.advance()
        else:
            values = self.parse_object("EOF", depth=0)
        self.skip_layout()
        if self.current.kind != "EOF":
            raise PuppetHoconError(f"unexpected content on line {self.current.line}")
        if not values and not self.include_count:
            raise PuppetHoconError("HOCON input does not contain settings")
        return values

    def parse_object(self, end_kind: str, *, depth: int) -> dict[str, Any]:
        if depth > _MAX_NESTING:
            raise PuppetHoconError("HOCON nesting exceeds the static analysis limit")
        result: dict[str, Any] = {}
        while True:
            self.skip_layout()
            if self.current.kind == end_kind:
                return result
            if self.current.kind == "EOF":
                raise PuppetHoconError("unterminated HOCON object")
            if self.current.kind not in {"BARE", "STRING"}:
                raise PuppetHoconError(f"expected a setting key on line {self.current.line}")
            key_token = self.advance()
            key = key_token.value
            if key_token.kind == "BARE" and key == "include":
                self.parse_include()
                continue
            if not key:
                raise PuppetHoconError(f"empty setting key on line {key_token.line}")
            if key in result:
                raise PuppetHoconError(f"duplicate HOCON key on line {key_token.line}")
            if self.current.kind == "LBRACE":
                self.advance()
                value = self.parse_object("RBRACE", depth=depth + 1)
                self.advance()
            else:
                if self.current.kind not in {"COLON", "EQUALS"}:
                    raise PuppetHoconError(
                        f"setting is missing ':' or '=' on line {key_token.line}"
                    )
                self.advance()
                value = self.parse_value(depth=depth)
            result[key] = value
            if self.current.kind not in {"COMMA", "NEWLINE", end_kind, "EOF"}:
                raise PuppetHoconError(
                    f"multiple unseparated values are unsupported on line {self.current.line}"
                )

    def parse_include(self) -> None:
        if self.current.kind in {"NEWLINE", "COMMA", "RBRACE", "EOF"}:
            raise PuppetHoconError(f"include target is missing on line {self.current.line}")
        depth = 0
        while self.current.kind not in {"NEWLINE", "EOF"}:
            if self.current.kind in {"LBRACE", "LBRACKET"}:
                depth += 1
            elif self.current.kind in {"RBRACE", "RBRACKET"}:
                if depth == 0:
                    break
                depth -= 1
            self.advance()
        self.include_count += 1

    def parse_value(self, *, depth: int) -> Any:
        line = self.current.line
        value = self.parse_atom(depth=depth)
        concatenated = [value]
        while self.current.kind in {"BARE", "STRING", "SUBSTITUTION"} and (
            self.current.line == line
        ):
            concatenated.append(self.parse_atom(depth=depth))
        if len(concatenated) == 1:
            return value
        if _DYNAMIC in concatenated:
            return _DYNAMIC
        return " ".join(str(item) for item in concatenated)

    def parse_atom(self, *, depth: int) -> Any:
        token = self.current
        if token.kind == "LBRACE":
            self.advance()
            value = self.parse_object("RBRACE", depth=depth + 1)
            self.advance()
            return value
        if token.kind == "LBRACKET":
            return self.parse_array(depth=depth + 1)
        if token.kind == "SUBSTITUTION":
            self.advance()
            self.substitution_count += 1
            return _DYNAMIC
        if token.kind == "STRING":
            self.advance()
            return token.value
        if token.kind != "BARE":
            raise PuppetHoconError(f"setting value is missing on line {token.line}")
        self.advance()
        lowered = token.value.casefold()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if lowered == "null":
            return None
        if _NUMBER.fullmatch(token.value):
            return float(token.value) if any(char in token.value for char in ".eE") else int(
                token.value
            )
        return token.value

    def parse_array(self, *, depth: int) -> list[Any]:
        if depth > _MAX_NESTING:
            raise PuppetHoconError("HOCON nesting exceeds the static analysis limit")
        self.advance()
        values: list[Any] = []
        while True:
            self.skip_layout()
            if self.current.kind == "RBRACKET":
                self.advance()
                return values
            if self.current.kind == "EOF":
                raise PuppetHoconError("unterminated HOCON array")
            values.append(self.parse_value(depth=depth))
            if self.current.kind not in {"COMMA", "NEWLINE", "RBRACKET"}:
                raise PuppetHoconError(
                    f"array values must be separated on line {self.current.line}"
                )
