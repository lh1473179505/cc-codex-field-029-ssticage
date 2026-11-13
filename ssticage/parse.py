"""Parse a Wisp template into an AST. Rendering and sandboxing are not implemented here."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ParseError(Exception):
    pass


@dataclass
class Text:
    value: str
    kind: str = "text"


@dataclass
class Var:
    path: list[str]
    filters: list[tuple[str, list[str]]]
    kind: str = "var"


@dataclass
class If:
    path: list[str]
    then: list[Any]
    else_: list[Any] = field(default_factory=list)
    kind: str = "if"


@dataclass
class For:
    item: str
    path: list[str]
    body: list[Any]
    kind: str = "for"


def _tokens(src: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    i = 0
    n = len(src)
    while i < n:
        if src.startswith("{{", i):
            j = src.find("}}", i)
            if j < 0:
                raise ParseError("unclosed_var")
            out.append(("var", src[i + 2:j].strip()))
            i = j + 2
            continue
        if src.startswith("{%", i):
            j = src.find("%}", i)
            if j < 0:
                raise ParseError("unclosed_tag")
            out.append(("tag", src[i + 2:j].strip()))
            i = j + 2
            continue
        nxt = n
        a = src.find("{{", i)
        b = src.find("{%", i)
        cands = [x for x in (a, b) if x >= 0]
        if cands:
            nxt = min(cands)
        out.append(("text", src[i:nxt]))
        i = nxt
    return out


def _path(expr: str) -> list[str]:
    expr = expr.strip()
    if not expr:
        raise ParseError("empty_path")
    if expr[0] in "0123456789" or any(ch in expr for ch in "()[]"):
        raise ParseError("bad_path")
    parts = expr.split(".")
    if any(not p or not (p[0].isalpha() or p[0] == "_") or not all(c.isalnum() or c == "_" for c in p) for p in parts):
        raise ParseError("bad_path")
    return parts


def _var_body(text: str) -> Var:
    bits = [b.strip() for b in text.split("|")]
    if not bits or not bits[0]:
        raise ParseError("empty_var")
    path = _path(bits[0])
    filters: list[tuple[str, list[str]]] = []
    for bit in bits[1:]:
        if not bit:
            raise ParseError("empty_filter")
        if ":" in bit:
            name, arg = bit.split(":", 1)
            filters.append((name.strip(), [arg.strip()]))
        else:
            filters.append((bit, []))
    return Var(path, filters)


def parse_template(src: str) -> list[Any]:
    toks = _tokens(src)
    pos = 0

    def block(until: set[str]) -> list[Any]:
        nonlocal pos
        nodes: list[Any] = []
        while pos < len(toks):
            kind, val = toks[pos]
            if kind == "text":
                nodes.append(Text(val))
                pos += 1
                continue
            if kind == "var":
                nodes.append(_var_body(val))
                pos += 1
                continue
            # tag
            parts = val.split()
            if not parts:
                raise ParseError("empty_tag")
            head = parts[0]
            if head in until:
                return nodes
            if head == "if":
                if len(parts) != 2:
                    raise ParseError("bad_if")
                pos += 1
                then = block({"else", "endif"})
                else_nodes: list[Any] = []
                if pos < len(toks) and toks[pos][0] == "tag" and toks[pos][1].split()[:1] == ["else"]:
                    pos += 1
                    else_nodes = block({"endif"})
                if pos >= len(toks) or toks[pos][0] != "tag" or toks[pos][1].split()[:1] != ["endif"]:
                    raise ParseError("unclosed_if")
                pos += 1
                nodes.append(If(_path(parts[1]), then, else_nodes))
                continue
            if head == "for":
                # for x in path
                if len(parts) != 4 or parts[2] != "in":
                    raise ParseError("bad_for")
                pos += 1
                body = block({"endfor"})
                if pos >= len(toks) or toks[pos][0] != "tag" or toks[pos][1].split()[:1] != ["endfor"]:
                    raise ParseError("unclosed_for")
                pos += 1
                nodes.append(For(parts[1], _path(parts[3]), body))
                continue
            raise ParseError(f"unknown_tag:{head}")
        if until:
            raise ParseError("unclosed_block")
        return nodes

    tree = block(set())
    if pos != len(toks):
        raise ParseError("trailing")
    return tree


def node_to_dict(n: Any) -> dict[str, Any]:
    if isinstance(n, Text):
        return {"kind": "text", "value": n.value}
    if isinstance(n, Var):
        return {"kind": "var", "path": n.path, "filters": [{"name": f, "args": a} for f, a in n.filters]}
    if isinstance(n, If):
        return {"kind": "if", "path": n.path, "then": [node_to_dict(x) for x in n.then], "else": [node_to_dict(x) for x in n.else_]}
    if isinstance(n, For):
        return {"kind": "for", "item": n.item, "path": n.path, "body": [node_to_dict(x) for x in n.body]}
    raise ParseError("unknown_node")


def load_template(path: str | Path) -> list[Any]:
    return parse_template(Path(path).read_text(encoding="utf-8"))
