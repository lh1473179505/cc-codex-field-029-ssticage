"""Sandboxed Wisp renderer with static, context-aware autoescaping.

The template is never executed as Python and no external template engine is
involved: the AST from ``ssticage.parse`` is walked directly. Literal template
text feeds a small markup scanner so each ``Var`` is emitted in one of the
``html`` / ``attr`` / ``js`` / ``url`` contexts.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

from ssticage.parse import For, If, Text, Var

BUILTIN_BLOCKED_NAMES = {
    "class",
    "mro",
    "__class__",
    "tb",
    "func_globals",
    "gi_frame",
}

URL_ATTRS = {"href", "src", "action", "formaction"}

_SCRIPT_OPEN = "</script"


class RenderDeny(Exception):
    """Raised when a sandbox or escaping policy stops rendering."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class HtmlScanner:
    """Stream literal template text and report the context of the next var.

    Only literal ``Text`` nodes are fed in; emitted variable values do not
    affect the state. The scanner tracks ordinary tags, quoted attribute
    values and ``<script>`` regions.
    """

    def __init__(self) -> None:
        self.mode = "data"  # "data" | "tag" | "script"
        self.tag_name = ""
        self.attr_name = ""
        self.quote = ""
        self.url_attr = False
        self._in_tag_name = False
        self._await_value = False
        self._tag_buf: list[str] = []
        self._attr_buf: list[str] = []
        self._script_pending = ""

    def feed(self, text: str) -> None:
        for ch in text:
            if self.mode == "script":
                self._feed_script(ch)
            elif self.mode == "data":
                if ch == "<":
                    self._enter_tag()
            else:
                self._feed_tag(ch)

    def _enter_tag(self) -> None:
        self.mode = "tag"
        self.tag_name = ""
        self.attr_name = ""
        self.quote = ""
        self.url_attr = False
        self._in_tag_name = True
        self._await_value = False
        self._tag_buf = []
        self._attr_buf = []

    def _reset_tag(self) -> None:
        self.mode = "data"
        self.tag_name = ""
        self.attr_name = ""
        self.quote = ""
        self.url_attr = False
        self._in_tag_name = False
        self._await_value = False
        self._tag_buf = []
        self._attr_buf = []

    def _flush_attr(self) -> None:
        if self._attr_buf:
            self.attr_name = "".join(self._attr_buf).lower()
            self._attr_buf = []

    def _feed_tag(self, ch: str) -> None:
        if self.quote:
            if ch == self.quote:
                self.quote = ""
                self.url_attr = False
                self.attr_name = ""
            return
        if ch in ('"', "'"):
            self._flush_attr()
            self.quote = ch
            self.url_attr = self.attr_name in URL_ATTRS
            self._await_value = False
            return
        if ch == ">":
            name = self.tag_name or "".join(self._tag_buf).lower()
            self._reset_tag()
            if name == "script":
                self.mode = "script"
                self._script_pending = ""
            return
        if ch.isspace() or ch == "/":
            if self._in_tag_name:
                self.tag_name = "".join(self._tag_buf).lower()
                self._in_tag_name = False
            self._flush_attr()
            self._await_value = False
            return
        if ch == "=":
            self._flush_attr()
            self._await_value = True
            return
        if self._in_tag_name:
            self._tag_buf.append(ch)
        elif not self._await_value:
            self._attr_buf.append(ch)

    def _feed_script(self, ch: str) -> None:
        wanted = _SCRIPT_OPEN[len(self._script_pending)]
        if ch.lower() == wanted:
            self._script_pending += ch.lower()
            if self._script_pending == _SCRIPT_OPEN:
                self.mode = "data"
                self._script_pending = ""
        elif ch == "<":
            self._script_pending = "<"
        else:
            self._script_pending = ""

    def context(self) -> str:
        if self.mode == "script":
            return "js"
        if self.quote:
            return "url" if self.url_attr else "attr"
        return "html"


def _is_blocked(name: str, policy: dict[str, Any]) -> bool:
    return (
        name.startswith("_")
        or name in BUILTIN_BLOCKED_NAMES
        or name in policy.get("blocked_names", [])
    )


def _lookup(
    path: list[str],
    context: dict[str, Any],
    loops: dict[str, Any],
    policy: dict[str, Any],
) -> Any:
    if path[0] in loops:
        value: Any = loops[path[0]]
        steps = path[1:]
    else:
        name = path[0]
        if _is_blocked(name, policy):
            raise RenderDeny("sandbox_attr")
        if name not in context:
            if policy.get("undefined") == "empty":
                return ""
            raise RenderDeny("undefined")
        value = context[name]
        steps = path[1:]

    for name in steps:
        if isinstance(value, dict):
            if _is_blocked(name, policy):
                raise RenderDeny("sandbox_attr")
            if name not in value:
                if policy.get("undefined") == "empty":
                    return ""
                raise RenderDeny("undefined")
            value = value[name]
        elif isinstance(value, (list, tuple)):
            if not name.isdecimal():
                raise RenderDeny("bad_index")
            index = int(name)
            if not 0 <= index < len(value):
                raise RenderDeny("bad_index")
            value = value[index]
        else:
            if policy.get("undefined") == "empty":
                return ""
            raise RenderDeny("undefined")

    if callable(value):
        raise RenderDeny("sandbox_call")
    return value


def _stringify(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _escape(context_name: str, value: str) -> str:
    if context_name in ("html", "attr"):
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
    if context_name == "js":
        body = json.dumps(value)[1:-1]
        return body.replace("<", r"\u003c").replace(">", r"\u003e")
    if context_name == "url":
        return urllib.parse.quote(value, safe="")
    raise RenderDeny(f"unknown_context:{context_name}")


def _truthy(value: Any) -> bool:
    return value not in (None, False, 0, "", [])


class Renderer:
    def __init__(self, context: dict[str, Any], policy: dict[str, Any]) -> None:
        self.context = context
        self.policy = policy
        self.loops: dict[str, Any] = {}
        self.scanner = HtmlScanner()
        self.out: list[str] = []
        self.notes: list[str] = []

    def render_nodes(self, nodes: list[Any]) -> None:
        for node in nodes:
            if isinstance(node, Text):
                self.scanner.feed(node.value)
                self.out.append(node.value)
            elif isinstance(node, Var):
                self.render_var(node)
            elif isinstance(node, If):
                branch = node.then if _truthy(self._lookup(node.path)) else node.else_
                self.render_nodes(branch)
            elif isinstance(node, For):
                self.render_for(node)
            else:
                raise RenderDeny("unknown_node")

    def _lookup(self, path: list[str]) -> Any:
        return _lookup(path, self.context, self.loops, self.policy)

    def render_for(self, node: For) -> None:
        items = self._lookup(node.path)
        if not isinstance(items, list):
            raise RenderDeny("bad_iter")
        if len(items) > self.policy.get("max_loop", 100):
            raise RenderDeny("loop_limit")
        self.loops[node.item] = None
        for item in items:
            self.loops[node.item] = item
            self.render_nodes(node.body)
        del self.loops[node.item]

    def render_var(self, node: Var) -> None:
        context_name = self.scanner.context()
        value = self._lookup(node.path)
        trusted = False
        escaped = False
        allowed_filters = self.policy.get("filters", [])
        for filter_name, _args in node.filters:
            if filter_name not in allowed_filters:
                raise RenderDeny("unknown_filter")
            if filter_name == "raw":
                path_key = ".".join(node.path)
                if not self.policy.get("allow_raw") or path_key not in self.policy.get("trusted_paths", []):
                    raise RenderDeny("raw_denied")
                trusted = True
            elif filter_name == "e":
                value = _escape(context_name, _stringify(value))
                escaped = True
            elif filter_name == "upper":
                value = _stringify(value).upper()
            elif filter_name == "lower":
                value = _stringify(value).lower()
            elif filter_name == "length":
                if not isinstance(value, (str, list, tuple)):
                    raise RenderDeny("bad_filter")
                value = len(value)
            elif filter_name == "json":
                value = json.dumps(value, separators=(",", ":"))

        self.notes.append(context_name)
        text = _stringify(value)
        if trusted or escaped or not self.policy.get("autoescape", False):
            self.out.append(text)
        else:
            self.out.append(_escape(context_name, text))


def render(tree: list, context: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    renderer = Renderer(context, policy)
    try:
        renderer.render_nodes(tree)
    except RenderDeny as exc:
        return {
            "decision": "deny",
            "reason_codes": [exc.reason],
            "output": "".join(renderer.out),
            "notes": renderer.notes,
        }
    return {
        "decision": "allow",
        "reason_codes": [],
        "output": "".join(renderer.out),
        "notes": renderer.notes,
    }
