# Render rules

Reuse `load_template` / the AST nodes in `ssticage.parse`. Do not exec the template as Python and do not call an external template engine.

`allow` means the template rendered to completion. `deny` means a sandbox or escaping policy stopped it (still put any partial output you produced in `output`, or the empty string). A parse error is handled by the CLI (exit 2) before `render` is called.

## Context lookup

A `path` `a.b.c` starts at the render context (the `--context` JSON object) plus loop variables. Only mappings (JSON objects) and lists/tuples may be stepped through:

- On a mapping, the next name must be a key. Names that start with `_` are `sandbox_attr`. The names `class`, `mro`, `__class__`, `tb`, `func_globals`, `gi_frame` and any name in `policy.blocked_names` (public includes those plus `constructor`) are `sandbox_attr` even without a leading underscore.
- On a list, the next name must be a decimal integer index in range; otherwise `bad_index`.
- A missing key is `undefined` unless `policy.undefined` is `"empty"` (public: `"empty"`), in which case the value is the empty string and rendering continues.
- You may not call a value. There are no method calls in the path syntax; `user.save` if `save` were a function is still just a lookup, but if the looked-up value is a callable (it will not be, in JSON fixtures) treat it as `sandbox_call`. Filters are the only calls allowed.

## Filters

Filters in a `Var` are applied left to right. Only names in `policy.filters` may run (`unknown_filter` otherwise). Public list: `e`, `raw`, `upper`, `lower`, `length`, `json`.

- `upper` / `lower` — stringify then case-fold. Do not mark the value trusted.
- `length` — `len` of string or list, else `bad_filter`.
- `json` — `json.dumps` with compact separators, not HTML-escaped yet; the result is still untrusted text.
- `e` — escape the current *output context* (see below) and mark the value escaped for that context.
- `raw` — allowed only if `policy.allow_raw` is true *and* the context path is listed in `policy.trusted_paths` (dot-joined, e.g. `bio_html`). Otherwise `raw_denied`. `raw` marks the value trusted so the final autoescape is skipped.

A chain that ends in `raw` after `e` is still trusted (and therefore unescaped at emit time) — that is why `raw` is gated. A chain that ends in `e` is escaped for the current context.

## Output context and autoescape

When a `Var` is emitted, decide its context from the *static* template text around it (the `Text` nodes, plus literal text inside the same `if`/`for` parent, concatenated as they appear in the AST, ignoring other vars):

- If the nearest preceding unmatched `<script` (case-insensitive, not inside a later `</script>`) is open, the context is `js`.
- Else if the var sits inside a double- or single-quoted attribute value of a tag, the context is `attr`. If that attribute name (case-insensitive) is `href`, `src`, `action`, or `formaction`, the context is `url` instead.
- Otherwise `html`.

Scan only literal text; you do not have to parse broken HTML perfectly, but you must get the public fixtures right. A simple approach that works: walk the rendered-so-far literal prefixes in source order, track tag/attr/script state as you emit `Text` nodes, and use the state at each `Var`.

Escape functions (apply on emit unless the value is trusted via `raw`):

- `html`: `&` `<` `>` `"` `'` → entities (`&amp;` `&lt;` `&gt;` `&quot;` `&#39;`)
- `attr`: same as `html`
- `js`: wrap as a JSON string (`json.dumps` of the string) so a value cannot break out of a JS string literal; if the surrounding template already has quotes around the var, do *not* add a second pair, only escape the contents the way `json.dumps` would *inside* the quotes (no surrounding quotes). Public fixtures put `{{ x }}` inside existing JS quotes.
- `url`: percent-encode everything except unreserved `A-Za-z0-9-._~` (bytes of UTF-8).

`policy.autoescape` is true in the public policy. If it were false, only an explicit `e` filter would escape.

## Control

`{% if path %}` is true when the looked-up value is not `null`, `false`, `0`, `""`, or `[]`. `{% for x in path %}` iterates a list; a non-list is `bad_iter`. Loop variable `x` shadows for the body only. Max loop length is `policy.max_loop` (public: 100); over is `loop_limit`. Recursion of template files is not supported (there is no include).

## Report

- `decision`: `allow` or `deny`
- `reason_codes`: empty on allow; the first (or all) sandbox/escape failures on deny
- `output`: the string produced
- `notes`: optional, may list the context (`html`/`attr`/`js`/`url`) used for each var, in order

Exit 0 / 1 / 2 as usual.

## Public fixtures

`--policy fixtures/policy.json --context fixtures/contexts/NAME.json --template fixtures/templates/NAME.wisp` (same NAME):

- `ok-html` → allow, `<` in the name is HTML-escaped
- `ok-attr` → allow, quotes in the title are escaped inside the attribute
- `ok-js` → allow, a `</script>` payload in the name cannot break the script string
- `ok-url` → allow, the href query value is percent-encoded
- `sandbox-dunder` → deny `sandbox_attr` (template walks `user.__class__`)
- `raw-denied` → deny `raw_denied` (uses `|raw` on an untrusted path)
- `ok-raw-trusted` → allow, `bio_html` is in `trusted_paths` and may use `|raw`
- `ok-if-for` → allow, renders the list items
