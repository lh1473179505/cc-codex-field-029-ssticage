# ssticage

A sandboxed renderer for Wisp, a small template dialect. Rendering has to pick an escape context from the surrounding markup, refuse sandbox escapes through underscored names, and keep filter chains from undoing autoescape.

`python -m ssticage inspect --template fixtures/templates/ok-html.wisp` already prints the AST. `render` is still a stub.

Standard library only. No Docker, no Jinja, no third-party template engines.
