"""CLI. inspect already works; render is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ssticage.parse import ParseError, load_template, node_to_dict


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ssticage")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="parse a template and print its AST")
    ins.add_argument("--template", required=True)
    rnd = sub.add_parser("render", help="render a template under the sandbox and escape policy")
    rnd.add_argument("--template", required=True)
    rnd.add_argument("--context", required=True)
    rnd.add_argument("--policy", required=True)
    rnd.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        tree = load_template(args.template)
    except (OSError, ParseError) as exc:
        print(f"failed to parse template: {exc}", file=sys.stderr)
        return 2
    if args.cmd == "inspect":
        print(json.dumps({"nodes": [node_to_dict(n) for n in tree]}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "render":
        try:
            context = json.loads(Path(args.context).read_text(encoding="utf-8"))
            policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"failed to load context or policy: {exc}", file=sys.stderr)
            return 2
        from ssticage.engine import render

        try:
            report = render(tree, context, policy)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
