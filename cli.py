"""Command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .graph import build_graph
from .hypotheses import evaluate
from .ingest import read_events
from .report import write_html


def _analyze(args: argparse.Namespace) -> int:
    events = read_events(args.input)
    graph = build_graph(events, args.correlation_minutes)
    findings = evaluate(graph)
    report = write_html(graph, findings, args.output)
    print(f"Analyzed {len(events)} events; found {len(findings)} hypothesis match(es).")
    print(f"Report: {report.resolve()}")
    return 0


def _inspect(args: argparse.Namespace) -> int:
    events = read_events(args.input)
    print(json.dumps({
        "events": len(events),
        "first_timestamp": events[0].timestamp.isoformat() if events and events[0].timestamp else None,
        "sources": sorted({event.source for event in events}),
        "event_types": sorted({event.event_type for event in events}),
    }, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chroniclegraph", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(required=True)
    analyze = commands.add_parser("analyze", help="Build an evidence graph and HTML report")
    analyze.add_argument("input", type=Path, help="Plaso JSON or JSONL export")
    analyze.add_argument("-o", "--output", type=Path, default=Path("chronicle-report.html"))
    analyze.add_argument("--correlation-minutes", type=int, default=30)
    analyze.set_defaults(handler=_analyze)
    inspect = commands.add_parser("inspect", help="Summarize an input export")
    inspect.add_argument("input", type=Path)
    inspect.set_defaults(handler=_inspect)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())

