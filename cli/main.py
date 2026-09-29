"""
AegisSOC CLI main entry point.

Usage:
    python -m cli investigate \\
        --events alerts.json \\
        --title "Application Shimming" \\
        --format markdown
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cli.loader import load_events
from internal.investigation.investigation_engine import investigate
from internal.reporter.report import InvestigatorReport
from pkg.models.investigation import (
    InvestigationCategory,
    InvestigationPriority,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AegisSOC investigation CLI",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="aegis-soc 1.0",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    inv = subparsers.add_parser(
        "investigate",
        help="Run end-to-end investigation",
    )
    inv.add_argument(
        "--events", required=True, type=Path,
        help="Path ke file JSON berisi list events",
    )
    inv.add_argument("--title", required=True)
    inv.add_argument("--description", default=None)
    inv.add_argument(
        "--format",
        choices=("markdown", "json", "text"),
        default="markdown",
    )
    inv.add_argument("--output", type=Path, default=None)
    inv.add_argument("--analyst", default=None)
    inv.add_argument("--tenant", default=None)
    inv.add_argument(
        "--category",
        choices=[c.value for c in InvestigationCategory],
        default=InvestigationCategory.UNKNOWN.value,
    )
    inv.add_argument(
        "--priority",
        choices=[p.value for p in InvestigationPriority],
        default=None,
    )
    inv.add_argument("--quiet", action="store_true")
    inv.add_argument(
        "--ai",
        action="store_true",
        help="Aktifkan AI narrative (rule engine deterministic)",
    )

    return parser


def cmd_investigate(args: argparse.Namespace) -> int:
    try:
        events = load_events(args.events)
    except (FileNotFoundError, ValueError) as exc:
        _err(str(exc))
        return 1

    if not events:
        _err("no events to investigate")
        return 1

    _info(f"Loaded {len(events)} event(s)", args)
    _info(f"Running investigation: {args.title!r}", args)

    try:
        result = investigate(
            events,
            title=args.title,
            description=args.description,
            tenant_id=args.tenant,
            analyst=args.analyst,
            category=InvestigationCategory(args.category),
            priority=(
                InvestigationPriority(args.priority)
                if args.priority else None
            ),
        )
    except Exception as exc:  # noqa: BLE001
        _err(f"investigation failed: {exc}")
        return 1

    _info(
        f"Risk score: {result.risk_score}/100 "
        f"(confidence {result.confidence:.2f})",
        args,
    )
    _info(
        f"Evidence: {result.evidence_count}, "
        f"Correlations: {result.correlation_count}, "
        f"Hypotheses: {result.hypothesis_count}",
        args,
    )

    report = InvestigatorReport(result)

    # -- AI narrative (opsional) --------------------------------------
    narrative: str | None = None
    if getattr(args, "ai", False):
        try:
            from internal.ai.router import narrate
            narrative = narrate(result)
            _info("AI narrative generated", args)
        except Exception as exc:  # noqa: BLE001
            _err(f"AI narrative failed: {exc}")
            narrative = None

    # -- Render ------------------------------------------------------
    if args.format == "json":
        import json
        data = report.to_dict()
        if narrative:
            data["ai_narrative"] = narrative
        text = json.dumps(data, indent=2, default=str)

    elif args.format == "markdown":
        text = report.to_markdown()
        if narrative:
            text = (
                "# AI Narrative\n\n"
                + narrative
                + "\n\n---\n\n"
                + text
            )

    else:  # "text"
        text = report.to_text()
        if narrative:
            text = narrative + "\n\n" + text

    if args.output is not None:
        try:
            args.output.write_text(text, encoding="utf-8")
        except OSError as exc:
            _err(f"cannot write output: {exc}")
            return 1
        _info(f"Report written to {args.output}", args)
    else:
        print(text)

    return 0


def _info(message: str, args: argparse.Namespace) -> None:
    if not getattr(args, "quiet", False):
        print(f"[aegis] {message}", file=sys.stderr)


def _err(message: str) -> None:
    print(f"[aegis] error: {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "investigate":
        return cmd_investigate(args)

    parser.print_help(sys.stderr)
    return 2


__all__ = ["build_parser", "main", "cmd_investigate"]
