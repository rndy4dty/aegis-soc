"""
Producer CLI: publish events ke Redis Stream.

Usage:
    python -m producer --file examples/application_shimming.json
    python -m producer --file /tmp/wazuh.json --stream aegis.alerts
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from internal.streaming.producer import (
    DEFAULT_STREAM,
    EventProducer,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-producer",
        description="Publish events ke Redis Stream",
    )
    parser.add_argument(
        "--file",
        type=Path,
        required=True,
        help="File events (canonical / Wazuh / Sysmon)",
    )
    parser.add_argument(
        "--stream",
        default=DEFAULT_STREAM,
        help=f"Nama Redis Stream (default: {DEFAULT_STREAM})",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        producer = EventProducer(stream=args.stream)
    except Exception as exc:  # noqa: BLE001
        _err(f"init producer failed: {exc}")
        return 1

    if not producer.bus.is_available():
        _err("Redis not available. Start with: docker compose up -d redis")
        return 1

    try:
        count = producer.publish_from_file(args.file)
    except FileNotFoundError as exc:
        _err(str(exc))
        return 1
    except ValueError as exc:
        _err(f"parse error: {exc}")
        return 1

    if not args.quiet:
        print(f"Published {count} events to '{args.stream}'")
    return 0


def _err(message: str) -> None:
    print(f"[producer] error: {message}", file=sys.stderr)


__all__ = ["build_parser", "main"]
