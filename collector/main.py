"""
Wazuh collector CLI.

Usage:
    python -m collector --once
    python -m collector
    python -m collector --max-iterations 5
    python -m collector --interval 60
"""

from __future__ import annotations

import argparse
import sys

from internal.collector import (
    DEFAULT_INITIAL_LOOKBACK,
    DEFAULT_POLL_INTERVAL,
    WazuhAPIClient,
    WazuhPoller,
)
from internal.streaming import DEFAULT_STREAM, StreamBus


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-collector",
        description="Poll Wazuh API & publish ke Redis Stream",
    )
    parser.add_argument("--stream", default=DEFAULT_STREAM)
    parser.add_argument(
        "--interval", type=int, default=DEFAULT_POLL_INTERVAL,
    )
    parser.add_argument(
        "--lookback", type=int, default=DEFAULT_INITIAL_LOOKBACK,
    )
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--max-iterations", type=int, default=None,
    )
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    api = WazuhAPIClient()
    if not api.is_configured:
        _err(
            "Wazuh API not configured. Set AEGIS_WAZUH_PASSWORD "
            "(dan opsional AEGIS_WAZUH_API_URL, AEGIS_WAZUH_USER)."
        )
        return 1

    bus = StreamBus()
    if not bus.is_available():
        _err(
            "Redis not available. Start with: "
            "docker compose up -d redis"
        )
        return 1

    poller = WazuhPoller(
        api=api,
        bus=bus,
        stream=args.stream,
        poll_interval=args.interval,
        initial_lookback=args.lookback,
        page_size=args.page_size,
    )

    if not args.quiet:
        _info(
            f"Poller started: {api.url} -> '{args.stream}' "
            f"(interval={args.interval}s)"
        )

    try:
        if args.once:
            published = poller.poll_once()
            if not args.quiet:
                _info(f"Polled once: published {published} alerts")
        else:
            poller.run_forever(max_iterations=args.max_iterations)
    except KeyboardInterrupt:
        if not args.quiet:
            _info("Interrupted")
    finally:
        s = poller.stats
        if not args.quiet:
            _info(
                f"Stopped: iterations={s.iterations} "
                f"fetched={s.alerts_fetched} "
                f"published={s.alerts_published} "
                f"skipped={s.alerts_skipped} "
                f"errors={len(s.errors)}"
            )

    return 0


def _info(message: str) -> None:
    print(f"[collector] {message}", file=sys.stderr)


def _err(message: str) -> None:
    print(f"[collector] error: {message}", file=sys.stderr)


__all__ = ["build_parser", "main"]
