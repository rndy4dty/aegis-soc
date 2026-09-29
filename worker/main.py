"""
Worker CLI: consume events dari Redis Stream, investigate, save.

Usage:
    python -m worker
    python -m worker --stream aegis.alerts --group investigators
    python -m worker --max-iterations 5   # untuk testing / shutdown
"""

from __future__ import annotations

import argparse
import sys

from internal.streaming import (
    DEFAULT_CONSUMER,
    DEFAULT_GROUP,
    DEFAULT_STREAM,
    EventBatcher,
    StreamWorker,
)
from internal.storage import StorageService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-worker",
        description="AegisSOC stream worker",
    )
    parser.add_argument(
        "--stream", default=DEFAULT_STREAM,
    )
    parser.add_argument(
        "--group", default=DEFAULT_GROUP,
    )
    parser.add_argument(
        "--consumer", default=DEFAULT_CONSUMER,
    )
    parser.add_argument(
        "--window-seconds", type=int, default=30,
    )
    parser.add_argument(
        "--idle-seconds", type=int, default=5,
    )
    parser.add_argument(
        "--max-batch-size", type=int, default=100,
    )
    parser.add_argument(
        "--group-by",
        choices=("tenant_id", "host"),
        default=None,
        help="Group events sebelum investigate",
    )
    parser.add_argument(
        "--block-ms", type=int, default=1000,
    )
    parser.add_argument(
        "--count", type=int, default=100,
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Stop setelah N iterasi (untuk testing)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # -- Setup storage (fail-fast kalau DB tidak connect) -------------
    try:
        storage = StorageService()
    except Exception as exc:  # noqa: BLE001
        _err(f"storage init failed: {exc}")
        return 1

    # -- Setup batcher ------------------------------------------------
    batcher = EventBatcher(
        window_seconds=args.window_seconds,
        idle_seconds=args.idle_seconds,
        max_batch_size=args.max_batch_size,
        group_by=args.group_by,
    )

    # -- Setup worker -------------------------------------------------
    worker = StreamWorker(
        storage=storage,
        batcher=batcher,
        stream=args.stream,
        group=args.group,
        consumer=args.consumer,
    )

    if not worker._bus.is_available():  # noqa: SLF001
        _err("Redis not available. Start with: docker compose up -d redis")
        return 1

    worker.ensure_group()

    if not args.quiet:
        _info(
            f"Worker started. "
            f"stream={args.stream} "
            f"group={args.group} "
            f"consumer={args.consumer}"
        )

    try:
        worker.run_forever(
            block_ms=args.block_ms,
            count=args.count,
            max_iterations=args.max_iterations,
        )
    except KeyboardInterrupt:
        _info("Interrupted, flushing pending...")
    finally:
        flushed = worker.flush_pending()
        if not args.quiet:
            s = worker.stats
            _info(
                f"Worker stopped. "
                f"consumed={s.messages_consumed} "
                f"acked={s.messages_acked} "
                f"investigations={s.investigations_created} "
                f"flushed_at_shutdown={flushed} "
                f"errors={len(s.errors)}"
            )

    return 0


def _info(message: str) -> None:
    print(f"[worker] {message}", file=sys.stderr)


def _err(message: str) -> None:
    print(f"[worker] error: {message}", file=sys.stderr)


__all__ = ["build_parser", "main"]
