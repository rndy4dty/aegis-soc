"""
AegisSOC CLI main entry point.

Usage:
    python -m cli investigate \\
        --events alerts.json \\
        --title "Application Shimming" \\
        --format markdown --ai --provider auto
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
        help="Aktifkan AI narrative",
    )
    inv.add_argument(
        "--provider",
        choices=("rule", "multi_agent", "ollama", "cloud", "auto"),
        default="rule",
        help=(
            "AI provider untuk narrative "
            "(default: rule — deterministic, offline)"
        ),
    )

    # -- scenario -----------------------------------------------------
    sc = subparsers.add_parser(
        "scenario",
        help="List or run built-in attack scenarios",
    )
    sc.add_argument(
        "action",
        choices=("list", "run"),
        help="list: tampilkan scenario; run: jalankan scenario",
    )
    sc.add_argument(
        "name",
        nargs="?",
        default=None,
        help="Nama scenario (untuk action=run)",
    )
    sc.add_argument(
        "--format",
        choices=("markdown", "json", "text"),
        default="text",
    )
    sc.add_argument(
        "--ai",
        action="store_true",
    )
    sc.add_argument(
        "--provider",
        choices=("rule", "multi_agent"),
        default="rule",
    )
    sc.add_argument("--output", type=Path, default=None)

    # -- graph --------------------------------------------------------
    gr = subparsers.add_parser(
        "graph",
        help="Jalankan preset Cypher query ke Neo4j",
    )
    gr_sub = gr.add_subparsers(dest="graph_action", required=True)

    gr_sub.add_parser("list", help="Daftar preset query")

    gr_run = gr_sub.add_parser("run", help="Jalankan satu preset")
    gr_run.add_argument("preset", help="nama preset")
    gr_run.add_argument(
        "-p", "--param", action="append", default=[],
        metavar="KEY=VALUE",
        help="parameter preset (boleh diulang)",
    )
    gr_run.add_argument(
        "--dry-run", action="store_true",
        help="cetak cypher + params saja, jangan eksekusi",
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
        narrative = _generate_narrative(result, args)

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

    else:  # text
        text = report.to_text()
        if narrative:
            text = narrative + "\n\n" + text

    # -- Output ------------------------------------------------------
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


def _generate_narrative(
    result, args: argparse.Namespace
) -> str | None:
    """
    Hasilkan AI narrative berdasarkan flag --provider.
    """
    try:
        from internal.ai import AIRouter
        from internal.ai.llm import (
            CloudLLMProvider,
            LocalLLMProvider,
        )
    except ImportError as exc:
        _err(f"AI layer not available: {exc}")
        return None

    provider_name = getattr(args, "provider", "rule")

    providers = []
    if provider_name == "ollama":
        providers = [LocalLLMProvider()]
    elif provider_name == "cloud":
        providers = [CloudLLMProvider()]
    elif provider_name == "multi_agent":
        from internal.ai import MultiAgentProvider
        providers = [MultiAgentProvider()]
    elif provider_name == "auto":
        from internal.ai import MultiAgentProvider
        providers = [
            CloudLLMProvider(),
            LocalLLMProvider(),
            MultiAgentProvider(),
        ]
    # provider_name == "rule": providers kosong,
    # AIRouter otomatis pakai RuleEngineProvider

    try:
        router = AIRouter(providers=providers)
        narrative = router.narrate(result)
        used = router.available_providers()
        _info(
            f"AI narrative generated (providers: {used})",
            args,
        )
        return narrative
    except Exception as exc:  # noqa: BLE001
        _err(f"AI narrative failed: {exc}")
        return None


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
    if args.command == "scenario":
        return cmd_scenario(args)
    if args.command == "graph":
        return cmd_graph(args)

    parser.print_help(sys.stderr)
    return 2

def cmd_scenario(args: argparse.Namespace) -> int:
    """
    List atau run built-in attack scenario.
    """
    from internal.simulation import (
        ATTACK_SCENARIOS,
        build_scenario,
        list_scenarios,
    )

def cmd_graph(args: argparse.Namespace) -> int:
    """List / run preset Cypher query."""
    from internal.storage.graph.queries import PRESETS

    # -- list ---------------------------------------------------------
    if args.graph_action == "list":
        print(f"{'name':<30} {'category':<12} description")
        print("-" * 78)
        for name, factory in PRESETS.items():
            try:
                sample = factory("X")
            except TypeError:
                sample = factory()
            print(f"{name:<30} {sample.category:<12} {sample.description}")
        return 0

    # -- run ----------------------------------------------------------
    if args.graph_action == "run":
        factory = PRESETS.get(args.preset)
        if factory is None:
            _err(f"preset tidak dikenal: {args.preset}")
            _err(f"tersedia: {', '.join(PRESETS)}")
            return 2

        raw: dict[str, str] = {}
        for kv in args.param:
            if "=" not in kv:
                _err(f"format -p harus key=value, dapat: {kv!r}")
                return 2
            k, v = kv.split("=", 1)
            raw[k.strip()] = v.strip()

        try:
            preset = factory(**raw)
        except TypeError as exc:
            _err(f"parameter salah untuk {args.preset}: {exc}")
            return 2

        # -- dry-run ------------------------------------------------
        if getattr(args, "dry_run", False):
            print("\u2500\u2500 cypher \u2500\u2500")
            print(preset.cypher.strip())
            print("\u2500\u2500 params \u2500\u2500")
            for k, v in preset.params.items():
                print(f"  {k} = {v!r}")
            return 0

        # -- eksekusi ke Neo4j --------------------------------------
        from internal.storage.graph.client import Neo4jClient

        client: Neo4jClient | None = None
        try:
            client = Neo4jClient(create_indexes=False)
            rows = client.run(preset.cypher, preset.params)
        except Exception as exc:  # noqa: BLE001
            _err(f"Neo4j error: {exc}")
            if client is not None:
                _err(f"uri: {client.uri}  db: {client.database}")
            else:
                _err("gagal membuat Neo4jClient (cek env AEGIS_NEO4J_*)")
            return 1
        finally:
            if client is not None:
                try:
                    client.driver.close()
                except Exception:  # noqa: BLE001
                    pass

        if not rows:
            print("(tidak ada hasil)")
            return 0

        headers = list(rows[0].keys())
        print("\t".join(headers))
        print("-" * 60)
        for row in rows:
            print("\t".join(_fmt_cell(row.get(h)) for h in headers))
        return 0

    _err(f"unknown graph action: {args.graph_action}")
    return 1


def _fmt_cell(value: object) -> str:
    """Format satu cell untuk output tab-separated."""
    if value is None:
        return ""
    return str(value).replace("\t", " ").replace("\n", " ")


__all__ = ["build_parser", "main", "cmd_investigate"]
