"""Contract tests untuk AegisSOC CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cli.main import build_parser, main


def _sample_event(
    event_id: str = "E-1",
    *,
    offset_seconds: int = 0,
    severity: int = 70,
    mitre: list[str] | None = None,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": f"2026-09-26T10:00:{offset_seconds:02d}Z",
        "source": "sysmon",
        "platform": "windows",
        "category": "process",
        "event_type": "process_creation",
        "severity": severity,
        "host": "WIN-01",
        "user": "ren",
        "process": {
            "name": "powershell.exe",
            "pid": 1234,
            "parent_pid": 800,
        },
        "mitre_techniques": mitre or [],
    }


@pytest.fixture
def events_file(tmp_path: Path) -> Path:
    path = tmp_path / "events.json"
    path.write_text(
        json.dumps([
            _sample_event("E-1", offset_seconds=0, mitre=["T1546.011"]),
            _sample_event("E-2", offset_seconds=5, mitre=["T1546.011"]),
        ]),
        encoding="utf-8",
    )
    return path


def test_build_parser_returns_parser():
    parser = build_parser()
    assert parser.prog == "aegis"


def test_parser_requires_subcommand():
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_investigate_args():
    parser = build_parser()
    args = parser.parse_args([
        "investigate",
        "--events", "events.json",
        "--title", "Test",
    ])
    assert args.command == "investigate"
    assert args.title == "Test"
    assert args.format == "markdown"
    assert args.output is None


def test_investigate_markdown_stdout(events_file, capsys):
    exit_code = main([
        "investigate",
        "--events", str(events_file),
        "--title", "Test Case",
        "--quiet",
    ])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "# Investigation Report" in captured.out
    assert "Test Case" in captured.out


def test_investigate_quiet_suppresses_stderr(events_file, capsys):
    main([
        "investigate",
        "--events", str(events_file),
        "--title", "Test",
        "--quiet",
    ])
    captured = capsys.readouterr()
    assert "[aegis]" not in captured.err


def test_investigate_info_in_stderr_without_quiet(events_file, capsys):
    main([
        "investigate",
        "--events", str(events_file),
        "--title", "Test",
    ])
    captured = capsys.readouterr()
    assert "[aegis]" in captured.err


def test_investigate_json_output(events_file, capsys):
    exit_code = main([
        "investigate",
        "--events", str(events_file),
        "--title", "JSON Case",
        "--format", "json",
        "--quiet",
    ])
    captured = capsys.readouterr()
    assert exit_code == 0
    data = json.loads(captured.out)
    assert data["case"]["title"] == "JSON Case"
    assert "risk" in data
    assert "graph" in data
    assert "hypotheses" in data


def test_investigate_text_output(events_file, capsys):
    exit_code = main([
        "investigate",
        "--events", str(events_file),
        "--title", "Text Case",
        "--format", "text",
        "--quiet",
    ])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "AEGISSOC INVESTIGATION SUMMARY" in captured.out


def test_investigate_output_to_file(events_file, tmp_path):
    out = tmp_path / "report.md"
    exit_code = main([
        "investigate",
        "--events", str(events_file),
        "--title", "File Output",
        "--output", str(out),
        "--quiet",
    ])
    assert exit_code == 0
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "# Investigation Report" in content
    assert "File Output" in content


def test_investigate_output_invalid_path(events_file, tmp_path):
    bad_path = tmp_path / "nonexistent_dir" / "report.md"
    exit_code = main([
        "investigate",
        "--events", str(events_file),
        "--title", "Test",
        "--output", str(bad_path),
        "--quiet",
    ])
    assert exit_code == 1


def test_investigate_with_analyst(events_file, capsys):
    main([
        "investigate",
        "--events", str(events_file),
        "--title", "Analyst Test",
        "--analyst", "ren",
        "--format", "json",
        "--quiet",
    ])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["case"]["analyst"] == "ren"


def test_investigate_with_category(events_file, capsys):
    main([
        "investigate",
        "--events", str(events_file),
        "--title", "Category Test",
        "--category", "persistence",
        "--format", "json",
        "--quiet",
    ])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["case"]["category"] == "persistence"


def test_investigate_with_priority(events_file, capsys):
    main([
        "investigate",
        "--events", str(events_file),
        "--title", "Priority Test",
        "--priority", "critical",
        "--format", "json",
        "--quiet",
    ])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["case"]["priority"] == "critical"


def test_investigate_with_tenant(events_file, capsys):
    main([
        "investigate",
        "--events", str(events_file),
        "--title", "Tenant Test",
        "--tenant", "tenant-a",
        "--format", "json",
        "--quiet",
    ])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["case"]["tenant_id"] == "tenant-a"


def test_investigate_missing_file(tmp_path, capsys):
    bad = tmp_path / "nonexistent.json"
    exit_code = main([
        "investigate",
        "--events", str(bad),
        "--title", "Test",
        "--quiet",
    ])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "not found" in captured.err.lower()


def test_investigate_invalid_json(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    exit_code = main([
        "investigate",
        "--events", str(bad),
        "--title", "Test",
        "--quiet",
    ])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "invalid json" in captured.err.lower()


def test_investigate_invalid_event(tmp_path, capsys):
    bad = tmp_path / "bad_event.json"
    bad.write_text(
        json.dumps([{"event_id": "E-1"}]),
        encoding="utf-8",
    )
    exit_code = main([
        "investigate",
        "--events", str(bad),
        "--title", "Test",
        "--quiet",
    ])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "invalid" in captured.err.lower()


def test_investigate_empty_events_list(tmp_path, capsys):
    empty = tmp_path / "empty.json"
    empty.write_text("[]", encoding="utf-8")
    exit_code = main([
        "investigate",
        "--events", str(empty),
        "--title", "Test",
        "--quiet",
    ])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "no events" in captured.err.lower()


def test_investigate_events_object_format(tmp_path):
    path = tmp_path / "wrapped.json"
    path.write_text(
        json.dumps({"events": [_sample_event()]}),
        encoding="utf-8",
    )
    exit_code = main([
        "investigate",
        "--events", str(path),
        "--title", "Wrapped",
        "--format", "json",
        "--quiet",
    ])
    assert exit_code == 0


def test_investigate_object_without_events_key(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    exit_code = main([
        "investigate",
        "--events", str(path),
        "--title", "Test",
        "--quiet",
    ])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "events" in captured.err.lower()


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "aegis-soc" in captured.out
