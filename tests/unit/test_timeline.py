from datetime import datetime, timedelta, timezone

import pytest

from internal.correlation.timeline import (
    EventLike,
    ProcessLike,
    Timeline,
    build_timeline,
)
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
    ProcessContext,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(event_id: str, offset_seconds: int = 0) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE + timedelta(seconds=offset_seconds),
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=50,
        host="WIN-01",
        user="ren",
        process=ProcessContext(
            name="sdbinst.exe",
            pid=1000,
            parent_pid=800,
        ),
    )


# ============================================================================
# 1. event_id validation
# ============================================================================


def test_event_id_empty_string_rejected():
    ev = make_event("E-1")
    ev.event_id = ""

    with pytest.raises(ValueError, match="empty event_id"):
        Timeline([ev])


def test_event_id_whitespace_rejected():
    ev = make_event("E-1")
    ev.event_id = "   "

    with pytest.raises(ValueError, match="empty event_id"):
        Timeline([ev])


def test_event_id_stripped():
    ev = make_event("E-1")
    ev.event_id = "  E-1  "

    tl = Timeline([ev])

    assert tl[0].event_id == "E-1"


def test_event_id_non_string_rejected():
    ev = make_event("E-1")
    object.__setattr__(ev, "event_id", 12345)

    with pytest.raises(ValueError, match="non-string event_id"):
        Timeline([ev])


def test_event_id_none_rejected():
    ev = make_event("E-1")
    object.__setattr__(ev, "event_id", None)

    with pytest.raises(ValueError, match="non-string event_id"):
        Timeline([ev])

def test_event_id_error_includes_index():
    ev_bad = make_event("E-2")
    ev_bad.event_id = ""

    with pytest.raises(ValueError, match="index 1"):
        Timeline(
            [
                make_event("E-1"),
                ev_bad,
            ]
        )


# ============================================================================
# 2. Type contract
# ============================================================================


def test_eventlike_protocol_runtime_check():
    ev = make_event("E-1")

    assert isinstance(ev, EventLike)


def test_processlike_protocol_runtime_check():
    proc = ProcessContext(
        name="sdbinst.exe",
        pid=1000,
        parent_pid=800,
    )

    assert isinstance(proc, ProcessLike)


def test_duck_typed_event_accepted():
    """
    Timeline harus menerima objek apa pun yang memenuhi EventLike,
    bukan hanya pkg.models.event.Event.
    """

    class FakeProcess:
        name = "sdbinst.exe"
        pid = 1000
        parent_pid = 800

    class FakeEvent:
        event_id = "FAKE-1"
        timestamp = BASE
        category = "process"
        event_type = "process_creation"
        severity = 50
        host = "WIN-01"
        user = "ren"
        process = FakeProcess()
        mitre_techniques = ["T1546.011"]
        rule_id = None
        rule_name = None

    tl = Timeline([FakeEvent()])

    assert tl.size == 1
    assert tl[0].event_id == "FAKE-1"
    assert tl[0].mitre_techniques == ("T1546.011",)


def test_dict_event_accepted():
    """
    _attr() mendukung dictionary.
    Timeline harus menerima dictionary event.
    """

    raw = {
        "event_id": "D-1",
        "timestamp": BASE,
        "category": "process",
        "event_type": "process_creation",
        "severity": 50,
        "host": "WIN-01",
        "user": "ren",
        "process": {
            "name": "sdbinst.exe",
            "pid": 1000,
            "parent_pid": 800,
        },
        "mitre_techniques": ["T1546.011"],
        "rule_id": None,
        "rule_name": None,
    }

    tl = Timeline([raw])

    assert tl.size == 1
    assert tl[0].event_id == "D-1"
    assert tl[0].process_pid == 1000


# ============================================================================
# 3. Duplicate event_id policy
# ============================================================================


def test_duplicate_event_id_raises_by_default():
    a = make_event("E-1", 0)
    b = make_event("E-1", 10)

    with pytest.raises(
        ValueError,
        match="duplicate event_id 'E-1'",
    ):
        Timeline([a, b])


def test_duplicate_event_id_error_includes_indices():
    a = make_event("E-1", 0)
    b = make_event("E-1", 10)

    with pytest.raises(
        ValueError,
        match="first seen at index 0",
    ):
        Timeline([a, b])


def test_duplicate_keep_first():
    a = make_event("E-1", 0)
    b = make_event("E-1", 10)

    tl = Timeline(
        [a, b],
        on_duplicate="first",
    )

    assert tl.size == 1
    assert tl[0].timestamp == a.timestamp


def test_duplicate_keep_last():
    a = make_event("E-1", 0)
    b = make_event("E-1", 10)

    tl = Timeline(
        [a, b],
        on_duplicate="last",
    )

    assert tl.size == 1
    assert tl[0].timestamp == b.timestamp


def test_duplicate_invalid_policy_rejected():
    with pytest.raises(
        ValueError,
        match="on_duplicate must be",
    ):
        Timeline(
            [],
            on_duplicate="ignore",  # type: ignore[arg-type]
        )


def test_no_duplicates_no_error():
    a = make_event("E-1", 0)
    b = make_event("E-2", 10)

    tl = Timeline([a, b])

    assert tl.size == 2
    assert [event.event_id for event in tl] == [
        "E-1",
        "E-2",
    ]


def test_build_timeline_factory_still_works():
    """
    Factory harus tetap kompatibel dengan signature baru.
    """

    tl = build_timeline(
        [
            make_event("E-1"),
            make_event("E-2"),
        ]
    )

    assert tl.size == 2
