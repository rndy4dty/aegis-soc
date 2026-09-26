from datetime import datetime, timezone

import pytest

from internal.correlation.process_tree import (
    ProcessNode,
    ProcessTree,
    build_process_tree,
)
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
    ProcessContext,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str,
    *,
    host: str = "WIN-01",
    pid: int,
    parent_pid: int | None = None,
    process_guid: str | None = None,
    parent_guid: str | None = None,
    name: str = "process.exe",
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE,
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=50,
        host=host,
        user="ren",
        process=ProcessContext(
            name=name,
            pid=pid,
            parent_pid=parent_pid,
            guid=process_guid,
            parent_guid=parent_guid,
        ),
    )


def test_process_node_contains_process_identity():
    event = make_event(
        "E-1",
        pid=1000,
        name="powershell.exe",
        process_guid="GUID-1000",
    )

    tree = ProcessTree.from_events([event])

    node = tree.get(host="WIN-01", pid=1000)

    assert isinstance(node, ProcessNode)
    assert node.pid == 1000
    assert node.parent_pid is None
    assert node.name == "powershell.exe"
    assert node.process_guid == "GUID-1000"
    assert node.event_id == "E-1"


def test_root_process_has_no_parent():
    event = make_event(
        "E-1",
        pid=1000,
        name="explorer.exe",
    )

    tree = ProcessTree.from_events([event])

    roots = tree.roots()

    assert len(roots) == 1
    assert roots[0].pid == 1000


def test_parent_child_relationship():
    parent = make_event(
        "E-1",
        pid=1000,
        name="explorer.exe",
    )

    child = make_event(
        "E-2",
        pid=2000,
        parent_pid=1000,
        name="powershell.exe",
    )

    tree = ProcessTree.from_events([parent, child])

    children = tree.children(host="WIN-01", pid=1000)

    assert len(children) == 1
    assert children[0].pid == 2000


def test_parent_lookup():
    parent = make_event(
        "E-1",
        pid=1000,
        name="explorer.exe",
    )

    child = make_event(
        "E-2",
        pid=2000,
        parent_pid=1000,
        name="powershell.exe",
    )

    tree = ProcessTree.from_events([parent, child])

    result = tree.parent(host="WIN-01", pid=2000)

    assert result is not None
    assert result.pid == 1000


def test_lineage_returns_root_to_process():
    e1 = make_event(
        "E-1",
        pid=1000,
        name="explorer.exe",
    )
    e2 = make_event(
        "E-2",
        pid=2000,
        parent_pid=1000,
        name="powershell.exe",
    )
    e3 = make_event(
        "E-3",
        pid=3000,
        parent_pid=2000,
        name="cmd.exe",
    )

    tree = ProcessTree.from_events([e1, e2, e3])

    lineage = tree.lineage(host="WIN-01", pid=3000)

    assert [node.pid for node in lineage] == [
        1000,
        2000,
        3000,
    ]


def test_descendants_returns_all_children():
    e1 = make_event("E-1", pid=1000, name="explorer.exe")
    e2 = make_event(
        "E-2",
        pid=2000,
        parent_pid=1000,
        name="powershell.exe",
    )
    e3 = make_event(
        "E-3",
        pid=3000,
        parent_pid=2000,
        name="cmd.exe",
    )
    e4 = make_event(
        "E-4",
        pid=4000,
        parent_pid=1000,
        name="notepad.exe",
    )

    tree = ProcessTree.from_events([e1, e2, e3, e4])

    descendants = tree.descendants(
        host="WIN-01",
        pid=1000,
    )

    assert {node.pid for node in descendants} == {
        2000,
        3000,
        4000,
    }


def test_pid_collision_across_hosts_is_not_merged():
    e1 = make_event(
        "E-1",
        host="WIN-01",
        pid=1000,
        name="powershell.exe",
    )

    e2 = make_event(
        "E-2",
        host="WIN-02",
        pid=1000,
        name="chrome.exe",
    )

    tree = ProcessTree.from_events([e1, e2])

    assert tree.size == 2

    win1 = tree.get(host="WIN-01", pid=1000)
    win2 = tree.get(host="WIN-02", pid=1000)

    assert win1 is not None
    assert win2 is not None
    assert win1.name == "powershell.exe"
    assert win2.name == "chrome.exe"


def test_orphan_process_is_detected():
    child = make_event(
        "E-1",
        pid=3000,
        parent_pid=9999,
        name="suspicious.exe",
    )

    tree = ProcessTree.from_events([child])

    node = tree.get(host="WIN-01", pid=3000)

    assert node is not None
    assert node.is_orphan is True


def test_non_orphan_process_is_detected():
    parent = make_event(
        "E-1",
        pid=1000,
        name="explorer.exe",
    )

    child = make_event(
        "E-2",
        pid=2000,
        parent_pid=1000,
        name="powershell.exe",
    )

    tree = ProcessTree.from_events([parent, child])

    node = tree.get(host="WIN-01", pid=2000)

    assert node is not None
    assert node.is_orphan is False


def test_parent_guid_is_preferred_when_available():
    parent = make_event(
        "E-1",
        pid=1000,
        process_guid="PARENT-GUID",
        name="explorer.exe",
    )

    child = make_event(
        "E-2",
        pid=1000,
        parent_pid=1000,
        process_guid="CHILD-GUID",
        parent_guid="PARENT-GUID",
        name="powershell.exe",
    )

    tree = ProcessTree.from_events([parent, child])

    parent_node = tree.get(
        host="WIN-01",
        process_guid="PARENT-GUID",
    )

    child_node = tree.get(
        host="WIN-01",
        process_guid="CHILD-GUID",
    )

    assert parent_node is not None
    assert child_node is not None

    assert tree.parent(
        host="WIN-01",
        process_guid="CHILD-GUID",
    ) == parent_node


def test_missing_process_is_rejected():
    event = make_event(
        "E-1",
        pid=1000,
    )

    event.process = None

    with pytest.raises(ValueError, match="process"):
        ProcessTree.from_events([event])


def test_cycle_is_rejected():
    e1 = make_event(
        "E-1",
        pid=1000,
        parent_pid=2000,
        name="a.exe",
    )

    e2 = make_event(
        "E-2",
        pid=2000,
        parent_pid=1000,
        name="b.exe",
    )

    with pytest.raises(ValueError, match="cycle"):
        ProcessTree.from_events([e1, e2])


def test_build_process_tree_factory():
    event = make_event(
        "E-1",
        pid=1000,
        name="explorer.exe",
    )

    tree = build_process_tree([event])

    assert isinstance(tree, ProcessTree)
    assert tree.size == 1

def test_parent_guid_resolves_when_parent_pid_is_none():
    parent = make_event(
        "E-1",
        pid=1000,
        process_guid="PARENT-GUID",
        name="explorer.exe",
    )

    child = make_event(
        "E-2",
        pid=2000,
        parent_pid=None,
        process_guid="CHILD-GUID",
        parent_guid="PARENT-GUID",
        name="powershell.exe",
    )

    tree = ProcessTree.from_events([parent, child])

    parent_node = tree.get(
        host="WIN-01",
        process_guid="PARENT-GUID",
    )

    child_node = tree.get(
        host="WIN-01",
        process_guid="CHILD-GUID",
    )

    assert parent_node is not None
    assert child_node is not None

    assert tree.parent(
        host="WIN-01",
        process_guid="CHILD-GUID",
    ) == parent_node

    assert [node.process_guid for node in tree.roots()] == [
        "PARENT-GUID"
    ]
