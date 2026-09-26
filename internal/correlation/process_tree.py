from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Protocol, runtime_checkable


# ===========================================================================
# Protocols — structural contract
# ===========================================================================

@runtime_checkable
class ProcessLike(Protocol):
    name: str | None
    pid: int | None
    parent_pid: int | None
    guid: str | None
    parent_guid: str | None


@runtime_checkable
class EventLike(Protocol):
    event_id: str
    host: str | None
    process: ProcessLike | None


# ===========================================================================
# Internal helpers
# ===========================================================================

def _attr(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _key_by_guid(host: str, guid: str) -> str:
    return f"{host}|guid:{guid}"


def _key_by_pid(host: str, pid: int) -> str:
    return f"{host}|pid:{pid}"


def _node_key(host: str, process_guid: str | None, pid: int) -> str:
    if process_guid:
        return _key_by_guid(host, process_guid)
    return _key_by_pid(host, pid)


# ===========================================================================
# ProcessNode
# ===========================================================================

@dataclass(frozen=True, slots=True)
class ProcessNode:
    """
    Satu proses di dalam ProcessTree.

    Field `is_orphan` dihitung saat build, bukan property.
    """

    host: str
    pid: int
    name: str
    parent_pid: int | None
    process_guid: str | None
    parent_guid: str | None
    event_id: str
    is_orphan: bool = False

    @property
    def key(self) -> str:
        return _node_key(self.host, self.process_guid, self.pid)


# ===========================================================================
# ProcessTree
# ===========================================================================

class ProcessTree:
    """
    Reconstructed process tree.

    Immutable setelah dibangun.
    """

    def __init__(
        self,
        nodes: dict[str, ProcessNode],
        parent_map: dict[str, str | None],
    ) -> None:
        self._nodes = nodes
        self._parent_map = parent_map

        # Children index
        self._children_map: dict[str, list[str]] = {}
        for child_key, parent_key in parent_map.items():
            if parent_key is None:
                continue
            self._children_map.setdefault(parent_key, []).append(child_key)
        for key in self._children_map:
            self._children_map[key].sort()

        # pid index: (host, pid) -> list[node_key]
        self._pid_index: dict[tuple[str, int], list[str]] = {}
        for node in nodes.values():
            self._pid_index.setdefault((node.host, node.pid), []).append(node.key)
        for key in self._pid_index:
            self._pid_index[key].sort()

    # -------------------------------------------------------------------
    # Construction
    # -------------------------------------------------------------------

    @classmethod
    def from_events(cls, events: Iterable[EventLike]) -> "ProcessTree":
        nodes: dict[str, ProcessNode] = {}
        guid_index: dict[tuple[str, str], str] = {}
        pid_index: dict[tuple[str, int], list[str]] = {}

        # -- Pass 1: materialize nodes ---------------------------------
        for raw in events:
            event_id = str(_attr(raw, "event_id", "")).strip()
            host = _attr(raw, "host") or ""
            process = _attr(raw, "process")

            if process is None:
                raise ValueError(
                    f"event {event_id!r} is missing process context"
                )

            pid = _attr(process, "pid")
            if not isinstance(pid, int):
                raise ValueError(
                    f"event {event_id!r} process is missing valid pid"
                )

            name = _attr(process, "name") or ""
            parent_pid = _attr(process, "parent_pid")
            if not isinstance(parent_pid, int):
                parent_pid = None

            process_guid = _attr(process, "guid")
            if not isinstance(process_guid, str) or not process_guid:
                process_guid = None

            parent_guid = _attr(process, "parent_guid")
            if not isinstance(parent_guid, str) or not parent_guid:
                parent_guid = None

            key = _node_key(host, process_guid, pid)

            if key in nodes:
                raise ValueError(
                    f"duplicate process node for key {key!r}"
                )

            nodes[key] = ProcessNode(
                host=host,
                pid=pid,
                name=str(name),
                parent_pid=parent_pid,
                process_guid=process_guid,
                parent_guid=parent_guid,
                event_id=event_id,
            )

            if process_guid:
                guid_index[(host, process_guid)] = key
            pid_index.setdefault((host, pid), []).append(key)

        # -- Pass 2: resolve parent key --------------------------------
        parent_map: dict[str, str | None] = {}
        for key, node in nodes.items():
            parent_map[key] = cls._resolve_parent_key(
                node,
                guid_index=guid_index,
                pid_index=pid_index,
            )

        # -- Pass 3: cycle detection -----------------------------------
        cls._detect_cycles(nodes, parent_map)

        # -- Pass 4: orphan detection ----------------------------------
        for key, node in list(nodes.items()):
            has_declared_parent = (
                node.parent_pid is not None or node.parent_guid is not None
            )
            if not has_declared_parent:
                continue
            if parent_map.get(key) is None:
                nodes[key] = ProcessNode(
                    host=node.host,
                    pid=node.pid,
                    name=node.name,
                    parent_pid=node.parent_pid,
                    process_guid=node.process_guid,
                    parent_guid=node.parent_guid,
                    event_id=node.event_id,
                    is_orphan=True,
                )

        return cls(nodes=nodes, parent_map=parent_map)

    @staticmethod
    def _resolve_parent_key(
        node: ProcessNode,
        *,
        guid_index: dict[tuple[str, str], str],
        pid_index: dict[tuple[str, int], list[str]],
    ) -> str | None:
        # Prefer parent_guid
        if node.parent_guid:
            result = guid_index.get((node.host, node.parent_guid))
            if result is not None:
                return result

        # Fall back to parent_pid, hanya kalau unik
        if node.parent_pid is not None:
            candidates = pid_index.get((node.host, node.parent_pid), [])
            if len(candidates) == 1:
                return candidates[0]

        return None

    @staticmethod
    def _detect_cycles(
        nodes: dict[str, ProcessNode],
        parent_map: dict[str, str | None],
    ) -> None:
        for start_key in nodes:
            seen: set[str] = set()
            current: str | None = start_key
            while current is not None:
                if current in seen:
                    raise ValueError(
                        f"cycle detected in process tree at {current!r}"
                    )
                seen.add(current)
                current = parent_map.get(current)

    # -------------------------------------------------------------------
    # Lookup
    # -------------------------------------------------------------------

    def get(
        self,
        *,
        host: str,
        pid: int | None = None,
        process_guid: str | None = None,
    ) -> ProcessNode | None:
        if process_guid:
            return self._nodes.get(_key_by_guid(host, process_guid))
        if pid is not None:
            candidates = self._pid_index.get((host, pid), [])
            if candidates:
                return self._nodes.get(candidates[0])
        return None

    # -------------------------------------------------------------------
    # Traversal
    # -------------------------------------------------------------------

    def roots(self) -> list[ProcessNode]:
        """
        Node yang tidak memiliki parent yang berhasil di-resolve.

        Root asli maupun orphan sama-sama berada di root set.
        Perbedaannya ditandai oleh `is_orphan`.
        """
        result = [
            node
            for node in self._nodes.values()
            if self._parent_map.get(node.key) is None
        ]

        return sorted(
            result,
            key=lambda n: (n.host, n.pid, n.event_id),
        )

    def parent(
        self,
        *,
        host: str,
        pid: int | None = None,
        process_guid: str | None = None,
    ) -> ProcessNode | None:
        node = self.get(host=host, pid=pid, process_guid=process_guid)
        if node is None:
            return None
        parent_key = self._parent_map.get(node.key)
        if parent_key is None:
            return None
        return self._nodes.get(parent_key)

    def children(
        self,
        *,
        host: str,
        pid: int | None = None,
        process_guid: str | None = None,
    ) -> list[ProcessNode]:
        node = self.get(host=host, pid=pid, process_guid=process_guid)
        if node is None:
            return []
        child_keys = self._children_map.get(node.key, [])
        return sorted(
            (self._nodes[k] for k in child_keys if k in self._nodes),
            key=lambda n: (n.pid, n.event_id),
        )

    def lineage(
        self,
        *,
        host: str,
        pid: int | None = None,
        process_guid: str | None = None,
    ) -> list[ProcessNode]:
        """
        Rantai root → ... → node (ascending).
        """
        node = self.get(host=host, pid=pid, process_guid=process_guid)
        if node is None:
            return []

        chain: list[ProcessNode] = [node]
        seen: set[str] = {node.key}
        current = node

        while True:
            parent_key = self._parent_map.get(current.key)
            if parent_key is None or parent_key in seen:
                break
            parent = self._nodes.get(parent_key)
            if parent is None:
                break
            chain.append(parent)
            seen.add(parent_key)
            current = parent

        return list(reversed(chain))

    def descendants(
        self,
        *,
        host: str,
        pid: int | None = None,
        process_guid: str | None = None,
    ) -> list[ProcessNode]:
        """
        Semua keturunan (recursive), sorted deterministik.
        """
        node = self.get(host=host, pid=pid, process_guid=process_guid)
        if node is None:
            return []

        result: list[ProcessNode] = []
        stack: list[str] = list(self._children_map.get(node.key, []))

        while stack:
            child_key = stack.pop()
            child = self._nodes.get(child_key)
            if child is None:
                continue
            result.append(child)
            stack.extend(self._children_map.get(child_key, []))

        return sorted(result, key=lambda n: (n.pid, n.event_id))

    # -------------------------------------------------------------------
    # Access & size
    # -------------------------------------------------------------------

    @property
    def size(self) -> int:
        return len(self._nodes)

    @property
    def nodes(self) -> tuple[ProcessNode, ...]:
        return tuple(sorted(
            self._nodes.values(),
            key=lambda n: (n.host, n.pid, n.event_id),
        ))

    def __len__(self) -> int:
        return len(self._nodes)

    def __iter__(self) -> Iterator[ProcessNode]:
        return iter(self.nodes)


# ===========================================================================
# Factory
# ===========================================================================

def build_process_tree(events: Iterable[EventLike]) -> ProcessTree:
    """Convenience factory untuk ProcessTree."""
    return ProcessTree.from_events(events)
