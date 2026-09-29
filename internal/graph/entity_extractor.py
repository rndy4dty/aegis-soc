"""
Entity extractor for AegisSOC.

Tugas:
    Event  ->  list[Entity]

Extractor TIDAK membuat Relationship, tidak melakukan correlation,
tidak menghitung risk, tidak memanggil LLM, tidak melakukan enrichment
eksternal, dan tidak mengubah Event.

Prinsip:
- Deterministik: Event yang sama menghasilkan entity yang sama,
  termasuk URUTAN output.
- Deduplication by identity fingerprint (bukan entity_id).
- Provenance (source_event_ids) selalu diisi.
- Tenant isolation dijaga.
- Identity Process membedakan instance:
      GUID tersedia    -> name + GUID       (quality: guid)
      PID tersedia     -> name + PID        (quality: pid)
      keduanya kosong  -> name saja         (quality: name_only, fallback lemah)
- Identity User membedakan local vs domain secara eksplisit.
- HASH adalah entity terpisah, bukan property dari FILE.
"""

from __future__ import annotations

from typing import Any

from pkg.models.entity import Entity, EntityType


# ===========================================================================
# Constants
# ===========================================================================

_TYPE_ORDER: dict[EntityType, int] = {
    EntityType.HOST: 0,
    EntityType.USER: 1,
    EntityType.PROCESS: 2,
    EntityType.FILE: 3,
    EntityType.HASH: 4,
    EntityType.IP: 5,
    EntityType.DOMAIN: 6,
    EntityType.MITRE_TECHNIQUE: 7,
}

IDENTITY_QUALITY_GUID = "guid"
IDENTITY_QUALITY_PID = "pid"
IDENTITY_QUALITY_NAME_ONLY = "name_only"

PROPERTY_IDENTITY_QUALITY = "identity_quality"


# ===========================================================================
# Internal helpers
# ===========================================================================

def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """Ambil atribut dari objek atau dict."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _enum_value(value: Any) -> str | None:
    """Konversi enum/str jadi string value, None kalau kosong."""
    if value is None:
        return None
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _normalize_str(value: Any) -> str | None:
    """String non-empty setelah strip, else None."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _normalize_domain(value: str) -> str:
    """
    Normalisasi domain:
    - lowercase
    - hapus trailing dot (FQDN absolute)
    """
    d = value.strip().lower()
    while d.endswith("."):
        d = d[:-1]
    return d


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _coerce_mitre_collection(raw: Any) -> list[Any]:
    """
    Kontrak input MITRE:
    - str            -> [str]      (single technique)
    - list/tuple     -> list(raw)
    - set/frozenset  -> sorted(raw)
    - lainnya        -> []

    String TIDAK dipecah menjadi karakter.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (set, frozenset)):
        return sorted(raw)
    if isinstance(raw, (list, tuple)):
        return list(raw)
    return []


# ===========================================================================
# EntityExtractor
# ===========================================================================

class EntityExtractor:
    """
    Stateless extractor: Event -> list[Entity].

    Bisa di-reuse berulang.
    """

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def extract(self, event: Any) -> list[Entity]:
        event_id = _normalize_str(_attr(event, "event_id"))
        tenant_id = _attr(event, "tenant_id")
        event_ts = _attr(event, "timestamp")
        platform = _enum_value(_attr(event, "platform"))

        host = _normalize_str(_attr(event, "host"))

        candidates: list[Entity] = []

        # -- HOST --------------------------------------------------------
        if host:
            candidates.append(
                self._build_host(host, tenant_id, event_id, event_ts)
            )

        # -- USER --------------------------------------------------------
        user_entity = self._build_user(
            event,
            host=host,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        )
        if user_entity is not None:
            candidates.append(user_entity)

        # -- PROCESS -----------------------------------------------------
        if host:
            candidates.extend(self._build_processes(
                event,
                host=host,
                tenant_id=tenant_id,
                event_id=event_id,
                event_ts=event_ts,
            ))

        # -- FILE + HASH -------------------------------------------------
        candidates.extend(self._build_file_and_hashes(
            event,
            host=host,
            platform=platform,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        ))

        # -- IP ----------------------------------------------------------
        candidates.extend(self._build_ips(
            event,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        ))

        # -- DOMAIN ------------------------------------------------------
        candidates.extend(self._build_domains(
            event,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        ))

        # -- MITRE -------------------------------------------------------
        candidates.extend(self._build_mitre(
            event,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        ))

        # -- Dedup + sort ------------------------------------------------
        deduped = self._deduplicate(candidates)
        return self._sort(deduped)

    # -------------------------------------------------------------------
    # HOST
    # -------------------------------------------------------------------

    @staticmethod
    def _build_host(
        host: str,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> Entity:
        return Entity(
            tenant_id=tenant_id,
            entity_type=EntityType.HOST,
            value=host,
            normalized_value=host.lower(),
            source_event_ids=[event_id] if event_id else [],
            first_seen=event_ts,
            last_seen=event_ts,
        )

    # -------------------------------------------------------------------
    # USER
    # -------------------------------------------------------------------

    @staticmethod
    def _build_user(
        event: Any,
        *,
        host: str | None,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> Entity | None:
        user = _normalize_str(_attr(event, "user"))
        if not user:
            return None

        user_ctx = _attr(event, "user_context")
        user_domain = _normalize_str(_attr(user_ctx, "domain"))

        source_ids = [event_id] if event_id else []

        # -- Domain user -------------------------------------------------
        if user_domain:
            return Entity(
                tenant_id=tenant_id,
                entity_type=EntityType.USER,
                value=user,
                normalized_value=user.lower(),
                identity_scope="domain",
                identity_domain=user_domain.lower(),
                source_event_ids=source_ids,
                first_seen=event_ts,
                last_seen=event_ts,
            )

        # -- Local user --------------------------------------------------
        if host:
            return Entity(
                tenant_id=tenant_id,
                entity_type=EntityType.USER,
                value=user,
                normalized_value=user.lower(),
                identity_scope="local",
                host=host.lower(),
                source_event_ids=source_ids,
                first_seen=event_ts,
                last_seen=event_ts,
            )

        # Ambiguous: user tanpa domain, tanpa host -> skip.
        return None

    # -------------------------------------------------------------------
    # PROCESS
    # -------------------------------------------------------------------

    @classmethod
    def _build_processes(
        cls,
        event: Any,
        *,
        host: str,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> list[Entity]:
        process = _attr(event, "process")
        if process is None:
            return []

        out: list[Entity] = []
        source_ids = [event_id] if event_id else []

        # -- Current process ---------------------------------------------
        name = _normalize_str(_attr(process, "name"))
        pid = _coerce_int(_attr(process, "pid"))
        guid = _normalize_str(_attr(process, "guid"))
        image_path = _normalize_str(_attr(process, "image_path"))
        parent_pid = _coerce_int(_attr(process, "parent_pid"))

        if name:
            normalized, quality = cls._process_identity(name, guid, pid)

            properties: dict[str, Any] = {
                PROPERTY_IDENTITY_QUALITY: quality,
            }
            if pid is not None:
                properties["pid"] = pid
            if parent_pid is not None:
                properties["parent_pid"] = parent_pid
            if guid:
                properties["guid"] = guid
            if image_path:
                properties["image_path"] = image_path

            out.append(Entity(
                tenant_id=tenant_id,
                entity_type=EntityType.PROCESS,
                value=name,
                normalized_value=normalized,
                host=host.lower(),
                properties=properties,
                source_event_ids=source_ids,
                first_seen=event_ts,
                last_seen=event_ts,
            ))

        # -- Parent process ----------------------------------------------
        parent_name = _normalize_str(_attr(process, "parent_name"))
        parent_guid = _normalize_str(_attr(process, "parent_guid"))

        if parent_name:
            parent_normalized, parent_quality = cls._process_identity(
                parent_name, parent_guid, parent_pid,
            )

            parent_props: dict[str, Any] = {
                PROPERTY_IDENTITY_QUALITY: parent_quality,
            }
            if parent_pid is not None:
                parent_props["pid"] = parent_pid
            if parent_guid:
                parent_props["guid"] = parent_guid

            out.append(Entity(
                tenant_id=tenant_id,
                entity_type=EntityType.PROCESS,
                value=parent_name,
                normalized_value=parent_normalized,
                host=host.lower(),
                properties=parent_props,
                source_event_ids=source_ids,
                first_seen=event_ts,
                last_seen=event_ts,
            ))

        return out

    @staticmethod
    def _process_identity(
        name: str,
        guid: str | None,
        pid: int | None,
    ) -> tuple[str, str]:
        """
        Identity Process = name + (guid | pid | nothing).

        Return (normalized_value, identity_quality).

        Prioritas:
        - guid         : paling stabil
        - pid          : fallback instance
        - name saja    : fallback lemah (name_only)
        """
        base = name.lower()

        if guid:
            return f"{base}|guid:{guid.lower()}", IDENTITY_QUALITY_GUID

        if pid is not None:
            return f"{base}|pid:{pid}", IDENTITY_QUALITY_PID

        return base, IDENTITY_QUALITY_NAME_ONLY

    # -------------------------------------------------------------------
    # FILE + HASH
    # -------------------------------------------------------------------

    @classmethod
    def _build_file_and_hashes(
        cls,
        event: Any,
        *,
        host: str | None,
        platform: str | None,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> list[Entity]:
        file_ctx = _attr(event, "file")
        if file_ctx is None:
            return []

        out: list[Entity] = []
        source_ids = [event_id] if event_id else []

        # -- FILE --------------------------------------------------------
        file_path = _normalize_str(_attr(file_ctx, "path"))
        file_name = _normalize_str(_attr(file_ctx, "name"))
        file_value = file_path or file_name

        if file_value:
            # Windows case-insensitive; Linux/macOS case-sensitive.
            if platform == "windows":
                normalized_path = file_value.lower()
            else:
                normalized_path = file_value

            file_props: dict[str, Any] = {}
            for key in ("size", "signed", "signer", "extension"):
                val = _attr(file_ctx, key)
                if val is not None:
                    file_props[key] = val

            out.append(Entity(
                tenant_id=tenant_id,
                entity_type=EntityType.FILE,
                value=file_value,
                normalized_value=normalized_path,
                host=host.lower() if host else None,
                properties=file_props,
                source_event_ids=source_ids,
                first_seen=event_ts,
                last_seen=event_ts,
            ))

        # -- HASH entities -----------------------------------------------
        file_hashes = _attr(file_ctx, "hashes") or {}
        if isinstance(file_hashes, dict):
            for algo, raw_value in file_hashes.items():
                algo_norm = _normalize_str(algo)
                hash_norm = _normalize_str(raw_value)
                if not algo_norm or not hash_norm:
                    continue

                out.append(Entity(
                    tenant_id=tenant_id,
                    entity_type=EntityType.HASH,
                    value=hash_norm,
                    normalized_value=hash_norm.lower(),
                    hash_algorithm=algo_norm.lower(),
                    source_event_ids=source_ids,
                    first_seen=event_ts,
                    last_seen=event_ts,
                ))

        return out

    # -------------------------------------------------------------------
    # IP
    # -------------------------------------------------------------------

    @staticmethod
    def _build_ips(
        event: Any,
        *,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> list[Entity]:
        network = _attr(event, "network")
        if network is None:
            return []

        source_ids = [event_id] if event_id else []
        out: list[Entity] = []

        for field in ("source_ip", "destination_ip"):
            ip_val = _normalize_str(_attr(network, field))
            if not ip_val:
                continue
            out.append(Entity(
                tenant_id=tenant_id,
                entity_type=EntityType.IP,
                value=ip_val,
                normalized_value=ip_val,
                source_event_ids=source_ids,
                first_seen=event_ts,
                last_seen=event_ts,
            ))

        return out

    # -------------------------------------------------------------------
    # DOMAIN
    # -------------------------------------------------------------------

    @staticmethod
    def _build_domains(
        event: Any,
        *,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> list[Entity]:
        source_ids = [event_id] if event_id else []
        raw_domains: list[str] = []

        event_domain = _normalize_str(_attr(event, "domain"))
        if event_domain:
            raw_domains.append(event_domain)

        dns_ctx = _attr(event, "dns")
        dns_query = _normalize_str(_attr(dns_ctx, "query"))
        if dns_query:
            raw_domains.append(dns_query)

        out: list[Entity] = []
        for dom in raw_domains:
            normalized = _normalize_domain(dom)
            if not normalized:
                continue
            out.append(Entity(
                tenant_id=tenant_id,
                entity_type=EntityType.DOMAIN,
                value=dom,
                normalized_value=normalized,
                source_event_ids=source_ids,
                first_seen=event_ts,
                last_seen=event_ts,
            ))
        return out

    # -------------------------------------------------------------------
    # MITRE
    # -------------------------------------------------------------------

    @staticmethod
    def _build_mitre(
        event: Any,
        *,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> list[Entity]:
        raw = _coerce_mitre_collection(_attr(event, "mitre_techniques"))

        source_ids = [event_id] if event_id else []
        out: list[Entity] = []

        for tech in raw:
            if tech is None:
                continue
            tech_str = _normalize_str(str(tech))
            if not tech_str:
                continue
            out.append(Entity(
                tenant_id=tenant_id,
                entity_type=EntityType.MITRE_TECHNIQUE,
                value=tech_str,
                normalized_value=tech_str.upper(),
                source_event_ids=source_ids,
                first_seen=event_ts,
                last_seen=event_ts,
            ))

        return out

    # -------------------------------------------------------------------
    # Dedup + sort
    # -------------------------------------------------------------------

    @staticmethod
    def _deduplicate(entities: list[Entity]) -> list[Entity]:
        """
        Dedup by identity fingerprint.

        Entity yang sama di-merge:
        - source_event_ids di-union
        - first_seen = min, last_seen = max
        - properties digabung sesuai merge policy Entity
        """
        by_fp: dict[str, Entity] = {}

        for candidate in entities:
            e = candidate.with_fingerprint()
            fp = e.fingerprint
            if fp in by_fp:
                by_fp[fp] = by_fp[fp].merge(e)
            else:
                by_fp[fp] = e

        return list(by_fp.values())

    @staticmethod
    def _sort(entities: list[Entity]) -> list[Entity]:
        """
        Deterministic sort.

        Key:
            1. type order
            2. normalized_value
            3. hash_algorithm   (disambiguasi HASH dengan value sama)
            4. identity_scope   (disambiguasi USER local/domain)
            5. identity_domain
            6. host
            7. fingerprint      (final, deterministik dari identity)

        entity_id TIDAK dipakai karena UUID acak.
        """
        return sorted(entities, key=lambda e: (
            _TYPE_ORDER.get(e.entity_type, 99),
            e.normalized_value,
            e.hash_algorithm or "",
            e.identity_scope or "",
            e.identity_domain or "",
            e.host or "",
            e.fingerprint or "",
        ))


# ===========================================================================
# Factory
# ===========================================================================

def extract_entities(event: Any) -> list[Entity]:
    """Convenience factory."""
    return EntityExtractor().extract(event)


__all__ = [
    "EntityExtractor",
    "extract_entities",
    "IDENTITY_QUALITY_GUID",
    "IDENTITY_QUALITY_PID",
    "IDENTITY_QUALITY_NAME_ONLY",
    "PROPERTY_IDENTITY_QUALITY",
]
