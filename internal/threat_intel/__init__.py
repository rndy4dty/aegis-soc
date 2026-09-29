"""
Threat Intelligence enrichment layer.

Provider:
- VirusTotalProvider : hash/IP/domain lookup via VT API
- OTXProvider        : AlienVault OTX lookup
- MISPProvider       : MISP lookup (stub)

Orkestrasi via ThreatIntelEnricher:
- extract indicators dari Event / Evidence
- query provider yang tersedia
- attach hasil ke evidence.metadata["threat_intel"]

Semua provider opsional; kalau tidak dikonfigurasi, di-skip.
"""

from internal.threat_intel.base import (
    Indicator,
    IndicatorType,
    IntelProvider,
    IntelResult,
)
from internal.threat_intel.virustotal import VirusTotalProvider
from internal.threat_intel.otx import OTXProvider
from internal.threat_intel.misp import MISPProvider
from internal.threat_intel.enricher import ThreatIntelEnricher

__all__ = [
    "Indicator",
    "IndicatorType",
    "IntelProvider",
    "IntelResult",
    "VirusTotalProvider",
    "OTXProvider",
    "MISPProvider",
    "ThreatIntelEnricher",
]
