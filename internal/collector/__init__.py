"""
Data ingestion layer.

Collectors membaca event dari berbagai sumber dan mengubahnya
menjadi canonical Event.

- WazuhCollector    : parse Wazuh alert JSON
- SysmonCollector   : parse Sysmon event JSON
- FileSource        : baca dari file / directory
"""

from internal.collector.base import (
    Collector,
    CollectorResult,
)
from internal.collector.wazuh import WazuhCollector
from internal.collector.sysmon import SysmonCollector
from internal.collector.file_source import FileSource

__all__ = [
    "Collector",
    "CollectorResult",
    "WazuhCollector",
    "SysmonCollector",
    "FileSource",
]
