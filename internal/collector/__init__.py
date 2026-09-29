"""
Data ingestion layer.
"""

from internal.collector.base import (
    Collector,
    CollectorResult,
)
from internal.collector.file_source import FileSource
from internal.collector.sysmon import SysmonCollector
from internal.collector.wazuh import WazuhCollector
from internal.collector.wazuh_api import (
    WazuhAPIClient,
    WazuhAlert,
)
from internal.collector.wazuh_poller import (
    DEFAULT_INITIAL_LOOKBACK,
    DEFAULT_POLL_INTERVAL,
    PollerStats,
    WazuhPoller,
)

__all__ = [
    "Collector",
    "CollectorResult",
    "WazuhCollector",
    "SysmonCollector",
    "FileSource",
    "WazuhAPIClient",
    "WazuhAlert",
    "WazuhPoller",
    "PollerStats",
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_INITIAL_LOOKBACK",
]
