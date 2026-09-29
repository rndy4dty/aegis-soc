"""
Notification layer.

Komponen:
- Notifier            : Protocol untuk semua notifier
- SlackNotifier       : kirim ke Slack webhook
- EmailNotifier       : kirim via SMTP
- WebhookNotifier     : POST ke URL generik
- NotificationRouter  : evaluasi rules + dispatch
"""

from internal.notifications.base import (
    NotificationLevel,
    NotificationResult,
    Notifier,
)
from internal.notifications.email import EmailNotifier
from internal.notifications.router import (
    NotificationRouter,
    NotificationRule,
)
from internal.notifications.slack import SlackNotifier
from internal.notifications.webhook import WebhookNotifier

__all__ = [
    "Notifier",
    "NotificationLevel",
    "NotificationResult",
    "SlackNotifier",
    "EmailNotifier",
    "WebhookNotifier",
    "NotificationRouter",
    "NotificationRule",
]
