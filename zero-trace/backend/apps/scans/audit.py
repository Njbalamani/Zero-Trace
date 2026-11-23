"""Privacy-safe audit event helpers. Events never contain raw secrets."""

from __future__ import annotations

from .models import AuditEvent


def log_event(user, action: str, target: str = "", metadata: dict | None = None) -> AuditEvent | None:
    if not user or not getattr(user, "is_authenticated", False):
        return None
    return AuditEvent.objects.create(
        user=user,
        action=action[:80],
        target=target[:255],
        metadata=metadata or {},
    )
