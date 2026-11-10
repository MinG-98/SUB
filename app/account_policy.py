"""Shared account/node expiry policy for control and data-plane paths."""

from __future__ import annotations

from datetime import datetime, timezone

from app.models import utcnow


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def is_expired(value: datetime | None, now: datetime | None = None) -> bool:
    """Compare SQLite-naive and aware timestamps consistently as UTC."""

    if value is None:
        return False
    if not isinstance(value, datetime):
        # Invalid persisted expiry data must not silently grant continued access.
        return True
    current = now or utcnow()
    return _utc_naive(value) <= _utc_naive(current)
