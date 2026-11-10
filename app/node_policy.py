"""Explicit classification for operational nodes versus legacy announcements."""


def is_real_node(node) -> bool:
    """Classify only by persisted entity type, never by endpoint/name heuristics."""
    return not bool(getattr(node, "is_announcement", False))
