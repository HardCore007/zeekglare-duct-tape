"""Scan completion notifications — unified dispatcher wrapper."""
from services.notification_hub import dispatch


def notify_scan_complete(user_id: int, scan_type: str, target: str,
                         findings: int, label: str = ""):
    """Backward-compatible wrapper that dispatches to all configured channels."""
    dispatch(user_id, scan_type, target, findings, label)
