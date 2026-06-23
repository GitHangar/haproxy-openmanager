"""Abstract DNS provider interface for ACME DNS-01 (Issue #35)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List


class DnsProviderError(Exception):
    """A DNS provider failure with a SANITIZED, user-safe message.

    The message must NEVER contain API tokens, request headers, or other secrets — it is
    persisted to acme_order_events / order error_detail and shown in the UI. Raise this (not a
    raw aiohttp/json error) so credentials can't leak into logs or the order timeline.
    """


class DnsProvider(ABC):
    """Base class for a pluggable DNS provider.

    RRset semantics are ADDITIVE: ``add_txt_record`` ensures a (name, value) TXT exists WITHOUT
    removing other values at the same name, and ``remove_txt_record`` deletes ONLY the record
    matching (name, value). This is required because a cert for ``example.com`` + ``*.example.com``
    publishes two distinct values at the SAME name ``_acme-challenge.example.com``.
    """

    # Stable machine name (used in DB + API); human label; whether the provider automates publishing.
    name: str = "base"
    label: str = "Base"
    automated: bool = True

    # Declarative schema the UI renders to collect credentials. Each field:
    #   {"key", "label", "type" ("text"|"password"), "required" (bool), "max_length" (int), "help" (str)}
    credential_fields: List[Dict] = []

    def __init__(self, credentials: Dict[str, str] | None = None):
        self.credentials = credentials or {}

    @abstractmethod
    async def verify_credentials(self) -> Dict:
        """Validate the stored credentials against the provider. Returns
        ``{"ok": bool, "detail": str}`` (detail is user-safe). Must not raise on auth failure —
        return ``ok=False`` with a sanitized detail; may raise DnsProviderError on transport errors.
        """

    @abstractmethod
    async def add_txt_record(self, name: str, value: str) -> None:
        """Ensure a TXT record (name, value) exists. Idempotent; must not remove other values
        at the same name. Raise DnsProviderError (sanitized) on failure."""

    @abstractmethod
    async def remove_txt_record(self, name: str, value: str) -> None:
        """Remove ONLY the TXT record matching (name, value). Tolerate 'already gone'.
        Raise DnsProviderError (sanitized) on a real failure."""
