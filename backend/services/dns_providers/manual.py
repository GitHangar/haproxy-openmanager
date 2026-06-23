"""Manual DNS provider for ACME DNS-01 (Issue #35).

The user publishes the `_acme-challenge` TXT record in their own DNS (any provider, including
fully internal/isolated DNS that no API can reach) and then confirms via the UI. There is no API
to call, so add/remove are no-ops and the orchestration waits for an explicit `dns-confirm`.
CNAME delegation works implicitly here: the CA follows a CNAME, so a user who delegates
`_acme-challenge` elsewhere just publishes the value there and confirms.
"""
from __future__ import annotations

from typing import Dict, List

from .base import DnsProvider


class ManualDNSProvider(DnsProvider):
    name = "manual"
    label = "Manual (publish the TXT record yourself)"
    automated = False
    credential_fields: List[Dict] = []  # no credentials needed

    async def verify_credentials(self) -> Dict:
        return {"ok": True, "detail": "Manual mode needs no credentials. You will publish the TXT record yourself."}

    async def add_txt_record(self, name: str, value: str) -> None:
        # No-op: the user publishes the record and confirms via the UI.
        return None

    async def remove_txt_record(self, name: str, value: str) -> None:
        # No-op: the user may remove the record manually after issuance.
        return None
