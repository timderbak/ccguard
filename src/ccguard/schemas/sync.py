"""SyncPayload — то, что агент отправляет на сервер."""

from __future__ import annotations

from ccguard.schemas._base import SchemaBase
from ccguard.schemas.audit import AuditEntry
from ccguard.schemas.finding import Finding
from ccguard.schemas.inventory import InventoryReport


class SyncPayload(SchemaBase):
    inventory: InventoryReport
    findings: list[Finding] = []
    audit_events: list[AuditEntry] = []
