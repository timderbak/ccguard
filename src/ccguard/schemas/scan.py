"""LLM content-scanner HTTP schemas (Plan 03-04).

Privacy: ``content_b64`` ONLY appears on the agent → server request path. Server
NEVER persists or logs raw content — see ScanService for the storage invariants.
The base64 wrapper exists so the HTTP layer is byte-safe (utf-8 content with
control characters or BOM survives JSON transport intact); the agent decodes
masked-then-base64-encoded bytes immediately before sending.

Locked decisions:
- D-02 one-pass protocol: agent ships content+hash in a single POST.
- schema_version=1 is the v0.2 baseline; bump on breaking changes so the agent
  can refuse mismatched servers and degrade to inventory-only mode.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from ccguard.schemas._base import SchemaBase


class ScannerConfig(SchemaBase):
    """GET /api/v1/scanner-config response.

    Agent calls this BEFORE collecting+sending content. ``enabled=false`` means
    skip the scan step entirely (no /scan-content POST). ``max_file_bytes`` is
    the server's hard cap per item — agents may collect larger files but the
    server will reject them with ``content_too_large``.
    """

    enabled: bool
    max_file_bytes: int = 1_048_576  # 1 MiB hard cap (per CONTEXT.md)
    schema_version: int = 1


class ScanRequestItem(SchemaBase):
    """One scannable artifact (agent or skill markdown), base64-encoded."""

    file_path: str
    scope: Literal["agent", "skill"]
    content_b64: str


class ScanRequest(SchemaBase):
    """POST /api/v1/scan-content body — batched per agent inventory cycle."""

    schema_version: int = 1
    items: list[ScanRequestItem] = Field(default_factory=list, max_length=50)


class ScanResponseItem(SchemaBase):
    """Per-item scan result. ``error`` set ⇒ all other fields may be None.

    Errors are surfaced per-item so one bad file never aborts the batch:
    - ``content_too_large`` — item exceeded ``max_file_bytes``; no LLM call made.
    - ``budget_exhausted`` — daily LLM budget was spent partway through batch.
    - ``scanner_disabled`` — server-wide scanner is off.
    - ``scanner_error`` — unexpected exception; details only in server logs.
    """

    file_path: str
    file_hash: str | None = None
    risk_score: int | None = None
    category: str | None = None
    severity: str | None = None
    cached: bool = False
    truncated: bool = False
    error: str | None = None


class ScanBatchResponse(SchemaBase):
    """POST /api/v1/scan-content response."""

    schema_version: int = 1
    items: list[ScanResponseItem] = Field(default_factory=list)
