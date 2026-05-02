"""AI-agent plan-read attestation helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping
from urllib.parse import quote, unquote


ATTESTATION_HEADER = "x-readtheplan-agent-read"
ATTESTATION_VERSION = "rtp-attest-v1"
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.:/@-]+$")


@dataclass(frozen=True)
class PlanReadAttestation:
    agent_id: str
    read_at: str
    plan_sha256: str
    source: str = "terraform-show-json"
    run_id: str | None = None
    signature: str | None = None

    def to_header_value(self) -> str:
        fields = {
            "agent": self.agent_id,
            "read_at": self.read_at,
            "plan_sha256": self.plan_sha256,
            "source": self.source,
        }
        if self.run_id:
            fields["run_id"] = self.run_id
        if self.signature:
            fields["sig"] = self.signature
        return serialize_attestation_fields(fields)


def plan_sha256(plan_json: str | bytes) -> str:
    payload = plan_json.encode("utf-8") if isinstance(plan_json, str) else plan_json
    return hashlib.sha256(payload).hexdigest()


def build_plan_read_attestation(
    *,
    agent_id: str,
    plan_json: str | bytes,
    read_at: datetime | None = None,
    source: str = "terraform-show-json",
    run_id: str | None = None,
    signature: str | None = None,
) -> PlanReadAttestation:
    timestamp = (read_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return PlanReadAttestation(
        agent_id=_validate_token("agent_id", agent_id),
        read_at=timestamp.isoformat().replace("+00:00", "Z"),
        plan_sha256=plan_sha256(plan_json),
        source=_validate_token("source", source),
        run_id=_validate_optional_token("run_id", run_id),
        signature=_validate_optional_token("signature", signature),
    )


def parse_attestation_header(value: str) -> PlanReadAttestation:
    fields = parse_attestation_fields(value)
    required = ("agent", "read_at", "plan_sha256", "source")
    missing = [name for name in required if not fields.get(name)]
    if missing:
        raise ValueError(f"attestation header missing required field(s): {', '.join(missing)}")

    digest = fields["plan_sha256"]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("attestation plan_sha256 must be a lowercase sha256 hex digest")

    return PlanReadAttestation(
        agent_id=_validate_token("agent", fields["agent"]),
        read_at=fields["read_at"],
        plan_sha256=digest,
        source=_validate_token("source", fields["source"]),
        run_id=_validate_optional_token("run_id", fields.get("run_id")),
        signature=_validate_optional_token("signature", fields.get("sig")),
    )


def serialize_attestation_fields(fields: Mapping[str, str]) -> str:
    parts = [ATTESTATION_VERSION]
    for key, value in fields.items():
        if not key or "=" in key or ";" in key:
            raise ValueError(f"invalid attestation field name: {key!r}")
        parts.append(f"{key}={quote(str(value), safe='._:/@-')}")
    return "; ".join(parts)


def parse_attestation_fields(value: str) -> dict[str, str]:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    if not parts or parts[0] != ATTESTATION_VERSION:
        raise ValueError(f"attestation header must start with {ATTESTATION_VERSION}")

    fields: dict[str, str] = {}
    for part in parts[1:]:
        if "=" not in part:
            raise ValueError(f"invalid attestation field: {part!r}")
        key, raw_value = part.split("=", 1)
        fields[key] = unquote(raw_value)
    return fields


def _validate_token(name: str, value: str) -> str:
    if not value or not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{name} must be a compact token")
    return value


def _validate_optional_token(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    return _validate_token(name, value)
