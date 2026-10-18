"""Shared validation helpers for security-sensitive domain records."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

Identifier = Annotated[
    str,
    Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]


def utc_now() -> datetime:
    """Return an aware UTC timestamp."""
    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    """Base model that rejects accidental or undocumented fields."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("*", mode="before")
    @classmethod
    def reject_empty_strings(cls, value: object) -> object:
        """Reject strings that become empty after trimming."""
        if isinstance(value, str) and not value.strip():
            raise ValueError("empty strings are not allowed")
        return value


def require_aware_utc(value: datetime) -> datetime:
    """Normalize an aware timestamp to UTC and reject ambiguous naive values."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(timezone.utc)


def normalize_ip(value: str) -> str:
    """Validate and canonicalize an IPv4 or IPv6 address."""
    return str(ip_address(value))

