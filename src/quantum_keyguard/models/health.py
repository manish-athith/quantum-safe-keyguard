"""Health-check data contracts."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Public liveness response."""

    status: str
    service: str

