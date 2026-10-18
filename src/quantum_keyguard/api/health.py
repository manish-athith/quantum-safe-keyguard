"""Service health endpoint."""

from fastapi import APIRouter

from quantum_keyguard.models.health import HealthResponse

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Return a dependency-free liveness response."""
    return HealthResponse(status="ok", service="quantum-safe-keyguard")

