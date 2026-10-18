"""Tests for the service entry point."""

from fastapi.testclient import TestClient

from quantum_keyguard.main import app


def test_health_check() -> None:
    """The application exposes a stable liveness contract."""
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "quantum-safe-keyguard",
    }

