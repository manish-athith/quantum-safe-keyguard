"""Operational restart behavior for the process-memory vault boundary."""

from pathlib import Path

from fastapi.testclient import TestClient

from quantum_keyguard.main import create_app

from test_phase8_dashboard import DashboardDetector, DashboardVault


def _login(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/auth/login",
        json={
            "user_id": "security_admin",
            "password": "correct horse battery",
            "device_id": "restart_test",
        },
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_restart_retires_key_whose_private_material_was_ephemeral(
    tmp_path: Path,
) -> None:
    database = tmp_path / "restart.db"
    first_app = create_app(
        database_path=database,
        model_path=Path("unused.json"),
        vault_factory=DashboardVault,
        detector=DashboardDetector(),
    )
    first_app.state.services.auth.bootstrap_admin(
        "security_admin", "Security Admin", "correct horse battery"
    )
    with TestClient(first_app) as client:
        headers = _login(client)
        created = client.post(
            "/keys",
            headers=headers,
            json={"key_id": "ephemeral-key", "algorithm": "ML-DSA-65"},
        )
        assert created.json()["executed"] is True

    second_app = create_app(
        database_path=database,
        model_path=Path("unused.json"),
        vault_factory=DashboardVault,
        detector=DashboardDetector(),
    )
    assert second_app.state.services.retired_ephemeral_keys == 1
    with TestClient(second_app) as client:
        headers = _login(client)
        snapshot = client.get("/dashboard/snapshot", headers=headers).json()
        key = next(item for item in snapshot["keys"] if item["key_id"] == "ephemeral-key")
        assert key["status"] == "revoked"
        assert snapshot["platform"]["retired_keys_on_startup"] == 1
