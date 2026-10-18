"""Judge dashboard, safe snapshot, and containment visibility tests."""

import hashlib
import hmac
from pathlib import Path

from fastapi.testclient import TestClient

from quantum_keyguard.crypto.oqs_vault import PublicKeyInfo, VaultError
from quantum_keyguard.detection.contracts import RiskAssessment
from quantum_keyguard.domain.enums import Algorithm, KeyStatus
from quantum_keyguard.main import create_app


class DashboardDetector:
    model_name = "dashboard-contextual-lstm"
    threshold = 0.85

    def score_session(self, _: object) -> RiskAssessment:
        return RiskAssessment(
            model_name=self.model_name,
            raw_score=0.08,
            risk_score=0.08,
            threshold=self.threshold,
            is_anomalous=False,
            signals=("behavior_within_learned_baseline",),
        )


class DashboardVault:
    def __init__(self) -> None:
        self.entries: dict[str, tuple[Algorithm, KeyStatus, bytes]] = {}

    def create_signature_key(self, key_id: str) -> PublicKeyInfo:
        self.entries[key_id] = (
            Algorithm.ML_DSA_65,
            KeyStatus.ACTIVE,
            f"public:{key_id}".encode(),
        )
        return self.public_info(key_id)

    def create_kem_key(self, key_id: str) -> PublicKeyInfo:
        self.entries[key_id] = (
            Algorithm.ML_KEM_768,
            KeyStatus.ACTIVE,
            f"kem-public:{key_id}".encode(),
        )
        return self.public_info(key_id)

    def public_info(self, key_id: str) -> PublicKeyInfo:
        if key_id not in self.entries:
            raise VaultError("requested key is unavailable")
        algorithm, status, public = self.entries[key_id]
        return PublicKeyInfo(
            key_id=key_id, algorithm=algorithm, status=status, public_key=public
        )

    def sign(self, key_id: str, message: bytes) -> bytes:
        entry = self.public_info(key_id)
        return hmac.digest(entry.public_key, message, "sha256")

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(
            hmac.digest(public_key, message, "sha256"), signature
        )

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        return b"dashboard-ciphertext", hashlib.sha256(public_key).digest()

    def decapsulate(self, key_id: str, _: bytes) -> bytes:
        return hashlib.sha256(self.public_info(key_id).public_key).digest()

    def lock_key(self, key_id: str) -> None:
        algorithm, _, public = self.entries[key_id]
        self.entries[key_id] = (algorithm, KeyStatus.LOCKED, public)

    def close(self) -> None:
        self.entries.clear()


def _login(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/auth/login",
        json={
            "user_id": "security_admin",
            "password": "correct horse battery",
            "device_id": "judge_dashboard",
        },
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_dashboard_assets_are_local_and_hardened(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "dashboard-assets.db",
        model_path=Path("unused.json"),
        vault_factory=DashboardVault,
        detector=DashboardDetector(),
    )
    with TestClient(app) as client:
        page = client.get("/dashboard")
        assert page.status_code == 200
        assert "Quantum-Safe KeyGuard" in page.text
        assert "Content-Security-Policy" in page.headers
        script = client.get("/dashboard/assets/dashboard.js")
        assert script.status_code == 200
        assert "localStorage" not in script.text
        assert "sessionStorage" not in script.text
        assert client.get("/dashboard/snapshot").status_code == 401


def test_dashboard_shows_live_journey_and_containment(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "dashboard-flow.db",
        model_path=Path("unused.json"),
        vault_factory=DashboardVault,
        detector=DashboardDetector(),
    )
    app.state.services.auth.bootstrap_admin(
        "security_admin", "Security Admin", "correct horse battery"
    )

    with TestClient(app) as client:
        headers = _login(client)
        first = client.get("/dashboard/snapshot", headers=headers)
        assert first.status_code == 200
        assert first.json()["platform"]["model"] == "dashboard-contextual-lstm"
        assert first.json()["metrics"]["audited_events"] == 1

        sign_key = client.post(
            "/keys",
            headers=headers,
            json={"key_id": "dashboard-sign-key", "algorithm": "ML-DSA-65"},
        )
        assert sign_key.json()["executed"] is True
        kem_key = client.post(
            "/keys",
            headers=headers,
            json={"key_id": "dashboard-kem-key", "algorithm": "ML-KEM-768"},
        )
        assert kem_key.json()["executed"] is True

        snapshot = client.get("/dashboard/snapshot", headers=headers).json()
        assert snapshot["metrics"]["active_keys"] == 2
        assert any(event["action"] == "CREATE_KEY" for event in snapshot["events"])
        assert all("source_ip" not in event for event in snapshot["events"])

        attack = client.post(
            "/demo/attempt",
            headers=headers,
            json={
                "action": "EXPORT_PRIVATE_KEY",
                "key_id": "dashboard-kem-key",
                "algorithm": "ML-KEM-768",
            },
        )
        assert attack.json()["effect"] == "contain"
        assert client.get("/dashboard/snapshot", headers=headers).status_code == 401

        replacement_headers = _login(client)
        contained = client.get(
            "/dashboard/snapshot", headers=replacement_headers
        ).json()
        kem = next(
            key for key in contained["keys"] if key["key_id"] == "dashboard-kem-key"
        )
        assert kem["status"] == "locked"
        assert contained["metrics"]["critical_alerts"] == 1
        assert contained["metrics"]["revoked_sessions"] == 1
        assert contained["alerts"][0]["severity"] == "critical"
        actions = {event["action"] for event in contained["events"]}
        assert {"EXPORT_PRIVATE_KEY", "REVOKE_SESSION", "LOCK_KEY"} <= actions
