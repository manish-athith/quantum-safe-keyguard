"""End-to-end authenticated Phase 7 API flow without native-test dependencies."""

import hashlib
import hmac
from pathlib import Path

from fastapi.testclient import TestClient

from quantum_keyguard.crypto.oqs_vault import PublicKeyInfo, VaultError
from quantum_keyguard.detection.contracts import RiskAssessment
from quantum_keyguard.domain.enums import Algorithm, KeyStatus
from quantum_keyguard.main import create_app


class LowRiskDetector:
    def score_session(self, _: object) -> RiskAssessment:
        return RiskAssessment(
            model_name="phase7-test-detector",
            raw_score=0.05,
            risk_score=0.05,
            threshold=0.8,
            is_anomalous=False,
            signals=("behavior_within_learned_baseline",),
        )


class FakeVault:
    def __init__(self) -> None:
        self.entries: dict[str, tuple[Algorithm, KeyStatus, bytes]] = {}

    def create_signature_key(self, key_id: str) -> PublicKeyInfo:
        public = f"public:{key_id}".encode()
        self.entries[key_id] = (Algorithm.ML_DSA_65, KeyStatus.ACTIVE, public)
        return self.public_info(key_id)

    def create_kem_key(self, key_id: str) -> PublicKeyInfo:
        public = f"kem-public:{key_id}".encode()
        self.entries[key_id] = (Algorithm.ML_KEM_768, KeyStatus.ACTIVE, public)
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
        if entry.status is not KeyStatus.ACTIVE:
            raise VaultError("requested key is not active")
        return hmac.digest(entry.public_key, message, "sha256")

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(hmac.digest(public_key, message, "sha256"), signature)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        secret = hashlib.sha256(public_key).digest()
        return b"fake-kem-ciphertext", secret

    def decapsulate(self, key_id: str, _: bytes) -> bytes:
        return hashlib.sha256(self.public_info(key_id).public_key).digest()

    def lock_key(self, key_id: str) -> None:
        algorithm, _, public = self.entries[key_id]
        self.entries[key_id] = (algorithm, KeyStatus.LOCKED, public)

    def close(self) -> None:
        self.entries.clear()


def test_authenticated_crypto_and_containment_flow(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "api.db",
        model_path=Path("unused.json"),
        vault_factory=FakeVault,
        detector=LowRiskDetector(),
    )
    app.state.services.auth.bootstrap_admin(
        "security_admin", "Security Admin", "correct horse battery"
    )

    with TestClient(app) as client:
        assert client.get("/keys").status_code == 401
        login = client.post(
            "/auth/login",
            json={
                "user_id": "security_admin",
                "password": "correct horse battery",
                "device_id": "judge_laptop",
            },
        )
        assert login.status_code == 200
        token = login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        assert client.get("/keys", headers=headers).status_code == 200
        created = client.post(
            "/keys",
            headers=headers,
            json={"key_id": "judge_signing_key", "algorithm": "ML-DSA-65"},
        )
        assert created.status_code == 200
        assert created.json()["executed"] is True
        assert "private" not in created.text.lower()

        signed = client.post(
            "/keys/judge_signing_key/sign",
            headers=headers,
            json={"message": "approve rotation"},
        )
        assert signed.status_code == 200
        signature = signed.json()["output"]["signature_b64"]
        verified = client.post(
            "/keys/judge_signing_key/verify",
            headers=headers,
            json={"message": "approve rotation", "signature_b64": signature},
        )
        assert verified.json()["output"]["valid"] is True

        attack = client.post(
            "/demo/attempt",
            headers=headers,
            json={"action": "EXPORT_PRIVATE_KEY", "key_id": "judge_signing_key"},
        )
        assert attack.status_code == 200
        assert attack.json()["effect"] == "contain"
        assert attack.json()["executed"] is False
        assert attack.json()["containment"]["session_revoked"] is True
        assert client.get("/auth/me", headers=headers).status_code == 401
