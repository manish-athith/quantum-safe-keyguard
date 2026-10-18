"""Native liboqs proof for the complete protected API flow."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

pytest.importorskip("oqs")

from quantum_keyguard.detection.contracts import RiskAssessment
from quantum_keyguard.main import create_app


class NativeFlowLowRiskDetector:
    def score_session(self, _: object) -> RiskAssessment:
        return RiskAssessment(
            model_name="native-flow-test-detector",
            raw_score=0.05,
            risk_score=0.05,
            threshold=0.8,
            is_anomalous=False,
            signals=("behavior_within_learned_baseline",),
        )


def test_native_ml_dsa_and_ml_kem_through_authenticated_api(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "native-api.db",
        model_path=Path("unused.json"),
        detector=NativeFlowLowRiskDetector(),
    )
    app.state.services.auth.bootstrap_admin(
        "native_admin", "Native Admin", "native integration password"
    )

    with TestClient(app) as client:
        login = client.post(
            "/auth/login",
            json={
                "user_id": "native_admin",
                "password": "native integration password",
                "device_id": "linuxone_test",
            },
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        client.get("/keys", headers=headers)

        dsa = client.post(
            "/keys",
            headers=headers,
            json={"key_id": "native_dsa_key", "algorithm": "ML-DSA-65"},
        )
        assert dsa.json()["executed"] is True
        signed = client.post(
            "/keys/native_dsa_key/sign",
            headers=headers,
            json={"message": "linuxone native signing"},
        )
        signature = signed.json()["output"]["signature_b64"]
        verified = client.post(
            "/keys/native_dsa_key/verify",
            headers=headers,
            json={"message": "linuxone native signing", "signature_b64": signature},
        )
        assert verified.json()["output"]["valid"] is True

        kem = client.post(
            "/keys",
            headers=headers,
            json={"key_id": "native_kem_key", "algorithm": "ML-KEM-768"},
        )
        assert kem.json()["executed"] is True
        protected = client.post(
            "/keys/native_kem_key/protect",
            headers=headers,
            json={"plaintext": "sensitive demo value", "context": "judge-demo"},
        )
        assert protected.json()["executed"] is True
        assert protected.json()["output"]["roundtrip_verified"] is True
        assert "sensitive demo value" not in protected.text
