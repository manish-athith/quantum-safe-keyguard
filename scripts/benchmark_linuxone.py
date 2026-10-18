"""Safe LinuxONE benchmark: timings only, never key or payload material."""

from __future__ import annotations

import json
import platform
import statistics
import tempfile
from pathlib import Path
from time import perf_counter

from quantum_keyguard.crypto.oqs_vault import OQSVault
from quantum_keyguard.domain.enums import Algorithm, PolicyEffect, Role
from quantum_keyguard.domain.policy import PolicyDecision
from quantum_keyguard.domain.records import KeyRecord, SessionRecord, UserRecord
from quantum_keyguard.persistence.audit_repository import AuditRepository
from quantum_keyguard.persistence.database import Database
from quantum_keyguard.persistence.state_repository import SecurityStateRepository
from quantum_keyguard.services.response_service import ContainmentRequest, ResponseService


def _milliseconds(started: float) -> float:
    return (perf_counter() - started) * 1_000.0


def _summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    p95_index = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95) - 1))
    return {
        "average_ms": round(statistics.fmean(values), 3),
        "p95_ms": round(ordered[p95_index], 3),
    }


def benchmark_crypto(rounds: int) -> dict[str, object]:
    with OQSVault() as vault:
        started = perf_counter()
        signing = vault.create_signature_key("benchmark-signing-key")
        signature_keygen_ms = _milliseconds(started)

        message = b"quantum-keyguard-linuxone-benchmark"
        sign_times: list[float] = []
        verify_times: list[float] = []
        for _ in range(rounds):
            started = perf_counter()
            signature = vault.sign(signing.key_id, message)
            sign_times.append(_milliseconds(started))
            started = perf_counter()
            assert vault.verify(signing.public_key, message, signature)
            verify_times.append(_milliseconds(started))

        started = perf_counter()
        kem = vault.create_kem_key("benchmark-kem-key")
        kem_keygen_ms = _milliseconds(started)
        kem_times: list[float] = []
        for _ in range(rounds):
            started = perf_counter()
            ciphertext, client_secret = vault.encapsulate(kem.public_key)
            server_secret = vault.decapsulate(kem.key_id, ciphertext)
            assert client_secret == server_secret
            kem_times.append(_milliseconds(started))

    return {
        "ml_dsa_65_keygen_ms": round(signature_keygen_ms, 3),
        "ml_dsa_65_sign": _summary(sign_times),
        "ml_dsa_65_verify": _summary(verify_times),
        "ml_kem_768_keygen_ms": round(kem_keygen_ms, 3),
        "ml_kem_768_roundtrip": _summary(kem_times),
    }


def benchmark_containment(rounds: int) -> dict[str, float]:
    with tempfile.TemporaryDirectory(prefix="keyguard-benchmark-") as directory:
        database = Database(Path(directory) / "containment.db")
        database.initialize()
        state = SecurityStateRepository(database)
        audit = AuditRepository(database)
        response = ResponseService(database, audit)
        state.save_user(
            UserRecord(
                user_id="benchmark_admin",
                display_name="Benchmark Admin",
                role=Role.KEY_ADMIN,
            )
        )
        decision = PolicyDecision(
            effect=PolicyEffect.CONTAIN,
            triggered_rules=("rule_private_export",),
            explanation="Benchmark containment operation.",
            risk_score=0.99,
        )
        times: list[float] = []
        for index in range(rounds):
            session_id = f"sess_benchmark_{index:03d}"
            key_id = f"benchmark-key-{index:03d}"
            state.save_session(
                SessionRecord(
                    session_id=session_id,
                    user_id="benchmark_admin",
                    device_id="benchmark_device",
                    source_ip="127.0.0.1",
                )
            )
            state.save_key(
                KeyRecord(
                    key_id=key_id,
                    algorithm=Algorithm.ML_KEM_768,
                    owner_role=Role.KEY_ADMIN,
                )
            )
            started = perf_counter()
            result = response.contain(
                ContainmentRequest(
                    correlation_id=f"corr_benchmark_{index:03d}",
                    session_id=session_id,
                    user_id="benchmark_admin",
                    role=Role.KEY_ADMIN,
                    source_ip="127.0.0.1",
                    device_id="benchmark_device",
                    key_id=key_id,
                ),
                decision,
            )
            times.append(_milliseconds(started))
            assert result.session_revoked and result.key_locked
        return _summary(times)


def main() -> None:
    rounds = 30
    print(
        json.dumps(
            {
                "platform": platform.machine(),
                "rounds": rounds,
                "cryptography": benchmark_crypto(rounds),
                "atomic_containment": benchmark_containment(rounds),
                "notes": (
                    "Software-backed liboqs timings; no private keys, shared secrets, "
                    "messages, tokens, or ciphertexts are printed."
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
