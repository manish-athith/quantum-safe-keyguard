"""Static release assertions that protect judge-facing security claims."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_release_artifacts_and_hardening_contract() -> None:
    required = (
        "Architecture.md",
        "Decision.md",
        "flow.md",
        "Rules.md",
        "phases.md",
        "Project_FAQ.md",
        "Judge_Demo.md",
        "deploy/quantum-keyguard.service",
        "evidence/linuxone_metrics.json",
    )
    for name in required:
        assert (ROOT / name).is_file(), name

    unit = (ROOT / "deploy/quantum-keyguard.service").read_text(encoding="utf-8")
    assert "User=linux1" in unit
    assert "--host 127.0.0.1" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=" in unit
    assert "UMask=0077" in unit

    page = (ROOT / "src/quantum_keyguard/web/dashboard.html").read_text(
        encoding="utf-8"
    )
    script = (ROOT / "src/quantum_keyguard/web/dashboard.js").read_text(
        encoding="utf-8"
    )
    assert "https://" not in page and "http://" not in page
    assert "localStorage" not in script and "sessionStorage" not in script
    assert "bearerToken" in script

    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "*.pem" in ignored and "*.key" in ignored and "*.db" in ignored


def test_linuxone_evidence_has_claim_boundaries() -> None:
    evidence = json.loads(
        (ROOT / "evidence/linuxone_metrics.json").read_text(encoding="utf-8")
    )
    assert evidence["environment"]["architecture"] == "s390x"
    assert evidence["verification"]["health_status"] == "ok"
    assert evidence["synthetic_model_evaluation"]["dataset_sessions"] == 30_000
    assert "not a production accuracy claim" in evidence[
        "synthetic_model_evaluation"
    ]["limitation"]
    not_claimed = set(evidence["claims_boundary"]["not_claimed"])
    assert {"Crypto Express", "HSM-backed keys"} <= not_claimed
