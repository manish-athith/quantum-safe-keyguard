"""Credential and opaque-session security tests."""

from pathlib import Path

import pytest

from quantum_keyguard.persistence.database import Database
from quantum_keyguard.security.passwords import token_digest
from quantum_keyguard.services.auth_service import (
    AuthenticationError,
    AuthService,
    BootstrapError,
)


def test_bootstrap_login_hashes_token_and_logout_revokes(tmp_path: Path) -> None:
    database = Database(tmp_path / "auth.db")
    database.initialize()
    service = AuthService(database)
    service.bootstrap_admin("admin_001", "Admin One", "correct horse battery")

    with pytest.raises(BootstrapError):
        service.bootstrap_admin("admin_002", "Admin Two", "another secure password")
    with pytest.raises(AuthenticationError):
        service.login("admin_001", "wrong password value", "device_001", "192.0.2.10")

    login = service.login(
        "admin_001", "correct horse battery", "device_001", "192.0.2.10"
    )
    assert service.authenticate(login.access_token).session_id == login.principal.session_id
    with database.connect() as connection:
        row = connection.execute("SELECT token_hash FROM session_tokens").fetchone()
    assert row["token_hash"] == token_digest(login.access_token)
    assert login.access_token not in row["token_hash"]

    service.logout(login.access_token)
    with pytest.raises(AuthenticationError):
        service.authenticate(login.access_token)
