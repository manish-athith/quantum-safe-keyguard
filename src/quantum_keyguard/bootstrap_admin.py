"""One-time Security Admin bootstrap without exposing passwords in arguments."""

from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
from typing import Iterator

from quantum_keyguard.persistence.database import Database
from quantum_keyguard.services.auth_service import AuthService


def parse_args(arguments: Iterator[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=Path("runtime/keyguard.db"))
    parser.add_argument("--user-id", default="security_admin")
    parser.add_argument("--display-name", default="Security Admin")
    return parser.parse_args(arguments)


def main() -> None:
    arguments = parse_args()
    password = os.getenv("KEYGUARD_ADMIN_PASSWORD") or getpass.getpass(
        "Initial admin password (minimum 12 characters): "
    )
    database = Database(arguments.database)
    database.initialize()
    user = AuthService(database).bootstrap_admin(
        arguments.user_id, arguments.display_name, password
    )
    print(f"Bootstrapped {user.user_id} with role {user.role.value}.")


if __name__ == "__main__":
    main()
