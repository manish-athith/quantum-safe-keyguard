"""Create a consistent, owner-only SQLite backup without stopping the service."""

from __future__ import annotations

import argparse
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", default="runtime/keyguard.db")
    parser.add_argument("--output-directory", default="runtime/backups")
    args = parser.parse_args()

    source = Path(args.database).resolve(strict=True)
    output_directory = Path(args.output_directory).resolve()
    output_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_directory, 0o700)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = output_directory / f"keyguard-{timestamp}.db"
    if destination.exists():
        raise FileExistsError(f"backup already exists: {destination}")

    with sqlite3.connect(source) as source_connection:
        with sqlite3.connect(destination) as destination_connection:
            source_connection.backup(destination_connection)
    os.chmod(destination, 0o600)
    print(destination)


if __name__ == "__main__":
    main()
