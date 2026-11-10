"""Fail closed unless SUB_APP_DB names an existing, initialized SQLite database."""

from __future__ import annotations

import os
import sqlite3
import stat
import sys
from contextlib import closing
from pathlib import Path

REQUIRED_TABLES = {"friends", "nodes"}


def validate_database_path(raw_path: str | None, allow_empty: bool = False) -> Path:
    """Check the configured database without creating or modifying it."""

    if raw_path is None or not raw_path.strip():
        raise ValueError("SUB_APP_DB must be explicitly configured")

    configured_path = Path(raw_path)
    if not configured_path.is_absolute():
        raise ValueError("SUB_APP_DB must be an absolute path")

    database_path = configured_path.resolve(strict=True)
    if not database_path.is_file():
        raise ValueError("SUB_APP_DB must point to an existing regular file")
    if not _has_private_write_permission(database_path):
        raise PermissionError(
            "SUB_APP_DB must be writable by its owner and inaccessible to group/other"
        )
    if not _has_write_permission(database_path.parent):
        raise PermissionError("SUB_APP_DB parent directory must be writable")

    uri = f"{database_path.as_uri()}?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if REQUIRED_TABLES.issubset(tables) and not allow_empty:
                populated = any(
                    connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
                    for table in sorted(REQUIRED_TABLES)
                )
                if not populated:
                    raise ValueError(
                        "SUB_APP_DB has no application records; set "
                        "SUB_APP_ALLOW_EMPTY_DB=1 only for an intentional fresh install"
                    )
    except sqlite3.Error as exc:
        raise ValueError("SUB_APP_DB is not a readable SQLite database") from exc

    if not REQUIRED_TABLES.issubset(tables):
        raise ValueError("SUB_APP_DB is missing required application tables")
    return database_path


def _has_write_permission(path: Path) -> bool:
    mode = path.stat().st_mode
    return bool(mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)) and os.access(
        path, os.W_OK
    )


def _has_private_write_permission(path: Path) -> bool:
    mode = stat.S_IMODE(path.stat().st_mode)
    private_bits = stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP
    private_bits |= stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
    return bool(mode & stat.S_IWUSR) and not bool(mode & private_bits) and os.access(
        path, os.W_OK
    )


def main() -> int:
    try:
        validate_database_path(
            os.environ.get("SUB_APP_DB"),
            allow_empty=os.environ.get("SUB_APP_ALLOW_EMPTY_DB") == "1",
        )
    except (OSError, ValueError) as exc:
        print(f"sub-app database preflight failed: {exc}", file=sys.stderr)
        return 1

    print("sub-app database preflight ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
