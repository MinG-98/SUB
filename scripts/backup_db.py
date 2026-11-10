"""Create a verified, permission-restricted SQLite online backup."""

from __future__ import annotations

import os
import sqlite3
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

BACKUP_PREFIX = "sub-app-backup-"


def backup_database(
    source_path: str | Path,
    backup_dir: str | Path,
    retention_days: int = 30,
    now: datetime | None = None,
) -> dict:
    """Take a transactionally consistent backup, verify it, then atomically publish it."""

    if retention_days < 0:
        raise ValueError("retention_days cannot be negative")

    source = Path(source_path).expanduser()
    if not source.is_absolute():
        raise ValueError("SUB_APP_DB must be an absolute path")
    source = source.resolve(strict=True)
    if not source.is_file():
        raise FileNotFoundError("SQLite source database is not a regular file")

    directory = Path(backup_dir).expanduser()
    if not directory.is_absolute():
        raise ValueError("SUB_APP_BACKUP_DIR must be an absolute path")
    if directory.is_symlink():
        raise PermissionError("backup directory must not be a symlink")
    created_directory = not directory.exists()
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not directory.is_dir():
        raise NotADirectoryError("backup destination is not a directory")
    if created_directory:
        os.chmod(directory, 0o700)
    elif stat.S_IMODE(directory.stat().st_mode) & 0o077:
        raise PermissionError("existing backup directory must have mode 0700")

    moment = now or datetime.now(timezone.utc)
    stamp = moment.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination = directory / f"{BACKUP_PREFIX}{stamp}.sqlite3"
    temporary = directory / f".{destination.name}.{os.getpid()}.tmp"
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.close(fd)

    source_db = None
    backup_db = None
    try:
        source_uri = f"file:{quote(str(source), safe='/')}?mode=ro"
        source_db = sqlite3.connect(source_uri, uri=True, timeout=30)
        backup_db = sqlite3.connect(temporary, timeout=30)
        source_db.backup(backup_db, pages=256, sleep=0.1)
        check = backup_db.execute("PRAGMA quick_check").fetchone()
        if not check or check[0] != "ok":
            raise sqlite3.DatabaseError("backup integrity check failed")
    except Exception:
        if backup_db is not None:
            backup_db.close()
            backup_db = None
        if source_db is not None:
            source_db.close()
            source_db = None
        temporary.unlink(missing_ok=True)
        raise
    finally:
        if backup_db is not None:
            backup_db.close()
        if source_db is not None:
            source_db.close()

    os.chmod(temporary, 0o600)
    with temporary.open("rb") as handle:
        os.fsync(handle.fileno())
    if destination.exists():
        temporary.unlink(missing_ok=True)
        raise FileExistsError("backup destination already exists")
    os.replace(temporary, destination)

    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)

    removed = 0
    if retention_days > 0:
        cutoff = moment.timestamp() - timedelta(days=retention_days).total_seconds()
        for candidate in directory.glob(f"{BACKUP_PREFIX}*.sqlite3"):
            if (
                candidate == destination
                or candidate.is_symlink()
                or not candidate.is_file()
            ):
                continue
            try:
                if os.path.samefile(candidate, source):
                    continue
                if candidate.stat().st_mtime < cutoff:
                    candidate.unlink()
                    removed += 1
            except OSError:
                continue

    return {
        "path": destination,
        "bytes": destination.stat().st_size,
        "pruned": removed,
    }


def main() -> int:
    backup_dir = os.environ.get("SUB_APP_BACKUP_DIR", "/var/backups/sub-app")
    try:
        source = os.environ.get("SUB_APP_DB")
        if source is None or not source.strip():
            raise ValueError("SUB_APP_DB must be explicitly configured")
        if not Path(source).is_absolute():
            raise ValueError("SUB_APP_DB must be an absolute path")
        retention = int(os.environ.get("SUB_APP_BACKUP_RETENTION_DAYS", "30"))
        result = backup_database(source, backup_dir, retention_days=retention)
    except Exception as exc:
        print(f"sub-app backup failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(
        f"sub-app backup ok: {result['path'].name} "
        f"({result['bytes']} bytes), pruned={result['pruned']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
