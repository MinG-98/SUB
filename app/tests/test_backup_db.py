import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone

import pytest

from scripts.backup_db import backup_database, main


def test_backup_uses_online_snapshot_and_protects_database(tmp_path):
    source = tmp_path / "source.db"
    connection = sqlite3.connect(source)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("CREATE TABLE records (value TEXT NOT NULL)")
        connection.execute("INSERT INTO records(value) VALUES ('committed in WAL')")
        connection.commit()

        result = backup_database(source, tmp_path / "private-backups")
        assert result["bytes"] > 0
        assert stat.S_IMODE(result["path"].stat().st_mode) == 0o600
        assert stat.S_IMODE(result["path"].parent.stat().st_mode) == 0o700

        restored = sqlite3.connect(result["path"])
        try:
            assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert restored.execute("SELECT value FROM records").fetchone()[0] == (
                "committed in WAL"
            )
        finally:
            restored.close()
    finally:
        connection.close()


def test_backup_refuses_insecure_existing_directory(tmp_path):
    source = tmp_path / "source.db"
    sqlite3.connect(source).close()
    backup_dir = tmp_path / "public-backups"
    backup_dir.mkdir()
    os.chmod(backup_dir, 0o755)

    with pytest.raises(PermissionError, match="mode 0700"):
        backup_database(source, backup_dir)


def test_backup_rejects_relative_database_and_backup_paths(tmp_path):
    source = tmp_path / "source.db"
    sqlite3.connect(source).close()
    backup_dir = tmp_path / "backups"

    with pytest.raises(ValueError, match="SUB_APP_DB must be an absolute path"):
        backup_database("relative.db", backup_dir)
    with pytest.raises(ValueError, match="SUB_APP_BACKUP_DIR must be an absolute path"):
        backup_database(source, "relative-backups")


@pytest.mark.parametrize(
    ("database_path", "error_message"),
    [
        (None, "SUB_APP_DB must be explicitly configured"),
        ("relative.db", "SUB_APP_DB must be an absolute path"),
    ],
)
def test_backup_command_requires_explicit_absolute_database_path(
    tmp_path, monkeypatch, capsys, database_path, error_message
):
    monkeypatch.delenv("SUB_APP_DB", raising=False)
    monkeypatch.setenv("SUB_APP_BACKUP_DIR", str(tmp_path / "backups"))
    if database_path is not None:
        monkeypatch.setenv("SUB_APP_DB", database_path)

    assert main() == 1
    assert error_message in capsys.readouterr().err


def test_backup_retention_only_removes_old_owned_snapshots(tmp_path):
    source = tmp_path / "source.db"
    sqlite3.connect(source).close()
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    old = backup_dir / "sub-app-backup-old.sqlite3"
    unrelated = backup_dir / "customer-backup-old.sqlite3"
    old.write_bytes(b"old backup")
    unrelated.write_bytes(b"unrelated")
    cutoff = datetime.now(timezone.utc) - timedelta(days=40)
    os.utime(old, (cutoff.timestamp(), cutoff.timestamp()))
    os.utime(unrelated, (cutoff.timestamp(), cutoff.timestamp()))

    result = backup_database(source, backup_dir, retention_days=30)

    assert result["pruned"] == 1
    assert not old.exists()
    assert unrelated.exists()


def test_backup_retention_never_deletes_source_inside_backup_directory(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    source = backup_dir / "sub-app-backup-20200101T000000.000000Z.sqlite3"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE records (value TEXT)")
    old = datetime.now(timezone.utc) - timedelta(days=60)
    os.utime(source, (old.timestamp(), old.timestamp()))

    result = backup_database(source, backup_dir, retention_days=30)

    assert source.exists()
    assert result["pruned"] == 0
    assert result["path"].exists()


def test_backup_reports_directory_fsync_failure_after_publish(tmp_path, monkeypatch):
    source = tmp_path / "source.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE records (value TEXT)")
    backup_dir = tmp_path / "backups"
    real_fsync = os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory fsync failed")
        return real_fsync(fd)

    monkeypatch.setattr("scripts.backup_db.os.fsync", fail_directory_fsync)

    with pytest.raises(OSError, match="directory fsync failed"):
        backup_database(source, backup_dir)

    published = list(backup_dir.glob("sub-app-backup-*.sqlite3"))
    assert len(published) == 1
    with sqlite3.connect(published[0]) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_backup_command_returns_failure_when_directory_fsync_fails(
    tmp_path, monkeypatch, capsys
):
    source = tmp_path / "source.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE records (value TEXT)")
    backup_dir = tmp_path / "backups"
    real_fsync = os.fsync

    def fail_directory_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("directory fsync failed")
        return real_fsync(fd)

    monkeypatch.setenv("SUB_APP_DB", str(source))
    monkeypatch.setenv("SUB_APP_BACKUP_DIR", str(backup_dir))
    monkeypatch.setattr("scripts.backup_db.os.fsync", fail_directory_fsync)

    assert main() == 1
    assert "sub-app backup failed: OSError" in capsys.readouterr().err
