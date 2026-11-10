import sqlite3

import pytest

from scripts.check_existing_db import main, validate_database_path


def make_application_database(path):
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE friends (id INTEGER PRIMARY KEY)")
        connection.execute("CREATE TABLE nodes (id INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO friends DEFAULT VALUES")
    path.chmod(0o600)
    return path


def test_preflight_accepts_existing_writable_application_database(tmp_path):
    database = make_application_database(tmp_path / "app.db")

    assert validate_database_path(str(database)) == database


@pytest.mark.parametrize("value", [None, "", "  "])
def test_preflight_requires_explicit_database_path(value):
    with pytest.raises(ValueError, match="explicitly configured"):
        validate_database_path(value)


def test_preflight_command_exits_nonzero_without_database_env(monkeypatch, capsys):
    monkeypatch.delenv("SUB_APP_DB", raising=False)

    assert main() == 1
    assert "preflight failed" in capsys.readouterr().err


def test_preflight_requires_absolute_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="absolute path"):
        validate_database_path("app.db")


def test_preflight_rejects_missing_database(tmp_path):
    with pytest.raises(FileNotFoundError):
        validate_database_path(str(tmp_path / "missing.db"))


def test_preflight_rejects_directory(tmp_path):
    with pytest.raises(ValueError, match="regular file"):
        validate_database_path(str(tmp_path))


def test_preflight_rejects_empty_or_uninitialized_database(tmp_path):
    database = tmp_path / "empty.db"
    sqlite3.connect(database).close()
    database.chmod(0o600)

    with pytest.raises(ValueError, match="required application tables"):
        validate_database_path(str(database))


def test_preflight_requires_explicit_opt_in_for_initialized_empty_database(tmp_path):
    database = tmp_path / "fresh-empty.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE friends (id INTEGER PRIMARY KEY)")
        connection.execute("CREATE TABLE nodes (id INTEGER PRIMARY KEY)")
    database.chmod(0o600)

    with pytest.raises(ValueError, match="no application records"):
        validate_database_path(str(database))

    assert validate_database_path(str(database), allow_empty=True) == database


def test_preflight_rejects_non_sqlite_file(tmp_path):
    database = tmp_path / "not-a-database.db"
    database.write_text("not sqlite")
    database.chmod(0o600)

    with pytest.raises(ValueError, match="readable SQLite database"):
        validate_database_path(str(database))


def test_preflight_rejects_unwritable_database(tmp_path):
    database = make_application_database(tmp_path / "readonly.db")
    database.chmod(0o400)

    with pytest.raises(PermissionError, match="must be writable"):
        validate_database_path(str(database))


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o660, 0o666])
def test_preflight_rejects_database_readable_or_writable_by_group_or_other(
    tmp_path, mode
):
    database = make_application_database(tmp_path / f"unsafe-{mode:o}.db")
    database.chmod(mode)

    with pytest.raises(PermissionError, match="inaccessible to group/other"):
        validate_database_path(str(database))


def test_preflight_rejects_unwritable_parent_directory(tmp_path):
    directory = tmp_path / "readonly-dir"
    directory.mkdir()
    database = make_application_database(directory / "app.db")
    directory.chmod(0o500)

    with pytest.raises(PermissionError, match="parent directory must be writable"):
        validate_database_path(str(database))

    directory.chmod(0o700)
