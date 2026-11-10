import pytest

from app.models import make_session_factory


def test_file_database_uses_wal_mode(tmp_path):
    session_factory = make_session_factory(tmp_path / "wal-check.db")
    engine = session_factory.kw["bind"]
    try:
        with engine.connect() as conn:
            mode = conn.exec_driver_sql("PRAGMA journal_mode").scalar_one()
        assert mode.lower() == "wal"
    finally:
        engine.dispose()


def test_relative_database_path_is_rejected_to_prevent_service_mismatch():
    with pytest.raises(ValueError, match="absolute path"):
        make_session_factory("relative-data.db")
