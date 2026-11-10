from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_uvicorn_reference_launches_do_not_log_subscription_paths():
    service = (ROOT / "deploy/systemd/sub-app.service").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "--no-access-log" in service
    assert "uvicorn app.main:app --host 127.0.0.1 --port 8080 --no-access-log" in readme


def test_root_backup_unit_uses_configured_database_and_existing_script():
    service_path = ROOT / "deploy/systemd/sub-app-backup-root.service"
    service = service_path.read_text(encoding="utf-8")

    assert "EnvironmentFile=/etc/sub-app/app.env" in service
    assert "Environment=SUB_APP_DB=" not in service
    assert "ExecStart=/usr/bin/python3 /opt/sub-app/scripts/backup_db.py" in service
    assert (ROOT / "scripts/backup_db.py").is_file()
    assert "CapabilityBoundingSet=CAP_DAC_READ_SEARCH" in service
    assert "AmbientCapabilities=CAP_DAC_READ_SEARCH" in service
    assert "NoNewPrivileges=yes" in service
