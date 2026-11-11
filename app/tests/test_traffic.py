from datetime import datetime, timedelta, timezone

from sqlalchemy import select

import app.traffic as traffic
from app.models import (
    CollectorRun,
    Device,
    FetchLog,
    Friend,
    Node,
    NodeMetricSample,
    make_session_factory,
)


def test_naive_utc_converts_offset_aware_values_to_utc():
    value = datetime(2026, 8, 20, 23, 35, tzinfo=timezone(timedelta(hours=8)))

    assert traffic._naive_utc(value) == datetime(2026, 8, 20, 15, 35)


def test_stale_nezha_last_active_overrides_nonempty_state():
    stale = datetime.now(timezone.utc) - timedelta(days=35)

    result = traffic.normalize_server(
        {
            "id": 13,
            "last_active": stale,
            "state": {"cpu": 0.25},
        }
    )

    assert result["online"] is False
    assert result["last_active"] == stale


def test_explicit_nezha_online_value_takes_precedence_over_old_timestamp():
    stale = datetime.now(timezone.utc) - timedelta(days=35)

    result = traffic.normalize_server(
        {
            "id": 13,
            "online": True,
            "last_active": stale,
            "state": {"cpu": 0.25},
        }
    )

    assert result["online"] is True


def test_collector_records_actual_finish_time(tmp_path, monkeypatch):
    db = make_session_factory(str(tmp_path / "collector.db"))()
    try:
        db.add(
            Node(
                name="US-Hy2",
                protocol="hysteria2",
                uri="hysteria2://password@example.com:8443#hy2",
                server="example.com",
                nezha_server_id=7,
            )
        )
        db.commit()
        monkeypatch.setattr(
            traffic,
            "fetch_servers",
            lambda _base, _token: [
                {
                    "id": 7,
                    "name": "US-Hy2",
                    "online": True,
                    "last_active": datetime.now(timezone.utc),
                    "net_in_transfer": 10,
                    "net_out_transfer": 20,
                    "net_in_speed": 0,
                    "net_out_speed": 0,
                }
            ],
        )
        monkeypatch.setenv("NEZHA_API_TOKEN", "test-token")
        started = datetime.now(timezone.utc) - timedelta(seconds=1)

        result = traffic.run_collector(db, now=started)

        run = db.scalar(
            select(CollectorRun)
            .where(CollectorRun.source == "nezha")
            .order_by(CollectorRun.id.desc())
        )
        sample = db.scalar(select(NodeMetricSample))
        assert result["status"] == "success"
        assert run.finished_at is not None
        assert run.finished_at > run.started_at
        assert sample.collected_at == run.finished_at
    finally:
        db.close()


def test_collector_prunes_old_fetch_logs_but_preserves_device_history(
    tmp_path, monkeypatch
):
    db = make_session_factory(str(tmp_path / "retention.db"))()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        friend = Friend(uid="retention-user", token="retention-token")
        db.add(friend)
        db.flush()
        old_device = Device(
            friend_id=friend.id,
            fingerprint="old-device",
            first_seen=now - timedelta(days=240),
            last_seen=now - timedelta(days=200),
        )
        old_log = FetchLog(
            friend_id=friend.id,
            device_id=None,
            created_at=now - timedelta(days=100),
        )
        recent_log = FetchLog(
            friend_id=friend.id,
            device_id=None,
            created_at=now - timedelta(days=10),
        )
        db.add_all([old_device, old_log, recent_log])
        db.commit()

        monkeypatch.setattr(traffic, "fetch_servers", lambda _base, _token: [])
        monkeypatch.setenv("NEZHA_API_TOKEN", "test-token")
        result = traffic.run_collector(
            db,
            now=now,
            fetch_log_retention_days=90,
        )

        assert result["status"] == "success"
        assert db.get(FetchLog, old_log.id) is None
        assert db.get(FetchLog, recent_log.id) is not None
        assert db.get(Device, old_device.id) is not None
    finally:
        db.close()


def test_fetch_log_retention_is_committed_when_nezha_fetch_fails(tmp_path, monkeypatch):
    db = make_session_factory(str(tmp_path / "retention-failure.db"))()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        friend = Friend(uid="retention-failure", token="retention-failure-token")
        db.add(friend)
        db.flush()
        old_log = FetchLog(
            friend_id=friend.id,
            device_id=None,
            created_at=now - timedelta(days=100),
        )
        db.add(old_log)
        db.commit()
        monkeypatch.setattr(
            traffic,
            "fetch_servers",
            lambda _base, _token: (_ for _ in ()).throw(
                traffic.CollectorError("Nezha unavailable")
            ),
        )
        monkeypatch.setenv("NEZHA_API_TOKEN", "test-token")

        try:
            traffic.run_collector(db, now=now, fetch_log_retention_days=90)
        except traffic.CollectorError:
            pass
        else:
            raise AssertionError("collector should surface the upstream failure")

        assert db.get(FetchLog, old_log.id) is None
    finally:
        db.close()
