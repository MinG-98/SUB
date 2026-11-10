from sqlalchemy import create_engine

from app.models import migrate_database


def test_v4_adapter_migration_backfills_only_matching_existing_rows():
    engine = create_engine("sqlite://")
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            conn.exec_driver_sql(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (4, 'test')"
            )
            conn.exec_driver_sql(
                "CREATE TABLE nodes ("
                "id INTEGER PRIMARY KEY, name TEXT NOT NULL, protocol TEXT NOT NULL, "
                "uri TEXT NOT NULL, server TEXT, enabled BOOLEAN NOT NULL DEFAULT 1, "
                "sort_order INTEGER NOT NULL DEFAULT 0, nezha_server_id INTEGER, "
                "per_user_enabled BOOLEAN NOT NULL DEFAULT 0, created_at DATETIME NOT NULL)"
            )
            conn.exec_driver_sql(
                "INSERT INTO nodes(id, name, protocol, uri, created_at) VALUES "
                "(4, 'local-hy2', 'hysteria2', 'hy2://x', '2026-01-01'), "
                "(5, 'id-reused', 'hysteria2', 'hy2://y', '2026-01-01'), "
                "(6, 'remote-hy2', 'hysteria2', 'hy2://r', '2026-01-01'), "
                "(11, 'legacy-announcement', 'vless', "
                "'vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?encryption=none#notice', "
                "'2026-01-01'), "
                "(19, 'new-node', 'hysteria2', 'hy2://z', '2026-01-01')"
            )
            conn.exec_driver_sql("UPDATE nodes SET server='127.0.0.1' WHERE id=11")
            conn.exec_driver_sql(
                "CREATE TABLE node_agents ("
                "id INTEGER PRIMARY KEY, node_id INTEGER NOT NULL, token_hash TEXT NOT NULL, "
                "status TEXT NOT NULL DEFAULT 'pending', agent_version TEXT NOT NULL DEFAULT '', "
                "capabilities TEXT NOT NULL DEFAULT '{}', desired_generation TEXT NOT NULL DEFAULT '', "
                "applied_generation TEXT NOT NULL DEFAULT '', last_seen DATETIME, "
                "last_error TEXT NOT NULL DEFAULT '', created_at DATETIME NOT NULL, "
                "updated_at DATETIME NOT NULL)"
            )
            conn.exec_driver_sql(
                "CREATE TABLE fetch_logs ("
                "id INTEGER PRIMARY KEY, target VARCHAR(32), created_at DATETIME)"
            )
            conn.exec_driver_sql(
                "INSERT INTO fetch_logs(id, target, created_at) "
                "VALUES (1, 'raw', '2026-01-01')"
            )

        migrate_database(engine)
        migrate_database(engine)
        with engine.connect() as conn:
            rows = dict(
                conn.exec_driver_sql("SELECT id, adapter_kind FROM nodes").all()
            )
            assert rows == {
                4: "local_hy2",
                5: "shared",
                6: "remote_agent",
                11: "shared",
                19: "shared",
            }
            announcement = conn.exec_driver_sql(
                "SELECT is_announcement, per_user_enabled FROM nodes WHERE id=11"
            ).one()
            assert announcement == (1, 0)
            # The migrated tombstone must not retain the unique local-VLESS slot.
            conn.exec_driver_sql(
                "UPDATE nodes SET protocol='vless', uri='vless://new@host:443' "
                "WHERE id=19"
            )
            conn.exec_driver_sql(
                "UPDATE nodes SET adapter_kind='local_vless' WHERE id=19"
            )
            versions = conn.exec_driver_sql(
                "SELECT MAX(version) FROM schema_migrations"
            ).scalar_one()
            assert versions == 15
            node_columns = {
                row[1] for row in conn.exec_driver_sql("PRAGMA table_info(nodes)")
            }
            assert {"expires_at", "updated_at", "is_announcement"} <= node_columns
            tables = {
                row[0]
                for row in conn.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            fetch_log_columns = (
                {
                    row[1]
                    for row in conn.exec_driver_sql("PRAGMA table_info(fetch_logs)")
                }
                if "fetch_logs" in tables
                else set()
            )
            if "fetch_logs" in tables:
                assert {
                    "shared_fallback_count",
                    "skipped_node_count",
                    "expired_node_count",
                } <= fetch_log_columns
                assert (
                    conn.exec_driver_sql(
                        "SELECT skipped_node_count FROM fetch_logs WHERE id=1"
                    ).scalar_one()
                    == 0
                )
            agent_columns = {
                row[1] for row in conn.exec_driver_sql("PRAGMA table_info(node_agents)")
            }
            assert {
                "pending_token_hash",
                "pending_token_expires_at",
                "pending_token_last_seen",
            } <= agent_columns
            assert {
                "admin_login_throttles",
                "admin_audit_logs",
                "admin_sessions",
                "admin_auth_state",
                "announcements",
                "announcement_allocations",
            } <= tables
            triggers = {
                row[0]
                for row in conn.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
            assert {
                "admin_audit_logs_no_update",
                "admin_audit_logs_no_delete",
            } <= triggers
    finally:
        engine.dispose()
