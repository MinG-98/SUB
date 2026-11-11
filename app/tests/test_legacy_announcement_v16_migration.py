from sqlalchemy import create_engine

from app.models import migrate_database


def test_v16_migrates_legacy_placeholders_without_collisions_or_false_positives():
    engine = create_engine("sqlite://")
    legacy_prefix = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:"
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            conn.exec_driver_sql(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (15, 'test')"
            )
            conn.exec_driver_sql(
                "CREATE TABLE nodes ("
                "id INTEGER PRIMARY KEY, name TEXT NOT NULL, protocol TEXT NOT NULL, "
                "uri TEXT NOT NULL, server TEXT NOT NULL, adapter_kind TEXT NOT NULL, "
                "enabled BOOLEAN NOT NULL, sort_order INTEGER NOT NULL, "
                "is_announcement BOOLEAN NOT NULL, per_user_enabled BOOLEAN NOT NULL, "
                "created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)"
            )
            conn.exec_driver_sql(
                "CREATE TABLE announcements ("
                "id INTEGER PRIMARY KEY, legacy_node_id INTEGER UNIQUE, "
                "name TEXT NOT NULL, enabled BOOLEAN NOT NULL, sort_order INTEGER NOT NULL, "
                "created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)"
            )
            conn.exec_driver_sql("CREATE TABLE friends (id INTEGER PRIMARY KEY)")
            conn.exec_driver_sql(
                "CREATE TABLE allocations ("
                "id INTEGER PRIMARY KEY, friend_id INTEGER NOT NULL, "
                "node_id INTEGER NOT NULL, created_at DATETIME NOT NULL, "
                "UNIQUE(friend_id, node_id))"
            )
            conn.exec_driver_sql(
                "CREATE TABLE announcement_allocations ("
                "id INTEGER PRIMARY KEY, friend_id INTEGER NOT NULL, "
                "announcement_id INTEGER NOT NULL, created_at DATETIME NOT NULL, "
                "UNIQUE(friend_id, announcement_id))"
            )
            conn.exec_driver_sql(
                "INSERT INTO announcements "
                "(id, legacy_node_id, name, enabled, sort_order, created_at, updated_at) "
                "VALUES (1, 1, 'existing notice', 1, 0, '2026-01-01', '2026-01-01'), "
                "(2, NULL, 'independent notice', 1, 1, '2026-01-01', '2026-01-01')"
            )
            conn.exec_driver_sql(
                "INSERT INTO nodes "
                "(id, name, protocol, uri, server, adapter_kind, enabled, sort_order, "
                "is_announcement, per_user_enabled, created_at, updated_at) VALUES "
                "(1, 'old notice', 'vless', ?, '127.0.0.1', 'shared', 1, 0, 1, 0, "
                "'2026-01-01', '2026-01-01'), "
                "(2, 'port two placeholder', 'vless', ?, '127.0.0.1', 'remote_agent', 1, 2, 0, 1, "
                "'2026-01-01', '2026-01-01'), "
                "(3, 'port three placeholder', 'vless', ?, '127.0.0.1', 'remote_agent', 1, 3, 0, 1, "
                "'2026-01-01', '2026-01-01'), "
                "(4, 'port twenty control', 'vless', ?, '127.0.0.1', 'shared', 1, 4, 0, 0, "
                "'2026-01-01', '2026-01-01'), "
                "(5, 'real localhost control', 'vless', "
                "'vless://11111111-1111-1111-1111-111111111111@127.0.0.1:2', "
                "'127.0.0.1', 'shared', 1, 5, 0, 0, '2026-01-01', '2026-01-01'), "
                "(6, 'suffix control', 'vless', ?, '127.0.0.1', 'shared', 1, 6, 0, 0, "
                "'2026-01-01', '2026-01-01')",
                (
                    legacy_prefix + "1?encryption=none#legacy",
                    legacy_prefix + "2?encryption=none#notice",
                    legacy_prefix + "3#notice",
                    legacy_prefix + "20?encryption=none#not-port-two",
                    legacy_prefix + "3extra#not-port-three",
                ),
            )
            conn.exec_driver_sql("INSERT INTO friends(id) VALUES (7)")
            conn.exec_driver_sql(
                "INSERT INTO allocations(friend_id, node_id, created_at) VALUES "
                "(7, 1, '2026-01-03'), (7, 2, '2026-01-04'), (7, 3, '2026-01-05')"
            )
            conn.exec_driver_sql(
                "INSERT INTO announcement_allocations "
                "(friend_id, announcement_id, created_at) VALUES (7, 1, '2026-01-03')"
            )

        migrate_database(engine)
        migrate_database(engine)

        with engine.connect() as conn:
            node_flags = conn.exec_driver_sql(
                "SELECT id, is_announcement, adapter_kind, per_user_enabled "
                "FROM nodes ORDER BY id"
            ).all()
            assert node_flags == [
                (1, 1, "shared", 0),
                (2, 1, "shared", 0),
                (3, 1, "shared", 0),
                (4, 0, "shared", 0),
                (5, 0, "shared", 0),
                (6, 0, "shared", 0),
            ]
            announcements = conn.exec_driver_sql(
                "SELECT id, legacy_node_id, name FROM announcements "
                "WHERE legacy_node_id IS NOT NULL ORDER BY legacy_node_id"
            ).all()
            assert announcements == [
                (1, 1, "existing notice"),
                (3, 2, "port two placeholder"),
                (4, 3, "port three placeholder"),
            ]
            assert conn.exec_driver_sql(
                "SELECT id, name FROM announcements WHERE id=2"
            ).one() == (2, "independent notice")
            migrated_allocations = conn.exec_driver_sql(
                "SELECT friend_id, announcement_id FROM announcement_allocations "
                "ORDER BY announcement_id"
            ).all()
            assert migrated_allocations == [(7, 1), (7, 3), (7, 4)]
            versions = conn.exec_driver_sql(
                "SELECT MAX(version) FROM schema_migrations"
            ).scalar_one()
            assert versions == 16
    finally:
        engine.dispose()
