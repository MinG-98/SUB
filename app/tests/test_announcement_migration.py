from sqlalchemy import create_engine

from app.models import migrate_database


def test_v14_migrates_only_known_announcement_rows_and_preserves_allocations():
    engine = create_engine("sqlite://")
    legacy_prefix = "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1"
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql(
                "CREATE TABLE schema_migrations "
                "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            conn.exec_driver_sql(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (13, 'test')"
            )
            conn.exec_driver_sql(
                "CREATE TABLE nodes ("
                "id INTEGER PRIMARY KEY, name TEXT NOT NULL, protocol TEXT NOT NULL, "
                "uri TEXT NOT NULL, server TEXT, enabled BOOLEAN NOT NULL, "
                "sort_order INTEGER NOT NULL, created_at DATETIME NOT NULL, "
                "updated_at DATETIME NOT NULL)"
            )
            conn.exec_driver_sql("CREATE TABLE friends (id INTEGER PRIMARY KEY)")
            conn.exec_driver_sql(
                "CREATE TABLE allocations ("
                "id INTEGER PRIMARY KEY, friend_id INTEGER NOT NULL, "
                "node_id INTEGER NOT NULL, created_at DATETIME NOT NULL, "
                "UNIQUE(friend_id, node_id))"
            )
            conn.exec_driver_sql(
                "INSERT INTO nodes(id, name, protocol, uri, server, enabled, "
                "sort_order, created_at, updated_at) VALUES "
                "(1, '订阅提示', 'vless', ?, '127.0.0.1', 1, 4, '2026-01-01', '2026-01-02'), "
                "(2, '真实本地节点', 'vless', "
                "'vless://11111111-1111-1111-1111-111111111111@127.0.0.1:1', "
                "'127.0.0.1', 1, 5, '2026-01-01', '2026-01-02')",
                (legacy_prefix + "?encryption=none#提示",),
            )
            conn.exec_driver_sql("INSERT INTO friends(id) VALUES (7)")
            conn.exec_driver_sql(
                "INSERT INTO allocations(friend_id, node_id, created_at) "
                "VALUES (7, 1, '2026-01-03')"
            )

        migrate_database(engine)
        migrate_database(engine)

        with engine.connect() as conn:
            rows = conn.exec_driver_sql(
                "SELECT id, is_announcement FROM nodes ORDER BY id"
            ).all()
            assert rows == [(1, 1), (2, 0)]
            announcement = conn.exec_driver_sql(
                "SELECT id, legacy_node_id, name, enabled, sort_order "
                "FROM announcements"
            ).one()
            assert announcement == (1, 1, "订阅提示", 1, 4)
            migrated = conn.exec_driver_sql(
                "SELECT friend_id, announcement_id FROM announcement_allocations"
            ).all()
            assert migrated == [(7, 1)]
            legacy = conn.exec_driver_sql(
                "SELECT friend_id, node_id FROM allocations"
            ).all()
            assert legacy == [(7, 1)]
    finally:
        engine.dispose()
