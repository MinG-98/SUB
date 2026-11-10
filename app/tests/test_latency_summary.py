from app.latency import _summary


def test_unsupported_probes_are_excluded_from_checked_denominators():
    result = _summary(
        [
            {
                "entry": {"state": "ok", "ms": 120},
                "proxy": {"state": "unsupported"},
            },
            {
                "entry": {"state": "bad"},
                "proxy": {"state": "bad"},
            },
        ]
    )

    assert result == {
        "nodes_total": 2,
        "entry_total": 2,
        "entry_ok": 1,
        "proxy_total": 1,
        "proxy_ok": 0,
        "entry_avg_ms": 120,
        "proxy_avg_ms": None,
    }
