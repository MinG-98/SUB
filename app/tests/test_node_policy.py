from types import SimpleNamespace

from app.node_policy import is_real_node


def test_legacy_localhost_notice_is_not_a_real_node():
    node = SimpleNamespace(
        name="使用前请更新订阅",
        server="127.0.0.1",
        uri="vless://uuid@127.0.0.1:1#notice",
        is_announcement=True,
    )

    assert is_real_node(node) is False


def test_normal_proxy_endpoint_is_a_real_node():
    node = SimpleNamespace(
        name="US-Hy2",
        server="example.com",
        uri="hysteria2://password@example.com:8443#hy2",
    )

    assert is_real_node(node) is True


def test_real_loopback_low_port_and_warning_name_are_not_guessed_as_announcements():
    node = SimpleNamespace(
        name="⚠️ 本地代理",
        server="127.0.0.1",
        uri="vless://uuid@127.0.0.1:1#local",
        is_announcement=False,
    )

    assert is_real_node(node) is True
