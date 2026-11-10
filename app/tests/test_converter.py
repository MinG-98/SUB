"""Regression test for the Clash/mihomo auth-truncation bug.

Per-user hysteria2/trojan credentials render as `username:password@host`
(see app/credentials.py `render_credential_uri`). `to_clash_proxy` used to
emit only `node["user"]` as the password, silently dropping the password
half whenever a URI carried both — every per-user hysteria2 subscriber's
Clash config had a truncated auth string while their v2ray/raw config was
fine, so it hid the moment anyone checked the wrong client.
"""

import base64

import yaml

from app.converter import parse_uri, render, to_clash_proxy, uri_with_name


def test_hysteria2_per_user_uri_keeps_full_auth():
    uri = "hysteria2://alice-n4-v1:SuperSecretPass99@node.example.test:8443"
    node = parse_uri(uri)
    proxy = to_clash_proxy(node)
    assert proxy["password"] == "alice-n4-v1:SuperSecretPass99"


def test_hysteria2_base_uri_unaffected():
    uri = "hysteria2://sharedpass@node.example.test:8443"
    node = parse_uri(uri)
    proxy = to_clash_proxy(node)
    assert proxy["password"] == "sharedpass"


def test_trojan_user_pass_uri_keeps_full_auth():
    uri = "trojan://tuser:tpass@node.example.test:443"
    node = parse_uri(uri)
    proxy = to_clash_proxy(node)
    assert proxy["password"] == "tuser:tpass"


def test_trojan_base_uri_unaffected():
    uri = "trojan://onlypass@node.example.test:443"
    node = parse_uri(uri)
    proxy = to_clash_proxy(node)
    assert proxy["password"] == "onlypass"


def test_clash_render_end_to_end():
    uri = "hysteria2://alice-n4-v1:SuperSecretPass99@node.example.test:8443"
    body, content_type = render([uri], "clash")
    assert content_type.startswith("text/yaml")
    proxy = yaml.safe_load(body)["proxies"][0]
    assert proxy["password"] == "alice-n4-v1:SuperSecretPass99"


def test_raw_and_v2ray_pass_uri_through_untouched():
    uri = "hysteria2://alice-n4-v1:SuperSecretPass99@node.example.test:8443"
    raw, _ = render([uri], "raw")
    assert raw.strip() == uri


def test_shadowrocket_render_is_base64_uri_subscription():
    uri = "hysteria2://alice-n4-v1:SuperSecretPass99@node.example.test:8443"
    body, content_type = render([uri], "shadowrocket")

    assert content_type.startswith("text/plain")
    assert base64.b64decode(body).decode("utf-8") == uri


def test_managed_node_name_replaces_missing_or_old_fragment():
    name = "14｜🇸🇬 新加坡 Reality"
    uri = "vless://uuid@example.com:443?security=reality#old-name"
    rendered = uri_with_name(uri, name)
    assert parse_uri(rendered)["name"] == name
    assert parse_uri(uri_with_name(uri.split("#")[0], name))["name"] == name


def test_invalid_ports_and_malformed_authority_are_rejected_without_raising():
    assert parse_uri("hysteria2://shared@node.example.test:70000") is None
    assert parse_uri("vless://id@[2001:db8::1:443") is None
    assert parse_uri("vless://id@:443") is None
    assert (
        parse_uri("vmess://eyJhZGQiOiJub2RlIiwiYWRkIjoibm9kZSIsInBvcnQiOiI3MDAwMCJ9")
        is None
    )


def test_vmess_non_object_payload_is_rejected_without_raising():
    assert parse_uri("vmess://W10=") is None
