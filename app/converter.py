"""Parse node URIs into a normalised dict, and render them per client format."""

import base64
import json
from urllib.parse import parse_qs, unquote, urlparse

import yaml

SUPPORTED = ("vless", "vmess", "trojan", "hysteria2", "hy2", "ss")


def _b64pad(s):
    return s + "=" * (-len(s) % 4)


def parse_uri(uri):
    """Return a dict describing the node, or None if unsupported."""
    uri = uri.strip()
    if not uri or "://" not in uri:
        return None
    scheme = uri.split("://", 1)[0].lower()
    if scheme not in SUPPORTED:
        return None

    if scheme == "vmess":
        return _parse_vmess(uri)

    try:
        p = urlparse(uri)
        host = p.hostname or ""
        port = p.port or 0
    except ValueError:
        # urllib.parse intentionally defers malformed host/port errors until
        # hostname/port access. Treat malformed pasted rows as invalid input.
        return None
    if (
        not host.strip()
        or any(character.isspace() or ord(character) < 33 for character in host)
        or not 1 <= port <= 65535
    ):
        return None
    if scheme == "vless" and not (p.username or "").strip():
        return None
    q = {k: v[0] for k, v in parse_qs(p.query).items()}
    name = unquote(p.fragment) if p.fragment else ""

    node = {
        "scheme": "hysteria2" if scheme == "hy2" else scheme,
        "name": name,
        "host": host,
        "port": port,
        "user": unquote(p.username) if p.username else "",
        "password": unquote(p.password) if p.password else "",
        "params": q,
        "uri": uri,
    }
    return node


def _parse_vmess(uri):
    raw = uri.split("://", 1)[1]
    try:
        cfg = json.loads(base64.b64decode(_b64pad(raw)).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(cfg, dict):
        return None
    host = cfg.get("add")
    user = cfg.get("id")
    if not isinstance(host, str) or not host.strip():
        return None
    if not isinstance(user, str) or not user.strip():
        return None
    try:
        port = int(cfg.get("port", 0) or 0)
    except (TypeError, ValueError):
        return None
    if not 1 <= port <= 65535:
        return None
    return {
        "scheme": "vmess",
        "name": cfg.get("ps", ""),
        "host": host,
        "port": port,
        "user": user,
        "password": "",
        "params": cfg,
        "uri": uri,
    }


def _combined_auth(node):
    """Combine a `user:pass@` userinfo into the single token hysteria2/trojan
    clients expect as their auth/password.

    Per-user credentials render as `username:password@host` (see
    app/credentials.py `render_credential_uri`), so `node["user"]` alone is
    only half the value once urlparse splits on the `:`.  A base URI with a
    single token before `@` is unaffected: p.password is empty and this
    reduces to node["user"], same as before.
    """
    user = node["user"] or ""
    password = node["password"] or ""
    return f"{user}:{password}" if user and password else user or password


def to_clash_proxy(node):
    """Convert a parsed node into a mihomo/Clash.Meta proxy mapping."""
    s = node["scheme"]
    p = node["params"]
    name = node["name"] or f"{s}-{node['host']}:{node['port']}"

    if s == "hysteria2":
        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": node["host"],
            "port": node["port"],
            "password": _combined_auth(node),
        }
        if p.get("sni"):
            proxy["sni"] = p["sni"]
        if p.get("insecure") in ("1", "true"):
            proxy["skip-cert-verify"] = True
        if p.get("obfs"):
            proxy["obfs"] = p["obfs"]
            if p.get("obfs-password"):
                proxy["obfs-password"] = p["obfs-password"]
        return proxy

    if s == "vless":
        proxy = {
            "name": name,
            "type": "vless",
            "server": node["host"],
            "port": node["port"],
            "uuid": node["user"],
            "udp": True,
            "tls": p.get("security") in ("tls", "reality"),
            "network": p.get("type", "tcp"),
        }
        if p.get("flow"):
            proxy["flow"] = p["flow"]
        if p.get("sni"):
            proxy["servername"] = p["sni"]
        if p.get("security") == "reality":
            ro = {"public-key": p.get("pbk", "")}
            if p.get("sid"):
                ro["short-id"] = p["sid"]
            proxy["reality-opts"] = ro
            proxy["client-fingerprint"] = p.get("fp", "chrome")
        if p.get("type") == "ws":
            wo = {"path": p.get("path", "/")}
            if p.get("host"):
                wo["headers"] = {"Host": p["host"]}
            proxy["ws-opts"] = wo
        if p.get("type") == "grpc":
            proxy["grpc-opts"] = {"grpc-service-name": p.get("serviceName", "")}
        return proxy

    if s == "trojan":
        proxy = {
            "name": name,
            "type": "trojan",
            "server": node["host"],
            "port": node["port"],
            "password": _combined_auth(node),
            "udp": True,
        }
        if p.get("sni"):
            proxy["sni"] = p["sni"]
        return proxy

    if s == "vmess":
        proxy = {
            "name": name,
            "type": "vmess",
            "server": node["host"],
            "port": node["port"],
            "uuid": node["user"],
            "alterId": int(p.get("aid", 0) or 0),
            "cipher": p.get("scy", "auto"),
            "udp": True,
        }
        if p.get("tls") == "tls":
            proxy["tls"] = True
            if p.get("sni"):
                proxy["servername"] = p["sni"]
        if p.get("net") == "ws":
            wo = {"path": p.get("path", "/")}
            if p.get("host"):
                wo["headers"] = {"Host": p["host"]}
            proxy["ws-opts"] = wo
            proxy["network"] = "ws"
        return proxy

    if s == "ss":
        return {
            "name": name,
            "type": "ss",
            "server": node["host"],
            "port": node["port"],
            "cipher": p.get("cipher", "aes-256-gcm"),
            "password": node["password"] or node["user"],
            "udp": True,
        }

    return None


def render(uris, target):
    """Render a list of raw URIs into the requested subscription format."""
    target = (target or "v2ray").lower()

    # Shadowrocket imports the standard Base64 subscription form: one raw
    # node URI per line, wrapped in ordinary (non-URL-safe) Base64.
    if target in ("v2ray", "base64", "shadowrocket"):
        body = "\n".join(uris)
        return (
            base64.b64encode(body.encode("utf-8")).decode(),
            "text/plain; charset=utf-8",
        )

    if target == "raw":
        return "\n".join(uris), "text/plain; charset=utf-8"

    if target in ("clash", "clashmeta", "mihomo"):
        proxies = []
        for u in uris:
            node = parse_uri(u)
            if not node:
                continue
            proxy = to_clash_proxy(node)
            if proxy:
                proxies.append(proxy)

        names = [p["name"] for p in proxies]
        config = {
            "proxies": proxies,
            "proxy-groups": [
                {
                    "name": "🚀 节点选择",
                    "type": "select",
                    "proxies": ["♻️ 自动选择"] + names,
                },
                {
                    "name": "♻️ 自动选择",
                    "type": "url-test",
                    "proxies": names,
                    "url": "http://www.gstatic.com/generate_204",
                    "interval": 300,
                },
            ],
            "rules": ["MATCH,🚀 节点选择"],
        }
        text = yaml.safe_dump(config, allow_unicode=True, sort_keys=False)
        return text, "text/yaml; charset=utf-8"

    raise ValueError(f"unsupported target: {target}")
