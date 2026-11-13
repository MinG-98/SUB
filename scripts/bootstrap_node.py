#!/usr/bin/env python3
"""Provision one NEW standalone HY2 node using the existing SUB admin API."""

import argparse
import getpass
import http.cookiejar
import ipaddress
import json
import re
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode

ROOT = Path(__file__).resolve().parents[1]
CENTER = "https://sub.m1n6.uk"
REGIONS = {
    "DE": "🇩🇪 德国",
    "HK": "🇭🇰 香港",
    "JP": "🇯🇵 日本",
    "KR": "🇰🇷 韩国",
    "MY": "🇲🇾 马来西亚",
    "SG": "🇸🇬 新加坡",
    "US": "🇺🇸 美国",
}


def hostname(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        pass
    if len(value) > 253 or not all(
        re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", p)
        for p in value.split(".")
    ):
        raise argparse.ArgumentTypeError("需要 IPv4 或 DNS 名")
    return value.lower()


def port(value):
    n = int(value)
    if not 1 <= n <= 65535:
        raise argparse.ArgumentTypeError("端口范围 1..65535")
    return n


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Center:
    def __init__(self):
        self.http = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )

    def __call__(self, method, path, data=None):
        req = urllib.request.Request(
            CENTER + path,
            method=method,
            data=None if data is None else json.dumps(data).encode(),
            headers={"Content-Type": "application/json", "Cache-Control": "no-store"},
        )
        with self.http.open(req, timeout=20) as r:
            return json.load(r)


def remote(a, action, **extra):
    worker = (ROOT / "deploy/bootstrap_worker.py").read_text()
    command = "/usr/bin/python3 -I -c " + shlex.quote(worker)
    cfg = dict(
        action=action,
        center=CENTER,
        listen_port=a.listen_port,
        sni=a.sni,
        cert=a.cert,
        key=a.key,
        acme_email=a.acme_email,
        **extra,
    )
    subprocess.run(
        [
            "ssh",
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ConnectTimeout=10",
            "-p",
            str(a.ssh_port),
            "-i",
            str(a.identity),
            "root@" + a.ssh_host,
            command,
        ],
        input=json.dumps(cfg).encode(),
        check=True,
        timeout=660,
    )


def canonical_hy2_name(nodes, region):
    """Number new nodes globally and keep one stable region/protocol label."""
    used = set()
    for node in nodes:
        match = re.match(r"^(\d{2})｜", str(node.get("name") or ""))
        if match:
            used.add(int(match.group(1)))
    number = max(used, default=0) + 1
    if number > 99:
        raise RuntimeError("节点编号已超过 99，请先整理现有编号")
    return f"{number:02d}｜{REGIONS[region]} Hy2"


def wait_ready(api, node_id, previous=None, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        row = api("GET", f"/api/admin/agents/{node_id}")
        wanted = row.get("desired_generation")
        if row.get("last_seen"):
            seen = datetime.fromisoformat(row["last_seen"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - seen).total_seconds()
            if (
                0 <= age < 90
                and row.get("status") == "ready"
                and wanted
                and wanted != previous
                and wanted == row.get("applied_generation")
            ):
                return wanted
        time.sleep(2)
    raise RuntimeError("未收到新鲜且版本匹配的 Agent 心跳")


def canary(client, a, password):
    with tempfile.TemporaryDirectory(prefix="sub-client-") as d:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            proxy = f"127.0.0.1:{s.getsockname()[1]}"
        config = Path(d) / "client.yaml"
        config.touch(mode=0o600)
        config.write_text(
            json.dumps(
                {
                    "server": f"{a.public_host}:{a.public_port}",
                    "auth": password,
                    "tls": {"sni": a.sni},
                    "socks5": {"listen": proxy},
                }
            )
        )
        proc = subprocess.Popen(
            [str(client), "client", "-c", str(config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for _ in range(4):
                time.sleep(1)
                if proc.poll() is not None:
                    break
                if (
                    subprocess.run(
                        [
                            "curl",
                            "-q",
                            "--silent",
                            "--fail",
                            "--output",
                            "/dev/null",
                            "--max-time",
                            "8",
                            "--noproxy",
                            "",
                            "--proxy",
                            "socks5h://" + proxy,
                            "https://example.com/",
                        ]
                    ).returncode
                    == 0
                    and proc.poll() is None
                ):
                    return
            raise RuntimeError("公网 Hy2 握手/代理 HTTPS 请求未通过")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def provision(a, api):
    path = "/api/admin/nodes"
    nodes = api("GET", path)
    a.name = canonical_hy2_name(nodes, a.region)
    print(f"规范节点名：{a.name}", flush=True)
    if any(
        n["name"] == a.name
        or (
            n["protocol"] == "hysteria2"
            and n["server"].lower() == a.public_host
            and n["port"] == a.public_port
        )
        for n in nodes
    ):
        raise RuntimeError("中心已有同名或同 Hy2 端点节点；不会重复创建或接管")
    password = secrets.token_urlsafe(32)
    marker = "bootstrap-" + secrets.token_hex(12)
    uri = (
        f"hysteria2://{password}@{a.public_host}:{a.public_port}?"
        + urlencode({"sni": a.sni})
        + "#"
        + quote(a.name, safe="")
    )
    node_id = None
    installing = False
    try:
        print(f"新建记录的临时名称：{marker}", flush=True)
        result = api("POST", path, {"name": marker, "uri": uri})
        if result.get("created") != [marker]:
            raise RuntimeError("未创建唯一的新记录")
        rows = [
            n
            for n in api("GET", path)
            if n["name"] == marker
            and n["protocol"] == "hysteria2"
            and n["server"] == a.public_host
            and n["port"] == a.public_port
            and n["allocated_to"] == 0
        ]
        if len(rows) != 1:
            raise RuntimeError("不能唯一确认新记录；请按临时名称核对，不要重试")
        node_id = rows[0]["id"]
        node = f"{path}/{node_id}"
        print(f"新节点 ID：{node_id}；仅操作此记录", flush=True)
        api(
            "PATCH",
            node,
            {"enabled": False, "adapter_kind": "remote_agent", "name": a.name},
        )
        token = api("POST", "/api/admin/agents", {"node_id": node_id})["token"]
        installing = True
        remote(
            a,
            "install",
            owner=marker,
            node_id=node_id,
            token=token,
            source=(ROOT / "agent/node-agent.py").read_text(),
        )
        denied = wait_ready(api, node_id)
        api("PATCH", node, {"enabled": True})
        wait_ready(api, node_id, previous=denied)
        remote(a, "verify-owned", owner=marker, password=password)
        if a.client:
            canary(a.client, a, password)
        print(
            f"节点 {node_id} 已接入，配置版本匹配，未分配用户。"
            + (" 公网 Hy2 代理出口已验证。" if a.client else " 公网代理出口尚未验证。")
        )
    except BaseException:
        if node_id is not None:
            try:
                api("PATCH", f"{path}/{node_id}", {"enabled": False})
                print(
                    f"失败保护：中心已停用新节点 {node_id}；并非远端停机证明。",
                    file=sys.stderr,
                )
            except Exception:
                print(f"中心停用未确认；请手动检查新节点 {node_id}。", file=sys.stderr)
        if installing:
            try:
                remote(a, "stop-owned", owner=marker)
            except Exception:
                print(
                    "未确认远端两项服务已停止，请按手册检查；未强制清理。",
                    file=sys.stderr,
                )
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ssh-host", required=True, type=hostname)
    p.add_argument("--ssh-port", type=port, default=22)
    p.add_argument("--identity", type=Path, required=True)
    p.add_argument("--public-host", required=True, type=hostname)
    p.add_argument("--public-port", required=True, type=port)
    p.add_argument("--listen-port", required=True, type=port)
    p.add_argument("--sni", required=True, type=hostname)
    p.add_argument("--cert", help="目标机上 /etc 下的完整证书链")
    p.add_argument("--key", help="目标机上 /etc 下的 TLS 私钥路径")
    p.add_argument(
        "--acme-email", help="新域名自动签证书；公网 TCP 80 必须映射至机内 80"
    )
    p.add_argument("--region", choices=sorted(REGIONS), required=True)
    p.add_argument(
        "--client", type=Path, help="管理机已安装的 Hy2 客户端，用于外部拨测"
    )
    p.add_argument("--apply", action="store_true", help="默认仅只读预检")
    a = p.parse_args()
    if (
        a.acme_email
        and (a.cert or a.key)
        or not a.acme_email
        and not (a.cert and a.key)
    ):
        p.error("使用 --acme-email 或同时指定 --cert 和 --key，不能混用")
    if not a.identity.is_file() or any(
        not x.startswith("/etc/") or ".." in Path(x).parts for x in (a.cert, a.key) if x
    ):
        p.error("请检查 SSH 密钥文件和目标证书路径（限 /etc 下）")
    if a.client and not a.client.is_file():
        p.error("管理机客户端文件不存在")
    print(
        f"目标 root@{a.ssh_host}:{a.ssh_port}；公网 {a.public_host}:{a.public_port}/UDP → 机内 {a.listen_port}/UDP；控制面 {CENTER}",
        flush=True,
    )
    if a.apply and not sys.stdin.isatty():
        p.error("--apply 需要交互终端，管理员密码不可通过管道传入")
    remote(a, "check")
    if not a.apply:
        print("新机预检通过；未安装、未注册。加 --apply 执行。")
        return
    api = Center()
    api(
        "POST",
        "/api/admin/login",
        {"password": getpass.getpass("SUB 管理员密码（仅发给控制面）：")},
    )
    try:
        provision(a, api)
    finally:
        try:
            api("POST", "/api/admin/logout")
        except Exception:
            print("会话注销未确认。", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except subprocess.SubprocessError:
        sys.exit("目标机预检或安装未完成；请检查 SSH/目标机提示。")
    except (OSError, ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
