"""Private worker sent over authenticated SSH by scripts/bootstrap_node.py."""

import hashlib
import importlib.util
import json
import os
import platform
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path

BASE = Path("/opt/sub-app-new-node")
UNITS = Path("/etc/systemd/system")
PROXY = "sub-app-new-hy2.service"
AGENT = "sub-app-new-agent.service"
TAG = "app/v2.13.0"
ARTIFACTS = {
    "x86_64": (
        "amd64",
        "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691",
    ),
    "aarch64": (
        "arm64",
        "a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7",
    ),
}
AUTH, STATS = 19281, 19282


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def run(*args, timeout=30):
    return subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=timeout)


def check(c):
    if os.geteuid() or not Path("/run/systemd/system").is_dir():
        raise ValueError("需要 root 和正在运行的 systemd")
    os_id = platform.freedesktop_os_release().get("ID")
    if os_id not in ("debian", "ubuntu") or platform.machine() not in ARTIFACTS:
        raise ValueError("仅支持 Debian/Ubuntu amd64 或 arm64")
    if sys.version_info < (3, 10):
        raise ValueError("目标机需要 Python 3.10+")
    if any(not shutil.which(x) for x in ("apt-get", "systemctl", "openssl")):
        raise ValueError("缺少系统管理工具")
    existing = run("systemctl", "list-unit-files", "--no-legend", "--no-pager").lower()
    for namefile in Path("/proc").glob("[0-9]*/comm"):
        try:
            procname = namefile.read_bytes().strip().lower()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if procname.startswith((b"hysteria", b"sing-box", b"xray")):
            raise ValueError("检测到正在运行的代理进程；拒绝接管")
    if any(
        x in existing
        for x in (
            b"hysteria",
            b"sing-box",
            b"xray",
            b"sub-app-node-agent",
            PROXY.encode(),
            AGENT.encode(),
        )
    ):
        raise ValueError("已有代理或 Agent unit；只允许在新机安装")
    if any(
        os.path.lexists(p)
        for p in (
            BASE,
            UNITS / AGENT,
            UNITS / PROXY,
            "/etc/sub-app/node-agent.json",
            "/etc/hysteria",
            "/etc/sing-box",
            "/etc/xray",
            "/usr/local/etc/xray",
        )
    ):
        raise ValueError("目标已有配置或安装残留；不接管、不覆盖")
    for port, kind, addr in (
        (c["listen_port"], socket.SOCK_DGRAM, "0.0.0.0"),
        (AUTH, socket.SOCK_STREAM, "127.0.0.1"),
        (STATS, socket.SOCK_STREAM, "127.0.0.1"),
    ):
        with socket.socket(socket.AF_INET, kind) as s:
            s.bind((addr, port))
    if shutil.disk_usage("/opt" if Path("/opt").is_dir() else "/").free < 150 * 1024**2:
        raise ValueError("可用磁盘不足 150 MiB")
    if c.get("acme_email"):
        socket.getaddrinfo(c["sni"], 80, socket.AF_INET)
        with socket.socket() as s:
            s.bind(("0.0.0.0", 80))
    else:
        # Verify the key pair and the complete public trust chain, including SNI.
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
            c["cert"], c["key"], password=lambda: ""
        )
        run(
            "openssl",
            "verify",
            "-purpose",
            "sslserver",
            "-verify_hostname",
            c["sni"],
            "-untrusted",
            c["cert"],
            c["cert"],
        )
        run("openssl", "x509", "-in", c["cert"], "-noout", "-checkend", "86400")
    with urllib.request.build_opener(NoRedirect()).open(
        c["center"] + "/healthz", timeout=12
    ) as r:
        if json.loads(r.read(8192)).get("ok") is not True:
            raise ValueError("控制面健康检查未通过")


def unit(executable):
    return f"""[Unit]
After=network-online.target
Wants=network-online.target
[Service]
ExecStart={executable}
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
[Install]
WantedBy=multi-user.target
"""


def install(c):
    os.umask(0o077)
    BASE.mkdir(mode=0o700)  # exclusive ownership marker, no overwrite
    created_units = []
    try:
        if importlib.util.find_spec("yaml") is None:
            run("apt-get", "update", timeout=180)
            run(
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                "python3-yaml",
                timeout=180,
            )
        arch, expected = ARTIFACTS[platform.machine()]
        url = f"https://github.com/HyNetworks/hysteria/releases/download/{TAG}/hysteria-linux-{arch}"
        binary = BASE / "hysteria"
        digest = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=45) as src, binary.open("xb") as dst:
            size = 0
            while block := src.read(256 * 1024):
                size += len(block)
                if size > 100 * 1024**2:
                    raise ValueError("Hy2 下载超出 100 MiB 上限")
                digest.update(block)
                dst.write(block)
        if digest.hexdigest() != expected:
            raise ValueError("Hy2 发布物摘要不符")
        binary.chmod(0o700)
        run(str(binary), "version")
        (BASE / "node-agent.py").write_text(c["source"])
        spec = dict(
            node_id=c["node_id"],
            protocol="hysteria2",
            token=c["token"],
            service=PROXY,
            hysteria_binary=str(binary),
            hysteria_config=str(BASE / "hy2.yaml"),
            auth_port=AUTH,
            stats_port=STATS,
            backup_dir=str(BASE / "backups"),
        )
        (BASE / "agent.json").write_text(
            json.dumps(
                dict(
                    endpoint=c["center"],
                    nodes=[spec],
                    poll_seconds=10,
                    state_path=str(BASE / "state.json"),
                )
            )
        )
        # Fail closed even before the first poll. No bootstrap shared password on disk.
        import yaml

        (BASE / "hy2.yaml").write_text(
            yaml.safe_dump(
                {
                    "listen": f"0.0.0.0:{c['listen_port']}",
                    **(
                        {
                            "acme": {
                                "domains": [c["sni"]],
                                "email": c["acme_email"],
                                "ca": "letsencrypt",
                                "type": "http",
                                "dir": str(BASE / "acme"),
                            }
                        }
                        if c.get("acme_email")
                        else {"tls": {"cert": c["cert"], "key": c["key"]}}
                    ),
                    "auth": {
                        "type": "http",
                        "http": {"url": f"http://127.0.0.1:{AUTH}/auth"},
                    },
                    "trafficStats": {
                        "listen": f"127.0.0.1:{STATS}",
                        "secret": secrets.token_urlsafe(32),
                    },
                },
                allow_unicode=True,
                sort_keys=False,
            )
        )
        for name, cmd in (
            (PROXY, f"{binary} server -c {BASE}/hy2.yaml"),
            (
                AGENT,
                f"/usr/bin/python3 {BASE}/node-agent.py --config {BASE}/agent.json",
            ),
        ):
            with (UNITS / name).open("x") as f:
                created_units.append(name)
                f.write(unit(cmd))
                os.fchmod(f.fileno(), 0o644)
        run("systemctl", "daemon-reload")
        run("systemctl", "enable", "--now", PROXY, AGENT)
        for name in (PROXY, AGENT):
            run("systemctl", "is-active", "--quiet", name)
        (BASE / "installation-id").write_text(c["owner"])
    except BaseException:
        # Never operate on a foreign unit. Keep private files for diagnosis.
        for name in reversed(created_units):
            subprocess.run(
                ["systemctl", "disable", "--now", name], capture_output=True, timeout=30
            )
        raise


def main():
    c = json.load(sys.stdin)
    try:
        if c["action"] in ("stop-owned", "verify-owned"):
            if (BASE / "installation-id").read_text() != c["owner"]:
                raise ValueError("安装标记不符；拒绝停止")
            for name in (PROXY, AGENT):
                fragment = (
                    run("systemctl", "show", "-p", "FragmentPath", "--value", name)
                    .decode()
                    .strip()
                )
                if Path(fragment) != UNITS / name:
                    raise ValueError("unit 路径不符；拒绝停止")
            if c["action"] == "stop-owned":
                run("systemctl", "disable", "--now", PROXY, AGENT)
                return
            import yaml

            for name in (PROXY, AGENT):
                run("systemctl", "is-active", "--quiet", name)
            local = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), NoRedirect()
            )
            secret = yaml.safe_load((BASE / "hy2.yaml").read_text())["trafficStats"][
                "secret"
            ]
            stats = urllib.request.Request(
                f"http://127.0.0.1:{STATS}/online", headers={"Authorization": secret}
            )
            with local.open(stats, timeout=4) as r:
                if not isinstance(json.load(r), dict):
                    raise ValueError("Hy2 统计服务未就绪")
            auth = urllib.request.Request(
                f"http://127.0.0.1:{AUTH}/auth",
                data=json.dumps({"auth": c["password"]}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with local.open(auth, timeout=4) as r:
                if json.load(r).get("ok") is not True:
                    raise ValueError("本机 Hy2 认证未通过")
            return
        check(c)
        if c["action"] == "install":
            install(c)
        print("OK")
    except subprocess.CalledProcessError as exc:
        sys.exit(f"命令失败：{Path(exc.cmd[0]).name}，退出码 {exc.returncode}")
    except Exception as exc:
        # Do not print HTTP bodies, config objects or any credentials.
        sys.exit(str(exc) if isinstance(exc, ValueError) else type(exc).__name__)


if __name__ == "__main__":
    main()
