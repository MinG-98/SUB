"""Real latency probes for the admin dashboard.

The probe has three deliberately separate measurements:

* control plane: the US application's local health endpoint;
* node entry: a direct TCP connection for TCP-based protocols, or a real
  Hysteria QUIC handshake for Hysteria2;
* proxy exit: a request to a public target through the node's real protocol.

Credentials — whether read from the local node URI or, for nodes with an
active per-user credential for the designated probe user, derived the same
way a real subscriber's would be — are used only while a probe is running
and are never written to the status file, logs, or API response.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Queue
from urllib.request import Request, urlopen

import yaml
from sqlalchemy import select

from app.converter import parse_uri
from app.credentials import per_user_feature_enabled, render_credential_uri
from app.models import Friend, Node, UserNodeCredential, make_session_factory
from app.node_policy import is_real_node

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = os.environ.get("SUB_APP_DB", str(ROOT / "data.db"))
STATUS_PATH = Path(
    os.environ.get("SUB_APP_LATENCY_STATUS", "/var/lib/sub-app/latency-status.json")
)
LOCK_PATH = Path(
    os.environ.get("SUB_APP_LATENCY_LOCK", "/var/lib/sub-app/latency-probe.lock")
)
PROBE_LOCK_START_GRACE_SECONDS = 30
PROBE_LOCK_MAX_AGE_SECONDS = 60 * 60
TMP_ROOT = Path(os.environ.get("SUB_APP_LATENCY_TMP", "/var/lib/sub-app/latency-tmp"))
TARGET_URL = os.environ.get(
    "SUB_APP_LATENCY_TARGET", "https://www.gstatic.com/generate_204"
)
PROBE_UID = os.environ.get("SUB_APP_LATENCY_PROBE_UID", "TEST")
LOCAL_HEALTH_URL = os.environ.get(
    "SUB_APP_LATENCY_LOCAL_HEALTH", "http://127.0.0.1:5000/healthz"
)
HYSTERIA_BIN = os.environ.get("SUB_APP_HYSTERIA_BIN", "/usr/local/bin/hysteria")
SING_BOX_BIN = os.environ.get(
    "SUB_APP_SING_BOX_PROBE_BIN", "/usr/local/libexec/sub-app-sing-box-probe"
)

HYSTERIA_CONNECTED_RE = re.compile(r"connected to server", re.IGNORECASE)
HY2_HANDSHAKE_TIMEOUT = 10.0
HY2_EXIT_TIMEOUT = 15.0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(payload: dict) -> None:
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix="latency-status.", suffix=".json", dir=str(STATUS_PATH.parent)
    )
    path = Path(name)
    try:
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"))
            handle.write("\n")
        os.replace(path, STATUS_PATH)
    finally:
        path.unlink(missing_ok=True)


def read_status() -> dict:
    try:
        value = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {"status": "never_run"}
    except (FileNotFoundError, OSError, ValueError):
        return {
            "status": "never_run",
            "started_at": None,
            "finished_at": None,
            "control": {"state": "pending", "value": "未测试"},
            "summary": {
                "nodes_total": 0,
                "entry_total": 0,
                "entry_ok": 0,
                "proxy_total": 0,
                "proxy_ok": 0,
            },
            "nodes": [],
            "target": {"url": TARGET_URL},
        }


def _probe_lock_is_live(now: float | None = None) -> bool:
    """Treat a lock as active only while its recorded process is plausibly alive."""

    now = time.time() if now is None else now
    try:
        stat = LOCK_PATH.stat()
        raw = LOCK_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    except OSError:
        return True

    try:
        payload = json.loads(raw)
        pid = int(payload.get("pid", 0))
        started_at = float(payload.get("started_at_epoch", 0))
    except (TypeError, ValueError, json.JSONDecodeError):
        age = now - stat.st_mtime
        return 0 <= age < PROBE_LOCK_START_GRACE_SECONDS

    age = now - started_at
    if pid <= 0:
        return 0 <= now - stat.st_mtime < PROBE_LOCK_START_GRACE_SECONDS
    if age < 0 or age > PROBE_LOCK_MAX_AGE_SECONDS:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        # An indeterminate OS error must not delete a plausibly live lock.
        return True
    return True


def start_probe() -> dict:
    """Start one detached probe run; the API remains responsive."""

    if LOCK_PATH.exists():
        if _probe_lock_is_live():
            return {"ok": True, "started": False, "status": "running"}
        try:
            LOCK_PATH.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            return {"ok": False, "started": False, "status": "error"}
    script = ROOT / "scripts" / "latency_probe.py"
    try:
        subprocess.Popen(
            [
                # Default to the interpreter already running this process —
                # it's guaranteed to have every dependency installed,
                # regardless of what the venv happens to be named.  The old
                # default guessed "venv/bin/python", which silently failed
                # to start whenever the documented setup ("python3 -m venv
                # .venv", README.md) was followed instead.
                os.environ.get("SUB_APP_PYTHON", sys.executable),
                str(script),
            ],
            cwd=str(ROOT),
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        return {"ok": False, "started": False, "status": "error"}
    return {"ok": True, "started": True, "status": "running"}


def _result(
    state: str, ms: int | None = None, reason: str = "", source: str = ""
) -> dict:
    value = (
        "正常"
        if state == "ok"
        else (
            "未就绪"
            if state == "unsupported"
            else "探测中"
            if state == "pending"
            else "不可达"
        )
    )
    if state == "ok" and ms is not None:
        value = f"{ms} ms"
    payload = {"state": state, "value": value}
    if ms is not None:
        payload["ms"] = int(ms)
    if reason:
        payload["reason"] = reason
    if source:
        payload["source"] = source
    return payload


def _remark_node(node: Node, parsed: dict | None) -> bool:
    return not is_real_node(node)


def _endpoint(host: str, port: int) -> str:
    return (
        f"[{host}]:{port}"
        if ":" in host and not host.startswith("[")
        else f"{host}:{port}"
    )


def _socket_probe(host: str, port: int, timeout: float = 4.0) -> dict:
    started = time.perf_counter()
    last_error = "连接失败"
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return _result("bad", reason="DNS 解析失败", source="tcp")
    for family, sock_type, proto, _canonname, sockaddr in addresses:
        sock = socket.socket(family, sock_type, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            elapsed = max(1, round((time.perf_counter() - started) * 1000))
            return _result("ok", elapsed, source="tcp")
        except TimeoutError:
            last_error = "连接超时"
        except OSError as exc:
            last_error = (
                "连接被拒绝"
                if getattr(exc, "errno", None) in {111, 61, 10061}
                else "连接失败"
            )
        finally:
            sock.close()
    return _result("bad", reason=last_error, source="tcp")


def _local_probe() -> dict:
    started = time.perf_counter()
    try:
        request = Request(LOCAL_HEALTH_URL, headers={"Accept": "application/json"})
        with urlopen(request, timeout=4) as response:
            response.read(1024)
        return _result(
            "ok",
            max(1, round((time.perf_counter() - started) * 1000)),
            source="healthz",
        )
    except Exception:
        return _result("bad", reason="控制面不可达", source="healthz")


def _hysteria_client_config(parsed: dict, local_port: int) -> dict:
    """Build the smallest safe Hysteria client config for a probe.

    A parsed subscription URI is the source of truth here.  Passing the URI
    through as ``server`` lets Hysteria parse every supported URI option
    itself (auth, SNI, insecure, pinSHA256, ECH and both obfuscation modes).
    The explicit-field fallback exists only for callers that construct a
    parsed mapping in isolation; normal probes always have ``uri`` from
    ``parse_uri``.
    """

    uri = str(parsed.get("uri") or "").strip()
    if uri.lower().startswith(("hysteria2://", "hy2://")):
        return {
            "server": uri,
            "socks5": {
                "listen": _endpoint("127.0.0.1", local_port),
                "disableUDP": True,
            },
        }

    username = parsed.get("user") or ""
    password = parsed.get("password") or ""
    auth = f"{username}:{password}" if username and password else username or password
    config = {
        "server": _endpoint(parsed["host"], int(parsed["port"])),
        "auth": auth,
        "tls": {
            "sni": parsed.get("params", {}).get("sni") or parsed["host"],
            "insecure": str(parsed.get("params", {}).get("insecure", "")).lower()
            in {"1", "true"},
        },
        "socks5": {
            "listen": _endpoint("127.0.0.1", local_port),
            "disableUDP": True,
        },
    }
    params = parsed.get("params", {})
    obfs_type = str(params.get("obfs") or "").lower()
    if obfs_type == "salamander":
        config["obfs"] = {
            "type": "salamander",
            "salamander": {"password": params.get("obfs-password", "")},
        }
    elif obfs_type == "gecko":
        config["obfs"] = {
            "type": "gecko",
            "gecko": {"password": params.get("obfs-password", "")},
        }
    elif obfs_type:
        raise ValueError("unsupported Hysteria obfuscation mode")
    return config


def _wait_for_local_listener(process, port: int, timeout: float = 3.0) -> bool:
    """Wait until the temporary Hysteria SOCKS5 listener accepts TCP."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _stop_hysteria_process(process, reader) -> None:
    """Stop the probe client, let its stdout reader reach EOF, then close it.

    Closing ``process.stdout`` before joining the reader races its iterator and
    can raise ``ValueError: I/O operation on closed file`` in the daemon thread.
    The child is reaped first so the pipe reaches EOF and the reader can finish.
    """

    if process is not None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    if reader is not None:
        reader.join()
    if process is not None and process.stdout is not None:
        process.stdout.close()


def _hysteria_failure_reason(output: str, *, connected: bool) -> str:
    """Classify a Hysteria failure without exposing command output."""

    lower = output.lower()
    if not connected:
        if any(
            marker in lower
            for marker in (
                "failed to load client config",
                "failed to parse client config",
                "invalid config",
                "unknown field",
                "yaml",
            )
        ):
            return "HY2 探测配置无效"
        if any(
            marker in lower
            for marker in ("authentication", "auth failed", "unauthorized")
        ):
            return "HY2 认证失败"
        if any(marker in lower for marker in ("timeout", "i/o timeout")):
            return "HY2 QUIC 握手超时"
        if any(
            marker in lower for marker in ("network is unreachable", "no route to host")
        ):
            return "HY2 网络不可达"
        return "HY2 QUIC 握手失败"
    if any(marker in lower for marker in ("timeout", "i/o timeout")):
        return "HY2 代理出口超时"
    return "HY2 代理出口失败"


def _hysteria_probe_results(parsed: dict) -> tuple[dict, dict]:
    """Return ``(entry, proxy)`` from one real Hysteria QUIC probe.

    Hysteria2 is UDP/QUIC, so a TCP connect to its advertised port is not an
    entry test.  Start a temporary Hysteria client with a loopback SOCKS5
    listener, use its ``connected to server`` log as the protocol-native
    handshake checkpoint, and only then send the target request through that
    listener.  This keeps a successful QUIC handshake visible even when the
    remote target or the server's outbound path fails.
    """

    username = parsed.get("user") or ""
    password = parsed.get("password") or ""
    auth = f"{username}:{password}" if username and password else username or password
    unavailable = _result(
        "unsupported", reason="HY2 探测器未就绪", source="hysteria-quic"
    )
    if not auth or not shutil.which(HYSTERIA_BIN):
        return unavailable, {**unavailable, "source": "hysteria-socks5"}

    path = None
    process = None
    reader = None
    output_queue = Queue()
    output_lines = []

    def read_output():
        if process is None or process.stdout is None:
            output_queue.put(None)
            return
        try:
            for line in process.stdout:
                output_queue.put(line)
        finally:
            output_queue.put(None)

    def drain_output():
        while True:
            try:
                line = output_queue.get_nowait()
            except Empty:
                return
            if line is None:
                return
            output_lines.append(line)

    try:
        port_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            port_sock.bind(("127.0.0.1", 0))
            local_port = port_sock.getsockname()[1]
        finally:
            port_sock.close()
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        os.chmod(TMP_ROOT, 0o700)
        config = _hysteria_client_config(parsed, local_port)
        fd, name = tempfile.mkstemp(prefix="hy2-", suffix=".yaml", dir=str(TMP_ROOT))
        path = Path(name)
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            yaml.safe_dump(config, handle, allow_unicode=True, sort_keys=False)
        command = [
            HYSTERIA_BIN,
            "--disable-update-check",
            "--log-level",
            "info",
            "-c",
            str(path),
            "client",
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        handshake_started = time.perf_counter()
        connected = False
        deadline = time.monotonic() + HY2_HANDSHAKE_TIMEOUT
        while time.monotonic() < deadline:
            if process.poll() is not None:
                reader.join(timeout=0.2)
                drain_output()
                break
            try:
                line = output_queue.get(timeout=min(0.2, deadline - time.monotonic()))
            except Empty:
                continue
            if line is None:
                break
            output_lines.append(line)
            if HYSTERIA_CONNECTED_RE.search(line):
                connected = True
                break

        output = "".join(output_lines)
        if not connected:
            reason = (
                "HY2 QUIC 握手超时"
                if time.monotonic() >= deadline
                else _hysteria_failure_reason(output, connected=False)
            )
            return (
                _result("bad", reason=reason, source="hysteria-quic"),
                _result(
                    "bad",
                    reason=f"{reason}，未验证代理出口",
                    source="hysteria-socks5",
                ),
            )

        entry = _result(
            "ok",
            max(1, round((time.perf_counter() - handshake_started) * 1000)),
            reason="HY2 QUIC 握手成功",
            source="hysteria-quic",
        )
        if not _wait_for_local_listener(process, local_port):
            return entry, _result(
                "bad",
                reason="HY2 SOCKS5 探测入口未就绪",
                source="hysteria-socks5",
            )

        curl = shutil.which("curl") or "/usr/bin/curl"
        if not shutil.which(curl):
            return entry, _result(
                "unsupported",
                reason="HY2 出口探测器未就绪",
                source="hysteria-socks5",
            )
        exit_started = time.perf_counter()
        try:
            completed = subprocess.run(
                [
                    curl,
                    "--socks5-hostname",
                    f"127.0.0.1:{local_port}",
                    "-sS",
                    "-o",
                    os.devnull,
                    "-w",
                    "%{http_code}",
                    "--connect-timeout",
                    "5",
                    "--max-time",
                    str(int(HY2_EXIT_TIMEOUT)),
                    TARGET_URL,
                ],
                capture_output=True,
                text=True,
                timeout=HY2_EXIT_TIMEOUT + 3,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return entry, _result(
                "bad",
                reason="HY2 代理出口超时",
                source="hysteria-socks5",
            )
        code = (completed.stdout or "").strip()
        if completed.returncode == 0 and code[:1] in {"2", "3"}:
            return entry, _result(
                "ok",
                max(1, round((time.perf_counter() - exit_started) * 1000)),
                source="hysteria-socks5",
            )
        return entry, _result(
            "bad",
            reason="HY2 代理出口失败",
            source="hysteria-socks5",
        )
    except (KeyError, OSError, TypeError, ValueError, yaml.YAMLError):
        reason = "HY2 探测配置或执行失败"
        return (
            _result("bad", reason=reason, source="hysteria-quic"),
            _result("bad", reason=reason, source="hysteria-socks5"),
        )
    finally:
        _stop_hysteria_process(process, reader)
        if path is not None:
            path.unlink(missing_ok=True)


def _hysteria_probe(parsed: dict) -> dict:
    """Return only the proxy result for compatibility with older callers."""

    _entry, proxy = _hysteria_probe_results(parsed)
    return proxy


def _sing_box_config(parsed: dict, port: int) -> dict:
    params = parsed.get("params", {})
    security = params.get("security", "")
    tls = {"enabled": security in {"tls", "reality"}}
    if params.get("sni"):
        tls["server_name"] = params["sni"]
    if params.get("fp"):
        tls["utls"] = {"enabled": True, "fingerprint": params["fp"]}
    if security == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": params.get("pbk", ""),
            "short_id": params.get("sid", ""),
        }
    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": parsed["host"],
        "server_port": int(parsed["port"]),
        "uuid": parsed.get("user", ""),
        "tls": tls,
    }
    if params.get("flow"):
        outbound["flow"] = params["flow"]
    if params.get("type") == "ws":
        transport = {"type": "ws", "path": params.get("path", "/")}
        if params.get("host"):
            transport["headers"] = {"Host": params["host"]}
        outbound["transport"] = transport
    elif params.get("type") == "grpc":
        outbound["transport"] = {
            "type": "grpc",
            "service_name": params.get("serviceName", ""),
        }
    return {
        "log": {"disabled": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        ],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }


def _sing_box_probe(parsed: dict) -> dict:
    if not parsed.get("user") or not Path(SING_BOX_BIN).is_file():
        return _result("unsupported", reason="VLESS 探测器未就绪", source="sing-box")
    port_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_sock.bind(("127.0.0.1", 0))
    port = port_sock.getsockname()[1]
    port_sock.close()
    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(TMP_ROOT, 0o700)
    path = None
    process = None
    try:
        fd, name = tempfile.mkstemp(prefix="vless-", suffix=".json", dir=str(TMP_ROOT))
        path = Path(name)
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(_sing_box_config(parsed, port), handle, ensure_ascii=False)
        checked = subprocess.run(
            [SING_BOX_BIN, "check", "-c", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
            check=False,
        )
        if checked.returncode:
            return _result("bad", reason="VLESS 配置校验失败", source="sing-box")
        process = subprocess.Popen(
            [SING_BOX_BIN, "run", "-c", str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        ready = False
        for _ in range(40):
            if process.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    ready = True
                    break
            except OSError:
                time.sleep(0.1)
        if not ready:
            return _result("bad", reason="VLESS 探测器未启动", source="sing-box")
        curl = shutil.which("curl") or "/usr/bin/curl"
        started = time.perf_counter()
        completed = subprocess.run(
            [
                curl,
                "--proxy",
                f"socks5h://127.0.0.1:{port}",
                "-sS",
                "-o",
                os.devnull,
                "-w",
                "%{http_code}",
                "--connect-timeout",
                "5",
                "--max-time",
                "12",
                TARGET_URL,
            ],
            capture_output=True,
            text=True,
            timeout=18,
            check=False,
        )
        code = (completed.stdout or "").strip()
        if completed.returncode == 0 and code[:1] in {"2", "3"}:
            return _result(
                "ok",
                max(1, round((time.perf_counter() - started) * 1000)),
                source="sing-box",
            )
        return _result("bad", reason="VLESS 代理出口失败", source="sing-box")
    except subprocess.TimeoutExpired:
        return _result("bad", reason="代理出口超时", source="sing-box")
    except (OSError, ValueError, TypeError):
        return _result("bad", reason="VLESS 探测失败", source="sing-box")
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if path is not None:
            path.unlink(missing_ok=True)


def _probe_node(node: dict) -> dict:
    parsed = parse_uri(node["uri"])
    if not parsed or not parsed.get("host") or not parsed.get("port"):
        return {
            "node_id": node["id"],
            "name": node["name"],
            "protocol": node["protocol"],
            "credential_source": node.get("credential_source", "base"),
            "entry": _result("bad", reason="节点链接无效"),
            "proxy": _result("bad", reason="节点链接无效"),
        }
    protocol = parsed.get("scheme", node["protocol"])
    if protocol == "hysteria2":
        entry, proxy = _hysteria_probe_results(parsed)
    elif protocol == "vless":
        entry = _socket_probe(parsed["host"], int(parsed["port"]))
        proxy = _sing_box_probe(parsed)
    else:
        entry = _socket_probe(parsed["host"], int(parsed["port"]))
        proxy = _result("unsupported", reason="协议暂未适配", source="probe")
    return {
        "node_id": node["id"],
        "name": node["name"],
        "protocol": protocol,
        "credential_source": node.get("credential_source", "base"),
        "entry": entry,
        "proxy": proxy,
    }


def _summary(nodes: list[dict]) -> dict:
    def checked(kind: str) -> list[dict]:
        return [row for row in nodes if row.get(kind, {}).get("state") in {"ok", "bad"}]

    def count(kind: str) -> int:
        return sum(row.get(kind, {}).get("state") == "ok" for row in nodes)

    entry_checked = checked("entry")
    proxy_checked = checked("proxy")

    def average(kind: str) -> int | None:
        values = [
            row[kind].get("ms")
            for row in nodes
            if row.get(kind, {}).get("ms") is not None
        ]
        return round(sum(values) / len(values)) if values else None

    return {
        "nodes_total": len(nodes),
        "entry_total": len(entry_checked),
        "entry_ok": count("entry"),
        "proxy_total": len(proxy_checked),
        "proxy_ok": count("proxy"),
        "entry_avg_ms": average("entry"),
        "proxy_avg_ms": average("proxy"),
    }


def run_probes() -> None:
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return
    try:
        lock_stat = os.fstat(fd)
        lock_identity = (lock_stat.st_dev, lock_stat.st_ino)
        os.write(
            fd,
            json.dumps(
                {"pid": os.getpid(), "started_at_epoch": time.time()},
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        os.fsync(fd)
    except OSError:
        try:
            LOCK_PATH.unlink()
        except OSError:
            pass
        return
    finally:
        os.close(fd)
    started = _now()
    try:
        _write_json(
            {
                "status": "running",
                "started_at": started,
                "finished_at": None,
                "control": {"state": "pending", "value": "探测中"},
                "summary": {
                    "nodes_total": 0,
                    "entry_total": 0,
                    "entry_ok": 0,
                    "proxy_total": 0,
                    "proxy_ok": 0,
                },
                "nodes": [],
                "target": {"url": TARGET_URL},
            }
        )
        factory = make_session_factory(DB_PATH)
        db = factory()
        try:
            # Gate on the same conditions the real subscription endpoint
            # does (app/main.py _friend_uris): the global feature flag,
            # then friend/status/protocol.  Skipping the flag check here
            # let the probe measure a per-user path nobody was actually
            # being served — real subscribers were still on the shared URI
            # (which is exactly what the agent's 24h legacy window drops)
            # while the dashboard read the TEST user's still-installed
            # credential and reported the node healthy.
            probe_credentials = {}
            if per_user_feature_enabled():
                probe_friend = db.scalar(
                    select(Friend).where(
                        Friend.uid == PROBE_UID,
                        Friend.enabled.is_(True),
                        Friend.per_user_credentials.is_(True),
                    )
                )
                if probe_friend is not None:
                    # Only "active", matching the real endpoint: a "grace"
                    # row is a rotation courtesy for existing clients, not
                    # something a fresh dial (which is all a probe ever
                    # does) is entitled to.  Keyed on (node_id, protocol)
                    # so a node that changed protocol without revoking its
                    # old-protocol credential can't have that stale row
                    # rendered onto its current URI.
                    credential_rows = db.scalars(
                        select(UserNodeCredential)
                        .where(
                            UserNodeCredential.friend_id == probe_friend.id,
                            UserNodeCredential.status == "active",
                            UserNodeCredential.revoked_at.is_(None),
                        )
                        .order_by(
                            UserNodeCredential.node_id,
                            UserNodeCredential.version.desc(),
                        )
                    ).all()
                    for row in credential_rows:
                        probe_credentials.setdefault((row.node_id, row.protocol), row)
            candidates = db.scalars(
                select(Node)
                .where(Node.enabled.is_(True))
                .order_by(Node.sort_order, Node.id)
            ).all()
            nodes = []
            for item in candidates:
                parsed = parse_uri(item.uri)
                if _remark_node(item, parsed):
                    continue
                credential = probe_credentials.get((item.id, item.protocol))
                if credential is not None:
                    try:
                        uri = render_credential_uri(item, credential)
                        source = f"user:{PROBE_UID}"
                    except (TypeError, ValueError, RuntimeError):
                        # RuntimeError is credential_values() refusing to
                        # derive a value without SUB_APP_SECRET — that must
                        # degrade to the base URI like any other rendering
                        # failure, not propagate to run_probes' outer catch
                        # and blank every node's result.
                        uri = item.uri
                        source = "base"
                else:
                    uri = item.uri
                    source = "base"
                nodes.append(
                    {
                        "id": item.id,
                        "name": item.name,
                        "protocol": item.protocol,
                        "uri": uri,
                        "credential_source": source,
                    }
                )
        finally:
            db.close()
        with ThreadPoolExecutor(max_workers=min(6, max(1, len(nodes)))) as pool:
            results = list(pool.map(_probe_node, nodes))
        summary = _summary(results)
        all_ok = bool(results) and summary["proxy_ok"] == summary["nodes_total"]
        _write_json(
            {
                "status": "success" if all_ok else "partial",
                "started_at": started,
                "finished_at": _now(),
                "control": _local_probe(),
                "summary": summary,
                "nodes": results,
                "target": {"url": TARGET_URL},
            }
        )
    except Exception as exc:
        _write_json(
            {
                "status": "error",
                "started_at": started,
                "finished_at": _now(),
                "control": {
                    "state": "bad",
                    "value": "不可用",
                    "reason": "探测任务失败",
                },
                "summary": {"nodes_total": 0, "entry_ok": 0, "proxy_ok": 0},
                "nodes": [],
                "target": {"url": TARGET_URL},
                "error": type(exc).__name__,
            }
        )
    finally:
        try:
            current = LOCK_PATH.stat()
            if (current.st_dev, current.st_ino) == lock_identity:
                LOCK_PATH.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
