"""start_probe must launch the probe script with an interpreter that
actually has the app's dependencies installed.

Found while auditing #6/#3: the fallback (when SUB_APP_PYTHON isn't set)
was a guessed path, ROOT/"venv/bin/python", which silently doesn't exist
if the documented setup was followed — README.md's local-run instructions
and the systemd example both use ".venv", not "venv". Every latency probe
triggered from the dashboard on such a deploy failed to even start, with
no error surfaced beyond the probe staying at "never_run".

The interpreter currently running this FastAPI process is guaranteed to
have every dependency installed, regardless of what the venv is named, so
that's the default now instead of a guess.
"""

import importlib
import json
import os
import sys
import time


def test_start_probe_defaults_to_the_running_interpreter(tmp_path, monkeypatch):
    monkeypatch.setenv("SUB_APP_LATENCY_LOCK", str(tmp_path / "lock"))
    monkeypatch.delenv("SUB_APP_PYTHON", raising=False)
    import app.latency as latency

    importlib.reload(latency)

    captured = {}

    class FakePopen:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv

    monkeypatch.setattr(latency.subprocess, "Popen", FakePopen)

    result = latency.start_probe()

    assert result == {"ok": True, "started": True, "status": "running"}
    assert captured["argv"][0] == sys.executable


def test_start_probe_honors_explicit_override(tmp_path, monkeypatch):
    monkeypatch.setenv("SUB_APP_LATENCY_LOCK", str(tmp_path / "lock"))
    monkeypatch.setenv("SUB_APP_PYTHON", "/opt/sub-app/.venv/bin/python")
    import app.latency as latency

    importlib.reload(latency)

    captured = {}

    class FakePopen:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv

    monkeypatch.setattr(latency.subprocess, "Popen", FakePopen)

    latency.start_probe()

    assert captured["argv"][0] == "/opt/sub-app/.venv/bin/python"


def test_start_probe_recovers_old_malformed_lock(tmp_path, monkeypatch):
    lock = tmp_path / "lock"
    lock.write_text("legacy-empty-lock", encoding="utf-8")
    old = time.time() - 120
    os.utime(lock, (old, old))
    monkeypatch.setenv("SUB_APP_LATENCY_LOCK", str(lock))
    monkeypatch.delenv("SUB_APP_PYTHON", raising=False)
    import app.latency as latency

    importlib.reload(latency)
    captured = {}

    class FakePopen:
        def __init__(self, argv, **kwargs):
            captured["argv"] = argv

    monkeypatch.setattr(latency.subprocess, "Popen", FakePopen)

    result = latency.start_probe()

    assert result == {"ok": True, "started": True, "status": "running"}
    assert "argv" in captured
    assert not lock.exists()


def test_start_probe_keeps_lock_for_live_recorded_process(tmp_path, monkeypatch):
    lock = tmp_path / "lock"
    lock.write_text(
        json.dumps({"pid": os.getpid(), "started_at_epoch": time.time()}),
        encoding="utf-8",
    )
    monkeypatch.setenv("SUB_APP_LATENCY_LOCK", str(lock))
    import app.latency as latency

    importlib.reload(latency)

    def unexpected_popen(*args, **kwargs):
        raise AssertionError("a live probe lock must prevent another process")

    monkeypatch.setattr(latency.subprocess, "Popen", unexpected_popen)

    assert latency.start_probe() == {
        "ok": True,
        "started": False,
        "status": "running",
    }
    assert lock.exists()
