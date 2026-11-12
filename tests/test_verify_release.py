import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import verify_release as verifier

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_release.py"
CSS = b"body { color: #123456; }\n"
HTML = """<!doctype html><html><head>
<script type="module" src="/static/assets/index-demo.js"></script>
<link rel="stylesheet" href="/static/assets/index-demo.css">
<link rel="icon" href="/static/favicon.svg">
</head><body><div id="app"></div></body></html>"""


@pytest.fixture
def release(tmp_path):
    root = tmp_path / "release"
    # Mirror the existing CI copy list, independently of the validator constants.
    for directory in (
        "app",
        "agent",
        "scripts",
        "deploy",
        "frontend/src",
        "frontend/public",
        "static/assets",
    ):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for name in (
        "app/main.py",
        "app/models.py",
        "agent/node-agent.py",
        "scripts/check_existing_db.py",
        "scripts/backup_db.py",
        "README.md",
        "LICENSE",
        "pyproject.toml",
        "requirements.txt",
        "frontend/index.html",
        "frontend/package.json",
        "frontend/package-lock.json",
        "frontend/vite.config.js",
    ):
        (root / name).write_text("fixture\n", encoding="utf-8")
    (root / "static/index.html").write_text(HTML, encoding="utf-8")
    (root / "static/favicon.svg").write_text("<svg/>", encoding="utf-8")
    (root / "static/assets/index-demo.js").write_text("export {};", encoding="utf-8")
    (root / "static/assets/index-demo.css").write_bytes(CSS)
    return root


def run_cli(root, *extra):
    result = subprocess.run(
        [sys.executable, "-B", str(SCRIPT), "--release-dir", str(root), *extra],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.stderr == ""
    return result.returncode, json.loads(result.stdout)


def assert_failure(release, code):
    status, report = run_cli(release)
    assert status == 1
    assert report["ok"] is False
    assert report["error"] == code
    assert str(release) not in json.dumps(report)


def snapshot(root):
    return {
        str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }


def test_good_artifact_is_read_only_and_reports_hashes(release):
    before = snapshot(release)
    status, report = run_cli(release)
    assert status == 0
    assert report["ok"] is True
    assert report["manifest"] == "static/index.html"
    assert (
        report["static_sha256"]["static/assets/index-demo.css"]
        == hashlib.sha256(CSS).hexdigest()
    )
    assert report["provenance"]["status"] == "not_verified"
    assert report["css_preservation"] == "not_requested"
    assert str(release) not in json.dumps(report)
    assert "body {" not in json.dumps(report)
    assert snapshot(release) == before


def test_current_repository_static_artifact(release):
    static = SCRIPT.parents[1] / "static"
    for source in static.rglob("*"):
        if source.is_file():
            destination = release / "static" / source.relative_to(static)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
    assert run_cli(release)[0] == 0


def test_missing_runtime_entrypoint_is_rejected(release):
    (release / "app/main.py").unlink()
    assert_failure(release, "release_layout")


@pytest.mark.parametrize("kind", ["missing", "empty", "directory"])
def test_missing_or_invalid_asset(release, kind):
    asset = release / "static/assets/index-demo.js"
    asset.unlink()
    if kind == "empty":
        asset.touch()
    elif kind == "directory":
        asset.mkdir()
    assert_failure(release, "missing_asset")


@pytest.mark.parametrize(
    "reference",
    [
        "/static/../private.js",
        "../private.js",
        "/static/%2e%2e/private.js",
        "/static/%252e%252e/private.js",
        "/static/assets/%2f..%2fprivate.js",
        "/static/assets/..%5cprivate.js",
        "/static//etc/passwd",
        "/private.js",
        "//example.invalid/private.js",
        "https://user:secret@example.invalid/private.js?token=secret",
        "file:///private.js",
        "/static/assets/%00private.js",
    ],
)
def test_traversal_and_external_urls_are_rejected_without_echo(release, reference):
    (release / "static/index.html").write_text(
        HTML.replace("/static/assets/index-demo.js", reference), encoding="utf-8"
    )
    status, report = run_cli(release)
    assert status == 1
    assert report["error"] == "asset_path"
    assert reference not in json.dumps(report)
    assert "secret" not in json.dumps(report)


def test_relative_urls_and_query_strings(release):
    (release / "static/index.html").write_text(
        HTML.replace("/static/assets/", "./assets/").replace(
            "index-demo.js", "index-demo.js?token=do-not-echo&amp;v=2#fragment"
        ),
        encoding="utf-8",
    )
    status, report = run_cli(release)
    assert status == 0
    assert "do-not-echo" not in json.dumps(report)


@pytest.mark.parametrize("path", ["._root", "app/._main.py", "static/._assets"])
def test_appledouble_anywhere(release, path):
    (release / path).write_bytes(b"metadata")
    assert_failure(release, "appledouble")


@pytest.mark.parametrize("target", ["missing", "static/assets", "static/index.html"])
def test_symlink_even_when_dangling_or_internal(release, target):
    (release / "app/link").symlink_to(release / target)
    assert_failure(release, "symlink")


def test_root_symlink(release):
    alias = release.parent / "alias"
    alias.symlink_to(release, target_is_directory=True)
    assert_failure(alias, "symlink")


def test_referenced_asset_symlink_is_not_read(release):
    outside = release.parent / "private.js"
    outside.write_text("private contents", encoding="utf-8")
    asset = release / "static/assets/index-demo.js"
    asset.unlink()
    asset.symlink_to(outside)
    assert_failure(release, "symlink")


def test_special_file_is_rejected_without_opening(release):
    os.mkfifo(release / "static/pipe")
    assert_failure(release, "special_file")


def test_css_preservation_matches_and_mismatches(release):
    expected = hashlib.sha256(CSS).hexdigest().upper()
    status, report = run_cli(release, "--expected-css-sha256", expected)
    assert status == 0
    assert report["css_preservation"] == "verified"
    (release / "static/assets/index-demo.css").write_bytes(CSS + b"/* changed */")
    status, report = run_cli(release, "--expected-css-sha256", expected)
    assert status == 1
    assert report["error"] == "css_mismatch"
    assert run_cli(release)[0] == 0  # Preservation is explicitly opt-in.


def test_css_preservation_rejects_ambiguous_multiple_stylesheets(release):
    (release / "static/assets/second.css").write_bytes(CSS)
    (release / "static/index.html").write_text(
        HTML + '<link rel="stylesheet" href="/static/assets/second.css">',
        encoding="utf-8",
    )
    assert run_cli(release)[0] == 0
    status, report = run_cli(
        release, "--expected-css-sha256", hashlib.sha256(CSS).hexdigest()
    )
    assert status == 1
    assert report["error"] == "css_count"


@pytest.mark.parametrize(
    "arguments", [["--expected-css-sha256", "secret"], ["--unknown"]]
)
def test_argument_failures_are_json(release, arguments):
    status, report = run_cli(release, *arguments)
    assert status == 2
    assert report["ok"] is False
    assert "secret" not in json.dumps(report)


def test_missing_release(release):
    assert_failure(release / "missing", "release_directory")


def test_source_layout_required(release):
    (release / "frontend/package-lock.json").unlink()
    assert_failure(release, "release_layout")


def test_node_modules_is_not_a_release_dependency(release):
    (release / "frontend/node_modules").mkdir()
    assert_failure(release, "release_layout")


def test_non_utf8_entrypoint(release):
    (release / "static/index.html").write_bytes(b"\xff")
    assert_failure(release, "entrypoint_encoding")


@pytest.mark.parametrize(
    "html, code",
    [
        ("<html></html>", "entrypoint_assets"),
        (HTML + '<base href="/elsewhere/">', "base_url"),
        (HTML + '<img srcset="/static/a.png 2x">', "unsupported_reference"),
    ],
)
def test_incomplete_or_unsupported_entrypoint(release, html, code):
    (release / "static/index.html").write_text(html, encoding="utf-8")
    assert_failure(release, code)


@pytest.mark.parametrize(
    "limit", ["MAX_ENTRIES", "MAX_DEPTH", "MAX_HTML_BYTES", "MAX_STATIC_BYTES"]
)
def test_limits_are_enforced(release, monkeypatch, limit):
    monkeypatch.setattr(verifier, limit, 1)
    with pytest.raises(verifier.ValidationError) as error:
        verifier.verify_release(release)
    assert error.value.code == "limit"


def test_io_errors_are_sanitized(release, monkeypatch, capsys):
    def unreadable(root):
        raise PermissionError("private absolute path and secret")

    monkeypatch.setattr(verifier, "inventory", unreadable)
    assert verifier.main(["--release-dir", str(release)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["error"] == "io_error"
    assert "secret" not in json.dumps(report)
