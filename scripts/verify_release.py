"""Read-only preflight for the source/static directory assembled by ci.yml.

The current manifest is static/index.html, not a JSON release manifest. Validate
its direct asset references; this is not a JS/CSS dependency parser, rebuild
comparison, runtime test, or proof of source commit. CI puts github.sha in the
uploaded artifact name only, so directory contents cannot authenticate it.
Run against an extracted, quiescent release directory, not a live mutable tree
or a development checkout containing .venv/node_modules. Only stdout is written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

MAX_ENTRIES = 20_000
MAX_DEPTH = 64
MAX_HTML_BYTES = 1024 * 1024
MAX_STATIC_BYTES = 512 * 1024 * 1024
REQUIRED_DIRS = (
    "app",
    "agent",
    "scripts",
    "deploy",
    "frontend/src",
    "frontend/public",
    "static/assets",
)
REQUIRED_FILES = (
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
    "static/index.html",
    "static/favicon.svg",
)


class ValidationError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def fail(code: str, message: str) -> None:
    raise ValidationError(code, message)


def inventory(root: Path) -> dict[str, os.stat_result]:
    """Bound traversal and lstat every entry, without following symlinks."""
    if root.is_symlink():
        fail("symlink", "Release directory must not be a symlink.")
    if not root.is_dir():
        fail("release_directory", "Release directory is missing or not a directory.")
    entries = {}
    pending = [(root, 0)]
    while pending:
        directory, depth = pending.pop()
        with os.scandir(directory) as children:
            for child in children:
                if len(entries) >= MAX_ENTRIES or depth >= MAX_DEPTH:
                    fail("limit", "Release directory exceeds traversal limits.")
                if child.name.startswith("._"):
                    fail("appledouble", "Release contains AppleDouble metadata (._*).")
                info = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    fail("symlink", "Release contains a symlink.")
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    fail("special_file", "Release contains a non-regular file.")
                path = Path(child.path)
                relative = path.relative_to(root).as_posix()
                entries[relative] = info
                if stat.S_ISDIR(info.st_mode):
                    pending.append((path, depth + 1))
    return entries


class Entrypoint(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag == "base":
            fail("base_url", "Entrypoint must not override the static base URL.")
        attributes = dict(attrs)
        if "srcset" in attributes:
            fail("unsupported_reference", "Entrypoint srcset is not supported.")
        if "src" in attributes:
            kind = "script" if tag == "script" else "asset"
            self.references.append((kind, attributes["src"] or ""))
        if tag == "link" and "href" in attributes:
            rel = (attributes.get("rel") or "").lower().split()
            kind = "css" if "stylesheet" in rel else "asset"
            self.references.append((kind, attributes["href"] or ""))
        if tag == "object" and "data" in attributes:
            self.references.append(("asset", attributes["data"] or ""))


def static_reference(raw: str) -> str:
    """Accept only local static URLs; never report raw URLs/query credentials."""
    if not raw or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        fail("asset_path", "Entrypoint contains an invalid asset URL.")
    try:
        url = urlsplit(raw)
        path = unquote(url.path, errors="strict")
    except (ValueError, UnicodeError):
        fail("asset_path", "Entrypoint contains an invalid asset URL.")
    if url.scheme or url.netloc or raw.startswith("//"):
        fail("asset_path", "Asset references must be local to static/.")
    if (
        "\\" in path
        or "%" in path
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
        or ".." in path.split("/")
    ):
        fail("asset_path", "Asset reference escapes static/ or is ambiguous.")
    if path.startswith("/static/"):
        path = path[len("/static/") :]
    elif path.startswith("/"):
        fail("asset_path", "Absolute asset references must start with /static/.")
    if not path or path.startswith("/") or path.endswith("/"):
        fail("asset_path", "Asset reference must name a file within static/.")
    return "static/" + PurePosixPath(path).as_posix()


def verify_release(root: Path, expected_css_sha256: str | None = None) -> dict:
    if expected_css_sha256 is not None and not re.fullmatch(
        r"[0-9a-fA-F]{64}", expected_css_sha256
    ):
        fail("css_hash_argument", "Expected CSS SHA-256 must be 64 hexadecimal digits.")
    entries = inventory(root)
    for relative in REQUIRED_DIRS:
        if relative not in entries or not stat.S_ISDIR(entries[relative].st_mode):
            fail(
                "release_layout",
                "Release is missing a required source/static directory.",
            )
    for relative in REQUIRED_FILES:
        if (
            relative not in entries
            or not stat.S_ISREG(entries[relative].st_mode)
            or entries[relative].st_size == 0
        ):
            fail(
                "release_layout",
                "Release is missing a nonempty required packaged file.",
            )
    if "frontend/node_modules" in entries:
        fail("release_layout", "Release must not include frontend/node_modules.")

    with (root / "static/index.html").open("rb") as stream:
        html = stream.read(MAX_HTML_BYTES + 1)
    if len(html) > MAX_HTML_BYTES:
        fail("limit", "Entrypoint exceeds the size limit.")
    parser = Entrypoint()
    try:
        parser.feed(html.decode("utf-8"))
        parser.close()
    except UnicodeError:
        fail("entrypoint_encoding", "Entrypoint must be UTF-8 HTML.")

    references: set[str] = set()
    css: set[str] = set()
    scripts: set[str] = set()
    for kind, raw in parser.references:
        relative = static_reference(raw)
        if (
            relative not in entries
            or not stat.S_ISREG(entries[relative].st_mode)
            or entries[relative].st_size == 0
        ):
            fail(
                "missing_asset",
                "Entrypoint references a missing, empty or non-file asset.",
            )
        references.add(relative)
        if kind == "css":
            css.add(relative)
        if kind == "script":
            scripts.add(relative)
    if not scripts or not css:
        fail(
            "entrypoint_assets",
            "Entrypoint must reference script and stylesheet assets.",
        )

    # Hash every static file, not source/config contents. Bound actual bytes read
    # as well as metadata sizes so a growing file cannot cause unbounded reads.
    hashes = {}
    remaining = MAX_STATIC_BYTES
    for relative, info in sorted(entries.items()):
        if not relative.startswith("static/") or not stat.S_ISREG(info.st_mode):
            continue
        if info.st_size > remaining:
            fail("limit", "Static files exceed the total byte limit.")
        digest = hashlib.sha256()
        with (root / relative).open("rb") as stream:
            while chunk := stream.read(min(1024 * 1024, remaining + 1)):
                remaining -= len(chunk)
                if remaining < 0:
                    fail("limit", "Static files exceed the total byte limit.")
                digest.update(chunk)
        hashes[relative] = digest.hexdigest()

    if expected_css_sha256 is not None:
        if len(css) != 1:
            fail(
                "css_count",
                "CSS preservation requires exactly one entrypoint stylesheet.",
            )
        if hashes[next(iter(css))] != expected_css_sha256.lower():
            fail(
                "css_mismatch",
                "Entrypoint CSS SHA-256 does not match the expected hash.",
            )

    return {
        "ok": True,
        "manifest": "static/index.html",
        "file_count": sum(stat.S_ISREG(info.st_mode) for info in entries.values()),
        "referenced_assets": sorted(references),
        "static_sha256": hashes,
        "css_preservation": "verified" if expected_css_sha256 else "not_requested",
        "provenance": {
            "status": "not_verified",
            "reason": "CI does not package commit provenance inside the release directory.",
        },
    }


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse messages can contain user-supplied paths/URLs. Do not echo them.
        fail("arguments", "Invalid arguments; use --help for usage.")


def main(argv: list[str] | None = None) -> int:
    parser = JsonArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument(
        "--expected-css-sha256",
        help="Require exactly one entrypoint stylesheet with this SHA-256 digest.",
    )
    try:
        args = parser.parse_args(argv)
        result = verify_release(args.release_dir, args.expected_css_sha256)
    except ValidationError as exc:
        print(json.dumps({"ok": False, "error": exc.code, "message": str(exc)}))
        return 2 if exc.code in {"arguments", "css_hash_argument"} else 1
    except OSError:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "io_error",
                    "message": "Release files could not be read; no paths or contents are reported.",
                }
            )
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
