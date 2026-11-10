import re
from pathlib import Path


def test_committed_static_entrypoint_references_existing_assets():
    static_dir = Path(__file__).resolve().parents[2] / "static"
    html = (static_dir / "index.html").read_text(encoding="utf-8")
    assets = re.findall(r"""(?:src|href)=["'](/static/[^"']+)["']""", html)

    assert assets, "static/index.html must reference at least one local asset"
    for asset in assets:
        relative_path = asset.removeprefix("/static/")
        assert (static_dir / relative_path).is_file(), f"missing static asset: {asset}"
