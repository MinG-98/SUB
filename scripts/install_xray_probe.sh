#!/usr/bin/env bash
set -euo pipefail

readonly version="v26.11.9"
readonly asset="Xray-linux-64.zip"
readonly expected_sha256="b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82"
readonly target="/usr/local/libexec/sub-app-xray-probe"
readonly url="https://github.com/XTLS/Xray-core/releases/download/${version}/${asset}"

if [[ "$(id -u)" -ne 0 ]]; then
    printf 'Run as root (for example: sudo %s)\n' "$0" >&2
    exit 1
fi

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
    printf 'This pinned asset supports Linux x86_64 only.\n' >&2
    exit 1
fi

for tool in curl sha256sum unzip install mv; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'Required command is missing: %s\n' "$tool" >&2
        exit 1
    fi
done

tmp_dir="$(mktemp -d /tmp/sub-app-xray-probe.XXXXXX)"
staged=""
cleanup() {
    rm -rf -- "$tmp_dir"
    if [[ -n "$staged" ]]; then
        rm -f -- "$staged"
    fi
}
trap cleanup EXIT

archive="${tmp_dir}/${asset}"
binary="${tmp_dir}/xray"

curl --fail --location --retry 2 --silent --show-error \
    --proto '=https' --tlsv1.2 "$url" --output "$archive"
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check --status
unzip -p "$archive" xray > "$binary"
chmod 0755 "$binary"
"$binary" version | grep -F "Xray 26.11.9" >/dev/null

install -d -o root -g root -m 0755 /usr/local/libexec
staged="$(mktemp /usr/local/libexec/.sub-app-xray-probe.XXXXXX)"
install -o root -g root -m 0755 "$binary" "$staged"
if [[ -L "$target" || -d "$target" ]]; then
    printf 'Refusing to replace a symlink or directory at %s\n' "$target" >&2
    exit 1
fi
mv -f -- "$staged" "$target"
staged=""
"$target" version
