#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Prepare a disposable upstream worktree; never modify an existing checkout.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_dir="$repo_root/.work/wireshark"
revision=3a22c3ef473d3f9c556d1fb13e3088c693d4fa96
if [[ -e "$source_dir" ]]; then
    echo "Refusing existing checkout: $source_dir" >&2
    exit 1
fi
mkdir -p "$repo_root/.work"
git clone --depth 1 --branch v4.6.6 https://github.com/wireshark/wireshark.git "$source_dir"
actual=$(git -C "$source_dir" rev-parse HEAD)
if [[ "$actual" != "$revision" ]]; then
    echo "Upstream revision mismatch: expected $revision, got $actual" >&2
    exit 1
fi
git -C "$source_dir" apply --check "$repo_root/patches/wireshark-4.6.6-live.patch"
git -C "$source_dir" apply "$repo_root/patches/wireshark-4.6.6-live.patch"
echo "Prepared $source_dir at $revision with SharkD Live patch"
