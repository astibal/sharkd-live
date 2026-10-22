# SharkD Live

Experimental incremental-reading extension for Wireshark's sharkd, maintained as
a small patch stack against an exact upstream revision. This repository contains
the patch and differential tests, not a vendored copy of Wireshark.

**Prototype only.** No production binary release, stable API, or automatic Viewer
integration is provided yet. See [results and limitations](docs/prototype.md).

## Pinned upstream

* Source: https://github.com/wireshark/wireshark.git
* Tag: `v4.6.6`
* Commit: `3a22c3ef473d3f9c556d1fb13e3088c693d4fa96`
* Patch: `patches/wireshark-4.6.6-live.patch`

## Build

Install Wireshark's normal build dependencies first (C/C++ toolchain, CMake,
Ninja, Python, Flex, GLib, libgcrypt, c-ares, PCRE2, libxml2 and SpeexDSP development
packages, plus optional dependencies required by your production feature set).

```sh
bash scripts/prepare.sh
cmake -S .work/wireshark -B build -G Ninja \
  -DBUILD_wireshark=OFF -DBUILD_sharkd=ON
cmake --build build --target sharkd -j 8
python3 tests/sharkd_live.py --live "$PWD/build/run/sharkd" --stock /usr/bin/sharkd
```

Preparation clones upstream into `.work/wireshark`, checks its exact commit and
applies the patch. It refuses to reuse an existing checkout; it never resets or
overwrites it. Neither build nor test installs anything or replaces system sharkd.

## Ownership and distribution boundary

Viewer backend owns capability detection and worker lifecycle. Portal and Saslik
consume Viewer, not this experimental RPC directly. Future releases should ship
a versioned private binary/library bundle, not overwrite `/usr/bin/sharkd`.
Runtime replacement and cache compatibility are specified in the prototype doc;
production integration remains to be implemented.

## Licensing and provenance

The upstream-derived patch is GPL-2.0-or-later, matching the modified Wireshark
files. New code and documentation in this repository are GPL-2.0-or-later.
See `COPYING`. Distributed builds must include the corresponding source and
applicable upstream notices. Do not treat this prototype tree as a complete
binary-release source bundle.

The differential harness and fixture were copied from the Capture.Zone Viewer
working tree (`benchmarks/sharkd_live.py`, `tests/fixtures/ipv6.pcapng`). The fixture
is a 10-packet regression sample; no Honeynet captures or runtime data are bundled.

Before a public release, finish the gates in `docs/prototype.md`, preserve all
upstream notices and verify the provenance/licensing of bundled test assets.
