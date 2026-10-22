# Incremental sharkd prototype

This is an isolated feasibility experiment, **not installed in the viewer or lab**.
The patch targets Wireshark `v4.6.6`, commit
`3a22c3ef473d3f9c556d1fb13e3088c693d4fa96`. It inherits the upstream source's
GPL-2.0-or-later license. No public fork or compatibility commitment is made yet.

## Build and test

Apply `patches/wireshark-4.6.6-live.patch` to that exact upstream tree with `git apply`.
Install the ordinary Wireshark build dependencies in your build environment, then:

```sh
cmake -S wireshark -B build -G Ninja -DBUILD_wireshark=OFF -DBUILD_sharkd=ON
cmake --build build --target sharkd -j 8
python3 tests/sharkd_live.py --live /absolute/path/to/build/run/sharkd
```

The differential harness creates its own temporary captures and configuration.
It compares live packet lists, filtered lists, the earlier HTTP request's protocol
tree, and TCP follow with a full reload after each append. It covers PCAP and
PCAPNG, deliberately split writes, idempotent calls, and poisoning after an
incorrect committed packet count. It checks stock capability fallback too.

## Measured result (2026-10-22)

The prototype built successfully and passed the differential fixture tests for
both PCAPNG and nanosecond PCAP (six append steps each). Packet list, HTTP filter,
request protocol tree and TCP follow results matched full loads. A split record
was not consumed before commit. Failed appends required reopen. The experimental
adapter switched live -> stock -> live and kept the original worker after a
candidate failed to open its file. This does not yet prove production pool
concurrency or persistent-cache integration.

Read-only source sample: `capture-2026-10-08_00-01-24.pcap`, 27,500,270 bytes
(26.23 MiB), 80,318 complete packets. Ten approximately equal increments:

| Measurement | Incremental | Fresh-worker full load |
| --- | ---: | ---: |
| Sum of ten load/append RPC times | 1.480 s | 9.699 s |
| Last update | 0.147 s | 1.627 s |

Incremental update times stayed between 0.146 and 0.152 s. The sum was about
6.6x faster in this single warm-filesystem run. The same prototype binary's
unchanged `load` path was used for the full-load comparison. Each prefix also
passed equality checks on its final 50 packet rows and first 50 HTTP responses.
Timings exclude file writing, framing scans, result validation and UI work; the
full-load RPC includes waiting for the new process to become ready. This is not
an end-to-end viewer benchmark or a guarantee for other traffic.

The local build disables optional Lua, GnuTLS and Kerberos support and is **not**
a production replacement for the installed binary. Normal packaging must retain
the same features/plugins as the standard build. No runtime installation changed.

Reproduce the additional measurement with:

```sh
python3 tests/sharkd_live.py --live /absolute/path/to/build/run/sharkd \
  --capture /absolute/path/to/sample.pcap
```

## Protocol experiment

* `live-capabilities` returns `{"append_protocol": 1}`. Stock responds with JSON-RPC
  method-not-found. Only that specific error means “unsupported”; transport,
  timeout, and malformed-response errors must not silently become fallback.
* `live-open(file, packets)` opens a new sequential reader and dissects precisely
  the supplied **absolute complete packet count**, including zero.
* `live-append(packets)` continues that reader to the new absolute count. An equal
  count is idempotent. The caller guarantees an unchanged append-only prefix.
* Failure poisons the live session. Reopen before attempting another append.
* Existing `load` retains stock semantics and exits live mode.

The count must come from a framing-aware scanner, not a size/average estimate.
In PCAPNG, count packet blocks, not metadata blocks. This first prototype does
not independently validate inode/prefix changes and is therefore not a safe
general-purpose live API for arbitrary callers yet.

The reader and epan state remain alive; the ordinary end-of-file cleanup is not
run between appends. Filter bitsets are invalidated globally: a new response can
change fields on a previously observed request. No offsets, Wiretap internals or
epan objects are persisted in the viewer cache.

## Runtime backend replacement contract

This contract is a design requirement, not yet wired into the production pool:

1. Select a configured binary and start a candidate worker with the SAME profile,
   preferences, plugins and interpretation settings; probe its capabilities.
2. Pin a source generation and committed packet count. Load that same prefix via
   `live-open` or stock `load(max_packets=...)`.
3. Only publish the candidate after successful loading and validation. Swap the
   worker pointer under the session lock; drain the old worker's requests before
   closing it. A failed candidate leaves the working view intact.
4. A changed binary configuration causes replacement, never mutation of an
   in-flight process. Switching live -> stock -> live must not import another
   archive item or modify the source.
5. Cache identity uses capture identity + source generation/revision + committed
   prefix + interpretation settings + dissection semantic version. The mere
   presence of live support is NOT a cache key. Different upstream/plugin
   semantics DO invalidate affected dissection results; “cache unaffected” must
   not mean serving stale results from an incompatible dissector version.
6. Growing revisions invalidate derived packet/filter/response caches, including
   earlier packets affected by later reassembly. Immutable content-addressed
   artefacts stay reusable. Never publish partially failed append results.

## Gates before production

* Backend adapter and atomic runtime switch tests, with queued/concurrent calls.
* Incremental framing scanner: PCAP endian/nanosecond variants, PCAPNG multiple
  sections/interfaces and packet block types, bounded lengths, trailing metadata.
* Source generation guards: truncation, rewrite, rotation, and inaccessible file.
* Fault injection: OOM/dissector exceptions, malformed blocks, worker death,
  producer shutdown, requests interleaved with append.
* Broader differential corpus: fragmented/retransmitted TCP, TLS secrets, HTTP/2,
  custom Smithproxy blocks, taps and iographs, and long-running memory growth.
* Stock fallback performance on realistic captures, with admission-controlled
  background replacement and no refresh storm.

In particular, metadata-only PCAPNG appends (e.g. new decryption secrets) are not
represented by packet count alone. Production needs a committed block boundary
and a defined redissection policy. This is intentionally NOT hidden by the small
packet-count prototype.
