#!/usr/bin/env python3
"""Isolated differential test for the experimental sharkd append protocol.

No library, application cache or running viewer is touched. The committed packet
count is supplied by this fixture writer, never inferred from file size. Production
integration needs a framing scanner and a source-generation guard instead.
"""
import argparse
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import tempfile
import time


class RPCError(RuntimeError):
    def __init__(self, error):
        super().__init__(error)
        self.code = error.get("code")


class RPC:
    def __init__(self, binary, config):
        self.err = tempfile.TemporaryFile()
        self.p = subprocess.Popen(
            [binary, "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.err, env={**os.environ, "WIRESHARK_CONFIG_DIR": str(config)},
        )
        self.ident = 0
        self.buffer = b""

    def call(self, method, **params):
        if method == "frames" and params.get("skip") == 0:
            params.pop("skip")  # Stock validates explicit skip as strictly positive.
        self.ident += 1
        self.p.stdin.write(json.dumps(dict(jsonrpc="2.0", id=self.ident,
                                         method=method, params=params)).encode() + b"\n")
        self.p.stdin.flush()
        deadline = time.monotonic() + 60
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.p.stdout], [], [], remaining)[0]:
                raise TimeoutError(method)
            data = os.read(self.p.stdout.fileno(), 65536)
            if not data:
                self.err.seek(0)
                raise RuntimeError(self.err.read().decode(errors="replace")[-3000:])
            self.buffer += data
        line, self.buffer = self.buffer.split(b"\n", 1)
        value = json.loads(line)
        assert value["id"] == self.ident
        if "error" in value:
            raise RPCError(value["error"])
        result = value["result"]
        if isinstance(result, dict) and result.get("err"):
            raise RuntimeError(result)
        return result

    def close(self):
        self.p.terminate()
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        self.p.stdin.close()
        self.p.stdout.close()
        self.err.close()


def fixture_parts(source):
    """Split our little-endian, single-interface fixture at packet boundaries."""
    data = source.read_bytes()
    offset = 0
    packets = []
    header = b""
    while offset < len(data):
        kind, length = struct.unpack_from("<II", data, offset)
        assert length >= 12 and length % 4 == 0
        block = data[offset:offset + length]
        assert len(block) == length and struct.unpack_from("<I", block, length - 4)[0] == length
        if kind == 6:
            packets.append(block)
        else:
            assert not packets, "This test fixture must have only leading metadata"
            header += block
        offset += length
    return header, packets


class SwitchingSession:
    """Single-threaded prototype of prepare-before-publish backend handover.

    Production must add session locks, reader leases, source generation checks
    and capacity admission. It must NOT cache this worker's internal state.
    """
    def __init__(self, config):
        self.config = config
        self.worker = None
        self.live = False

    def switch(self, binary, path, committed):
        candidate = RPC(binary, self.config)
        try:
            try:
                capable = candidate.call("live-capabilities").get("append_protocol") == 1
            except RPCError as error:
                if error.code != -32601:
                    raise
                capable = False
            if capable:
                candidate.call("live-open", file=str(path), packets=committed)
            else:
                if committed == 0:
                    raise ValueError("Stock max_packets=0 means unlimited, not empty")
                candidate.call("load", file=str(path), max_packets=committed)
            assert candidate.call("status")["frames"] == committed
        except BaseException:
            candidate.close()
            raise
        old = self.worker
        self.worker, self.live = candidate, capable
        if old:
            old.close()


def views(rpc):
    # Filtered results exercise cache invalidation; frame 4 acquires an HTTP
    # response link after frame 6 arrives. Follow exercises TCP reassembly.
    return {
        "frames": rpc.call("frames", skip=0, limit=100),
        "responses": rpc.call("frames", filter="http.response", skip=0, limit=100),
        "answered_requests": rpc.call("frames", filter="http.response_in", skip=0, limit=100),
        "request": rpc.call("frame", frame=4, proto=True),
        "follow": rpc.call("follow", follow="TCP", filter="tcp.stream eq 0"),
    }


def run(binary, stock, fixture):
    results = []
    header, packets = fixture_parts(fixture)
    # This fixture's IDB declares LINKTYPE_RAW (101) and if_tsresol=9.
    # Preserve nanoseconds and link type when constructing its PCAP equivalent.
    pcap_header = struct.pack("<IHHIIII", 0xa1b23c4d, 2, 4, 0, 0, 262144, 101)
    pcap_packets = []
    for block in packets:
        _, hi, lo, caplen, wirelen = struct.unpack_from("<IIIII", block, 8)
        ticks = (hi << 32) | lo
        pcap_packets.append(struct.pack("<IIII", ticks // 1000000000, ticks % 1000000000,
                                        caplen, wirelen) + block[28:28 + caplen])
    with tempfile.TemporaryDirectory(prefix="sharkd-live-test-") as directory:
        root = Path(directory)
        config = root / "config"
        config.mkdir()
        for suffix, prefix, records in [("pcapng", header, packets),
                                        ("pcap", pcap_header, pcap_packets)]:
            path = root / ("growing." + suffix)
            path.write_bytes(prefix + b"".join(records[:4]))
            live, full = RPC(binary, config), RPC(binary, config)
            try:
                assert live.call("live-capabilities")["append_protocol"] == 1
                live.call("live-open", file=str(path), packets=4)
                # Populate caches before a response exists.
                views(live)
                append_ms = []
                for count in range(5, len(records) + 1):
                    record = records[count - 1]
                    with path.open("ab") as output:
                        output.write(record[:7])
                    # A writer can pause midway through a header. No new packet
                    # has been committed, so an idempotent append must not read it.
                    live.call("live-append", packets=count - 1)
                    assert live.call("status")["frames"] == count - 1
                    with path.open("ab") as output:
                        output.write(record[7:])
                    start = time.monotonic()
                    live.call("live-append", packets=count)
                    append_ms.append((time.monotonic() - start) * 1000)
                    full.call("load", file=str(path))
                    actual, expected = views(live), views(full)
                    for key in expected:
                        assert actual[key] == expected[key], (suffix, count, key, actual[key], expected[key])
                # Incorrect boundary poisons the reader; a subsequent append is
                # rejected until reopen. Do not silently publish partial results.
                for count in [len(records) + 1, len(records)]:
                    try:
                        live.call("live-append", packets=count)
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError("Expected failed/poisoned append")
                live.call("live-open", file=str(path), packets=len(records))
                assert live.call("status")["frames"] == len(records)
                results.append(dict(format=suffix, packets=len(records),
                                    differential_steps=len(append_ms), append_ms=append_ms))
            finally:
                live.close()
                full.close()
        fallback = RPC(stock, config)
        try:
            try:
                fallback.call("live-capabilities")
            except RPCError as error:
                assert error.code == -32601, error
            else:
                raise AssertionError("Expected unmodified stock sharkd")
            fallback.call("load", file=str(path), max_packets=len(records))
            assert fallback.call("status")["frames"] == len(records)
        finally:
            fallback.close()
        session = SwitchingSession(config)
        try:
            for executable, expected in [(binary, True), (stock, False), (binary, True)]:
                session.switch(executable, path, len(records))
                assert session.live is expected
                assert session.worker.call("status")["frames"] == len(records)
            before = session.worker
            try:
                session.switch(stock, root / "missing.pcap", len(records))
            except RuntimeError:
                pass
            else:
                raise AssertionError("Missing source must not publish a candidate")
            assert session.worker is before
            assert session.worker.call("status")["frames"] == len(records)
            results.append(dict(handover="live -> stock -> live", failed_candidate="old worker retained"))
        finally:
            if session.worker:
                session.worker.close()
    return results


def measure_capture(binary, source):
    """Compare ten growing-prefix loads on a real classic PCAP, without logging payloads."""
    data = source.read_bytes()
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}[data[:4]]
    ends = []
    offset = 24
    while offset + 16 <= len(data):
        length = struct.unpack_from(endian + "I", data, offset + 8)[0]
        end = offset + 16 + length
        if end > len(data):
            break  # A captured file may itself have an unfinished final record.
        ends.append(end)
        offset = end
    assert ends
    measurements = []
    with tempfile.TemporaryDirectory(prefix="sharkd-live-perf-") as directory:
        root = Path(directory)
        config = root / "config"
        config.mkdir()
        path = root / "growing.pcap"
        path.write_bytes(data[:24])
        live = RPC(binary, config)
        try:
            live.call("live-open", file=str(path), packets=0)
            previous_end = 24
            for count in sorted({max(1, len(ends) * step // 10) for step in range(1, 11)}):
                end = ends[count - 1]
                with path.open("ab") as output:
                    output.write(data[previous_end:end])
                previous_end = end
                start = time.monotonic()
                live.call("live-append", packets=count)
                incremental = time.monotonic() - start
                # Fresh worker avoids repeated-load resource retention in stock.
                full = RPC(binary, config)
                try:
                    start = time.monotonic()
                    full.call("load", file=str(path), max_packets=count)
                    reload = time.monotonic() - start
                    assert live.call("status")["frames"] == count
                    for parameters in [dict(skip=max(0, count - 50), limit=50),
                                       dict(filter="http.response", skip=0, limit=50)]:
                        assert live.call("frames", **parameters) == full.call("frames", **parameters)
                finally:
                    full.close()
                measurements.append(dict(packets=count, append_seconds=incremental,
                                         replacement_load_seconds=reload))
        finally:
            live.close()
    return dict(bytes=len(data), complete_packets=len(ends), steps=measurements,
                append_total_seconds=sum(x["append_seconds"] for x in measurements),
                replacement_total_seconds=sum(x["replacement_load_seconds"] for x in measurements))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", required=True)
    parser.add_argument("--stock", default="sharkd")
    parser.add_argument("--fixture", type=Path, default=Path(__file__).resolve().parents[1] / "tests/fixtures/ipv6.pcapng")
    parser.add_argument("--capture", type=Path, help="Optional read-only real PCAP performance sample")
    args = parser.parse_args()
    print(json.dumps(run(args.live, args.stock, args.fixture), indent=2))
    if args.capture:
        print(json.dumps(measure_capture(args.live, args.capture), indent=2))
