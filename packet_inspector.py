#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
packet_inspector.py — XTTP packet visualization

- Parse XTTP frames from PCAP or hex logs
- Validate fields against a schema
- Render timelines and per-field diffs
- Export JSON for downstream tooling

Usage:
  python packet_inspector.py --pcap capture.pcap
  python packet_inspector.py --hex logs/xttp_hex.txt
  python packet_inspector.py --method QUERY --out packets.json
"""

import argparse
import binascii
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Optional dependencies gated to run without them when parsing hex logs only.
try:
    from scapy.all import rdpcap, Raw
except Exception:
    rdpcap = None
    Raw = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except Exception:
    Console = None
    Table = None
    Panel = None
    box = None

# -------------------------
# XTTP schema (adjust as needed)
# -------------------------

# Simple helpers for typed reads from a bytes cursor
def read_u8(buf, off):
    return buf[off], off + 1

def read_u16(buf, off):
    return int.from_bytes(buf[off:off+2], "big"), off + 2

def read_u32(buf, off):
    return int.from_bytes(buf[off:off+4], "big"), off + 4

def read_len_prefixed_str(buf, off):
    """Reads: u16 length, then UTF-8 bytes"""
    ln, off = read_u16(buf, off)
    s = buf[off:off+ln]
    try:
        val = s.decode("utf-8", errors="replace")
    except Exception:
        val = s.hex()
    return val, off + ln

def read_len_prefixed_bytes(buf, off):
    ln, off = read_u16(buf, off)
    return buf[off:off+ln], off + ln

# Define the protocol fields and parsers.
# Tailor this to your wire format.
XTTP_SCHEMA = [
    ("version", read_u8),
    ("flags", read_u8),
    ("session_id", read_u32),
    ("seq", read_u32),
    ("method", read_len_prefixed_str),   # e.g., QUERY, SEND, ACK
    ("status", read_u16),                # e.g., 0, 200, 404 (optional for responses)
    ("path", read_len_prefixed_str),     # e.g., /resource/sub
    ("header_count", read_u16),
    ("headers", "headers"),              # k/v pairs (header_count items)
    ("payload_len", read_u32),
    ("payload", "payload"),
    ("aead_tag_len", read_u16),
    ("aead_tag", "aead"),
]

ALLOWED_METHODS = {"QUERY", "SEND", "ACK", "PING", "PONG"}

@dataclass
class XTTPPacket:
    raw: bytes
    fields: Dict[str, Any]
    src: Optional[str] = None
    dst: Optional[str] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    ts: Optional[float] = None
    flow_key: Optional[Tuple[str, int, str, int]] = None

# -------------------------
# Parsing
# -------------------------

class XTTPParser:
    def parse(self, raw: bytes) -> XTTPPacket:
        off = 0
        fields: Dict[str, Any] = {}

        # Basic sequential parsing
        for name, reader in XTTP_SCHEMA:
            if reader == "headers":
                hc = fields.get("header_count", 0)
                headers = []
                for _ in range(hc):
                    k, off = read_len_prefixed_str(raw, off)
                    v, off = read_len_prefixed_str(raw, off)
                    headers.append((k, v))
                fields["headers"] = headers
                continue
            elif reader == "payload":
                # Uses payload_len
                ln = fields.get("payload_len", 0)
                payload = raw[off:off+ln]
                fields["payload"] = payload
                off += ln
                continue
            elif reader == "aead":
                ln = fields.get("aead_tag_len", 0)
                aead = raw[off:off+ln]
                fields["aead_tag"] = aead
                off += ln
                continue
            else:
                val, off = reader(raw, off)
                fields[name] = val

        self._validate(fields, raw_len=len(raw))
        return XTTPPacket(raw=raw, fields=fields)

    def _validate(self, fields: Dict[str, Any], raw_len: int):
        # Version bounds
        ver = fields.get("version", 0)
        if ver not in (1, 2):  # tweak as needed
            fields["_warn_version"] = f"Unexpected version: {ver}"

        # Method check
        method = fields.get("method", "")
        if method and method not in ALLOWED_METHODS:
            fields["_warn_method"] = f"Unknown method: {method}"

        # Payload length consistency
        plen = fields.get("payload_len", 0)
        payload = fields.get("payload", b"")
        if plen != len(payload):
            fields["_warn_payload_len"] = f"Declared {plen}, actual {len(payload)}"

        # AEAD tag sanity
        tlen = fields.get("aead_tag_len", 0)
        aead = fields.get("aead_tag", b"")
        if tlen != len(aead):
            fields["_warn_aead_len"] = f"Declared {tlen}, actual {len(aead)}"

# -------------------------
# Sources: PCAP or hex log
# -------------------------

def load_hex_lines(path: str) -> List[bytes]:
    packets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                packets.append(binascii.unhexlify(s))
            except Exception:
                # Allow spaced hex
                s2 = s.replace(" ", "")
                packets.append(binascii.unhexlify(s2))
    return packets

def load_pcap(path: str) -> List[Tuple[bytes, float, str, int, str, int]]:
    if rdpcap is None:
        raise RuntimeError("PCAP parsing requires scapy. Please: pip install scapy")
    pkts = rdpcap(path)
    out = []
    for p in pkts:
        ts = float(getattr(p, "time", 0.0))
        raw = None
        src = dst = None
        sport = dport = None
        try:
            if Raw in p:
                raw = bytes(p[Raw].load)
            # Try to infer addresses/ports
            if hasattr(p, "haslayer"):
                if p.haslayer("IP"):
                    src = p["IP"].src
                    dst = p["IP"].dst
                if p.haslayer("TCP"):
                    sport = p["TCP"].sport
                    dport = p["TCP"].dport
                elif p.haslayer("UDP"):
                    sport = p["UDP"].sport
                    dport = p["UDP"].dport
        except Exception:
            pass
        if raw:
            out.append((raw, ts, src, sport, dst, dport))
    return out

# -------------------------
# Rendering
# -------------------------

def fmt_bytes(b: bytes, max_len: int = 64) -> str:
    if not b:
        return ""
    h = b.hex()
    if len(h) > max_len:
        return h[:max_len] + "...+" + str(len(b)) + "B"
    return h

def safe_text(b: bytes, max_len: int = 96) -> str:
    try:
        s = b.decode("utf-8", errors="replace")
    except Exception:
        s = b.hex()
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s

def make_flow_key(pkt: XTTPPacket) -> Optional[Tuple[str, int, str, int]]:
    if pkt.src and pkt.dst and pkt.sport and pkt.dport:
        return (pkt.src, pkt.sport, pkt.dst, pkt.dport)
    return None

def render_packets(console: Optional[Any], packets: List[XTTPPacket], title: str = "XTTP Packets"):
    # Fallback to plain text if rich is unavailable
    if console is None or Table is None or Panel is None:
        print(f"=== {title} ===")
        for i, p in enumerate(packets):
            f = p.fields
            print(f"[{i}] ts={p.ts} {p.src}:{p.sport} -> {p.dst}:{p.dport} seq={f.get('seq')} method={f.get('method')} status={f.get('status')}")
            print(f"   path={f.get('path')} payload={fmt_bytes(f.get('payload', b''))} aead={fmt_bytes(f.get('aead_tag', b''))}")
            for k in sorted(f.keys()):
                if k.startswith("_warn"):
                    print(f"   WARN {k}: {f[k]}")
        return

    table = Table(title=title, box=box.MINIMAL_HEAVY_HEAD)
    table.add_column("Idx", style="bold cyan", width=4)
    table.add_column("Time", style="magenta", width=10)
    table.add_column("Flow", style="green")
    table.add_column("Seq", style="yellow", width=7)
    table.add_column("Method", style="bold")
    table.add_column("Status", style="bold")
    table.add_column("Path")
    table.add_column("Payload")
    table.add_column("AEAD")

    for i, p in enumerate(packets):
        f = p.fields
        flow = f"{p.src}:{p.sport} → {p.dst}:{p.dport}" if all([p.src, p.sport, p.dst, p.dport]) else "—"
        table.add_row(
            str(i),
            f"{p.ts:.3f}" if p.ts else "—",
            flow,
            str(f.get("seq", "—")),
            str(f.get("method", "—")),
            str(f.get("status", "—")),
            f.get("path", "—"),
            fmt_bytes(f.get("payload", b"")),
            fmt_bytes(f.get("aead_tag", b""))
        )

    console.print(table)

    # Per-field warnings panel
    warns = []
    for p in packets:
        for k, v in p.fields.items():
            if k.startswith("_warn"):
                warns.append((k, v))
    if warns:
        content = "\n".join([f"{k}: {v}" for (k, v) in warns])
        console.print(Panel(content, title="Validation warnings", border_style="red"))

def timeline_by_flow(console: Optional[Any], packets: List[XTTPPacket]):
    if console is None or Table is None:
        print("=== Timeline by flow ===")
        by_flow: Dict[str, List[XTTPPacket]] = {}
        for p in packets:
            key = p.flow_key or "unknown"
            by_flow.setdefault(str(key), []).append(p)
        for flow, items in by_flow.items():
            print(f"Flow {flow}:")
            for p in sorted(items, key=lambda x: (x.ts or 0.0, x.fields.get("seq", 0))):
                print(f"  t={p.ts} seq={p.fields.get('seq')} method={p.fields.get('method')} status={p.fields.get('status')} path={p.fields.get('path')}")
        return

    # Rich table grouped by flow
    grouped: Dict[str, List[XTTPPacket]] = {}
    for p in packets:
        key = p.flow_key or ("unknown", 0, "unknown", 0)
        grouped.setdefault(str(key), []).append(p)

    for flow, items in grouped.items():
        table = Table(title=f"Flow {flow}", box=box.SIMPLE)
        table.add_column("Time", width=10)
        table.add_column("Seq", width=7)
        table.add_column("Method", width=10)
        table.add_column("Status", width=8)
        table.add_column("Path")
        table.add_column("Headers")
        table.add_column("Payload (text)")
        for p in sorted(items, key=lambda x: (x.ts or 0.0, x.fields.get("seq", 0))):
            f = p.fields
            headers = ", ".join([f"{k}={v}" for k, v in f.get("headers", [])])
            table.add_row(
                f"{p.ts:.3f}" if p.ts else "—",
                str(f.get("seq", "—")),
                str(f.get("method", "—")),
                str(f.get("status", "—")),
                f.get("path", "—"),
                headers,
                safe_text(f.get("payload", b""))
            )
        console.print(table)

# -------------------------
# Diffing successive packets
# -------------------------

def field_diff(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Tuple[Any, Any]]:
    diff = {}
    keys = set(a.keys()) | set(b.keys())
    for k in keys:
        if a.get(k) != b.get(k):
            diff[k] = (a.get(k), b.get(k))
    return diff

def render_diffs(console: Optional[Any], packets: List[XTTPPacket]):
    if not packets:
        return
    # Group by flow and sort by seq/time, then show diffs
    flows: Dict[str, List[XTTPPacket]] = {}
    for p in packets:
        key = p.flow_key or "unknown"
        flows.setdefault(str(key), []).append(p)

    for flow, items in flows.items():
        items = sorted(items, key=lambda x: (x.ts or 0.0, x.fields.get("seq", 0)))
        if console is None or Table is None or Panel is None:
            print(f"=== Diffs for {flow} ===")
            for i in range(1, len(items)):
                d = field_diff(items[i-1].fields, items[i].fields)
                print(f"  [{i-1}→{i}] {len(d)} fields changed: {list(d.keys())}")
            continue

        table = Table(title=f"Diffs for {flow}", box=box.SIMPLE_HEAVY)
        table.add_column("Prev→Curr", width=10)
        table.add_column("Changed fields")
        for i in range(1, len(items)):
            d = field_diff(items[i-1].fields, items[i].fields)
            changed = ", ".join(sorted(d.keys()))
            table.add_row(f"{i-1}→{i}", changed or "—")
        console.print(table)

# -------------------------
# Aggregates
# -------------------------

def aggregates(console: Optional[Any], packets: List[XTTPPacket]):
    by_method: Dict[str, int] = {}
    statuses: Dict[int, int] = {}
    for p in packets:
        m = p.fields.get("method")
        if m:
            by_method[m] = by_method.get(m, 0) + 1
        s = p.fields.get("status")
        if isinstance(s, int):
            statuses[s] = statuses.get(s, 0) + 1

    if console is None or Table is None:
        print("=== Aggregates ===")
        print("By method:", by_method)
        print("By status:", statuses)
        return

    t1 = Table(title="By method", box=box.MINIMAL)
    t1.add_column("Method", style="bold")
    t1.add_column("Count", style="yellow")
    for k, v in sorted(by_method.items()):
        t1.add_row(k, str(v))

    t2 = Table(title="By status", box=box.MINIMAL)
    t2.add_column("Status", style="bold")
    t2.add_column("Count", style="yellow")
    for k, v in sorted(statuses.items()):
        t2.add_row(str(k), str(v))

    console.print(t1)
    console.print(t2)

# -------------------------
# CLI
# -------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="XTTP packet inspector and visualization")
    ap.add_argument("--pcap", type=str, help="PCAP file containing XTTP payloads")
    ap.add_argument("--hex", type=str, help="Text file with newline-delimited hex frames")
    ap.add_argument("--method", type=str, help="Filter by method (e.g., QUERY)")
    ap.add_argument("--status", type=int, help="Filter by status code")
    ap.add_argument("--session", type=int, help="Filter by session_id")
    ap.add_argument("--out", type=str, help="Export parsed packets as JSON")
    ap.add_argument("--limit", type=int, default=0, help="Limit packet count")
    return ap.parse_args()

def main():
    args = parse_args()
    parser = XTTPParser()

    # Console for pretty output
    console_instance = Console() if Console else None

    raw_entries: List[Tuple[bytes, float, str, int, str, int]] = []

    if args.pcap:
        raw_entries = load_pcap(args.pcap)
    elif args.hex:
        raw_hex = load_hex_lines(args.hex)
        # synthesize minimal metadata
        raw_entries = [(b, None, None, None, None, None) for b in raw_hex]
    else:
        print("Provide --pcap or --hex.")
        sys.exit(1)

    packets: List[XTTPPacket] = []
    for (raw, ts, src, sport, dst, dport) in raw_entries:
        try:
            pkt = parser.parse(raw)
            pkt.ts = ts
            pkt.src = src
            pkt.sport = sport
            pkt.dst = dst
            pkt.dport = dport
            pkt.flow_key = make_flow_key(pkt)
            packets.append(pkt)
        except Exception as e:
            # Keep going; record malformed frames as warnings
            bad = XTTPPacket(raw=raw, fields={"_warn_parse": str(e)})
            bad.ts = ts
            packets.append(bad)

    # Filters
    def keep(p: XTTPPacket) -> bool:
        if args.method and p.fields.get("method") != args.method:
            return False
        if args.status is not None:
            if p.fields.get("status") != args.status:
                return False
        if args.session is not None:
            if p.fields.get("session_id") != args.session:
                return False
        return True

    packets = [p for p in packets if keep(p)]
    if args.limit and args.limit > 0:
        packets = packets[:args.limit]

    # Render
    render_packets(console_instance, packets, title="XTTP Packets")
    timeline_by_flow(console_instance, packets)
    render_diffs(console_instance, packets)
    aggregates(console_instance, packets)

    # Export
    if args.out:
        serial = []
        for p in packets:
            f = dict(p.fields)
            # Normalize bytes to hex
            for k in ("payload", "aead_tag"):
                if isinstance(f.get(k), (bytes, bytearray)):
                    f[k] = f[k].hex()
            serial.append({
                "ts": p.ts,
                "src": p.src,
                "sport": p.sport,
                "dst": p.dst,
                "dport": p.dport,
                "fields": f
            })
        with open(args.out, "w", encoding="utf-8") as fo:
            json.dump(serial, fo, indent=2)
        if console_instance:
            console_instance.print(Panel(f"Exported {len(serial)} packets to {args.out}", border_style="green"))
        else:
            print(f"Exported {len(serial)} packets to {args.out}")

if __name__ == "__main__":
    main()
