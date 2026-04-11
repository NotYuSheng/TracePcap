#!/usr/bin/env python3
"""
Generate a large synthetic PCAP with 5000+ distinct TCP connections.

Run:  python3 gen_large.py
Output:  large_5k_connections.pcap  (target: <40 MB, >5000 flows)

Strategy: minimal TCP handshake (SYN/SYN-ACK/ACK) per flow plus a small
application payload so each flow is ~5 packets / ~500 bytes on disk.
5 000 flows × 500 B ≈ 2.5 MB — well under the 40 MB budget, so we inflate
with an HTTP-ish payload to produce realistic-looking traffic.

Varied dimensions:
  - 250 client IPs spread across 5 /24 subnets (192.168.1-5.x)
  - 250 server IPs spread across 10 /24 subnets (10.0.1-10.x)
  - 20 dst ports    (common service ports)
  - Unique src port per flow
"""

import os
import sys
import struct
import random

try:
    from scapy.all import wrpcap
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Raw
except ImportError:
    sys.exit("scapy not found — run:  pip install scapy")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT     = os.path.join(SCRIPT_DIR, "large_5k_connections.pcap")

TARGET_FLOWS = 5_200   # slightly above 5 000 to give headroom
SEED         = 42
random.seed(SEED)

# ── address pools ─────────────────────────────────────────────────────────────
# 250 client IPs across 5 /24 subnets: 192.168.1.x – 192.168.5.x (50 hosts each)
CLIENT_IPS = [f"192.168.{b}.{h}" for b in range(1, 6) for h in range(1, 51)]  # 250 IPs

# 250 server IPs across 10 /24 subnets: 10.0.{1..10}.x (25 hosts each)
# This ensures /24 clustering groups them into 10 clusters instead of 250 singletons
SERVER_IPS = [f"10.0.{b}.{h}" for b in range(1, 11) for h in range(1, 26)]  # 250 IPs

DST_PORTS = [
    80, 443, 8080, 8443,        # HTTP/HTTPS
    22, 23, 21, 25, 587,        # SSH, Telnet, FTP, SMTP
    53, 110, 143, 993, 995,     # DNS, POP3, IMAP, secure variants
    3306, 5432, 6379, 27017,    # MySQL, Postgres, Redis, Mongo
    3389, 5900,                  # RDP, VNC
]

CLIENT_MAC = "aa:bb:cc:dd:ee:01"
SERVER_MAC = "aa:bb:cc:dd:ee:02"


MSS = 1460  # max segment size for splitting large payloads

def tcp_flow(src_ip, dst_ip, sport, dport, payload: bytes = b"") -> list:
    """TCP flow: SYN / SYN-ACK / ACK, then segmented data transfer."""
    eth_c = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    eth_s = Ether(src=SERVER_MAC, dst=CLIENT_MAC)

    seq_c, seq_s = 1000, 5000
    pkts = [
        eth_c / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S",  seq=seq_c),
        eth_s / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1),
        eth_c / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A",  seq=seq_c + 1, ack=seq_s + 1),
    ]
    if payload:
        # Split payload into MSS-sized segments
        offset = 0
        seq = seq_c + 1
        while offset < len(payload):
            chunk = payload[offset:offset + MSS]
            last  = (offset + MSS) >= len(payload)
            flags = "PA" if last else "A"
            pkts.append(
                eth_c / IP(src=src_ip, dst=dst_ip)
                / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=seq_s + 1)
                / Raw(chunk)
            )
            seq    += len(chunk)
            offset += len(chunk)
        # Final server ACK
        pkts.append(
            eth_s / IP(src=dst_ip, dst=src_ip)
            / TCP(sport=dport, dport=sport, flags="A", seq=seq_s + 1, ack=seq)
        )
    return pkts


def udp_flow(src_ip, dst_ip, sport, dport, payload: bytes) -> list:
    """Simple UDP request/response pair."""
    eth_c = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    eth_s = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
    return [
        eth_c / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / Raw(payload),
        eth_s / IP(src=dst_ip, dst=src_ip) / UDP(sport=dport, dport=sport) / Raw(b"\x00" * 20),
    ]


def http_get(host: str, path: str = "/") -> bytes:
    # Pad with fake query params and headers to bulk up the payload realistically
    padding = f"X-Request-ID: {'a' * 64}\r\nX-Trace-ID: {'b' * 64}\r\n"
    body = "x" * 9400   # simulate a moderate JSON/form body (~9.5 KB)
    return (
        f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: TestClient/1.0\r\n"
        f"Accept: application/json\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{padding}"
        f"Connection: close\r\n\r\n{body}"
    ).encode()


def dns_query(name: str) -> bytes:
    return bytes(DNS(rd=1, qd=DNSQR(qname=name, qtype="A")))


# ── generate flows ────────────────────────────────────────────────────────────
packets = []
sport_counter = 1025   # monotonically increasing source port

print(f"Generating {TARGET_FLOWS} flows …")

for i in range(TARGET_FLOWS):
    src_ip  = random.choice(CLIENT_IPS)
    dst_ip  = random.choice(SERVER_IPS)
    dport   = random.choice(DST_PORTS)
    sport   = sport_counter
    sport_counter += 1
    if sport_counter > 65000:
        sport_counter = 1025

    if dport == 53:
        # DNS over UDP
        name = f"host{i}.example{random.randint(0,99)}.com"
        packets += udp_flow(src_ip, dst_ip, sport, 53, dns_query(name))
    elif dport in (443, 8443, 993, 995):
        # TLS-ish: TCP handshake + minimal TLS ClientHello marker
        payload = b"\x16\x03\x01" + struct.pack("!H", 32) + bytes(32)  # fake TLS record
        packets += tcp_flow(src_ip, dst_ip, sport, dport, payload)
    else:
        # HTTP-ish plain TCP
        host = f"srv{random.randint(0,99)}.internal"
        path = f"/api/resource/{i}"
        packets += tcp_flow(src_ip, dst_ip, sport, dport, http_get(host, path))

    if (i + 1) % 500 == 0:
        print(f"  {i + 1}/{TARGET_FLOWS} flows ({len(packets)} packets so far) …")

# ── write output ──────────────────────────────────────────────────────────────
print(f"\nWriting {len(packets)} packets to {OUTPUT} …")
wrpcap(OUTPUT, packets)

size_mb = os.path.getsize(OUTPUT) / 1_048_576
print(f"Done.  File size: {size_mb:.1f} MB   Flows: {TARGET_FLOWS}   Packets: {len(packets)}")

if size_mb > 40:
    print("WARNING: file exceeds 40 MB target!")
else:
    print("OK: within 40 MB budget.")
