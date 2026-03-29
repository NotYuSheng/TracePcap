#!/usr/bin/env python3
"""
Generate demo_all_rules.pcap — a single capture that exercises every
TracePcap custom signature match type.

Run:  python3 gen_demo.py
Output:  demo_all_rules.pcap  (in the same directory)

After running, check the printed JA3 hash and update signatures.yml if needed.
"""

import hashlib
import os
import struct
import sys

try:
    from scapy.all import wrpcap, rdpcap
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.packet import Raw
except ImportError:
    sys.exit("scapy not found — run:  pip install scapy")

# MAC addresses used in synthetic frames
CLIENT_MAC = "aa:bb:cc:dd:ee:01"
GW_MAC     = "aa:bb:cc:dd:ee:02"
BCAST_MAC  = "ff:ff:ff:ff:ff:ff"

def eth(src_mac=CLIENT_MAC, dst_mac=GW_MAC):
    """Ethernet header for unicast synthetic frame."""
    return Ether(src=src_mac, dst=dst_mac)

def eth_bcast():
    """Ethernet header for broadcast frame."""
    return Ether(src=CLIENT_MAC, dst=BCAST_MAC)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── IPs ─────────────────────────────────────────────────────────────────────
CLIENT_IP   = "192.168.100.10"
DROPBOX_IP  = "162.125.19.131"   # → dropbox_telemetry_server  (ip exact)
AZURE_IP    = "52.114.128.5"     # → microsoft_azure_traffic   (cidr 52.114.0.0/16)
TROUTER_IP  = "52.114.252.8"     # → teams_trouter_signalling  (ip+dstPort) + microsoft_azure_traffic
DNS_SERVER  = "8.8.8.8"
TARGET_PORT = "203.0.113.10"     # generic target for port-based rules
TARGET_SNI  = "203.0.113.20"     # target for TLS-SNI flows
TARGET_JA3  = "203.0.113.30"     # target for JA3 flow


# ── helpers ──────────────────────────────────────────────────────────────────

def tcp_flow(src_ip, dst_ip, sport, dport, payload: bytes = b""):
    """Minimal TCP exchange with Ethernet headers: SYN / SYN-ACK / ACK [/ PSH+data / ACK]."""
    pkts = [
        eth() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S",  seq=1000),
        eth(src_mac=GW_MAC, dst_mac=CLIENT_MAC) / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001),
        eth() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A",  seq=1001, ack=5001),
    ]
    if payload:
        pkts += [
            eth() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=5001) / Raw(payload),
            eth(src_mac=GW_MAC, dst_mac=CLIENT_MAC) / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="A", seq=5001, ack=1001 + len(payload)),
        ]
    return pkts


def build_tls_client_hello(sni: bytes, cipher_suites: list[int],
                            extra_exts: bytes = b"") -> bytes:
    """
    Craft a minimal TLS 1.2 ClientHello record.
    Extensions included: SNI (0), supported_groups (10), ec_point_formats (11),
    and anything in extra_exts.
    """
    rnd = bytes(range(32))                                          # deterministic random

    # cipher suites
    cs_payload = b"".join(struct.pack("!H", c) for c in cipher_suites)

    # --- SNI extension (type 0) ---
    sni_entry  = struct.pack("!BH", 0, len(sni)) + sni             # type=host(0), len, name
    sni_list   = struct.pack("!H", len(sni_entry)) + sni_entry     # list_len + entry
    ext_sni    = struct.pack("!HH", 0, len(sni_list)) + sni_list

    # --- supported_groups extension (type 10): secp256r1=23, secp384r1=24 ---
    groups_list = struct.pack("!HH", 23, 24)
    groups_data = struct.pack("!H", len(groups_list)) + groups_list
    ext_groups  = struct.pack("!HH", 10, len(groups_data)) + groups_data

    # --- ec_point_formats extension (type 11): uncompressed=0 ---
    ec_data    = struct.pack("!BB", 1, 0)                           # len=1, uncompressed
    ext_ec     = struct.pack("!HH", 11, len(ec_data)) + ec_data

    all_exts   = ext_sni + ext_groups + ext_ec + extra_exts
    exts_block = struct.pack("!H", len(all_exts)) + all_exts

    # ClientHello body
    ch_body = (
        b"\x03\x03"                                 # version: TLS 1.2
        + rnd                                       # random (32 bytes)
        + b"\x00"                                   # session_id length = 0
        + struct.pack("!H", len(cs_payload))        # cipher suites length
        + cs_payload                                # cipher suites
        + b"\x01\x00"                               # compression: len=1, null
        + exts_block                                # extensions
    )

    # Handshake header: type=1 (ClientHello), 3-byte length
    hs_len  = struct.pack("!I", len(ch_body))[1:]   # drop MSB → 3 bytes
    hs      = b"\x01" + hs_len + ch_body

    # TLS record header: content_type=22, version=TLS1.0, length
    rec_len = struct.pack("!H", len(hs))
    return b"\x16\x03\x01" + rec_len + hs


def build_tls_server_hello(cipher_suite: int) -> bytes:
    """
    Craft a minimal TLS 1.2 ServerHello record (no extensions).
    JA3S string for this: "771,{cipher},"
    """
    rnd = bytes(range(32, 64))  # deterministic random, different from client

    sh_body = (
        b"\x03\x03"                             # version: TLS 1.2
        + rnd                                   # random (32 bytes)
        + b"\x00"                               # session_id length = 0
        + struct.pack("!H", cipher_suite)       # selected cipher suite
        + b"\x00"                               # compression method: null
        + b"\x00\x00"                           # extensions length = 0
    )

    sh_len  = struct.pack("!I", len(sh_body))[1:]   # 3-byte big-endian
    hs      = b"\x02" + sh_len + sh_body            # HandshakeType=2 (ServerHello)
    rec_len = struct.pack("!H", len(hs))
    return b"\x16\x03\x01" + rec_len + hs


def ja3s_hash(cipher_suite: int, tls_ver: int = 771) -> tuple[str, str]:
    """Return (ja3s_string, md5_hex) for a ServerHello with no extensions."""
    s = f"{tls_ver},{cipher_suite},"
    return s, hashlib.md5(s.encode()).hexdigest()


def ja3_hash(cipher_suites: list[int], ext_types: list[int],
             groups: list[int], ec_fmts: list[int],
             tls_ver: int = 771) -> tuple[str, str]:
    """Return (ja3_string, md5_hex)."""
    def no_grease(lst):
        grease = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
                  0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
                  0xcaca, 0xdada, 0xeaea, 0xfafa}
        return [v for v in lst if v not in grease]

    parts = [
        str(tls_ver),
        "-".join(str(c) for c in no_grease(cipher_suites)),
        "-".join(str(e) for e in no_grease(ext_types)),
        "-".join(str(g) for g in no_grease(groups)),
        "-".join(str(f) for f in ec_fmts),
    ]
    s = ",".join(parts)
    return s, hashlib.md5(s.encode()).hexdigest()


# ── build packet list ─────────────────────────────────────────────────────────

packets = []

# ── 1. protocol: ICMP  →  icmp_detected ──────────────────────────────────────
for _ in range(3):
    packets.append(eth() / IP(src=CLIENT_IP, dst="1.1.1.1") / ICMP(type=8))
    packets.append(eth(src_mac=GW_MAC, dst_mac=CLIENT_MAC) / IP(src="1.1.1.1", dst=CLIENT_IP) / ICMP(type=0))

# ── 2. dstPort:443 + protocol:UDP  →  quic_https ─────────────────────────────
# (telegram.pcap also covers this, but include it here too for completeness)
quic_init = b"\xc0\x00\x00\x00\x01" + b"\x00" * 15   # fake QUIC Initial
packets.append(eth() / IP(src=CLIENT_IP, dst=TARGET_PORT) / UDP(sport=54321, dport=443) / Raw(quic_init))
packets.append(eth(src_mac=GW_MAC, dst_mac=CLIENT_MAC) / IP(src=TARGET_PORT, dst=CLIENT_IP) / UDP(sport=443, dport=54321) / Raw(b"\x00" * 20))

# ── 3. dstPort:4434  →  teams_media_relay_port ───────────────────────────────
packets += tcp_flow(CLIENT_IP, TARGET_PORT, 55000, 4434)

# ── 4. srcPort:67  →  rogue_dhcp_server ─────────────────────────────────────
# DHCP Offer sent *from* port 67 (server side)
packets.append(
    eth_bcast()
    / IP(src="192.168.100.254", dst="255.255.255.255")
    / UDP(sport=67, dport=68)
    / BOOTP(op=2, yiaddr=CLIENT_IP, siaddr="192.168.100.254",
            xid=0xABCD1234, flags=0x8000)
    / DHCP(options=[("message-type", "offer"),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", "192.168.100.1"),
                    "end"])
)

# ── 5. ip:162.125.19.131  →  dropbox_telemetry_server ───────────────────────
packets += tcp_flow(CLIENT_IP, DROPBOX_IP, 56000, 443)

# ── 6. cidr:52.114.0.0/16  →  microsoft_azure_traffic ───────────────────────
packets += tcp_flow(CLIENT_IP, AZURE_IP, 56001, 80)

# ── 7. ip:52.114.252.8 + dstPort:443  →  teams_trouter_signalling ────────────
# also matches microsoft_azure_traffic (same /16)
packets += tcp_flow(CLIENT_IP, TROUTER_IP, 56002, 443)

# ── 8. app:DNS (UDP)  →  dns_app_detected ────────────────────────────────────
packets.append(
    eth() / IP(src=CLIENT_IP, dst=DNS_SERVER)
    / UDP(sport=50000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
)
packets.append(
    eth(src_mac=GW_MAC, dst_mac=CLIENT_MAC) / IP(src=DNS_SERVER, dst=CLIENT_IP)
    / UDP(sport=53, dport=50000)
    / DNS(qr=1, aa=1, qd=DNSQR(qname="example.com"),
          an=DNSRR(rrname="example.com", rdata="1.2.3.4"))
)

# ── 9. app:DNS + protocol:TCP  →  dns_over_tcp ───────────────────────────────
dns_query_bytes = bytes(DNS(rd=1, qd=DNSQR(qname="tcp.example.com", qtype="A")))
dns_tcp_payload = struct.pack("!H", len(dns_query_bytes)) + dns_query_bytes

dns_reply_bytes = bytes(DNS(qr=1, aa=1,
                            qd=DNSQR(qname="tcp.example.com"),
                            an=DNSRR(rrname="tcp.example.com", rdata="5.6.7.8")))
dns_tcp_reply = struct.pack("!H", len(dns_reply_bytes)) + dns_reply_bytes

packets += tcp_flow(CLIENT_IP, DNS_SERVER, 50001, 53, dns_tcp_payload)
# add the server reply in the same flow
packets += [
    eth(src_mac=GW_MAC, dst_mac=CLIENT_MAC)
    / IP(src=DNS_SERVER, dst=CLIENT_IP)
    / TCP(sport=53, dport=50001, flags="PA", seq=5001,
          ack=1001 + len(dns_tcp_payload))
    / Raw(dns_tcp_reply),
    eth()
    / IP(src=CLIENT_IP, dst=DNS_SERVER)
    / TCP(sport=50001, dport=53, flags="A",
          seq=1001 + len(dns_tcp_payload),
          ack=5001 + len(dns_tcp_reply)),
]

# ── 10. hostname (exact): "mobile.pipe.aria.microsoft.com"  →  microsoft_telemetry_pipeline
#    AND hostname (wildcard): "*.microsoft.com"              →  microsoft_domain_traffic
STANDARD_CIPHERS = [0xC02C, 0xC02B, 0xC030, 0xC02F, 0x009F, 0x009E,
                    0xC024, 0xC023, 0xC028, 0xC027, 0x006B, 0x0067,
                    0x009D, 0x009C, 0x003D, 0x003C, 0x0035, 0x002F]

tls_msft = build_tls_client_hello(
    sni=b"mobile.pipe.aria.microsoft.com",
    cipher_suites=STANDARD_CIPHERS,
)
packets += tcp_flow(CLIENT_IP, TARGET_SNI, 57000, 443, tls_msft)

# ── 11. ja3 hash  →  suspected_meterpreter_tls ───────────────────────────────
# Use a small, distinctive cipher suite list so the JA3 is unique.
JA3_CIPHERS  = [0x0035, 0x002F, 0x0005, 0x0004]        # AES256-SHA, AES128-SHA, RC4-SHA, RC4-MD5
JA3_EXT_TYPES = [0, 10, 11]                             # SNI, supported_groups, ec_point_formats
JA3_GROUPS   = [23, 24]
JA3_EC_FMTS  = [0]

# Server will select 0x0035 (AES-256-SHA = 53) from the ClientHello list
JA3_SERVER_CIPHER = 0x0035

ja3_str,  ja3_md5  = ja3_hash(JA3_CIPHERS, JA3_EXT_TYPES, JA3_GROUPS, JA3_EC_FMTS)
ja3s_str, ja3s_md5 = ja3s_hash(JA3_SERVER_CIPHER)
print(f"\n── JA3 info ────────────────────────────────────────────")
print(f"  JA3  string : {ja3_str}")
print(f"  JA3  md5    : {ja3_md5}  (client — nDPI 5.x no longer outputs this)")
print(f"  JA3S string : {ja3s_str}")
print(f"  JA3S md5    : {ja3s_md5}  ← use this in signatures.yml")
print(f"────────────────────────────────────────────────────────\n")

tls_client_hello = build_tls_client_hello(
    sni=b"malware.example.com",
    cipher_suites=JA3_CIPHERS,
)
tls_server_hello = build_tls_server_hello(JA3_SERVER_CIPHER)

# Full TLS exchange: TCP handshake → ClientHello → ServerHello
# The ServerHello travels in the reverse direction
packets += tcp_flow(CLIENT_IP, TARGET_JA3, 58000, 443, tls_client_hello)
client_hello_len = len(tls_client_hello)
packets += [
    # ServerHello from server → client
    eth(src_mac=GW_MAC, dst_mac=CLIENT_MAC)
    / IP(src=TARGET_JA3, dst=CLIENT_IP)
    / TCP(sport=443, dport=58000, flags="PA",
          seq=5001, ack=1001 + client_hello_len)
    / Raw(tls_server_hello),
    # Client ACK
    eth()
    / IP(src=CLIENT_IP, dst=TARGET_JA3)
    / TCP(sport=58000, dport=443, flags="A",
          seq=1001 + client_hello_len,
          ack=5001 + len(tls_server_hello)),
]

# ── write synthetic pcap ──────────────────────────────────────────────────────
synthetic_path = os.path.join(SCRIPT_DIR, "_synthetic_rules.pcap")
wrpcap(synthetic_path, packets)
print(f"Synthetic packets : {len(packets)}  →  {synthetic_path}")

# ── merge with telegram.pcap (provides: telegram_usage, extra quic_https) ────
telegram_path = os.path.join(SCRIPT_DIR, "telegram.pcap")
output_path   = os.path.join(SCRIPT_DIR, "demo_all_rules.pcap")

if os.path.exists(telegram_path):
    telegram_pkts = rdpcap(telegram_path)
    all_pkts = list(telegram_pkts) + packets
    wrpcap(output_path, all_pkts)
    print(f"Merged with telegram.pcap : {len(all_pkts)} total packets")
else:
    # Just use synthetic if telegram.pcap not found
    import shutil
    shutil.copy(synthetic_path, output_path)
    print("telegram.pcap not found — using synthetic only")

os.remove(synthetic_path)
print(f"Output : {output_path}")
print()
print("Next step: upload demo_all_rules.pcap to TracePcap, then")
print("check /api/conversations/<fileId>/custom-signatures to verify all rules fire.")
print(f"Also update 'suspected_meterpreter_tls' ja3 in signatures.yml to: {ja3_md5}")
