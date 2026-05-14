#!/usr/bin/env python3
"""
Generate test_media.pcap — a minimal capture for testing issue #210
(audio/video stream decoder and media preview in session view).

Contains three independent conversations:

1. RTP audio stream (UDP, port range 10000-10001)
   - 8 packets: 4 client→server, 4 server→client
   - Payload type 0 (PCMU / G.711 µ-law), two SSRCs
   - Detected as: protocol=RTP, mediaType=AUDIO, containerFormat=RTP, codec=PCMU

2. HTTP transfer of a JPEG image (TCP, port 80)
   - Client GET /photo.jpg  →  Server 200 OK + minimal JPEG payload
   - Detected as: protocol=HTTP (standard HTTP decoder shows body)
   - Session media info: containerFormat=JPEG, mediaType=IMAGE

3. HTTP transfer of a PNG image (TCP, port 80)
   - Client GET /icon.png  →  Server 200 OK + minimal 4×4 px PNG payload
   - Session media info: containerFormat=PNG, mediaType=IMAGE, width=4, height=4

Usage:
  cd sample-files
  python3 gen_media.py
  # Produces test_media.pcap in the current directory.
"""

import struct
import socket

OUT = "test_media.pcap"

# ── Addresses ─────────────────────────────────────────────────────────────────
CLIENT_IP  = "192.168.1.50"
SERVER_IP  = "10.0.0.1"
CLIENT_MAC = b"\x00\x11\x22\x33\x44\x55"
SERVER_MAC = b"\x00\xAA\xBB\xCC\xDD\xEE"

# ── Low-level PCAP helpers ─────────────────────────────────────────────────────

def pcap_global_header():
    # magic, major, minor, thiszone, sigfigs, snaplen, network(1=Ethernet)
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

def pcap_record(ts_sec, ts_usec, data):
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data

def eth_ip_udp(src_ip, src_port, dst_ip, dst_port, payload):
    udp = struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    ip  = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp),
        1, 0,
        64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    eth = CLIENT_MAC + SERVER_MAC + b"\x08\x00" + ip + udp
    return eth

def eth_ip_tcp(src_ip, src_port, dst_ip, dst_port, payload,
               seq=1, ack=0, flags=0x018, window=65535):
    # flags: 0x018 = PSH+ACK
    tcp = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port,
        seq, ack,
        0x50,      # data offset = 5 (20 bytes), reserved = 0
        flags,
        window,
        0,         # checksum (ignored by tshark in many cases)
        0,         # urgent pointer
    ) + payload
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcp),
        2, 0,
        64, 6, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    eth = CLIENT_MAC + SERVER_MAC + b"\x08\x00" + ip + tcp
    return eth

# ── 1. RTP audio stream ───────────────────────────────────────────────────────
# RFC 3550 header: V=2 P=0 X=0 CC=0 M=0 PT=0 (PCMU)
# Format: [V/P/X/CC][M/PT][seq(2)][timestamp(4)][ssrc(4)][payload...]

RTP_PORT_CLIENT = 10000   # client sends from this port (SSRC A)
RTP_PORT_SERVER = 10002   # server sends from this port (SSRC B)
SSRC_A = 0xAABBCCDD
SSRC_B = 0x11223344

def rtp_packet(seq, timestamp, ssrc, payload_type=0, payload=b"\x00" * 20):
    """Build a minimal RTP packet (V=2, no padding, no extension, no CSRC)."""
    byte0 = 0x80           # V=2, P=0, X=0, CC=0
    byte1 = payload_type & 0x7F  # M=0
    return struct.pack(">BBHII", byte0, byte1, seq, timestamp, ssrc) + payload

# 160 bytes = 20ms of G.711 at 8kHz
SILENCE = bytes([0x7F] * 160)

rtp_packets = []
t0 = 1_700_100_000

for i in range(4):
    # Client → Server (SSRC_A)
    rtp = rtp_packet(seq=i, timestamp=i * 160, ssrc=SSRC_A, payload=SILENCE)
    rtp_packets.append(pcap_record(
        t0 + i * 20, 0,
        eth_ip_udp(CLIENT_IP, RTP_PORT_CLIENT, SERVER_IP, RTP_PORT_SERVER, rtp),
    ))
    # Server → Client (SSRC_B, interleaved)
    rtp = rtp_packet(seq=i, timestamp=i * 160, ssrc=SSRC_B, payload=SILENCE)
    rtp_packets.append(pcap_record(
        t0 + i * 20, 10_000,
        eth_ip_udp(SERVER_IP, RTP_PORT_SERVER, CLIENT_IP, RTP_PORT_CLIENT, rtp),
    ))

# ── 2. HTTP transfer of a JPEG ────────────────────────────────────────────────
# Minimal valid JPEG: SOI + APP0 + SOF0 (12×8) + SOS stub + EOI
# We only need the magic bytes (0xFF 0xD8) plus a SOF0 marker so our parser
# can read dimensions.

def jpeg_payload(width=12, height=8):
    soi  = b"\xFF\xD8"
    # APP0 marker (JFIF)
    app0 = b"\xFF\xE0" + struct.pack(">H", 16) + b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    # SOF0: 0xFF 0xC0, length=11+3*1=17, precision=8, height, width, components=1
    sof0 = (b"\xFF\xC0"
            + struct.pack(">H", 11)   # segment length (including the 2-byte length field)
            + struct.pack(">B", 8)    # precision
            + struct.pack(">HH", height, width)
            + struct.pack(">B", 1)    # components
            + b"\x01\x11\x00")       # component spec
    eoi  = b"\xFF\xD9"
    return soi + app0 + sof0 + eoi

JPEG_BODY = jpeg_payload(width=320, height=240)

HTTP_GET_JPEG = (
    b"GET /photo.jpg HTTP/1.1\r\n"
    b"Host: 10.0.0.1\r\n"
    b"Accept: image/*\r\n"
    b"\r\n"
)
HTTP_RSP_JPEG = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: image/jpeg\r\n"
    + b"Content-Length: " + str(len(JPEG_BODY)).encode() + b"\r\n"
    + b"Connection: close\r\n"
    b"\r\n"
    + JPEG_BODY
)

TCP_PORT_JPEG  = 59001   # client ephemeral
HTTP_PORT      = 80

t1 = 1_700_200_000
jpeg_packets = [
    # SYN
    pcap_record(t1 + 0, 0,       eth_ip_tcp(CLIENT_IP, TCP_PORT_JPEG, SERVER_IP, HTTP_PORT,
                                             b"", seq=0, ack=0, flags=0x002)),
    # SYN-ACK
    pcap_record(t1 + 0, 100_000, eth_ip_tcp(SERVER_IP, HTTP_PORT, CLIENT_IP, TCP_PORT_JPEG,
                                             b"", seq=0, ack=1, flags=0x012)),
    # ACK
    pcap_record(t1 + 0, 200_000, eth_ip_tcp(CLIENT_IP, TCP_PORT_JPEG, SERVER_IP, HTTP_PORT,
                                             b"", seq=1, ack=1, flags=0x010)),
    # HTTP GET
    pcap_record(t1 + 1, 0,       eth_ip_tcp(CLIENT_IP, TCP_PORT_JPEG, SERVER_IP, HTTP_PORT,
                                             HTTP_GET_JPEG, seq=1, ack=1)),
    # HTTP 200 + JPEG body
    pcap_record(t1 + 1, 200_000, eth_ip_tcp(SERVER_IP, HTTP_PORT, CLIENT_IP, TCP_PORT_JPEG,
                                             HTTP_RSP_JPEG, seq=1, ack=len(HTTP_GET_JPEG) + 1)),
    # FIN
    pcap_record(t1 + 2, 0,       eth_ip_tcp(SERVER_IP, HTTP_PORT, CLIENT_IP, TCP_PORT_JPEG,
                                             b"", seq=1 + len(HTTP_RSP_JPEG), ack=len(HTTP_GET_JPEG) + 1, flags=0x011)),
]

# ── 3. HTTP transfer of a PNG ─────────────────────────────────────────────────
# Minimal valid PNG: signature + IHDR (4×4) + IDAT (empty) + IEND

def png_payload(width=4, height=4):
    sig  = b"\x89PNG\r\n\x1a\n"
    # IHDR chunk: length=13, type="IHDR", data, CRC
    ihdr_data = struct.pack(">II", width, height) + b"\x08\x02\x00\x00\x00"  # 8-bit RGB
    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"  # fake CRC
    # IEND chunk
    iend = b"\x00\x00\x00\x00IEND\xAE\x42\x60\x82"
    return sig + ihdr + iend

PNG_BODY = png_payload(width=4, height=4)

HTTP_GET_PNG = (
    b"GET /icon.png HTTP/1.1\r\n"
    b"Host: 10.0.0.1\r\n"
    b"Accept: image/*\r\n"
    b"\r\n"
)
HTTP_RSP_PNG = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: image/png\r\n"
    + b"Content-Length: " + str(len(PNG_BODY)).encode() + b"\r\n"
    + b"Connection: close\r\n"
    b"\r\n"
    + PNG_BODY
)

TCP_PORT_PNG = 59002

t2 = 1_700_300_000
png_packets = [
    pcap_record(t2 + 0, 0,       eth_ip_tcp(CLIENT_IP, TCP_PORT_PNG, SERVER_IP, HTTP_PORT,
                                             b"", seq=0, ack=0, flags=0x002)),
    pcap_record(t2 + 0, 100_000, eth_ip_tcp(SERVER_IP, HTTP_PORT, CLIENT_IP, TCP_PORT_PNG,
                                             b"", seq=0, ack=1, flags=0x012)),
    pcap_record(t2 + 0, 200_000, eth_ip_tcp(CLIENT_IP, TCP_PORT_PNG, SERVER_IP, HTTP_PORT,
                                             b"", seq=1, ack=1, flags=0x010)),
    pcap_record(t2 + 1, 0,       eth_ip_tcp(CLIENT_IP, TCP_PORT_PNG, SERVER_IP, HTTP_PORT,
                                             HTTP_GET_PNG, seq=1, ack=1)),
    pcap_record(t2 + 1, 200_000, eth_ip_tcp(SERVER_IP, HTTP_PORT, CLIENT_IP, TCP_PORT_PNG,
                                             HTTP_RSP_PNG, seq=1, ack=len(HTTP_GET_PNG) + 1)),
    pcap_record(t2 + 2, 0,       eth_ip_tcp(SERVER_IP, HTTP_PORT, CLIENT_IP, TCP_PORT_PNG,
                                             b"", seq=1 + len(HTTP_RSP_PNG), ack=len(HTTP_GET_PNG) + 1, flags=0x011)),
]

# ── Write PCAP ────────────────────────────────────────────────────────────────

all_packets = rtp_packets + jpeg_packets + png_packets

with open(OUT, "wb") as f:
    f.write(pcap_global_header())
    for pkt in all_packets:
        f.write(pkt)

total = len(rtp_packets) + len(jpeg_packets) + len(png_packets)
print(f"Written {total} packets to {OUT}")
print()
print("Conversations:")
print(f"  1. RTP audio  {CLIENT_IP}:{RTP_PORT_CLIENT} <-> {SERVER_IP}:{RTP_PORT_SERVER}  (UDP, {len(rtp_packets)} pkts)")
print(f"     SSRC A: 0x{SSRC_A:08X}  SSRC B: 0x{SSRC_B:08X}  PT=0 (PCMU G.711)")
print(f"  2. HTTP JPEG  {CLIENT_IP}:{TCP_PORT_JPEG} -> {SERVER_IP}:{HTTP_PORT}  (TCP, {len(jpeg_packets)} pkts)")
print(f"     320x240 px JPEG body ({len(JPEG_BODY)} bytes)")
print(f"  3. HTTP PNG   {CLIENT_IP}:{TCP_PORT_PNG} -> {SERVER_IP}:{HTTP_PORT}  (TCP, {len(png_packets)} pkts)")
print(f"     4x4 px PNG body ({len(PNG_BODY)} bytes)")
