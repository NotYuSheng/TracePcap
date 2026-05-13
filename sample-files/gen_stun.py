#!/usr/bin/env python3
"""
Generate stun_webrtc.pcap — a minimal STUN capture for testing the STUN
session decoder in TracePcap.

Contains 6 UDP packets on port 3478:
  - 2x Binding Request / Binding Success Response (ICE keepalives)
  - 1x Allocate Request / Allocate Success Response (TURN)

Usage:
  python3 gen_stun.py
"""

import struct
import socket

OUT = "stun_webrtc.pcap"
CLIENT_IP = "192.168.1.10"
SERVER_IP = "185.125.180.97"
CLIENT_PORT = 54321
STUN_PORT = 3478
MAGIC = 0x2112A442


def pcap_global_header():
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def pcap_record(ts_sec, ts_usec, data):
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def udp_packet(src_ip, src_port, dst_ip, dst_port, payload):
    udp = struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp),
        0, 0,
        64, 17, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    eth = b"\xff\xff\xff\xff\xff\xff" + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x00" + ip + udp
    return eth


def xor_mapped_attr(ip_str, port):
    xport = port ^ ((MAGIC >> 16) & 0xFFFF)
    xip = struct.unpack(">I", socket.inet_aton(ip_str))[0] ^ MAGIC
    return struct.pack(">HHBBHI", 0x0020, 8, 0, 1, xport, xip)


def stun_binding_request(tx_id):
    return struct.pack(">HHI", 0x0001, 0, MAGIC) + tx_id


def stun_binding_response(tx_id, mapped_ip, mapped_port):
    attr = xor_mapped_attr(mapped_ip, mapped_port)
    sw = b"TracePcap-Test"
    sw_padded = sw + b"\x00" * ((4 - len(sw) % 4) % 4)
    attr += struct.pack(">HH", 0x8022, len(sw)) + sw_padded
    return struct.pack(">HHI", 0x0101, len(attr), MAGIC) + tx_id + attr


def stun_allocate_request(tx_id):
    user = b"testuser:peer"
    user_padded = user + b"\x00" * ((4 - len(user) % 4) % 4)
    attr = struct.pack(">HH", 0x0006, len(user)) + user_padded
    return struct.pack(">HHI", 0x0003, len(attr), MAGIC) + tx_id + attr


def stun_allocate_response(tx_id, relayed_ip, relayed_port):
    attr = xor_mapped_attr(relayed_ip, relayed_port)
    return struct.pack(">HHI", 0x0103, len(attr), MAGIC) + tx_id + attr


tx1 = b"\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22\x33\x44\x55\x66"
tx2 = b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0\x11\x22\x33\x44"
tx3 = b"\xCA\xFE\xBA\xBE\xDE\xAD\xBE\xEF\xCA\xFE\x00\x01"

t = 1700000000
packets = [
    pcap_record(t + 0, 0,      udp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, STUN_PORT, stun_binding_request(tx1))),
    pcap_record(t + 1, 500000, udp_packet(SERVER_IP, STUN_PORT, CLIENT_IP, CLIENT_PORT, stun_binding_response(tx1, CLIENT_IP, CLIENT_PORT))),
    pcap_record(t + 2, 0,      udp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, STUN_PORT, stun_binding_request(tx2))),
    pcap_record(t + 3, 300000, udp_packet(SERVER_IP, STUN_PORT, CLIENT_IP, CLIENT_PORT, stun_binding_response(tx2, CLIENT_IP, CLIENT_PORT))),
    pcap_record(t + 4, 0,      udp_packet(CLIENT_IP, CLIENT_PORT, SERVER_IP, STUN_PORT, stun_allocate_request(tx3))),
    pcap_record(t + 5, 200000, udp_packet(SERVER_IP, STUN_PORT, CLIENT_IP, CLIENT_PORT, stun_allocate_response(tx3, "10.0.0.1", 49152))),
]

with open(OUT, "wb") as f:
    f.write(pcap_global_header() + b"".join(packets))

print(f"Written {len(packets)} packets to {OUT}")
