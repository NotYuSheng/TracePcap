#!/usr/bin/env python3
"""Generate dhcp_address_reuse.pcap: one address held by two devices in turn (#918).

Office Wi-Fi, 10:00 to 12:00. Alice's Windows laptop is leased 10.0.0.50 at 10:00, signs in,
browses and uses a file share, then releases the address at 10:59. At 11:00 a visitor's Android
phone is leased the same address. From 11:32 the phone beacons to a suspicious domain once a minute.

At 11:05 Alice's laptop comes back and is leased a different address, 10.0.0.73, and carries on
with mail and the file share until 12:00: the same device on a new address.

A static host (10.0.0.20, a printer) talks throughout, so the capture also has an address that
never changes hands.

What TracePcap should show:
- the host 10.0.0.50 has two occupancies: f8:bc:12:... (Dell, LAPTOP-ALICE) then 8c:71:f8:... (Samsung, Galaxy-S24),
  split by the DHCP lease to a different MAC at 11:00;
- with per-occupancy classification (#918 slice 2), the laptop and the phone are classified
  separately, and the beacon conversations belong to the phone;
- the laptop moved from 10.0.0.50 to 10.0.0.73 (same MAC, a new DHCP lease at 11:05): the graph
  links its two nodes as one device.
"""
import os
from datetime import datetime, timezone

from scapy.all import wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

ROUTER_IP, ROUTER_MAC = "10.0.0.1", "00:11:22:33:44:01"
FILESRV_IP, FILESRV_MAC = "10.0.0.10", "00:11:22:33:44:10"
PRINTER_IP, PRINTER_MAC = "10.0.0.20", "00:11:22:33:44:20"
SHARED_IP = "10.0.0.50"
LAPTOP_MAC, LAPTOP_NAME = "f8:bc:12:00:00:01", "LAPTOP-ALICE"
PHONE_MAC, PHONE_NAME = "8c:71:f8:00:00:02", "Galaxy-S24"
BEACON_DOMAIN = "update-check.cdn-telemetry.top"
BEACON_IP = "185.220.101.77"

T0 = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc).timestamp()
pkts = []


def at(minutes, seconds=0.0):
    return T0 + minutes * 60 + seconds


def add(pkt, t):
    pkt.time = t
    pkts.append(pkt)


def dhcp_handshake(t, mac, hostname, ip, xid):
    chaddr = bytes.fromhex(mac.replace(":", ""))
    common = dict(chaddr=chaddr, xid=xid)
    add(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67) / BOOTP(op=1, **common)
        / DHCP(options=[("message-type", "discover"), ("hostname", hostname), "end"]), t)
    add(Ether(src=ROUTER_MAC, dst=mac) / IP(src=ROUTER_IP, dst=ip)
        / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=ip, siaddr=ROUTER_IP, **common)
        / DHCP(options=[("message-type", "offer"), ("server_id", ROUTER_IP), ("lease_time", 3600), "end"]), t + 0.01)
    add(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67) / BOOTP(op=1, **common)
        / DHCP(options=[("message-type", "request"), ("requested_addr", ip), ("server_id", ROUTER_IP),
                        ("hostname", hostname), "end"]), t + 0.02)
    add(Ether(src=ROUTER_MAC, dst=mac) / IP(src=ROUTER_IP, dst=ip)
        / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=ip, siaddr=ROUTER_IP, **common)
        / DHCP(options=[("message-type", "ack"), ("server_id", ROUTER_IP), ("lease_time", 3600), "end"]), t + 0.03)


def arp_announce(t, mac, ip):
    """The holder answering for the address (an ARP reply to the router)."""
    add(Ether(src=ROUTER_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=ROUTER_MAC, psrc=ROUTER_IP, pdst=ip), t)
    add(Ether(src=mac, dst=ROUTER_MAC) / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=ROUTER_MAC, pdst=ROUTER_IP), t + 0.001)


def tcp_session(t, src_mac, src_ip, dst_mac, dst_ip, sport, dport, ttl, payload=b"", reply=b""):
    """A short TCP exchange: handshake, one request, one response, close."""
    c = dict(src=src_ip, dst=dst_ip, ttl=ttl)
    s = dict(src=dst_ip, dst=src_ip, ttl=64)
    add(Ether(src=src_mac, dst=dst_mac) / IP(**c) / TCP(sport=sport, dport=dport, flags="S", seq=1000), t)
    add(Ether(src=dst_mac, dst=src_mac) / IP(**s) / TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=1001), t + 0.01)
    add(Ether(src=src_mac, dst=dst_mac) / IP(**c) / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=5001), t + 0.02)
    if payload:
        add(Ether(src=src_mac, dst=dst_mac) / IP(**c) / TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=5001) / payload, t + 0.03)
    if reply:
        add(Ether(src=dst_mac, dst=src_mac) / IP(**s) / TCP(sport=dport, dport=sport, flags="PA", seq=5001, ack=1001 + len(payload)) / reply, t + 0.05)
    add(Ether(src=src_mac, dst=dst_mac) / IP(**c) / TCP(sport=sport, dport=dport, flags="FA", seq=1001 + len(payload), ack=5001 + len(reply)), t + 0.07)


def dns(t, mac, ip, ttl, name, answer, sport):
    add(Ether(src=mac, dst=ROUTER_MAC) / IP(src=ip, dst=ROUTER_IP, ttl=ttl) / UDP(sport=sport, dport=53)
        / DNS(id=sport, rd=1, qd=DNSQR(qname=name)), t)
    add(Ether(src=ROUTER_MAC, dst=mac) / IP(src=ROUTER_IP, dst=ip) / UDP(sport=53, dport=sport)
        / DNS(id=sport, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=answer)), t + 0.02)


# ── The printer: static, the whole capture ─────────────────────────────────────
for m in range(0, 120, 15):
    arp_announce(at(m, 5), PRINTER_MAC, PRINTER_IP)
    tcp_session(at(m, 6), PRINTER_MAC, PRINTER_IP, FILESRV_MAC, FILESRV_IP, 40000 + m, 9100, 64, b"status", b"ok")

# ── 10:00–10:59 Alice's Windows laptop ─────────────────────────────────────────
dhcp_handshake(at(0, 1), LAPTOP_MAC, LAPTOP_NAME, SHARED_IP, 0x1A2B0001)
arp_announce(at(0, 2), LAPTOP_MAC, SHARED_IP)
port = 50000
for m in range(1, 58, 4):
    arp_announce(at(m, 0), LAPTOP_MAC, SHARED_IP)
    dns(at(m, 1), LAPTOP_MAC, SHARED_IP, 128, "outlook.office365.com", "52.97.1.10", port)
    tcp_session(at(m, 2), LAPTOP_MAC, SHARED_IP, ROUTER_MAC, "52.97.1.10", port + 1, 443, 128,
                b"\x16\x03\x01\x00\x05hello", b"\x16\x03\x03\x00\x05hello")
    tcp_session(at(m, 3), LAPTOP_MAC, SHARED_IP, FILESRV_MAC, FILESRV_IP, port + 2, 445, 128,
                b"\x00\x00\x00\x2f\xfeSMB", b"\x00\x00\x00\x2f\xfeSMB")
    port += 3
# Release at 10:59.
add(Ether(src=LAPTOP_MAC, dst=ROUTER_MAC) / IP(src=SHARED_IP, dst=ROUTER_IP, ttl=128) / UDP(sport=68, dport=67)
    / BOOTP(op=1, ciaddr=SHARED_IP, chaddr=bytes.fromhex(LAPTOP_MAC.replace(":", "")), xid=0x1A2B0002)
    / DHCP(options=[("message-type", "release"), ("server_id", ROUTER_IP), "end"]), at(59, 0))

# ── 11:05–12:00 Alice's laptop is back, on a new address ─────────────────────────
NEW_IP = "10.0.0.73"
dhcp_handshake(at(65, 1), LAPTOP_MAC, LAPTOP_NAME, NEW_IP, 0x1A2B0003)
arp_announce(at(65, 2), LAPTOP_MAC, NEW_IP)
port = 51000
for m in range(66, 120, 4):
    arp_announce(at(m, 0), LAPTOP_MAC, NEW_IP)
    dns(at(m, 1), LAPTOP_MAC, NEW_IP, 128, "outlook.office365.com", "52.97.1.10", port)
    tcp_session(at(m, 2), LAPTOP_MAC, NEW_IP, ROUTER_MAC, "52.97.1.10", port + 1, 443, 128,
                b"\x16\x03\x01\x00\x05hello", b"\x16\x03\x03\x00\x05hello")
    tcp_session(at(m, 3), LAPTOP_MAC, NEW_IP, FILESRV_MAC, FILESRV_IP, port + 2, 445, 128,
                b"\x00\x00\x00\x2f\xfeSMB", b"\x00\x00\x00\x2f\xfeSMB")
    port += 3

# ── 11:00–12:00 the visitor's Android phone ────────────────────────────────────
dhcp_handshake(at(60, 1), PHONE_MAC, PHONE_NAME, SHARED_IP, 0x3C4D0001)
arp_announce(at(60, 2), PHONE_MAC, SHARED_IP)
port = 40100
for m in range(61, 120, 3):
    arp_announce(at(m, 0), PHONE_MAC, SHARED_IP)
    dns(at(m, 1), PHONE_MAC, SHARED_IP, 64, "connectivitycheck.gstatic.com", "142.250.4.94", port)
    tcp_session(at(m, 2), PHONE_MAC, SHARED_IP, ROUTER_MAC, "142.250.4.94", port + 1, 80, 64,
                b"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n"
                b"User-Agent: Dalvik/2.1.0 (Linux; U; Android 14; SM-S921B)\r\n\r\n",
                b"HTTP/1.1 204 No Content\r\n\r\n")
    port += 2
# From 11:32, a beacon once a minute.
for m in range(92, 120):
    dns(at(m, 30), PHONE_MAC, SHARED_IP, 64, BEACON_DOMAIN, BEACON_IP, 41000 + m)
    tcp_session(at(m, 31), PHONE_MAC, SHARED_IP, ROUTER_MAC, BEACON_IP, 42000 + m, 443, 64,
                b"\x16\x03\x01\x00\x05ping!", b"\x16\x03\x03\x00\x05pong!")

pkts.sort(key=lambda p: float(p.time))
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dhcp_address_reuse.pcap")
wrpcap(out, pkts)
print(f"Wrote {out}: {len(pkts)} packets")
