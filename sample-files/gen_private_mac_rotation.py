#!/usr/bin/env python3
"""Generate private_mac_week1.pcap and private_mac_week2.pcap: one phone whose private MAC
rotated between two weekly snapshots (#918 slice 4b).

Phones use a private (locally administered) MAC per Wi-Fi network by default (iOS 14+,
Android 10+), and newer versions can rotate it. Matching devices by MAC then fails.

- Bobs-iPhone: week 1 as 3a:1f:9c:52:0e:11, week 2 as 7e:02:41:9a:c3:07. Same DHCP hostname,
  same DHCP fingerprint (parameter request list), same TLS client hello, same services.
- Carols-Pixel: a different phone with a private MAC that stays the same both weeks, a different
  DHCP fingerprint, and a different hostname. It must not be suggested as Bob's phone.
- LAPTOP-ALICE (Dell, hardware MAC) and a router, both weeks.

Upload both, add them to one monitored network in order, and open Devices: the two private
MACs of Bobs-iPhone should be suggested as one device, Carol's should not.
"""
import os
from datetime import datetime, timezone

from scapy.all import wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.tls.all import TLS, TLSClientHello
from scapy.layers.tls.extensions import (
    ServerName,
    TLS_Ext_ServerName,
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedPointFormat,
)

ROUTER_IP, ROUTER_MAC = "10.0.0.1", "00:11:22:33:44:01"
LAPTOP = ("f8:bc:12:00:00:01", "LAPTOP-ALICE", "10.0.0.50", 128, [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252])
IPHONE_PRL = [1, 121, 3, 6, 15, 108, 114, 119, 252]
PIXEL_PRL = [1, 3, 6, 15, 26, 28, 51, 58, 59, 43, 114, 108]
WEEKS = {
    1: {
        "start": datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc),
        "bob": ("3a:1f:9c:52:0e:11", "10.0.0.61"),
        "carol": ("6a:44:10:7c:21:5e", "10.0.0.62"),
    },
    2: {
        "start": datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc),
        "bob": ("7e:02:41:9a:c3:07", "10.0.0.88"),
        "carol": ("6a:44:10:7c:21:5e", "10.0.0.62"),
    },
}
def client_hello(sni, ciphers, groups):
    """A real TLS ClientHello, so its JA3 fingerprint can be computed."""
    return bytes(TLS(msg=[TLSClientHello(ciphers=ciphers, ext=[
        TLS_Ext_ServerName(servernames=[ServerName(servername=sni.encode())]),
        TLS_Ext_SupportedGroups(groups=groups),
        TLS_Ext_SupportedPointFormat(ecpl=[0]),
    ])]))


# The same client stack both weeks for each phone, so its TLS fingerprint matches across MACs.
IOS = ([0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030, 0xC02F], [29, 23, 24])
ANDROID = ([0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8], [29, 23, 24, 25])
WINDOWS = ([0xC02C, 0xC02B, 0xC030, 0xC02F, 0x009F, 0x009E], [29, 23, 24])


def build(week):
    w = WEEKS[week]
    t0 = w["start"].timestamp()
    pkts = []

    def add(p, t):
        p.time = t0 + t
        pkts.append(p)

    def dhcp(t, mac, name, ip, prl, xid):
        ch = bytes.fromhex(mac.replace(":", ""))
        opts = [("message-type", "request"), ("requested_addr", ip), ("hostname", name), ("param_req_list", prl), "end"]
        add(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
            / BOOTP(op=1, chaddr=ch, xid=xid) / DHCP(options=opts), t)
        add(Ether(src=ROUTER_MAC, dst=mac) / IP(src=ROUTER_IP, dst=ip) / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=ip, siaddr=ROUTER_IP, chaddr=ch, xid=xid)
            / DHCP(options=[("message-type", "ack"), ("server_id", ROUTER_IP), ("lease_time", 86400), "end"]), t + 0.01)
        add(Ether(src=mac, dst=ROUTER_MAC) / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=ROUTER_MAC, pdst=ROUTER_IP), t + 0.02)

    def tls(t, mac, ip, ttl, dst, sport, hello):
        c = dict(src=ip, dst=dst, ttl=ttl)
        add(Ether(src=mac, dst=ROUTER_MAC) / IP(**c) / TCP(sport=sport, dport=443, flags="S", seq=100), t)
        add(Ether(src=ROUTER_MAC, dst=mac) / IP(src=dst, dst=ip) / TCP(sport=443, dport=sport, flags="SA", seq=900, ack=101), t + 0.01)
        add(Ether(src=mac, dst=ROUTER_MAC) / IP(**c) / TCP(sport=sport, dport=443, flags="A", seq=101, ack=901), t + 0.02)
        add(Ether(src=mac, dst=ROUTER_MAC) / IP(**c) / TCP(sport=sport, dport=443, flags="PA", seq=101, ack=901) / hello, t + 0.03)

    add(Ether(src=ROUTER_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=ROUTER_MAC, psrc=ROUTER_IP, pdst=ROUTER_IP), 0)
    mac, name, ip, ttl, prl = LAPTOP
    dhcp(1, mac, name, ip, prl, 0x100 + week)
    bob_mac, bob_ip = w["bob"]
    dhcp(5, bob_mac, "Bobs-iPhone", bob_ip, IPHONE_PRL, 0x200 + week)
    carol_mac, carol_ip = w["carol"]
    dhcp(9, carol_mac, "Carols-Pixel", carol_ip, PIXEL_PRL, 0x300 + week)
    port = 50000
    for i in range(30):
        t = 20 + i * 60
        tls(t, mac, ip, 128, "52.97.1.10", port, client_hello("outlook.office365.com", *WINDOWS))
        tls(t + 5, bob_mac, bob_ip, 64, "17.248.1.10", port + 1, client_hello("api.push.apple.com", *IOS))
        tls(t + 7, bob_mac, bob_ip, 64, "17.57.144.20", port + 2, client_hello("gateway.icloud.com", *IOS))
        tls(t + 9, carol_mac, carol_ip, 64, "142.250.4.188", port + 3, client_hello("android.googleapis.com", *ANDROID))
        port += 4
    pkts.sort(key=lambda p: float(p.time))
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"private_mac_week{week}.pcap")
    wrpcap(out, pkts)
    print(f"Wrote {out}: {len(pkts)} packets")


for wk in WEEKS:
    build(wk)
