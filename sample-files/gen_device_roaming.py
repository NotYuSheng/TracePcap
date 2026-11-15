#!/usr/bin/env python3
"""Generate device_roaming.pcap: one laptop that moves address three times and comes back, next to a
server that is on two addresses at once (multi-homed, not moving).

On 10.0.0.0/24 (DHCP from 10.0.0.1), over an hour:
- LAPTOP-ALICE (f8:bc:12:00:00:01) leases 10.0.0.50 at 10:00, 10.0.0.73 at 10:15, 10.0.0.88 at
  10:30, and 10.0.0.50 again at 10:45, browsing on each in turn. That is three moves, the last one
  back to where it started: .50 → .73 → .88 → .50.
- FILESERVER (00:50:56:00:00:10) answers on 10.0.0.10 and 10.0.0.11 the whole hour, the same MAC on
  both at once: multi-homed, so no moves.
"""
import os
from datetime import datetime, timezone

from scapy.all import wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

T0 = datetime(2026, 11, 14, 10, 0, tzinfo=timezone.utc).timestamp()
GW, GW_MAC = "10.0.0.1", "00:1b:21:00:00:01"
LAPTOP = "f8:bc:12:00:00:01"
SERVER = "00:50:56:00:00:10"
pkts = []
ports = iter(range(40000, 65000))


def add(p, t):
    p.time = T0 + t
    pkts.append(p)


def tcp(smac, sip, dmac, dip, dport, t):
    sport = next(ports)
    add(Ether(src=smac, dst=dmac) / IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport, flags="S"), t)
    add(Ether(src=dmac, dst=smac) / IP(src=dip, dst=sip) / TCP(sport=dport, dport=sport, flags="SA"), t + 0.02)
    add(Ether(src=smac, dst=dmac) / IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport, flags="A"), t + 0.04)


add(Ether(src=GW_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=GW_MAC, psrc=GW, pdst=GW), 0.5)
for ip in ("10.0.0.10", "10.0.0.11"):
    add(Ether(src=SERVER, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=SERVER, psrc=ip, pdst=ip), 1)

# The laptop's four stays: 15 minutes each.
ch = bytes.fromhex(LAPTOP.replace(":", ""))
for k, ip in enumerate(["10.0.0.50", "10.0.0.73", "10.0.0.88", "10.0.0.50"]):
    t = 10 + k * 900
    xid = 0x900 + k
    add(Ether(src=LAPTOP, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=ch, xid=xid)
        / DHCP(options=[("message-type", "request"), ("requested_addr", ip), ("hostname", "LAPTOP-ALICE"), "end"]), t)
    add(Ether(src=GW_MAC, dst=LAPTOP) / IP(src=GW, dst=ip) / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=ip, siaddr=GW, chaddr=ch, xid=xid)
        / DHCP(options=[("message-type", "ack"), ("server_id", GW), ("router", GW), ("domain", "corp.example"),
                        ("lease_time", 900), ("subnet_mask", "255.255.255.0"), "end"]), t + 0.01)
    add(Ether(src=LAPTOP, dst=GW_MAC) / ARP(op=2, hwsrc=LAPTOP, psrc=ip, hwdst=GW_MAC, pdst=GW), t + 0.02)
    # Browse and use the file share while on this address, until just before the next lease.
    for j in range(8):
        tt = t + 20 + j * 100
        tcp(LAPTOP, ip, GW_MAC, "93.184.216.34", 443, tt)
        tcp(LAPTOP, ip, SERVER, "10.0.0.10" if j % 2 == 0 else "10.0.0.11", 445, tt + 30)

# The server talks on both addresses throughout (backups to the gateway's syslog).
for j in range(30):
    tcp(SERVER, "10.0.0.10", GW_MAC, GW, 514, 5 + j * 118)
    tcp(SERVER, "10.0.0.11", GW_MAC, GW, 514, 7 + j * 118)

pkts.sort(key=lambda p: float(p.time))
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_roaming.pcap")
wrpcap(out, pkts)
print(f"Wrote {out}: {len(pkts)} packets")
