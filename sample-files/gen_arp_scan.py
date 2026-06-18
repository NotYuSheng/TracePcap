#!/usr/bin/env python3
"""Generate arp_scan.pcap — one host ARP-scanning a /24, only some hosts reply.

Demonstrates issue #387: the conversation tracer should distinguish responding
from silent nodes. Scanner 192.168.1.10 sends "who-has" for .1 .. .12;
a subset reply with their MAC, the rest stay silent.
"""
import os
from scapy.all import wrpcap
from scapy.layers.l2 import Ether, ARP

SCANNER_IP = "192.168.1.10"
SCANNER_MAC = "aa:bb:cc:00:00:10"

# .ip -> mac for hosts that ARE alive (will reply); others are silent.
ALIVE = {
    1: "aa:bb:cc:00:00:01",
    5: "aa:bb:cc:00:00:05",
    7: "aa:bb:cc:00:00:07",
    11: "aa:bb:cc:00:00:0b",
}
TARGETS = range(1, 13)  # probe .1 .. .12

pkts = []
for n in TARGETS:
    target_ip = f"192.168.1.{n}"
    # Broadcast ARP request "who has target_ip, tell SCANNER_IP"
    req = Ether(src=SCANNER_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc=SCANNER_MAC, psrc=SCANNER_IP, hwdst="00:00:00:00:00:00", pdst=target_ip
    )
    pkts.append(req)
    if n in ALIVE:
        # ARP reply: target_ip is-at its MAC, unicast back to scanner
        reply = Ether(src=ALIVE[n], dst=SCANNER_MAC) / ARP(
            op=2, hwsrc=ALIVE[n], psrc=target_ip, hwdst=SCANNER_MAC, pdst=SCANNER_IP
        )
        pkts.append(reply)

out = os.path.join(os.path.dirname(__file__), "arp_scan.pcap")
wrpcap(out, pkts)
print(f"Wrote {out}: {len(pkts)} packets, {len(ALIVE)} of {len(list(TARGETS))} targets alive")
