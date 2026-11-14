#!/usr/bin/env python3
"""Generate two_sites_overlap.pcap and two_sites_overlap_untagged.pcap: two networks that both use
192.168.1.0/24, seen in one capture (#462).

Two sites, HQ and Branch, each have a router at 192.168.1.1 running DHCP for 192.168.1.0/24. A
capture from a trunk port (or two site captures merged) holds both, so the same addresses appear
twice: 192.168.1.10 at HQ is a different machine from 192.168.1.10 at Branch.

What tells the networks apart:
- DHCP: each router names itself (option 54), hands out itself as the router (option 3) and its
  own domain (option 15: hq.corp.example vs branch.corp.example) and lease time (option 51).
- The router's MAC: both are 192.168.1.1, with different MACs.
- 802.1Q VLAN tags: VLAN 10 (HQ) and 20 (Branch), in two_sites_overlap.pcap only. The untagged
  variant has to be told apart from DHCP and the routers' MACs alone.

HQ has 6 DHCP clients (.10 to .15), Branch 4 (.10 to .13), so .10 to .13 are used on both.
"""
import os
from datetime import datetime, timezone

from scapy.all import wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Dot1Q, Ether

GW_IP = "192.168.1.1"
SITES = {
    "hq": {
        "vlan": 10,
        "router_mac": "00:1b:21:aa:00:01",
        "domain": "hq.corp.example",
        "lease": 86400,
        "clients": [
            ("f8:bc:12:10:00:%02x" % i, "192.168.1.%d" % (10 + i), name)
            for i, name in enumerate(["HQ-LAPTOP-01", "HQ-LAPTOP-02", "HQ-PRINTER", "HQ-LAPTOP-03", "HQ-NAS", "HQ-LAPTOP-04"])
        ],
    },
    "branch": {
        "vlan": 20,
        "router_mac": "00:1b:21:bb:00:01",
        "domain": "branch.corp.example",
        "lease": 3600,
        "clients": [
            ("8c:71:f8:20:00:%02x" % i, "192.168.1.%d" % (10 + i), name)
            for i, name in enumerate(["BR-TILL-01", "BR-TILL-02", "BR-LAPTOP-01", "BR-CAMERA"])
        ],
    },
}
T0 = datetime(2026, 11, 12, 8, 0, tzinfo=timezone.utc).timestamp()


def build(tagged):
    pkts = []

    def add(site, p, t):
        if tagged:
            # Re-wrap with the site's VLAN tag between Ethernet and the payload.
            eth = p[Ether]
            p = Ether(src=eth.src, dst=eth.dst) / Dot1Q(vlan=SITES[site]["vlan"]) / eth.payload
        p.time = T0 + t
        pkts.append(p)

    for s_i, (site, cfg) in enumerate(SITES.items()):
        gw = cfg["router_mac"]
        # The router answering for 192.168.1.1.
        add(site, Ether(src=gw, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=gw, psrc=GW_IP, pdst=GW_IP), 1 + s_i)
        for c_i, (mac, ip, name) in enumerate(cfg["clients"]):
            t = 10 + s_i * 2 + c_i * 7
            ch = bytes.fromhex(mac.replace(":", ""))
            xid = 0x1000 * (s_i + 1) + c_i
            add(site, Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
                / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=ch, xid=xid)
                / DHCP(options=[("message-type", "request"), ("requested_addr", ip), ("hostname", name),
                                ("param_req_list", [1, 3, 6, 15, 51]), "end"]), t)
            add(site, Ether(src=gw, dst=mac) / IP(src=GW_IP, dst=ip) / UDP(sport=67, dport=68)
                / BOOTP(op=2, yiaddr=ip, siaddr=GW_IP, chaddr=ch, xid=xid)
                / DHCP(options=[("message-type", "ack"), ("server_id", GW_IP), ("router", GW_IP),
                                ("domain", cfg["domain"]), ("lease_time", cfg["lease"]),
                                ("subnet_mask", "255.255.255.0"), "end"]), t + 0.01)
            add(site, Ether(src=mac, dst=gw) / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=gw, pdst=GW_IP), t + 0.02)
            # Some traffic out through the site's router.
            for k in range(5):
                tt = t + 1 + k * 30
                add(site, Ether(src=mac, dst=gw) / IP(src=ip, dst="93.184.216.34", ttl=128)
                    / TCP(sport=40000 + c_i * 10 + k, dport=443, flags="S"), tt)
                add(site, Ether(src=gw, dst=mac) / IP(src="93.184.216.34", dst=ip, ttl=52)
                    / TCP(sport=443, dport=40000 + c_i * 10 + k, flags="SA"), tt + 0.02)

    pkts.sort(key=lambda p: float(p.time))
    name = "two_sites_overlap.pcap" if tagged else "two_sites_overlap_untagged.pcap"
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    wrpcap(out, pkts)
    print(f"Wrote {out}: {len(pkts)} packets")


build(tagged=True)
build(tagged=False)
