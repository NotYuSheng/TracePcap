#!/usr/bin/env python3
"""Generate small_office.pcap: a small office with several networks, for the network map layout.

One router serves four VLANs. Three of them hand out addresses by DHCP, each with its own domain;
the server VLAN is statically addressed, so no DHCP describes it:

- VLAN 10  staff.office.example    10.20.10.0/24  laptops (Dell, Apple), staff phones
- VLAN 20  guest.office.example    10.20.20.0/24  visitors' phones; one joins halfway through
- VLAN 30  devices.office.example  10.20.30.0/24  printers (HP), cameras (Hikvision), a NAS (Synology)
- VLAN 40  servers, static         10.20.40.0/24  DNS 10.20.40.53, file server, domain controller

Traffic that fills each part of the map:
- DHCP for every client (hostname, domain, lease), so devices land in their network.
- DNS lookups through 10.20.40.53 with answers, then HTTPS to the answered addresses, so internet
  hosts have names and group by domain (google.com, github.com, office365.com, example.co.uk…).
- Between VLANs: laptops to the file server (SMB) and printers (IPP), cameras to the NAS (RTSP).
- mDNS from the phones, and DHCP's 0.0.0.0 / 255.255.255.255, for the broadcast group.

The capture runs 30 minutes, so the time axis has something to play: the guest phone appears at
15 minutes, and the cameras only start recording at 5.
"""
import os
from datetime import datetime, timezone

from scapy.all import wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Dot1Q, Ether

ROUTER_MAC = "00:1b:21:c0:00:01"
T0 = datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc).timestamp()

VLANS = {
    10: {"net": "10.20.10", "domain": "staff.office.example", "lease": 28800, "clients": [
        ("f8:bc:12:a0:00:01", 21, "LAPTOP-ANNA", 0),
        ("f8:bc:12:a0:00:02", 22, "LAPTOP-BEN", 0),
        ("f8:bc:12:a0:00:03", 23, "LAPTOP-CHLOE", 60),
        ("a4:83:e7:a0:00:04", 24, "Davids-MacBook-Pro", 120),
        ("a4:83:e7:a0:00:05", 25, "Annas-iPhone", 30),
        ("8c:71:f8:a0:00:06", 26, "Galaxy-S24-Ben", 90),
    ]},
    20: {"net": "10.20.20", "domain": "guest.office.example", "lease": 3600, "clients": [
        ("8c:71:f8:b0:00:01", 51, "Galaxy-A55", 200),
        ("a4:83:e7:b0:00:02", 52, "Visitors-iPhone", 900),
    ]},
    30: {"net": "10.20.30", "domain": "devices.office.example", "lease": 86400, "clients": [
        ("3c:d9:2b:c0:00:01", 31, "HP-LaserJet-2F", 0),
        ("3c:d9:2b:c0:00:02", 32, "HP-LaserJet-3F", 0),
        ("44:19:b6:c0:00:03", 41, "CAM-ENTRANCE", 300),
        ("44:19:b6:c0:00:04", 42, "CAM-CARPARK", 300),
        ("00:11:32:c0:00:05", 50, "NAS-OFFICE", 0),
    ]},
}
SERVERS = {  # VLAN 40, static
    "dns": ("00:50:56:d0:00:53", "10.20.40.53"),
    "files": ("00:50:56:d0:00:10", "10.20.40.10"),
    "dc": ("00:50:56:d0:00:11", "10.20.40.11"),
}
SITES = [  # name -> address answered by DNS
    ("www.google.com", "142.250.4.100"),
    ("mail.google.com", "142.250.4.101"),
    ("api.github.com", "140.82.112.6"),
    ("github.com", "140.82.112.3"),
    ("outlook.office365.com", "52.97.1.20"),
    ("teams.microsoft.com", "52.113.194.1"),
    ("cdn.example.co.uk", "93.184.216.50"),
    ("www.bbc.co.uk", "151.101.0.81"),
]

pkts = []
ports = iter(range(40000, 65000))


def add(vlan, p, t):
    eth = p[Ether]
    p = Ether(src=eth.src, dst=eth.dst) / Dot1Q(vlan=vlan) / eth.payload
    p.time = T0 + t
    pkts.append(p)


def tcp_flow(vlan, smac, sip, dmac, dip, dport, t, n=3):
    """A short TCP exchange: handshake plus a few data packets each way."""
    sport = next(ports)
    add(vlan, Ether(src=smac, dst=dmac) / IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport, flags="S"), t)
    add(vlan, Ether(src=dmac, dst=smac) / IP(src=dip, dst=sip) / TCP(sport=dport, dport=sport, flags="SA"), t + 0.02)
    for k in range(n):
        add(vlan, Ether(src=smac, dst=dmac) / IP(src=sip, dst=dip) / TCP(sport=sport, dport=dport, flags="PA") / (b"q" * 200), t + 0.05 + k * 0.1)
        add(vlan, Ether(src=dmac, dst=smac) / IP(src=dip, dst=sip) / TCP(sport=dport, dport=sport, flags="PA") / (b"r" * 1200), t + 0.08 + k * 0.1)


# Servers announce themselves.
for i, (mac, ip) in enumerate(SERVERS.values()):
    add(40, Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=mac, psrc=ip, pdst=ip), 0.5 + i * 0.1)

for vlan, cfg in VLANS.items():
    gw = f"{cfg['net']}.1"
    add(vlan, Ether(src=ROUTER_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=ROUTER_MAC, psrc=gw, pdst=gw), 1)
    for c_i, (mac, host, name, start) in enumerate(cfg["clients"]):
        ip = f"{cfg['net']}.{host}"
        t = 5 + start + c_i * 3
        ch = bytes.fromhex(mac.replace(":", ""))
        xid = vlan * 0x100 + c_i
        add(vlan, Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=ch, xid=xid)
            / DHCP(options=[("message-type", "request"), ("requested_addr", ip), ("hostname", name),
                            ("param_req_list", [1, 3, 6, 15, 51]), "end"]), t)
        add(vlan, Ether(src=ROUTER_MAC, dst=mac) / IP(src=gw, dst=ip) / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=ip, siaddr=gw, chaddr=ch, xid=xid)
            / DHCP(options=[("message-type", "ack"), ("server_id", gw), ("router", gw),
                            ("name_server", SERVERS["dns"][1]), ("domain", cfg["domain"]),
                            ("lease_time", cfg["lease"]), ("subnet_mask", "255.255.255.0"), "end"]), t + 0.01)
        add(vlan, Ether(src=mac, dst=ROUTER_MAC) / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=ROUTER_MAC, pdst=gw), t + 0.02)

        is_phone = "iPhone" in name or "Galaxy" in name
        is_laptop = "LAPTOP" in name or "MacBook" in name
        if is_phone:
            # mDNS, to the multicast group.
            add(vlan, Ether(src=mac, dst="01:00:5e:00:00:fb") / IP(src=ip, dst="224.0.0.251")
                / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="_companion-link._tcp.local", qtype="PTR")), t + 1)
        if vlan == 10 or vlan == 20:
            # Browse: look a name up, then HTTPS to the answer. Every few minutes, a different site.
            span = 1800 - t
            for k in range(6):
                name_q, addr = SITES[(c_i * 3 + k + vlan) % len(SITES)]
                tt = t + 20 + k * span / 7
                qid = (xid + k) & 0xFFFF
                dns_mac, dns_ip = SERVERS["dns"]
                # The query is routed to the server VLAN; seen here on the client's.
                add(vlan, Ether(src=mac, dst=ROUTER_MAC) / IP(src=ip, dst=dns_ip) / UDP(sport=next(ports), dport=53)
                    / DNS(id=qid, rd=1, qd=DNSQR(qname=name_q)), tt)
                add(vlan, Ether(src=ROUTER_MAC, dst=mac) / IP(src=dns_ip, dst=ip) / UDP(sport=53, dport=next(ports))
                    / DNS(id=qid, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=name_q),
                          an=DNSRR(rrname=name_q, type="A", ttl=300, rdata=addr)), tt + 0.01)
                tcp_flow(vlan, mac, ip, ROUTER_MAC, addr, 443, tt + 0.05)
        if is_laptop:
            # Office work across VLANs: the file server, the domain controller, a print job.
            for k in range(4):
                tt = t + 40 + k * 400
                tcp_flow(vlan, mac, ip, ROUTER_MAC, SERVERS["files"][1], 445, tt)
                tcp_flow(vlan, mac, ip, ROUTER_MAC, SERVERS["dc"][1], 88, tt + 2, n=1)
            tcp_flow(vlan, mac, ip, ROUTER_MAC, "10.20.30.31" if c_i % 2 == 0 else "10.20.30.32", 631, t + 300)
        if name.startswith("CAM-"):
            # Cameras record to the NAS, from minute 5 on.
            for k in range(8):
                tcp_flow(vlan, mac, ip, VLANS[30]["clients"][4][0], "10.20.30.50", 554, t + k * 180, n=4)

pkts.sort(key=lambda p: float(p.time))
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "small_office.pcap")
wrpcap(out, pkts)
print(f"Wrote {out}: {len(pkts)} packets")
