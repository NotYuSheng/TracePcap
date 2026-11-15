#!/usr/bin/env python3
"""Generate site_to_site_vpn.pcap: two office networks joined over the internet by their gateways.

HQ and Branch each have a LAN behind a gateway that does DHCP, DNS forwarding and NAT, and the two
gateways run a WireGuard site-to-site tunnel between their public addresses:

    HQ LAN 192.168.10.0/24 ── gw 192.168.10.1 │ 203.0.113.10 ══ WireGuard ══ 198.51.100.20 │ gw 10.50.0.1 ── Branch LAN 10.50.0.0/24
                                                         ╲                      ╱
                                                          ╲── the internet ────╱   (each site browses, NAT'd to its public address)

The capture is merged from four taps, the way an investigator would combine them:
- each site's LAN side: DHCP, DNS through the gateway, and inner traffic between the sites as it
  enters or leaves the tunnel (Branch PCs to the HQ file server and ERP server, HQ to the Branch
  till for its nightly sync);
- each site's internet side: the tunnel itself (UDP 51820, encrypted, one flow between the two
  public addresses) and the sites' browsing after NAT, from the public address.

Reverse-DNS answers name the two public addresses (vpn.hq.acme.example, vpn.branch.acme.example),
so the gateways' outside faces group together in the network map's Internet box.
"""
import os
from datetime import datetime, timezone

from scapy.all import Raw, wrpcap
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

T0 = datetime(2026, 11, 14, 13, 0, tzinfo=timezone.utc).timestamp()
ISP_MAC = "00:00:5e:00:01:01"  # the ISP's next hop, on both sites' internet side

SITES = {
    "hq": {
        "lan": "192.168.10", "gw_lan_mac": "00:0d:b9:a0:00:01", "gw_wan_mac": "00:0d:b9:a0:00:02",
        "public": "203.0.113.10", "ptr": "vpn.hq.acme.example", "domain": "hq.acme.example",
        "clients": [  # mac, host, hostname
            ("f8:bc:12:10:00:21", 21, "HQ-PC-01"),
            ("f8:bc:12:10:00:22", 22, "HQ-PC-02"),
            ("a4:83:e7:10:00:23", 23, "HQ-MacBook"),
        ],
        "servers": [  # static: mac, host, name
            ("00:50:56:10:00:10", 10, "HQ-FILESERVER"),
            ("00:50:56:10:00:11", 11, "HQ-ERP"),
        ],
    },
    "branch": {
        "lan": "10.50.0", "gw_lan_mac": "00:0d:b9:b0:00:01", "gw_wan_mac": "00:0d:b9:b0:00:02",
        "public": "198.51.100.20", "ptr": "vpn.branch.acme.example", "domain": "branch.acme.example",
        "clients": [
            ("f8:bc:12:50:00:21", 21, "BR-PC-01"),
            ("f8:bc:12:50:00:22", 22, "BR-PC-02"),
            ("3c:d9:2b:50:00:30", 30, "BR-TILL"),
        ],
        "servers": [],
    },
}
WEB = [("www.google.com", "142.250.4.100"), ("outlook.office365.com", "52.97.1.20"), ("github.com", "140.82.112.3")]

pkts = []
ports = iter(range(41000, 65000))
wg_counter = iter(range(1, 10**6))


def add(p, t):
    p.time = T0 + t
    pkts.append(p)


def site(name):
    return SITES[name]


def gw_ip(s):
    return f"{s['lan']}.1"


def tunnel(src_site, nbytes, t):
    """One WireGuard transport packet carrying `nbytes` of inner traffic, on the internet side."""
    a, b = site(src_site), site("branch" if src_site == "hq" else "hq")
    # Type 4 (transport data): 16-byte header, then ciphertext and a 16-byte tag.
    payload = bytes([4, 0, 0, 0]) + (0x1234).to_bytes(4, "little") + next(wg_counter).to_bytes(8, "little")
    payload += os.urandom(max(16, nbytes)) + os.urandom(16)
    add(Ether(src=a["gw_wan_mac"], dst=ISP_MAC) / IP(src=a["public"], dst=b["public"], ttl=64)
        / UDP(sport=51820, dport=51820) / Raw(payload), t)


def inner_flow(cli_site, cli_mac, cli_ip, srv_site, srv_mac, srv_ip, dport, t, rounds=3):
    """TCP across the tunnel: seen on the client's LAN, the tunnel, and the server's LAN."""
    c, s = site(cli_site), site(srv_site)
    sport = next(ports)

    def leg(src_mac_lan, dst_mac_lan, src, dst, sp, dp, flags, data, tt, from_site, to_site):
        f, to = site(from_site), site(to_site)
        seg = TCP(sport=sp, dport=dp, flags=flags) / (data if data else b"")
        # Leaving the sender's LAN, towards its gateway.
        add(Ether(src=src_mac_lan, dst=f["gw_lan_mac"]) / IP(src=src, dst=dst, ttl=128) / seg, tt)
        # Through the tunnel.
        tunnel(from_site, len(bytes(seg)) + 20, tt + 0.004)
        # Arriving on the receiver's LAN, from its gateway.
        add(Ether(src=to["gw_lan_mac"], dst=dst_mac_lan) / IP(src=src, dst=dst, ttl=126) / seg, tt + 0.03)

    leg(cli_mac, srv_mac, cli_ip, srv_ip, sport, dport, "S", None, t, cli_site, srv_site)
    leg(srv_mac, cli_mac, srv_ip, cli_ip, dport, sport, "SA", None, t + 0.06, srv_site, cli_site)
    for k in range(rounds):
        tt = t + 0.15 + k * 0.2
        leg(cli_mac, srv_mac, cli_ip, srv_ip, sport, dport, "PA", b"q" * 180, tt, cli_site, srv_site)
        leg(srv_mac, cli_mac, srv_ip, cli_ip, dport, sport, "PA", b"r" * 1100, tt + 0.08, srv_site, cli_site)


def browse(site_name, cli_mac, cli_ip, name, addr, t):
    """DNS through the gateway, then HTTPS out: on the LAN from the client, outside from the public address."""
    s = site(site_name)
    qid = next(ports) & 0xFFFF
    add(Ether(src=cli_mac, dst=s["gw_lan_mac"]) / IP(src=cli_ip, dst=gw_ip(s)) / UDP(sport=next(ports), dport=53)
        / DNS(id=qid, rd=1, qd=DNSQR(qname=name)), t)
    add(Ether(src=s["gw_lan_mac"], dst=cli_mac) / IP(src=gw_ip(s), dst=cli_ip) / UDP(sport=53, dport=next(ports))
        / DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type="A", ttl=300, rdata=addr)), t + 0.02)
    sport, nat_port = next(ports), next(ports)
    for k, (flags, data) in enumerate([("S", None), ("PA", b"g" * 300), ("PA", b"g" * 200)]):
        tt = t + 0.05 + k * 0.1
        seg_lan = TCP(sport=sport, dport=443, flags=flags) / (data or b"")
        seg_wan = TCP(sport=nat_port, dport=443, flags=flags) / (data or b"")
        add(Ether(src=cli_mac, dst=s["gw_lan_mac"]) / IP(src=cli_ip, dst=addr, ttl=128) / seg_lan, tt)
        add(Ether(src=s["gw_wan_mac"], dst=ISP_MAC) / IP(src=s["public"], dst=addr, ttl=127) / seg_wan, tt + 0.001)
        back_lan = TCP(sport=443, dport=sport, flags="SA" if flags == "S" else "PA") / (b"" if flags == "S" else b"w" * 1300)
        back_wan = TCP(sport=443, dport=nat_port, flags="SA" if flags == "S" else "PA") / (b"" if flags == "S" else b"w" * 1300)
        add(Ether(src=ISP_MAC, dst=s["gw_wan_mac"]) / IP(src=addr, dst=s["public"], ttl=54) / back_wan, tt + 0.03)
        add(Ether(src=s["gw_lan_mac"], dst=cli_mac) / IP(src=addr, dst=cli_ip, ttl=53) / back_lan, tt + 0.031)


# ── The gateways come up and bring up the tunnel ────────────────────────────────────────────────
for name, s in SITES.items():
    add(Ether(src=s["gw_lan_mac"], dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=s["gw_lan_mac"], psrc=gw_ip(s), pdst=gw_ip(s)), 0.5)
    for mac, host, _ in s["servers"]:
        ip = f"{s['lan']}.{host}"
        add(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=mac, psrc=ip, pdst=ip), 0.8)
hq, br = site("hq"), site("branch")
# WireGuard handshake: initiation (type 1, 148 bytes) and response (type 2, 92 bytes).
add(Ether(src=hq["gw_wan_mac"], dst=ISP_MAC) / IP(src=hq["public"], dst=br["public"]) / UDP(sport=51820, dport=51820)
    / Raw(bytes([1, 0, 0, 0]) + os.urandom(144)), 2)
add(Ether(src=br["gw_wan_mac"], dst=ISP_MAC) / IP(src=br["public"], dst=hq["public"]) / UDP(sport=51820, dport=51820)
    / Raw(bytes([2, 0, 0, 0]) + os.urandom(88)), 2.05)
# Keepalives every 25 s through the capture (empty transport packets).
for k in range(48):
    tunnel("hq" if k % 2 == 0 else "branch", 0, 5 + k * 25)

# ── Clients join their LAN (DHCP) ───────────────────────────────────────────────────────────────
for name, s in SITES.items():
    for c_i, (mac, host, hostname) in enumerate(s["clients"]):
        ip, t = f"{s['lan']}.{host}", 10 + c_i * 4 + (2 if name == "branch" else 0)
        ch, xid = bytes.fromhex(mac.replace(":", "")), (0x500 if name == "hq" else 0x600) + c_i
        add(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
            / BOOTP(op=1, chaddr=ch, xid=xid)
            / DHCP(options=[("message-type", "request"), ("requested_addr", ip), ("hostname", hostname), "end"]), t)
        add(Ether(src=s["gw_lan_mac"], dst=mac) / IP(src=gw_ip(s), dst=ip) / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=ip, siaddr=gw_ip(s), chaddr=ch, xid=xid)
            / DHCP(options=[("message-type", "ack"), ("server_id", gw_ip(s)), ("router", gw_ip(s)),
                            ("name_server", gw_ip(s)), ("domain", s["domain"]), ("lease_time", 43200),
                            ("subnet_mask", "255.255.255.0"), "end"]), t + 0.01)

# ── Someone at HQ looks the gateways' public addresses up (reverse DNS) ─────────────────────────
pc_mac, pc_ip = hq["clients"][0][0], f"{hq['lan']}.21"
for k, s in enumerate(SITES.values()):
    rev = ".".join(reversed(s["public"].split("."))) + ".in-addr.arpa"
    qid = 0x7000 + k
    add(Ether(src=pc_mac, dst=hq["gw_lan_mac"]) / IP(src=pc_ip, dst=gw_ip(hq)) / UDP(sport=next(ports), dport=53)
        / DNS(id=qid, rd=1, qd=DNSQR(qname=rev, qtype="PTR")), 40 + k)
    add(Ether(src=hq["gw_lan_mac"], dst=pc_mac) / IP(src=gw_ip(hq), dst=pc_ip) / UDP(sport=53, dport=next(ports))
        / DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=rev, qtype="PTR"),
              an=DNSRR(rrname=rev, type="PTR", ttl=3600, rdata=s["ptr"])), 40.02 + k)

# ── Work across the tunnel ──────────────────────────────────────────────────────────────────────
fs_mac, fs_ip = hq["servers"][0][0], f"{hq['lan']}.10"
erp_mac, erp_ip = hq["servers"][1][0], f"{hq['lan']}.11"
for c_i, (mac, host, hostname) in enumerate(br["clients"]):
    ip = f"{br['lan']}.{host}"
    for k in range(5):
        t = 60 + c_i * 11 + k * 220
        if hostname == "BR-TILL":
            inner_flow("branch", mac, ip, "hq", erp_mac, erp_ip, 8443, t)  # the till posts sales to the ERP
        else:
            inner_flow("branch", mac, ip, "hq", fs_mac, fs_ip, 445, t)     # Branch PCs use the HQ file share
# HQ's ERP pulls the till's day at the end (HQ → Branch).
till_mac, till_ip = br["clients"][2][0], f"{br['lan']}.30"
inner_flow("hq", erp_mac, erp_ip, "branch", till_mac, till_ip, 9100, 1100, rounds=6)
# HQ PCs use the local file server too (stays on the HQ LAN).
for c_i, (mac, host, _) in enumerate(hq["clients"]):
    ip = f"{hq['lan']}.{host}"
    for k in range(3):
        sport = next(ports)
        t = 30 + c_i * 9 + k * 300
        add(Ether(src=mac, dst=fs_mac) / IP(src=ip, dst=fs_ip) / TCP(sport=sport, dport=445, flags="S"), t)
        add(Ether(src=fs_mac, dst=mac) / IP(src=fs_ip, dst=ip) / TCP(sport=445, dport=sport, flags="SA"), t + 0.01)

# ── Each site browses the internet, NAT'd to its own public address ─────────────────────────────
for name, s in SITES.items():
    for c_i, (mac, host, hostname) in enumerate(s["clients"]):
        if hostname == "BR-TILL":
            continue
        ip = f"{s['lan']}.{host}"
        for k in range(3):
            n, a = WEB[(c_i + k) % len(WEB)]
            browse(name, mac, ip, n, a, 90 + c_i * 13 + k * 330 + (7 if name == "branch" else 0))

pkts.sort(key=lambda p: float(p.time))
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site_to_site_vpn.pcap")
wrpcap(out, pkts)
print(f"Wrote {out}: {len(pkts)} packets")
