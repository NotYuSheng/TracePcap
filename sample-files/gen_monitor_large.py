"""
Generate 8 synthetic PCAPs for the Network Monitor demo.

Scenario: External auditor handed weekly captures from a mid-sized office
network. No documentation provided. The auditor pieces together the topology
from traffic alone — and discovers a string of internal policy violations that
escalate over the audit period before subsiding.

Network segments (inferred from traffic — not provided upfront)
──────────────────────────────────────────────────────────────
  10.0.1.0/24   Staff workstations        (~120 hosts)
  10.0.2.0/24   Servers (file, mail, web) (~20 hosts)
  10.0.3.0/24   Printers / peripherals    (~15 hosts)
  10.0.4.0/24   WiFi / BYOD               (~80 hosts)

Core named devices
──────────────────
  GW            10.0.1.1    Corporate gateway / router
  FILESERVER    10.0.2.10   Internal file server (SMB :445)
  MAILSERVER    10.0.2.20   Internal mail server (SMTP :25, IMAP :143)
  WEBSERVER     10.0.2.30   Internal intranet (HTTP :80)
  PRINTER_A     10.0.3.5    Floor printer (LPD :515, IPP :631)
  PRINTER_B     10.0.3.6    Second printer

  WS_ALICE      10.0.1.10   Alice — compliant employee
  WS_BOB        10.0.1.11   Bob — policy violator
  WS_CAROL      10.0.1.12   Carol — joins week 3, Telnet user
  WS_DAVE       10.0.1.13   Dave — joins week 5, shadow-IT device
  LAPTOP_BOB    10.0.4.20   Bob's personal laptop on WiFi (joins week 2)
  MOBILE_EVE    10.0.4.30   Eve's personal mobile (joins week 4)
  SHADOW_DEV    10.0.4.50   Unknown device — unusual MAC OUI (joins week 5)

External IPs
────────────
  GW_PRIMARY    203.0.113.1   ISP primary (weeks 1-3, 7-8)
  GW_SECONDARY  198.51.100.1  ISP secondary failover (weeks 4-6)
  EXFIL_IP      192.0.2.99    External FTP server (Bob exfiltrates week 4-5)
  VPN_ENDPOINT  198.51.100.50 VPN server Bob tunnels to (weeks 2-6)

Policy violations story arc
───────────────────────────
  Week 1        Clean baseline — normal office traffic
  Week 2        Bob's personal laptop joins WiFi; WireGuard VPN tunnel appears
  Week 3        Carol uses Telnet to file server (cleartext); Bob runs BitTorrent
  Week 4        Bob FTP-exfiltrates to external IP; ISP failover (gateway change)
  Week 5        Shadow device appears (no hostname, unusual OUI); ARP anomaly
  Week 6        Multiple violations peak — FTP + BitTorrent + Telnet still active
  Week 7        Violations drop off (audit notice sent); gateway back to primary
  Week 8        Near-baseline; shadow device gone; one lingering personal device

Output: ./monitor_large/week{1..8}_*.pcap
Usage:  python3 gen_monitor_large.py
"""

import os
import random
import struct
from datetime import datetime, timedelta, timezone
from scapy.all import Ether, IP, TCP, UDP, ARP, DNS, DNSQR, Raw, wrpcap

random.seed(42)

OUTDIR = os.path.join(os.path.dirname(__file__), "monitor_large")
os.makedirs(OUTDIR, exist_ok=True)

# ── Timestamps ────────────────────────────────────────────────────────────────

BASE = datetime(2024, 1, 8, 9, 0, 0, tzinfo=timezone.utc)

def week_start(week: int) -> float:
    return (BASE + timedelta(weeks=week - 1)).timestamp()


# ── Packet helpers ────────────────────────────────────────────────────────────

def arp_reply(sender_mac, sender_ip, target_mac, target_ip, t=0.0):
    p = Ether(src=sender_mac, dst=target_mac) / ARP(
        op=2, hwsrc=sender_mac, psrc=sender_ip, hwdst=target_mac, pdst=target_ip)
    p.time = t
    return p


def tcp_session(src_mac, dst_mac, src_ip, dst_ip, sport, dport,
                payload=b"GET / HTTP/1.1\r\nHost: internal\r\n\r\n", t0=0.0):
    pkts, t = [], t0
    def pk(flags, data=b"", rev=False):
        nonlocal t
        sm, dm = (src_mac, dst_mac) if not rev else (dst_mac, src_mac)
        si, di = (src_ip, dst_ip)   if not rev else (dst_ip, src_ip)
        sp, dp = (sport, dport)     if not rev else (dport, sport)
        pp = Ether(src=sm, dst=dm) / IP(src=si, dst=di) / TCP(sport=sp, dport=dp, flags=flags)
        if data: pp = pp / Raw(data)
        pp.time = t; t += 0.003
        return pp
    pkts += [pk("S"), pk("SA", rev=True), pk("A"),
             pk("PA", payload), pk("PA", b"HTTP/1.1 200 OK\r\n\r\nOK", rev=True), pk("FA")]
    return pkts


def udp_burst(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload, t0, count=15, gap=0.3):
    pkts = []
    for i in range(count):
        p = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
            UDP(sport=sport, dport=dport) / Raw(payload)
        p.time = t0 + i * gap
        pkts.append(p)
    return pkts


def wireguard_burst(src_mac, dst_mac, src_ip, dst_ip, t0, count=20):
    payload = bytes([0x01, 0x00, 0x00, 0x00]) + os.urandom(144)
    return udp_burst(src_mac, dst_mac, src_ip, dst_ip, 51820, 51820, payload, t0, count)


def bittorrent_burst(src_mac, dst_mac, src_ip, dst_ip, t0, count=15):
    payload = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
    return udp_burst(src_mac, dst_mac, src_ip, dst_ip, 6881, 6881, payload, t0, count)


def ftp_session(src_mac, dst_mac, src_ip, dst_ip, t0):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49300, 21,
                       payload=b"USER ftpuser\r\nPASS letmein\r\nSTOR report_q4.pdf\r\n", t0=t0)


def telnet_session(src_mac, dst_mac, src_ip, dst_ip, t0):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49200, 23,
                       payload=b"login: admin\r\nPassword: P@ssw0rd\r\nls /home\r\n", t0=t0)


def smb_session(src_mac, dst_mac, src_ip, dst_ip, t0):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49500, 445,
                       payload=b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18", t0=t0)


def smtp_session(src_mac, dst_mac, src_ip, dst_ip, t0):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49600, 25,
                       payload=b"EHLO workstation\r\nMAIL FROM:<user@corp.internal>\r\nRCPT TO:<ceo@corp.internal>\r\n", t0=t0)


def imap_session(src_mac, dst_mac, src_ip, dst_ip, t0):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49700, 143,
                       payload=b"A001 LOGIN user password\r\nA002 SELECT INBOX\r\n", t0=t0)


def http_session(src_mac, dst_mac, src_ip, dst_ip, t0, host=b"intranet.corp.internal"):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49800, 80,
                       payload=b"GET /index.html HTTP/1.1\r\nHost: " + host + b"\r\n\r\n", t0=t0)


def https_session(src_mac, dst_mac, src_ip, dst_ip, t0):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49900, 443,
                       payload=b"\x16\x03\x01\x00\xf1\x01\x00\x00", t0=t0)


def ipp_session(src_mac, dst_mac, src_ip, dst_ip, t0):
    """IPP print job."""
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49100, 631,
                       payload=b"POST /ipp/print HTTP/1.1\r\nContent-Type: application/ipp\r\n\r\n", t0=t0)


def dns_query(src_mac, src_ip, dst_mac, dst_ip, name, t=0.0):
    p = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
        UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
    p.time = t
    return p


# ── MAC / IP generation ───────────────────────────────────────────────────────

def mac(i: int) -> str:
    """Deterministic MAC — uses 02:xx OUI (locally administered)."""
    b = struct.pack(">I", i)
    return f"02:00:{b[0]:02x}:{b[1]:02x}:{b[2]:02x}:{b[3]:02x}"


def ip_in_subnet(subnet_prefix: str, host_index: int) -> str:
    """Return 10.0.<subnet>.<host> where host is 2..253."""
    host = (host_index % 252) + 2
    return f"10.0.{subnet_prefix}.{host}"


# ── Named devices ─────────────────────────────────────────────────────────────

GW_MAC          = "00:aa:bb:cc:dd:01";  GW_IP           = "10.0.1.1"
FILESERVER_MAC  = "00:aa:bb:cc:dd:10";  FILESERVER_IP   = "10.0.2.10"
MAILSERVER_MAC  = "00:aa:bb:cc:dd:20";  MAILSERVER_IP   = "10.0.2.20"
WEBSERVER_MAC   = "00:aa:bb:cc:dd:30";  WEBSERVER_IP    = "10.0.2.30"
PRINTER_A_MAC   = "00:aa:bb:cc:dd:50";  PRINTER_A_IP    = "10.0.3.5"
PRINTER_B_MAC   = "00:aa:bb:cc:dd:51";  PRINTER_B_IP    = "10.0.3.6"

WS_ALICE_MAC    = "ac:de:48:11:11:01";  WS_ALICE_IP     = "10.0.1.10"
WS_BOB_MAC      = "ac:de:48:22:22:02";  WS_BOB_IP       = "10.0.1.11"
WS_CAROL_MAC    = "ac:de:48:33:33:03";  WS_CAROL_IP     = "10.0.1.12"  # joins week 3
WS_DAVE_MAC     = "ac:de:48:44:44:04";  WS_DAVE_IP      = "10.0.1.13"  # joins week 5
LAPTOP_BOB_MAC  = "dc:a6:32:55:55:05";  LAPTOP_BOB_IP   = "10.0.4.20"  # Bob's personal, joins week 2
MOBILE_EVE_MAC  = "f0:18:98:66:66:06";  MOBILE_EVE_IP   = "10.0.4.30"  # personal mobile, joins week 4
SHADOW_DEV_MAC  = "b8:27:eb:77:77:07";  SHADOW_DEV_IP   = "10.0.4.50"  # unknown device, joins week 5

# External
GW_PRIMARY      = "203.0.113.1"
GW_SECONDARY    = "198.51.100.1"
EXFIL_IP        = "192.0.2.99"
VPN_ENDPOINT    = "198.51.100.50"

# Convenience
BROADCAST_MAC   = "ff:ff:ff:ff:ff:ff"


# ── Background host pool ──────────────────────────────────────────────────────
# 120 staff workstations + 80 WiFi/BYOD + 5 spare servers = 205 background hosts

BG_STAFF  = [(mac(200 + i), ip_in_subnet("1", 20 + i))  for i in range(120)]  # 10.0.1.22+
BG_WIFI   = [(mac(400 + i), ip_in_subnet("4", 60 + i))  for i in range(80)]   # 10.0.4.62+
BG_ALL    = BG_STAFF + BG_WIFI


def active_bg(week: int):
    """Background hosts active this week. A few join progressively; some WiFi devices churn."""
    staff = BG_STAFF[:]
    # 5 new staff workstations join each week from week 2 (new hires / equipment refresh)
    if week >= 2:
        staff = BG_STAFF[:min(120, 100 + (week - 1) * 5)]
    # WiFi: rotate which 50 of 80 are present (simulate daily connect/disconnect)
    random.seed(week * 7)
    wifi = random.sample(BG_WIFI, 50)
    return staff + wifi


def drifted_ip(original_ip: str, delta: int) -> str:
    parts = original_ip.split(".")
    host = (int(parts[3]) + delta) % 252 + 2
    return f"{parts[0]}.{parts[1]}.{parts[2]}.{host}"


# ── Background traffic helpers ────────────────────────────────────────────────

def bg_arp_announce(hosts, t0, gap=0.02):
    return [arp_reply(m, ip, GW_MAC, GW_IP, t=t0 + i * gap)
            for i, (m, ip) in enumerate(hosts)]


def bg_http(hosts, gateway, t0, frac=0.5):
    pkts = []
    for i, (m, ip) in enumerate(hosts):
        if random.random() < frac:
            pkts += http_session(m, GW_MAC, ip, gateway, t0 + i * 0.01)
    return pkts


def bg_https(hosts, gateway, t0, frac=0.6):
    pkts = []
    for i, (m, ip) in enumerate(hosts):
        if random.random() < frac:
            pkts += https_session(m, GW_MAC, ip, gateway, t0=t0 + i * 0.01)
    return pkts


def bg_dns(hosts, t0, frac=0.4):
    pkts = []
    for i, (m, ip) in enumerate(hosts):
        if random.random() < frac:
            pkts.append(dns_query(m, ip, GW_MAC, GW_IP, "corp.internal", t=t0 + i * 0.015))
    return pkts


def bg_smb(hosts, t0, frac=0.3):
    """Staff workstations accessing file server."""
    pkts = []
    for i, (m, ip) in enumerate(hosts):
        if random.random() < frac:
            pkts += smb_session(m, GW_MAC, ip, FILESERVER_IP, t0 + i * 0.02)
    return pkts


def bg_print(hosts, t0, frac=0.1):
    """Some staff send print jobs."""
    pkts = []
    printer = PRINTER_A_IP if random.random() < 0.5 else PRINTER_B_IP
    printer_mac = PRINTER_A_MAC if printer == PRINTER_A_IP else PRINTER_B_MAC
    for i, (m, ip) in enumerate(hosts):
        if random.random() < frac:
            pkts += ipp_session(m, printer_mac, ip, printer, t0 + i * 0.05)
    return pkts


# ── Save ──────────────────────────────────────────────────────────────────────

def save(pkts, filename):
    pkts.sort(key=lambda p: p.time)
    path = os.path.join(OUTDIR, filename)
    wrpcap(path, pkts)
    unique_macs = len(set(p[Ether].src for p in pkts if Ether in p))
    unique_ips  = len(set(p[IP].src   for p in pkts if IP   in p))
    print(f"  {filename:60s} {len(pkts):5d} pkts  {unique_macs:4d} MACs  {unique_ips:4d} src IPs")


# ── Week builders ─────────────────────────────────────────────────────────────

def make_week1():
    """
    Clean baseline — normal office Monday.
    Alice, Bob, servers, printers all behaving normally.
    Gateway: ISP primary.
    """
    t0 = week_start(1)
    pkts = []
    bg = active_bg(1)
    gw = GW_PRIMARY

    # Server ARPs
    pkts += [
        arp_reply(GW_MAC,         GW_IP,         BROADCAST_MAC, "0.0.0.0",    t=t0 + 0.0),
        arp_reply(FILESERVER_MAC, FILESERVER_IP,  GW_MAC, GW_IP,              t=t0 + 0.1),
        arp_reply(MAILSERVER_MAC, MAILSERVER_IP,  GW_MAC, GW_IP,              t=t0 + 0.2),
        arp_reply(WEBSERVER_MAC,  WEBSERVER_IP,   GW_MAC, GW_IP,              t=t0 + 0.3),
        arp_reply(PRINTER_A_MAC,  PRINTER_A_IP,   GW_MAC, GW_IP,              t=t0 + 0.4),
        arp_reply(PRINTER_B_MAC,  PRINTER_B_IP,   GW_MAC, GW_IP,              t=t0 + 0.5),
        arp_reply(WS_ALICE_MAC,   WS_ALICE_IP,    GW_MAC, GW_IP,              t=t0 + 0.6),
        arp_reply(WS_BOB_MAC,     WS_BOB_IP,      GW_MAC, GW_IP,              t=t0 + 0.7),
    ]

    # Alice — normal workday: intranet, email, file server, internet HTTPS
    pkts += http_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, WEBSERVER_IP,   t0=t0 + 2.0)
    pkts += smb_session( WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, FILESERVER_IP,  t0=t0 + 5.0)
    pkts += smtp_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP,  t0=t0 + 8.0)
    pkts += imap_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP,  t0=t0 + 11.0)
    pkts += https_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, gw,            t0=t0 + 14.0)
    pkts += ipp_session(WS_ALICE_MAC, PRINTER_A_MAC, WS_ALICE_IP, PRINTER_A_IP, t0=t0 + 17.0)

    # Bob — normal workday
    pkts += http_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, WEBSERVER_IP,      t0=t0 + 3.0)
    pkts += smb_session( WS_BOB_MAC, GW_MAC, WS_BOB_IP, FILESERVER_IP,     t0=t0 + 6.0)
    pkts += smtp_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, MAILSERVER_IP,     t0=t0 + 9.0)
    pkts += https_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, gw,               t0=t0 + 12.0)

    # DNS
    pkts += [
        dns_query(WS_ALICE_MAC, WS_ALICE_IP, GW_MAC, GW_IP, "corp.internal",   t=t0 + 20.0),
        dns_query(WS_BOB_MAC,   WS_BOB_IP,   GW_MAC, GW_IP, "corp.internal",   t=t0 + 21.0),
        dns_query(WS_ALICE_MAC, WS_ALICE_IP, GW_MAC, GW_IP, "google.com",      t=t0 + 22.0),
    ]

    # Background
    pkts += bg_arp_announce(bg, t0 + 30.0)
    pkts += bg_http(bg, gw, t0 + 60.0)
    pkts += bg_https(bg, gw, t0 + 120.0)
    pkts += bg_dns(bg, t0 + 200.0)
    pkts += bg_smb(bg, t0 + 250.0)
    pkts += bg_print(bg, t0 + 350.0)

    save(pkts, "week1_baseline.pcap")


def make_week2():
    """
    Bob's personal laptop appears on WiFi.
    WireGuard VPN tunnel from Bob's laptop to external endpoint.
    New staff workstations join (MAC_ADDED from background).
    Gateway: ISP primary.
    """
    t0 = week_start(2)
    pkts = []
    bg = active_bg(2)
    gw = GW_PRIMARY

    # ARPs — Bob's laptop joins WiFi
    pkts += [
        arp_reply(GW_MAC,         GW_IP,         BROADCAST_MAC, "0.0.0.0",   t=t0 + 0.0),
        arp_reply(FILESERVER_MAC, FILESERVER_IP,  GW_MAC, GW_IP,             t=t0 + 0.1),
        arp_reply(MAILSERVER_MAC, MAILSERVER_IP,  GW_MAC, GW_IP,             t=t0 + 0.2),
        arp_reply(WEBSERVER_MAC,  WEBSERVER_IP,   GW_MAC, GW_IP,             t=t0 + 0.3),
        arp_reply(PRINTER_A_MAC,  PRINTER_A_IP,   GW_MAC, GW_IP,             t=t0 + 0.4),
        arp_reply(PRINTER_B_MAC,  PRINTER_B_IP,   GW_MAC, GW_IP,             t=t0 + 0.5),
        arp_reply(WS_ALICE_MAC,   WS_ALICE_IP,    GW_MAC, GW_IP,             t=t0 + 0.6),
        arp_reply(WS_BOB_MAC,     WS_BOB_IP,      GW_MAC, GW_IP,             t=t0 + 0.7),
        # NEW: Bob's personal laptop on WiFi
        arp_reply(LAPTOP_BOB_MAC, LAPTOP_BOB_IP,  GW_MAC, GW_IP,             t=t0 + 0.8),
    ]

    # Alice — normal
    pkts += http_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, WEBSERVER_IP,  t0=t0 + 2.0)
    pkts += smb_session( WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, FILESERVER_IP, t0=t0 + 5.0)
    pkts += smtp_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP, t0=t0 + 8.0)
    pkts += https_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, gw,           t0=t0 + 11.0)

    # Bob — workstation normal traffic
    pkts += smb_session(WS_BOB_MAC,  GW_MAC, WS_BOB_IP,    FILESERVER_IP, t0=t0 + 3.0)
    pkts += https_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP,   gw,            t0=t0 + 6.0)

    # Bob's laptop — WireGuard VPN to bypass corporate proxy (POLICY VIOLATION)
    pkts += wireguard_burst(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, VPN_ENDPOINT, t0=t0 + 15.0, count=25)
    pkts += https_session(LAPTOP_BOB_MAC,  GW_MAC, LAPTOP_BOB_IP, gw,            t0=t0 + 25.0)
    pkts += [
        dns_query(LAPTOP_BOB_MAC, LAPTOP_BOB_IP, GW_MAC, GW_IP, "personal-vpn.example.com", t=t0 + 30.0),
    ]

    # DNS
    pkts += [
        dns_query(WS_ALICE_MAC, WS_ALICE_IP, GW_MAC, GW_IP, "corp.internal", t=t0 + 40.0),
        dns_query(WS_BOB_MAC,   WS_BOB_IP,   GW_MAC, GW_IP, "corp.internal", t=t0 + 41.0),
    ]

    # Background
    pkts += bg_arp_announce(bg, t0 + 50.0)
    pkts += bg_http(bg, gw, t0 + 80.0)
    pkts += bg_https(bg, gw, t0 + 140.0)
    pkts += bg_dns(bg, t0 + 220.0)
    pkts += bg_smb(bg, t0 + 270.0)
    pkts += bg_print(bg, t0 + 370.0)

    save(pkts, "week2_personal_laptop_vpn.pcap")


def make_week3():
    """
    Carol's workstation joins.
    Carol uses Telnet to file server — cleartext credentials (POLICY VIOLATION).
    Bob runs BitTorrent from his personal laptop.
    Gateway: ISP primary.
    """
    t0 = week_start(3)
    pkts = []
    bg = active_bg(3)
    gw = GW_PRIMARY

    pkts += [
        arp_reply(GW_MAC,         GW_IP,         BROADCAST_MAC, "0.0.0.0",   t=t0 + 0.0),
        arp_reply(FILESERVER_MAC, FILESERVER_IP,  GW_MAC, GW_IP,             t=t0 + 0.1),
        arp_reply(MAILSERVER_MAC, MAILSERVER_IP,  GW_MAC, GW_IP,             t=t0 + 0.2),
        arp_reply(WEBSERVER_MAC,  WEBSERVER_IP,   GW_MAC, GW_IP,             t=t0 + 0.3),
        arp_reply(PRINTER_A_MAC,  PRINTER_A_IP,   GW_MAC, GW_IP,             t=t0 + 0.4),
        arp_reply(WS_ALICE_MAC,   WS_ALICE_IP,    GW_MAC, GW_IP,             t=t0 + 0.5),
        arp_reply(WS_BOB_MAC,     WS_BOB_IP,      GW_MAC, GW_IP,             t=t0 + 0.6),
        # NEW: Carol joins
        arp_reply(WS_CAROL_MAC,   WS_CAROL_IP,    GW_MAC, GW_IP,             t=t0 + 0.7),
        arp_reply(LAPTOP_BOB_MAC, LAPTOP_BOB_IP,  GW_MAC, GW_IP,             t=t0 + 0.8),
    ]

    # Alice — normal
    pkts += http_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, WEBSERVER_IP,  t0=t0 + 2.0)
    pkts += smb_session( WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, FILESERVER_IP, t0=t0 + 5.0)
    pkts += smtp_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP, t0=t0 + 8.0)
    pkts += https_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, gw,           t0=t0 + 11.0)
    pkts += ipp_session(WS_ALICE_MAC, PRINTER_A_MAC, WS_ALICE_IP, PRINTER_A_IP, t0=t0 + 14.0)

    # Bob — workstation normal
    pkts += smb_session(WS_BOB_MAC,   GW_MAC, WS_BOB_IP,   FILESERVER_IP, t0=t0 + 3.0)
    pkts += https_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP,   gw,            t0=t0 + 6.0)

    # Carol — Telnet to file server (POLICY VIOLATION: cleartext protocol)
    pkts += telnet_session(WS_CAROL_MAC, GW_MAC, WS_CAROL_IP, FILESERVER_IP, t0=t0 + 20.0)
    pkts += smb_session(WS_CAROL_MAC,   GW_MAC, WS_CAROL_IP, FILESERVER_IP, t0=t0 + 25.0)
    pkts += http_session(WS_CAROL_MAC,  GW_MAC, WS_CAROL_IP, WEBSERVER_IP,  t0=t0 + 28.0)

    # Bob's laptop — WireGuard + BitTorrent (POLICY VIOLATION: P2P)
    pkts += wireguard_burst(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, VPN_ENDPOINT, t0=t0 + 35.0)
    pkts += bittorrent_burst(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, gw,           t0=t0 + 50.0)

    pkts += [
        dns_query(WS_ALICE_MAC,   WS_ALICE_IP,   GW_MAC, GW_IP, "corp.internal",  t=t0 + 60.0),
        dns_query(WS_CAROL_MAC,   WS_CAROL_IP,   GW_MAC, GW_IP, "fileserver.corp", t=t0 + 61.0),
        dns_query(LAPTOP_BOB_MAC, LAPTOP_BOB_IP, GW_MAC, GW_IP, "tracker.example", t=t0 + 62.0),
    ]

    pkts += bg_arp_announce(bg, t0 + 70.0)
    pkts += bg_http(bg, gw, t0 + 100.0)
    pkts += bg_https(bg, gw, t0 + 160.0)
    pkts += bg_dns(bg, t0 + 240.0)
    pkts += bg_smb(bg, t0 + 290.0)
    pkts += bg_print(bg, t0 + 390.0)

    save(pkts, "week3_telnet_bittorrent.pcap")


def make_week4():
    """
    Bob FTP-exfiltrates files to external IP (CRITICAL policy violation).
    ISP failover — gateway changes to secondary (GATEWAY_CHANGE).
    Eve's personal mobile joins WiFi.
    """
    t0 = week_start(4)
    pkts = []
    bg = active_bg(4)
    gw = GW_SECONDARY   # <-- gateway changed

    pkts += [
        arp_reply(GW_MAC,         GW_IP,         BROADCAST_MAC, "0.0.0.0",   t=t0 + 0.0),
        arp_reply(FILESERVER_MAC, FILESERVER_IP,  GW_MAC, GW_IP,             t=t0 + 0.1),
        arp_reply(MAILSERVER_MAC, MAILSERVER_IP,  GW_MAC, GW_IP,             t=t0 + 0.2),
        arp_reply(WEBSERVER_MAC,  WEBSERVER_IP,   GW_MAC, GW_IP,             t=t0 + 0.3),
        arp_reply(PRINTER_A_MAC,  PRINTER_A_IP,   GW_MAC, GW_IP,             t=t0 + 0.4),
        arp_reply(WS_ALICE_MAC,   WS_ALICE_IP,    GW_MAC, GW_IP,             t=t0 + 0.5),
        arp_reply(WS_BOB_MAC,     WS_BOB_IP,      GW_MAC, GW_IP,             t=t0 + 0.6),
        arp_reply(WS_CAROL_MAC,   WS_CAROL_IP,    GW_MAC, GW_IP,             t=t0 + 0.7),
        arp_reply(LAPTOP_BOB_MAC, LAPTOP_BOB_IP,  GW_MAC, GW_IP,             t=t0 + 0.8),
        # NEW: Eve's mobile joins WiFi
        arp_reply(MOBILE_EVE_MAC, MOBILE_EVE_IP,  GW_MAC, GW_IP,             t=t0 + 0.9),
    ]

    # Alice — normal
    pkts += http_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, WEBSERVER_IP,  t0=t0 + 2.0)
    pkts += smb_session( WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, FILESERVER_IP, t0=t0 + 5.0)
    pkts += imap_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP, t0=t0 + 8.0)
    pkts += https_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, gw,           t0=t0 + 11.0)

    # Bob's workstation — FTP to external exfil server (POLICY VIOLATION: data exfiltration)
    pkts += ftp_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, EXFIL_IP, t0=t0 + 15.0)
    pkts += ftp_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, EXFIL_IP, t0=t0 + 20.0)  # second transfer
    pkts += smb_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, FILESERVER_IP, t0=t0 + 25.0)

    # Carol — Telnet still happening
    pkts += telnet_session(WS_CAROL_MAC, GW_MAC, WS_CAROL_IP, FILESERVER_IP, t0=t0 + 30.0)
    pkts += smb_session(WS_CAROL_MAC,   GW_MAC, WS_CAROL_IP, FILESERVER_IP, t0=t0 + 35.0)

    # Bob's laptop — WireGuard + BitTorrent continues
    pkts += wireguard_burst(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, VPN_ENDPOINT, t0=t0 + 40.0)
    pkts += bittorrent_burst(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, gw,           t0=t0 + 55.0)

    # Eve's mobile — typical mobile browsing
    pkts += https_session(MOBILE_EVE_MAC, GW_MAC, MOBILE_EVE_IP, gw,           t0=t0 + 60.0)
    pkts += dns_query(MOBILE_EVE_MAC, MOBILE_EVE_IP, GW_MAC, GW_IP, "icloud.com", t=t0 + 65.0)

    pkts += [
        dns_query(WS_BOB_MAC,   WS_BOB_IP,   GW_MAC, GW_IP, "exfil.example.com", t=t0 + 70.0),
        dns_query(WS_ALICE_MAC, WS_ALICE_IP, GW_MAC, GW_IP, "corp.internal",     t=t0 + 71.0),
    ]

    pkts += bg_arp_announce(bg, t0 + 80.0)
    pkts += bg_http(bg, gw, t0 + 110.0)
    pkts += bg_https(bg, gw, t0 + 170.0)
    pkts += bg_dns(bg, t0 + 250.0)
    pkts += bg_smb(bg, t0 + 300.0)
    pkts += bg_print(bg, t0 + 400.0)

    save(pkts, "week4_ftp_exfil_gateway_change.pcap")


def make_week5():
    """
    Shadow device appears (Raspberry Pi OUI — b8:27:eb — no hostname in DNS).
    ARP spoofing: shadow device claims Bob's workstation IP (CRITICAL).
    FTP exfiltration continues.
    Dave's workstation joins.
    """
    t0 = week_start(5)
    pkts = []
    bg = active_bg(5)
    gw = GW_SECONDARY

    pkts += [
        arp_reply(GW_MAC,         GW_IP,         BROADCAST_MAC, "0.0.0.0",   t=t0 + 0.0),
        arp_reply(FILESERVER_MAC, FILESERVER_IP,  GW_MAC, GW_IP,             t=t0 + 0.1),
        arp_reply(MAILSERVER_MAC, MAILSERVER_IP,  GW_MAC, GW_IP,             t=t0 + 0.2),
        arp_reply(WEBSERVER_MAC,  WEBSERVER_IP,   GW_MAC, GW_IP,             t=t0 + 0.3),
        arp_reply(PRINTER_A_MAC,  PRINTER_A_IP,   GW_MAC, GW_IP,             t=t0 + 0.4),
        arp_reply(WS_ALICE_MAC,   WS_ALICE_IP,    GW_MAC, GW_IP,             t=t0 + 0.5),
        arp_reply(WS_BOB_MAC,     WS_BOB_IP,      GW_MAC, GW_IP,             t=t0 + 0.6),
        arp_reply(WS_CAROL_MAC,   WS_CAROL_IP,    GW_MAC, GW_IP,             t=t0 + 0.7),
        arp_reply(LAPTOP_BOB_MAC, LAPTOP_BOB_IP,  GW_MAC, GW_IP,             t=t0 + 0.8),
        arp_reply(MOBILE_EVE_MAC, MOBILE_EVE_IP,  GW_MAC, GW_IP,             t=t0 + 0.9),
        # NEW: Dave's workstation
        arp_reply(WS_DAVE_MAC,    WS_DAVE_IP,     GW_MAC, GW_IP,             t=t0 + 1.0),
        # NEW: Shadow device with its own IP
        arp_reply(SHADOW_DEV_MAC, SHADOW_DEV_IP,  GW_MAC, GW_IP,             t=t0 + 1.1),
        # ARP SPOOF: shadow device claims Bob's workstation IP (CRITICAL)
        arp_reply(SHADOW_DEV_MAC, WS_BOB_IP,      GW_MAC, GW_IP,             t=t0 + 1.5),
    ]

    # Alice — normal
    pkts += http_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, WEBSERVER_IP,  t0=t0 + 3.0)
    pkts += smb_session( WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, FILESERVER_IP, t0=t0 + 6.0)
    pkts += smtp_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP, t0=t0 + 9.0)
    pkts += https_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, gw,           t0=t0 + 12.0)

    # Bob — FTP exfiltration continues
    pkts += ftp_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, EXFIL_IP, t0=t0 + 15.0)
    pkts += smb_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, FILESERVER_IP,     t0=t0 + 20.0)

    # Carol — Telnet
    pkts += telnet_session(WS_CAROL_MAC, GW_MAC, WS_CAROL_IP, FILESERVER_IP, t0=t0 + 25.0)

    # Dave — normal new employee
    pkts += http_session(WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, WEBSERVER_IP,   t0=t0 + 28.0)
    pkts += smb_session( WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, FILESERVER_IP,  t0=t0 + 31.0)
    pkts += imap_session(WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, MAILSERVER_IP,  t0=t0 + 34.0)

    # Shadow device — makes internal connections after spoofing Bob's IP
    pkts += smb_session( SHADOW_DEV_MAC, GW_MAC, WS_BOB_IP,      FILESERVER_IP, t0=t0 + 40.0)
    pkts += http_session(SHADOW_DEV_MAC, GW_MAC, SHADOW_DEV_IP,  WEBSERVER_IP,  t0=t0 + 45.0)

    # Bob's laptop
    pkts += wireguard_burst(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, VPN_ENDPOINT, t0=t0 + 50.0)
    pkts += bittorrent_burst(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, gw,           t0=t0 + 65.0)

    # Eve's mobile
    pkts += https_session(MOBILE_EVE_MAC, GW_MAC, MOBILE_EVE_IP, gw, t0=t0 + 70.0)

    pkts += [
        dns_query(WS_ALICE_MAC,   WS_ALICE_IP,   GW_MAC, GW_IP, "corp.internal",  t=t0 + 80.0),
        dns_query(WS_DAVE_MAC,    WS_DAVE_IP,    GW_MAC, GW_IP, "corp.internal",  t=t0 + 81.0),
        dns_query(SHADOW_DEV_MAC, SHADOW_DEV_IP, GW_MAC, GW_IP, "10.0.2.10",     t=t0 + 82.0),
    ]

    pkts += bg_arp_announce(bg, t0 + 90.0)
    pkts += bg_http(bg, gw, t0 + 120.0)
    pkts += bg_https(bg, gw, t0 + 180.0)
    pkts += bg_dns(bg, t0 + 260.0)
    pkts += bg_smb(bg, t0 + 310.0)
    pkts += bg_print(bg, t0 + 410.0)

    save(pkts, "week5_shadow_device_arp_spoof.pcap")


def make_week6():
    """
    Peak violations week: FTP + BitTorrent + Telnet all still active.
    Shadow device still present.
    Gateway still on secondary ISP.
    """
    t0 = week_start(6)
    pkts = []
    bg = active_bg(6)
    gw = GW_SECONDARY

    pkts += [
        arp_reply(GW_MAC,         GW_IP,         BROADCAST_MAC, "0.0.0.0",  t=t0 + 0.0),
        arp_reply(FILESERVER_MAC, FILESERVER_IP,  GW_MAC, GW_IP,            t=t0 + 0.1),
        arp_reply(MAILSERVER_MAC, MAILSERVER_IP,  GW_MAC, GW_IP,            t=t0 + 0.2),
        arp_reply(WEBSERVER_MAC,  WEBSERVER_IP,   GW_MAC, GW_IP,            t=t0 + 0.3),
        arp_reply(PRINTER_A_MAC,  PRINTER_A_IP,   GW_MAC, GW_IP,            t=t0 + 0.4),
        arp_reply(WS_ALICE_MAC,   WS_ALICE_IP,    GW_MAC, GW_IP,            t=t0 + 0.5),
        arp_reply(WS_BOB_MAC,     WS_BOB_IP,      GW_MAC, GW_IP,            t=t0 + 0.6),
        arp_reply(WS_CAROL_MAC,   WS_CAROL_IP,    GW_MAC, GW_IP,            t=t0 + 0.7),
        arp_reply(WS_DAVE_MAC,    WS_DAVE_IP,     GW_MAC, GW_IP,            t=t0 + 0.8),
        arp_reply(LAPTOP_BOB_MAC, LAPTOP_BOB_IP,  GW_MAC, GW_IP,            t=t0 + 0.9),
        arp_reply(MOBILE_EVE_MAC, MOBILE_EVE_IP,  GW_MAC, GW_IP,            t=t0 + 1.0),
        arp_reply(SHADOW_DEV_MAC, SHADOW_DEV_IP,  GW_MAC, GW_IP,            t=t0 + 1.1),
    ]

    # Alice — normal
    pkts += http_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, WEBSERVER_IP,  t0=t0 + 2.0)
    pkts += smb_session( WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, FILESERVER_IP, t0=t0 + 5.0)
    pkts += imap_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP, t0=t0 + 8.0)
    pkts += https_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, gw,           t0=t0 + 11.0)
    pkts += ipp_session(WS_ALICE_MAC, PRINTER_A_MAC, WS_ALICE_IP, PRINTER_A_IP, t0=t0 + 14.0)

    # Bob — FTP exfil + normal
    pkts += ftp_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, EXFIL_IP,          t0=t0 + 15.0)
    pkts += smb_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, FILESERVER_IP,     t0=t0 + 20.0)
    pkts += https_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, gw,              t0=t0 + 23.0)

    # Carol — Telnet persists
    pkts += telnet_session(WS_CAROL_MAC, GW_MAC, WS_CAROL_IP, FILESERVER_IP, t0=t0 + 26.0)
    pkts += smb_session(WS_CAROL_MAC,   GW_MAC, WS_CAROL_IP, FILESERVER_IP, t0=t0 + 31.0)

    # Dave — normal
    pkts += http_session(WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, WEBSERVER_IP,  t0=t0 + 33.0)
    pkts += smb_session( WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, FILESERVER_IP, t0=t0 + 36.0)

    # Shadow device — still active, probing internally
    pkts += smb_session( SHADOW_DEV_MAC, GW_MAC, SHADOW_DEV_IP, FILESERVER_IP, t0=t0 + 40.0)
    pkts += telnet_session(SHADOW_DEV_MAC, GW_MAC, SHADOW_DEV_IP, FILESERVER_IP, t0=t0 + 45.0)

    # Bob's laptop — WireGuard + BitTorrent
    pkts += wireguard_burst(LAPTOP_BOB_MAC,  GW_MAC, LAPTOP_BOB_IP, VPN_ENDPOINT, t0=t0 + 50.0)
    pkts += bittorrent_burst(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, gw,           t0=t0 + 65.0)

    # Eve's mobile
    pkts += https_session(MOBILE_EVE_MAC, GW_MAC, MOBILE_EVE_IP, gw, t0=t0 + 75.0)
    pkts += dns_query(MOBILE_EVE_MAC, MOBILE_EVE_IP, GW_MAC, GW_IP, "android.com", t=t0 + 78.0)

    pkts += [
        dns_query(WS_ALICE_MAC, WS_ALICE_IP, GW_MAC, GW_IP, "corp.internal", t=t0 + 85.0),
        dns_query(WS_BOB_MAC,   WS_BOB_IP,   GW_MAC, GW_IP, "exfil.example", t=t0 + 86.0),
    ]

    pkts += bg_arp_announce(bg, t0 + 95.0)
    pkts += bg_http(bg, gw, t0 + 125.0)
    pkts += bg_https(bg, gw, t0 + 185.0)
    pkts += bg_dns(bg, t0 + 265.0)
    pkts += bg_smb(bg, t0 + 315.0)
    pkts += bg_print(bg, t0 + 415.0)

    save(pkts, "week6_peak_violations.pcap")


def make_week7():
    """
    Audit notice sent — violations drop off significantly.
    Shadow device disappears.
    Bob stops FTP exfiltration and BitTorrent.
    Carol stops Telnet.
    Gateway returns to ISP primary.
    WireGuard VPN from Bob's laptop also stops.
    """
    t0 = week_start(7)
    pkts = []
    bg = active_bg(7)
    gw = GW_PRIMARY   # <-- gateway back to primary

    pkts += [
        arp_reply(GW_MAC,         GW_IP,         BROADCAST_MAC, "0.0.0.0",  t=t0 + 0.0),
        arp_reply(FILESERVER_MAC, FILESERVER_IP,  GW_MAC, GW_IP,            t=t0 + 0.1),
        arp_reply(MAILSERVER_MAC, MAILSERVER_IP,  GW_MAC, GW_IP,            t=t0 + 0.2),
        arp_reply(WEBSERVER_MAC,  WEBSERVER_IP,   GW_MAC, GW_IP,            t=t0 + 0.3),
        arp_reply(PRINTER_A_MAC,  PRINTER_A_IP,   GW_MAC, GW_IP,            t=t0 + 0.4),
        arp_reply(PRINTER_B_MAC,  PRINTER_B_IP,   GW_MAC, GW_IP,            t=t0 + 0.5),
        arp_reply(WS_ALICE_MAC,   WS_ALICE_IP,    GW_MAC, GW_IP,            t=t0 + 0.6),
        arp_reply(WS_BOB_MAC,     WS_BOB_IP,      GW_MAC, GW_IP,            t=t0 + 0.7),
        arp_reply(WS_CAROL_MAC,   WS_CAROL_IP,    GW_MAC, GW_IP,            t=t0 + 0.8),
        arp_reply(WS_DAVE_MAC,    WS_DAVE_IP,     GW_MAC, GW_IP,            t=t0 + 0.9),
        arp_reply(LAPTOP_BOB_MAC, LAPTOP_BOB_IP,  GW_MAC, GW_IP,            t=t0 + 1.0),
        # Mobile Eve still connected; shadow device GONE
    ]

    # Alice — normal
    pkts += http_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, WEBSERVER_IP,  t0=t0 + 2.0)
    pkts += smb_session( WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, FILESERVER_IP, t0=t0 + 5.0)
    pkts += smtp_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP, t0=t0 + 8.0)
    pkts += https_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, gw,           t0=t0 + 11.0)
    pkts += ipp_session(WS_ALICE_MAC, PRINTER_A_MAC, WS_ALICE_IP, PRINTER_A_IP, t0=t0 + 14.0)

    # Bob — back to normal workstation use (no FTP)
    pkts += smb_session(WS_BOB_MAC,   GW_MAC, WS_BOB_IP, FILESERVER_IP,   t0=t0 + 3.0)
    pkts += https_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, gw,              t0=t0 + 6.0)
    pkts += smtp_session(WS_BOB_MAC,  GW_MAC, WS_BOB_IP, MAILSERVER_IP,   t0=t0 + 9.0)

    # Carol — SMB only, no more Telnet
    pkts += smb_session(WS_CAROL_MAC, GW_MAC, WS_CAROL_IP, FILESERVER_IP, t0=t0 + 17.0)
    pkts += http_session(WS_CAROL_MAC, GW_MAC, WS_CAROL_IP, WEBSERVER_IP, t0=t0 + 20.0)

    # Dave — normal
    pkts += http_session(WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, WEBSERVER_IP,  t0=t0 + 22.0)
    pkts += smb_session( WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, FILESERVER_IP, t0=t0 + 25.0)

    # Bob's laptop — no WireGuard, no BitTorrent; just browsing
    pkts += https_session(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, gw, t0=t0 + 30.0)

    pkts += [
        dns_query(WS_ALICE_MAC,   WS_ALICE_IP,   GW_MAC, GW_IP, "corp.internal", t=t0 + 40.0),
        dns_query(WS_BOB_MAC,     WS_BOB_IP,     GW_MAC, GW_IP, "corp.internal", t=t0 + 41.0),
        dns_query(LAPTOP_BOB_MAC, LAPTOP_BOB_IP, GW_MAC, GW_IP, "google.com",    t=t0 + 42.0),
    ]

    pkts += bg_arp_announce(bg, t0 + 50.0)
    pkts += bg_http(bg, gw, t0 + 80.0)
    pkts += bg_https(bg, gw, t0 + 140.0)
    pkts += bg_dns(bg, t0 + 220.0)
    pkts += bg_smb(bg, t0 + 270.0)
    pkts += bg_print(bg, t0 + 370.0)

    save(pkts, "week7_violations_drop_gateway_back.pcap")


def make_week8():
    """
    Near-baseline. Shadow device gone. Bob's workstation clean.
    Carol still using SMB normally (Telnet gone).
    Bob's personal laptop still on WiFi — personal device policy unresolved.
    Mobile Eve still on network — another unresolved personal device.
    """
    t0 = week_start(8)
    pkts = []
    bg = active_bg(8)
    gw = GW_PRIMARY

    pkts += [
        arp_reply(GW_MAC,         GW_IP,         BROADCAST_MAC, "0.0.0.0",  t=t0 + 0.0),
        arp_reply(FILESERVER_MAC, FILESERVER_IP,  GW_MAC, GW_IP,            t=t0 + 0.1),
        arp_reply(MAILSERVER_MAC, MAILSERVER_IP,  GW_MAC, GW_IP,            t=t0 + 0.2),
        arp_reply(WEBSERVER_MAC,  WEBSERVER_IP,   GW_MAC, GW_IP,            t=t0 + 0.3),
        arp_reply(PRINTER_A_MAC,  PRINTER_A_IP,   GW_MAC, GW_IP,            t=t0 + 0.4),
        arp_reply(PRINTER_B_MAC,  PRINTER_B_IP,   GW_MAC, GW_IP,            t=t0 + 0.5),
        arp_reply(WS_ALICE_MAC,   WS_ALICE_IP,    GW_MAC, GW_IP,            t=t0 + 0.6),
        arp_reply(WS_BOB_MAC,     WS_BOB_IP,      GW_MAC, GW_IP,            t=t0 + 0.7),
        arp_reply(WS_CAROL_MAC,   WS_CAROL_IP,    GW_MAC, GW_IP,            t=t0 + 0.8),
        arp_reply(WS_DAVE_MAC,    WS_DAVE_IP,     GW_MAC, GW_IP,            t=t0 + 0.9),
        arp_reply(LAPTOP_BOB_MAC, LAPTOP_BOB_IP,  GW_MAC, GW_IP,            t=t0 + 1.0),
        arp_reply(MOBILE_EVE_MAC, MOBILE_EVE_IP,  GW_MAC, GW_IP,            t=t0 + 1.1),
    ]

    # Everyone — normal office traffic
    pkts += http_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, WEBSERVER_IP,  t0=t0 + 2.0)
    pkts += smb_session( WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, FILESERVER_IP, t0=t0 + 5.0)
    pkts += smtp_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP, t0=t0 + 8.0)
    pkts += imap_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, MAILSERVER_IP, t0=t0 + 11.0)
    pkts += https_session(WS_ALICE_MAC, GW_MAC, WS_ALICE_IP, gw,           t0=t0 + 14.0)
    pkts += ipp_session(WS_ALICE_MAC, PRINTER_A_MAC, WS_ALICE_IP, PRINTER_A_IP, t0=t0 + 17.0)

    pkts += smb_session(WS_BOB_MAC,   GW_MAC, WS_BOB_IP, FILESERVER_IP,   t0=t0 + 3.0)
    pkts += https_session(WS_BOB_MAC, GW_MAC, WS_BOB_IP, gw,              t0=t0 + 6.0)
    pkts += smtp_session(WS_BOB_MAC,  GW_MAC, WS_BOB_IP, MAILSERVER_IP,   t0=t0 + 9.0)
    pkts += ipp_session(WS_BOB_MAC,  PRINTER_B_MAC, WS_BOB_IP, PRINTER_B_IP, t0=t0 + 12.0)

    pkts += smb_session(WS_CAROL_MAC, GW_MAC, WS_CAROL_IP, FILESERVER_IP, t0=t0 + 20.0)
    pkts += http_session(WS_CAROL_MAC, GW_MAC, WS_CAROL_IP, WEBSERVER_IP, t0=t0 + 23.0)
    pkts += imap_session(WS_CAROL_MAC, GW_MAC, WS_CAROL_IP, MAILSERVER_IP, t0=t0 + 26.0)

    pkts += http_session(WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, WEBSERVER_IP,  t0=t0 + 28.0)
    pkts += smb_session( WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, FILESERVER_IP, t0=t0 + 31.0)
    pkts += smtp_session(WS_DAVE_MAC,  GW_MAC, WS_DAVE_IP, MAILSERVER_IP, t0=t0 + 34.0)

    # Bob's laptop — still on WiFi (personal device policy still unresolved)
    pkts += https_session(LAPTOP_BOB_MAC, GW_MAC, LAPTOP_BOB_IP, gw, t0=t0 + 37.0)

    # Eve's mobile — still on network
    pkts += https_session(MOBILE_EVE_MAC, GW_MAC, MOBILE_EVE_IP, gw, t0=t0 + 40.0)

    pkts += [
        dns_query(WS_ALICE_MAC,   WS_ALICE_IP,   GW_MAC, GW_IP, "corp.internal", t=t0 + 50.0),
        dns_query(WS_BOB_MAC,     WS_BOB_IP,     GW_MAC, GW_IP, "corp.internal", t=t0 + 51.0),
        dns_query(WS_CAROL_MAC,   WS_CAROL_IP,   GW_MAC, GW_IP, "corp.internal", t=t0 + 52.0),
        dns_query(LAPTOP_BOB_MAC, LAPTOP_BOB_IP, GW_MAC, GW_IP, "google.com",    t=t0 + 53.0),
    ]

    pkts += bg_arp_announce(bg, t0 + 60.0)
    pkts += bg_http(bg, gw, t0 + 90.0)
    pkts += bg_https(bg, gw, t0 + 150.0)
    pkts += bg_dns(bg, t0 + 230.0)
    pkts += bg_smb(bg, t0 + 280.0)
    pkts += bg_print(bg, t0 + 380.0)

    save(pkts, "week8_near_baseline.pcap")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Generating 8 office audit PCAPs into {OUTDIR}/\n")

    make_week1()
    make_week2()
    make_week3()
    make_week4()
    make_week5()
    make_week6()
    make_week7()
    make_week8()

    import glob as _glob
    from scapy.all import rdpcap
    all_ips = set()
    for f in sorted(_glob.glob(os.path.join(OUTDIR, "*.pcap"))):
        for p in rdpcap(f):
            if IP in p:
                all_ips.add(p[IP].src)
    print(f"\nTotal unique src IPs across all 8 snapshots: {len(all_ips)}")

    print("""
Expected change signals
───────────────────────────────────────────────────────────────────────────────
Week 1→2:  MAC_ADDED (LAPTOP_BOB on WiFi), VPN_DRIFT new (WireGuard), APP_ADDED
Week 2→3:  MAC_ADDED (WS_CAROL), PROTOCOL_ADDED (Telnet), APP_ADDED (BitTorrent)
Week 3→4:  MAC_ADDED (MOBILE_EVE), PROTOCOL_ADDED (FTP), GATEWAY_CHANGE (ISP failover)
Week 4→5:  MAC_ADDED (WS_DAVE, SHADOW_DEV), IP_MAC_DRIFT CRITICAL (shadow device ARP spoof)
Week 5→6:  (no new story signals — violations peak and persist)
Week 6→7:  GATEWAY_CHANGE (back to primary), VPN_DRIFT gone (WireGuard stops),
           APP_ADDED gone (BitTorrent stops), Telnet gone, MAC absent (SHADOW_DEV)
Week 7→8:  (near stable — personal devices still present)

Policy violations visible in captures
───────────────────────────────────────────────────────────────────────────────
- WireGuard VPN bypass (LAPTOP_BOB → VPN_ENDPOINT, weeks 2-6)
- BitTorrent P2P (LAPTOP_BOB, weeks 3-6)
- Telnet cleartext to file server (WS_CAROL, weeks 3-6)
- FTP data exfiltration to external IP (WS_BOB → 192.0.2.99, weeks 4-6)
- Unauthorised shadow device with RPi OUI (weeks 5-6)
- ARP spoofing by shadow device claiming Bob's IP (week 5, CRITICAL)
- Personal devices on corporate network (LAPTOP_BOB, MOBILE_EVE — weeks 2-8)

Subnet structure (for subnet detection demo)
───────────────────────────────────────────────────────────────────────────────
  10.0.1.0/24  Staff workstations
  10.0.2.0/24  Servers (file, mail, web)
  10.0.3.0/24  Printers / peripherals
  10.0.4.0/24  WiFi / BYOD
""")
