"""
Generate 8 synthetic PCAPs for the Network Monitor demo.

Scenario: A small office LAN captured weekly over 8 weeks, with deliberate
changes to exercise every change-detection signal and UI panel feature.

Change signals covered
──────────────────────
  MAC_ADDED        — new device joins the network
  IP_MAC_DRIFT     — same MAC gets a new IP (DHCP reassignment)
                   — same IP claimed by a different MAC (ARP spoof, CRITICAL)
  ASN_CHANGE       — a new external ASN/ISP appears in traffic
  GATEWAY_CHANGE   — top-traffic external IP (gateway heuristic) changes
  PROTOCOL_ADDED   — a new L4/L7 protocol appears
  APP_ADDED        — a new application appears (nDPI-detected)
  VPN_DRIFT (new)  — VPN fingerprint appears (WireGuard on UDP 51820)
  VPN_DRIFT (gone) — VPN fingerprint disappears (meaningful: masking stopped)

Absent-entity panels (no events emitted, shown as greyed badges)
  Absent devices   — DEV_B disappears after week 1
  Absent protocols — Telnet disappears after week 3, FTP after week 5
  Absent apps      — BitTorrent disappears after week 4

Weeks
─────
  Week 1 — Stable baseline: A, B, D on LAN; HTTP, Telnet, DNS
  Week 2 — DEV_B leaves; DEV_C (IoT) joins; WireGuard VPN appears; SSH added
  Week 3 — Gateway switches ISP (A→B); ARP spoof (DEV_C claims DEV_A IP)
  Week 4 — VPN gone (WireGuard stops); BitTorrent appears; FTP appears
  Week 5 — New ASN in traffic; DEV_E joins; BitTorrent still present
  Week 6 — BitTorrent gone; FTP gone; DEV_C gets new IP (DHCP drift)
  Week 7 — DEV_F joins (another new device); gateway switches back (B→A)
  Week 8 — Stable again; all changes settled; clean snapshot

Output: ./monitor/week{1..8}_*.pcap
Usage:  python3 gen_monitor.py
"""

import os
from datetime import datetime, timezone

from scapy.all import (
    Ether, IP, TCP, UDP, ARP, DNS, DNSQR,
    Raw, wrpcap,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
OUTDIR = os.path.join(os.path.dirname(__file__), "monitor")
os.makedirs(OUTDIR, exist_ok=True)


def ts(dt: datetime) -> float:
    return dt.timestamp()


def week_start(week: int) -> datetime:
    from datetime import timedelta
    # 2024-01-08 = Monday of week 2, 2024
    base = datetime(2024, 1, 8, 9, 0, 0, tzinfo=timezone.utc)
    return base + timedelta(weeks=week - 1)


def tcp_session(src_mac, dst_mac, src_ip, dst_ip, sport, dport,
                payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                base_ts=0.0, ts_offset=0.0):
    """6-packet TCP SYN→SYN-ACK→ACK→DATA→RESP→FIN."""
    pkts = []
    t = base_ts + ts_offset

    def pkt(flags, data=b"", reverse=False):
        nonlocal t
        sm, dm = (src_mac, dst_mac) if not reverse else (dst_mac, src_mac)
        si, di = (src_ip,  dst_ip)  if not reverse else (dst_ip,  src_ip)
        sp, dp = (sport,   dport)   if not reverse else (dport,   sport)
        p = Ether(src=sm, dst=dm) / IP(src=si, dst=di) / TCP(sport=sp, dport=dp, flags=flags)
        if data:
            p = p / Raw(data)
        p.time = t
        t += 0.002
        return p

    pkts += [
        pkt("S"),
        pkt("SA", reverse=True),
        pkt("A"),
        pkt("PA", payload),
        pkt("PA", b"HTTP/1.1 200 OK\r\n\r\nOK", reverse=True),
        pkt("FA"),
    ]
    return pkts


def udp_burst(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload, base_ts, count=20, gap=0.3):
    pkts = []
    for i in range(count):
        p = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / \
            UDP(sport=sport, dport=dport) / Raw(payload)
        p.time = base_ts + i * gap
        pkts.append(p)
    return pkts


def arp_reply(sender_mac, sender_ip, target_mac, target_ip, t=0.0):
    p = Ether(src=sender_mac, dst=target_mac) / ARP(
        op=2, hwsrc=sender_mac, psrc=sender_ip, hwdst=target_mac, pdst=target_ip)
    p.time = t
    return p


def dns_query(src_mac, src_ip, router_mac, router_ip, name, t=0.0):
    p = (Ether(src=src_mac, dst=router_mac)
         / IP(src=src_ip, dst=router_ip)
         / UDP(sport=12345, dport=53)
         / DNS(rd=1, qd=DNSQR(qname=name)))
    p.time = t
    return p


def wireguard_burst(src_mac, dst_mac, src_ip, dst_ip, base_ts, count=25):
    payload = bytes([0x01, 0x00, 0x00, 0x00]) + os.urandom(144)
    return udp_burst(src_mac, dst_mac, src_ip, dst_ip, 51820, 51820, payload, base_ts, count)


def bittorrent_burst(src_mac, dst_mac, src_ip, dst_ip, base_ts, count=20):
    # BitTorrent DHT ping (BEP 5): bencoded "ping" query
    payload = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
    return udp_burst(src_mac, dst_mac, src_ip, dst_ip, 6881, 6881, payload, base_ts, count)


def ftp_session(src_mac, dst_mac, src_ip, dst_ip, base_ts):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49300, 21,
                       payload=b"USER anonymous\r\nPASS guest@\r\n",
                       base_ts=base_ts, ts_offset=0)


def ssh_session(src_mac, dst_mac, src_ip, dst_ip, base_ts):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49400, 22,
                       payload=b"SSH-2.0-OpenSSH_8.9\r\n",
                       base_ts=base_ts, ts_offset=0)


def telnet_session(src_mac, dst_mac, src_ip, dst_ip, base_ts):
    return tcp_session(src_mac, dst_mac, src_ip, dst_ip, 49200, 23,
                       payload=b"login: admin\r\nPassword: secret\r\n",
                       base_ts=base_ts, ts_offset=0)


def save(pkts, filename):
    pkts.sort(key=lambda p: p.time)
    path = os.path.join(OUTDIR, filename)
    wrpcap(path, pkts)
    macs = len(set(p[Ether].src for p in pkts if Ether in p))
    print(f"  {filename:50s} {len(pkts):4d} pkts, {macs} src MACs")


# ---------------------------------------------------------------------------
# Network topology
# ---------------------------------------------------------------------------
ROUTER_MAC = "00:11:22:33:44:00"
ROUTER_IP  = "192.168.1.1"

# External IPs — two different ISPs/gateways
GW_A = "203.0.113.1"    # ISP-A (weeks 1-3, 7-8)
GW_B = "198.51.100.1"   # ISP-B (weeks 4-6) — gateway change signal
GW_C = "192.0.2.50"     # A third external host (new ASN signal in week 5)

# LAN devices
DEV_A_MAC = "aa:bb:cc:11:11:11"  # Workstation — present all weeks
DEV_A_IP  = "192.168.1.10"

DEV_B_MAC = "aa:bb:cc:22:22:22"  # Laptop — week 1 only (absent thereafter)
DEV_B_IP  = "192.168.1.20"

DEV_C_MAC = "aa:bb:cc:33:33:33"  # IoT device — joins week 2
DEV_C_IP  = "192.168.1.30"
DEV_C_IP2 = "192.168.1.35"       # Gets new IP in week 6 (DHCP drift)

DEV_D_MAC = "aa:bb:cc:44:44:44"  # Printer — present all weeks
DEV_D_IP  = "192.168.1.40"

DEV_E_MAC = "aa:bb:cc:55:55:55"  # Joins week 5
DEV_E_IP  = "192.168.1.50"

DEV_F_MAC = "aa:bb:cc:66:66:66"  # Joins week 7
DEV_F_IP  = "192.168.1.60"

# IP used by DEV_B in week1 — claimed by DEV_C in week3 (ARP spoof, CRITICAL)
SPOOFED_IP = DEV_A_IP


# ---------------------------------------------------------------------------
# Week 1 — Stable baseline
# Devices: A, B, D | Protocols: HTTP, TELNET, DNS | Apps: HTTP | GW: ISP-A
# ---------------------------------------------------------------------------
def make_week1():
    t0 = ts(week_start(1))
    pkts = []

    pkts += [
        arp_reply(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.0),
        arp_reply(DEV_B_MAC, DEV_B_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.1),
        arp_reply(DEV_D_MAC, DEV_D_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.2),
    ]
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_A, 49152, 80,  base_ts=t0, ts_offset=2.0)
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_A, 49153, 443, payload=b"\x16\x03\x01", base_ts=t0, ts_offset=8.0)
    pkts += tcp_session(DEV_B_MAC, ROUTER_MAC, DEV_B_IP, GW_A, 49160, 80,  base_ts=t0, ts_offset=15.0)
    pkts += telnet_session(DEV_D_MAC, ROUTER_MAC, DEV_D_IP, "192.168.1.100", base_ts=t0 + 25.0)
    pkts += [dns_query(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, "example.com", t=t0 + 40.0)]
    pkts += udp_burst(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_A, 12000, 123, b"\x1b" + b"\x00" * 47, t0 + 50.0, count=10)

    save(pkts, "week1_baseline.pcap")


# ---------------------------------------------------------------------------
# Week 2 — DEV_B leaves; DEV_C (IoT) joins; WireGuard VPN + SSH appear
# Signals: MAC_ADDED (DEV_C), PROTOCOL_ADDED (SSH), VPN_DRIFT (WireGuard new)
# Absent:  DEV_B now absent
# ---------------------------------------------------------------------------
def make_week2():
    t0 = ts(week_start(2))
    pkts = []

    pkts += [
        arp_reply(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.0),
        arp_reply(DEV_C_MAC, DEV_C_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.1),
        arp_reply(DEV_D_MAC, DEV_D_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.2),
    ]
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_A, 49152, 443, payload=b"\x16\x03\x01", base_ts=t0, ts_offset=2.0)
    pkts += tcp_session(DEV_C_MAC, ROUTER_MAC, DEV_C_IP, GW_A, 49170, 80,  base_ts=t0, ts_offset=8.0)
    pkts += telnet_session(DEV_D_MAC, ROUTER_MAC, DEV_D_IP, "192.168.1.100", base_ts=t0 + 20.0)
    pkts += ssh_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_A, base_ts=t0 + 30.0)
    pkts += wireguard_burst(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_A, base_ts=t0 + 45.0)
    pkts += [dns_query(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, "vpn.example.com", t=t0 + 80.0)]

    save(pkts, "week2_new_device_vpn_ssh.pcap")


# ---------------------------------------------------------------------------
# Week 3 — Gateway switches ISP-A→ISP-B; ARP spoof DEV_C claims DEV_A IP
# Signals: GATEWAY_CHANGE (GW_A→GW_B), IP_MAC_DRIFT CRITICAL (ARP spoof)
# Continuing: Telnet, WireGuard, SSH
# ---------------------------------------------------------------------------
def make_week3():
    t0 = ts(week_start(3))
    pkts = []

    pkts += [
        arp_reply(DEV_A_MAC, DEV_A_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.0),
        arp_reply(DEV_C_MAC, DEV_C_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.1),
        arp_reply(DEV_D_MAC, DEV_D_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.2),
        # ARP spoof: DEV_C claims DEV_A's IP → CRITICAL IP_MAC_DRIFT
        arp_reply(DEV_C_MAC, SPOOFED_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.5),
    ]
    # Both MACs using DEV_A IP (different src MACs, same IP in IP header)
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, 49152, 443, payload=b"\x16\x03\x01", base_ts=t0, ts_offset=2.0)
    pkts += tcp_session(DEV_C_MAC, ROUTER_MAC, DEV_A_IP, GW_B, 49161, 80,  base_ts=t0, ts_offset=6.0)
    pkts += telnet_session(DEV_D_MAC, ROUTER_MAC, DEV_D_IP, "192.168.1.100", base_ts=t0 + 20.0)
    pkts += ssh_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, base_ts=t0 + 30.0)
    pkts += wireguard_burst(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, base_ts=t0 + 45.0)
    pkts += [dns_query(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, "example.com", t=t0 + 80.0)]

    save(pkts, "week3_gateway_change_arp_spoof.pcap")


# ---------------------------------------------------------------------------
# Week 4 — WireGuard VPN stops; BitTorrent + FTP appear
# Signals: VPN_DRIFT (WireGuard gone, WARNING), PROTOCOL_ADDED (FTP), APP_ADDED (BitTorrent)
# Continuing: Telnet, SSH; GW still ISP-B
# ---------------------------------------------------------------------------
def make_week4():
    t0 = ts(week_start(4))
    pkts = []

    pkts += [
        arp_reply(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.0),
        arp_reply(DEV_C_MAC, DEV_C_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.1),
        arp_reply(DEV_D_MAC, DEV_D_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.2),
    ]
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, 49152, 443, payload=b"\x16\x03\x01", base_ts=t0, ts_offset=2.0)
    pkts += telnet_session(DEV_D_MAC, ROUTER_MAC, DEV_D_IP, "192.168.1.100", base_ts=t0 + 15.0)
    pkts += ssh_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, base_ts=t0 + 25.0)
    pkts += ftp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, base_ts=t0 + 35.0)
    pkts += bittorrent_burst(DEV_C_MAC, ROUTER_MAC, DEV_C_IP, GW_B, base_ts=t0 + 50.0)
    # No WireGuard this week — VPN gone signal
    pkts += [dns_query(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, "example.com", t=t0 + 80.0)]

    save(pkts, "week4_vpn_gone_bittorrent_ftp.pcap")


# ---------------------------------------------------------------------------
# Week 5 — DEV_E joins; new ASN (GW_C) appears in traffic
# Signals: MAC_ADDED (DEV_E), ASN_CHANGE (new external IP GW_C)
# Continuing: BitTorrent, FTP, SSH, Telnet
# ---------------------------------------------------------------------------
def make_week5():
    t0 = ts(week_start(5))
    pkts = []

    pkts += [
        arp_reply(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.0),
        arp_reply(DEV_C_MAC, DEV_C_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.1),
        arp_reply(DEV_D_MAC, DEV_D_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.2),
        arp_reply(DEV_E_MAC, DEV_E_IP, ROUTER_MAC, ROUTER_IP, t=t0 + 0.3),
    ]
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, 49152, 443, payload=b"\x16\x03\x01", base_ts=t0, ts_offset=2.0)
    # New external IP GW_C — will appear as new ASN in geo data
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_C, 49155, 443, payload=b"\x16\x03\x01", base_ts=t0, ts_offset=8.0)
    pkts += tcp_session(DEV_E_MAC, ROUTER_MAC, DEV_E_IP, GW_B, 49180, 80,  base_ts=t0, ts_offset=14.0)
    pkts += telnet_session(DEV_D_MAC, ROUTER_MAC, DEV_D_IP, "192.168.1.100", base_ts=t0 + 25.0)
    pkts += ssh_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, base_ts=t0 + 35.0)
    pkts += ftp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, base_ts=t0 + 45.0)
    pkts += bittorrent_burst(DEV_C_MAC, ROUTER_MAC, DEV_C_IP, GW_B, base_ts=t0 + 55.0)
    pkts += [dns_query(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, "example.com", t=t0 + 80.0)]

    save(pkts, "week5_new_device_new_asn.pcap")


# ---------------------------------------------------------------------------
# Week 6 — BitTorrent gone; FTP gone; DEV_C gets new IP (DHCP drift)
# Signals: IP_MAC_DRIFT WARNING (DEV_C: .30→.35), absent BitTorrent + FTP
# Continuing: SSH, Telnet; GW still ISP-B
# ---------------------------------------------------------------------------
def make_week6():
    t0 = ts(week_start(6))
    pkts = []

    pkts += [
        arp_reply(DEV_A_MAC, DEV_A_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.0),
        # DEV_C now has a new IP — DHCP drift (same MAC, different IP)
        arp_reply(DEV_C_MAC, DEV_C_IP2, ROUTER_MAC, ROUTER_IP, t=t0 + 0.1),
        arp_reply(DEV_D_MAC, DEV_D_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.2),
        arp_reply(DEV_E_MAC, DEV_E_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.3),
    ]
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP,  GW_B, 49152, 443, payload=b"\x16\x03\x01", base_ts=t0, ts_offset=2.0)
    pkts += tcp_session(DEV_C_MAC, ROUTER_MAC, DEV_C_IP2, GW_B, 49171, 80,  base_ts=t0, ts_offset=8.0)
    pkts += telnet_session(DEV_D_MAC, ROUTER_MAC, DEV_D_IP, "192.168.1.100", base_ts=t0 + 20.0)
    pkts += ssh_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_B, base_ts=t0 + 30.0)
    pkts += tcp_session(DEV_E_MAC, ROUTER_MAC, DEV_E_IP, GW_B, 49182, 80,   base_ts=t0, ts_offset=40.0)
    # No BitTorrent, no FTP — absent
    pkts += [dns_query(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, "example.com", t=t0 + 60.0)]

    save(pkts, "week6_dhcp_drift_apps_gone.pcap")


# ---------------------------------------------------------------------------
# Week 7 — DEV_F joins; gateway switches back ISP-B→ISP-A; Telnet gone
# Signals: MAC_ADDED (DEV_F), GATEWAY_CHANGE (GW_B→GW_A)
# Absent:  Telnet now gone
# ---------------------------------------------------------------------------
def make_week7():
    t0 = ts(week_start(7))
    pkts = []

    pkts += [
        arp_reply(DEV_A_MAC, DEV_A_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.0),
        arp_reply(DEV_C_MAC, DEV_C_IP2, ROUTER_MAC, ROUTER_IP, t=t0 + 0.1),
        arp_reply(DEV_D_MAC, DEV_D_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.2),
        arp_reply(DEV_E_MAC, DEV_E_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.3),
        arp_reply(DEV_F_MAC, DEV_F_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.4),
    ]
    # Back on ISP-A gateway
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP,  GW_A, 49152, 443, payload=b"\x16\x03\x01", base_ts=t0, ts_offset=2.0)
    pkts += tcp_session(DEV_C_MAC, ROUTER_MAC, DEV_C_IP2, GW_A, 49172, 80,  base_ts=t0, ts_offset=8.0)
    pkts += tcp_session(DEV_F_MAC, ROUTER_MAC, DEV_F_IP,  GW_A, 49190, 80,  base_ts=t0, ts_offset=14.0)
    pkts += ssh_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_A, base_ts=t0 + 25.0)
    pkts += tcp_session(DEV_E_MAC, ROUTER_MAC, DEV_E_IP, GW_A, 49183, 443,  payload=b"\x16\x03\x01", base_ts=t0, ts_offset=35.0)
    # No Telnet this week — absent
    pkts += [dns_query(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, "example.com", t=t0 + 60.0)]

    save(pkts, "week7_new_device_gateway_back.pcap")


# ---------------------------------------------------------------------------
# Week 8 — Stable; all changes settled
# No new signals; provides a clean "all quiet" baseline for comparison
# ---------------------------------------------------------------------------
def make_week8():
    t0 = ts(week_start(8))
    pkts = []

    pkts += [
        arp_reply(DEV_A_MAC, DEV_A_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.0),
        arp_reply(DEV_C_MAC, DEV_C_IP2, ROUTER_MAC, ROUTER_IP, t=t0 + 0.1),
        arp_reply(DEV_D_MAC, DEV_D_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.2),
        arp_reply(DEV_E_MAC, DEV_E_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.3),
        arp_reply(DEV_F_MAC, DEV_F_IP,  ROUTER_MAC, ROUTER_IP, t=t0 + 0.4),
    ]
    pkts += tcp_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP,  GW_A, 49152, 443, payload=b"\x16\x03\x01", base_ts=t0, ts_offset=2.0)
    pkts += tcp_session(DEV_C_MAC, ROUTER_MAC, DEV_C_IP2, GW_A, 49173, 80,  base_ts=t0, ts_offset=8.0)
    pkts += tcp_session(DEV_D_MAC, ROUTER_MAC, DEV_D_IP,  GW_A, 49201, 80,  base_ts=t0, ts_offset=14.0)
    pkts += ssh_session(DEV_A_MAC, ROUTER_MAC, DEV_A_IP, GW_A, base_ts=t0 + 25.0)
    pkts += tcp_session(DEV_E_MAC, ROUTER_MAC, DEV_E_IP, GW_A, 49184, 443,  payload=b"\x16\x03\x01", base_ts=t0, ts_offset=35.0)
    pkts += tcp_session(DEV_F_MAC, ROUTER_MAC, DEV_F_IP, GW_A, 49191, 80,   base_ts=t0, ts_offset=45.0)
    pkts += [dns_query(DEV_A_MAC, DEV_A_IP, ROUTER_MAC, ROUTER_IP, "example.com", t=t0 + 60.0)]

    save(pkts, "week8_stable.pcap")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Generating 8 monitor demo PCAPs...\n")
    make_week1()
    make_week2()
    make_week3()
    make_week4()
    make_week5()
    make_week6()
    make_week7()
    make_week8()
    print(f"\nDone → {OUTDIR}")
    print("""
Expected change signals per consecutive pair
────────────────────────────────────────────
Week 1→2:  MAC_ADDED (DEV_C), PROTOCOL_ADDED (SSH), VPN_DRIFT new (WireGuard)
Week 2→3:  GATEWAY_CHANGE (ISP-A→ISP-B), IP_MAC_DRIFT CRITICAL (ARP spoof)
Week 3→4:  VPN_DRIFT gone (WireGuard stops), PROTOCOL_ADDED (FTP), APP_ADDED (BitTorrent)
Week 4→5:  MAC_ADDED (DEV_E), ASN_CHANGE (new external IP GW_C)
Week 5→6:  IP_MAC_DRIFT WARNING (DEV_C DHCP: .30→.35)
Week 6→7:  MAC_ADDED (DEV_F), GATEWAY_CHANGE (ISP-B→ISP-A)
Week 7→8:  (no new signals — stable)

Absent entities shown in panels (no events emitted)
────────────────────────────────────────────────────
Devices:   DEV_B absent from week 2 onward
Protocols: Telnet absent from week 7 onward; FTP absent from week 6 onward
Apps:      BitTorrent absent from week 6 onward
""")
