#!/usr/bin/env python3
"""
Generate dns_demo.pcap — a realistic DNS capture for the Network Intelligence
"DNS Servers" view (#362).

The goal is to show DNS activity *in general*, not just anomalies: two LAN
resolvers answering a variety of record types (A, AAAA, CNAME, MX, TXT, PTR,
SRV) for several client hosts, with mostly-successful resolution plus a few
ordinary NXDOMAIN / NODATA failures — well below the suspicious threshold, so
nothing is flagged. This is the everyday case the feature is meant to surface.

Run:     python3 gen_dns_demo.py
Output:  dns_demo.pcap  (in the same directory)
"""

import os
import sys

try:
    from scapy.all import wrpcap
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRMX, DNSRRSRV
except ImportError:
    sys.exit("scapy not found — run:  pip install scapy")

# ── Topology ────────────────────────────────────────────────────────────────
# Two recursive resolvers on the LAN; a handful of clients querying them.
RESOLVER_A = "192.168.1.1"    # the home/office gateway resolver
RESOLVER_B = "192.168.1.53"   # a secondary internal resolver
CLIENTS = ["192.168.1.20", "192.168.1.21", "192.168.1.22"]

SRV_MAC = "52:54:00:aa:00:01"
CLIENT_MACS = {
    "192.168.1.20": "52:54:00:bb:00:20",
    "192.168.1.21": "52:54:00:bb:00:21",
    "192.168.1.22": "52:54:00:bb:00:22",
}

pkts = []
_txid = 0


def _next_id():
    global _txid
    _txid = (_txid + 1) & 0xFFFF
    return _txid


def exchange(client, resolver, qname, qtype, answers, rcode=0):
    """Append a query + its response. `answers` is a list of DNSRR (may be empty)."""
    tid = _next_id()
    sport = 40000 + (tid % 20000)
    cmac = CLIENT_MACS[client]

    query = (
        Ether(src=cmac, dst=SRV_MAC)
        / IP(src=client, dst=resolver)
        / UDP(sport=sport, dport=53)
        / DNS(id=tid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )

    # scapy needs a list (not a "/"-chain) to encode more than one answer record.
    an = answers if answers else None
    response = (
        Ether(src=SRV_MAC, dst=cmac)
        / IP(src=resolver, dst=client)
        / UDP(sport=53, dport=sport)
        / DNS(id=tid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype), an=an)
    )
    pkts.extend([query, response])


def A(name, ip, ttl=300):
    return DNSRR(rrname=name, type="A", ttl=ttl, rdata=ip)


def AAAA(name, ip, ttl=300):
    return DNSRR(rrname=name, type="AAAA", ttl=ttl, rdata=ip)


def CNAME(name, target, ttl=300):
    return DNSRR(rrname=name, type="CNAME", ttl=ttl, rdata=target)


def MX(name, exchange_host, pref=10, ttl=3600):
    return DNSRRMX(rrname=name, ttl=ttl, preference=pref, exchange=exchange_host)


def TXT(name, text, ttl=3600):
    return DNSRR(rrname=name, type="TXT", ttl=ttl, rdata=text)


def PTR(name, target, ttl=3600):
    return DNSRR(rrname=name, type="PTR", ttl=ttl, rdata=target)


def SRV(name, target, port, prio=10, weight=5, ttl=3600):
    return DNSRRSRV(rrname=name, ttl=ttl, priority=prio, weight=weight, port=port, target=target)


# ── Resolver A: everyday browsing, rich record-type variety (all successful) ──
exchange(CLIENTS[0], RESOLVER_A, "example.com", "A", [A("example.com", "93.184.216.34")])
exchange(CLIENTS[0], RESOLVER_A, "www.example.com", "A",
         [CNAME("www.example.com", "example.com"), A("example.com", "93.184.216.34")])
exchange(CLIENTS[1], RESOLVER_A, "google.com", "A", [A("google.com", "142.250.190.78")])
exchange(CLIENTS[1], RESOLVER_A, "google.com", "AAAA", [AAAA("google.com", "2607:f8b0:4005:80a::200e")])
exchange(CLIENTS[2], RESOLVER_A, "github.com", "A", [A("github.com", "140.82.121.3")])
exchange(CLIENTS[2], RESOLVER_A, "cloudflare.com", "A",
         [A("cloudflare.com", "104.16.132.229"), A("cloudflare.com", "104.16.133.229")])
exchange(CLIENTS[0], RESOLVER_A, "cloudflare.com", "AAAA", [AAAA("cloudflare.com", "2606:4700::6810:84e5")])
exchange(CLIENTS[1], RESOLVER_A, "wikipedia.org", "A", [A("wikipedia.org", "198.35.26.96")])
exchange(CLIENTS[2], RESOLVER_A, "example.com", "MX", [MX("example.com", "mail.example.com.", 10)])
exchange(CLIENTS[0], RESOLVER_A, "example.com", "TXT", [TXT("example.com", "v=spf1 -all")])
# Reverse lookups (PTR) for a couple of addresses.
exchange(CLIENTS[1], RESOLVER_A, "34.216.184.93.in-addr.arpa", "PTR",
         [PTR("34.216.184.93.in-addr.arpa", "example.com.")])
exchange(CLIENTS[2], RESOLVER_A, "8.8.8.8.in-addr.arpa", "PTR",
         [PTR("8.8.8.8.in-addr.arpa", "dns.google.")])
# Repeat a popular lookup so query_count aggregates above 1.
for _ in range(3):
    exchange(CLIENTS[0], RESOLVER_A, "google.com", "A", [A("google.com", "142.250.190.78")])
# An ordinary typo → NXDOMAIN, and a NODATA (name exists, no AAAA).
exchange(CLIENTS[2], RESOLVER_A, "exmaple.com", "A", [], rcode=3)
exchange(CLIENTS[1], RESOLVER_A, "github.com", "AAAA", [])  # NODATA: NOERROR, no answer

# ── Resolver B: service discovery + internal names (all successful) ───────────
exchange(CLIENTS[0], RESOLVER_B, "_ldap._tcp.corp.local", "SRV",
         [SRV("_ldap._tcp.corp.local", "dc1.corp.local.", 389)])
exchange(CLIENTS[1], RESOLVER_B, "dc1.corp.local", "A", [A("dc1.corp.local", "192.168.1.10")])
exchange(CLIENTS[2], RESOLVER_B, "fileserver.corp.local", "A", [A("fileserver.corp.local", "192.168.1.15")])
exchange(CLIENTS[0], RESOLVER_B, "printer.corp.local", "A", [A("printer.corp.local", "192.168.1.30")])
exchange(CLIENTS[1], RESOLVER_B, "intranet.corp.local", "A", [A("intranet.corp.local", "192.168.1.40")])
exchange(CLIENTS[2], RESOLVER_B, "oldhost.corp.local", "A", [], rcode=3)  # one decommissioned host

out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_demo.pcap")
wrpcap(out, pkts)
print(f"wrote {len(pkts)} packets ({len(pkts) // 2} DNS exchanges) to {out}")
