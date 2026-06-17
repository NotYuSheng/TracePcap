"""
Generate a PCAP containing all four ghost node types for testing issue #342.

Ghost nodes created:
  10.0.0.101  — ping sweep target, no response (ghost: no-response, icmp-unreachable)
  10.0.0.102  — ARP scan target, no reply     (ghost: no-response, arp-no-reply)
  10.0.0.103  — another ping sweep target     (ghost: no-response, icmp-unreachable)
  192.168.1.2 — traceroute hop (TTL-exceeded) (ghost: ttl-exceeded)

Real nodes:
  10.0.0.1   — local host (initiates scans)
  10.0.0.5   — a real server (bidirectional TCP)
"""

from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, ARP,
    wrpcap, RandMAC
)

pkts = []

SRC   = "10.0.0.1"
REAL  = "10.0.0.5"
GHOST_PING1  = "10.0.0.101"
GHOST_PING2  = "10.0.0.103"
GHOST_ARP    = "10.0.0.102"
HOP          = "192.168.1.2"   # traceroute intermediate hop

MAC_SRC  = "aa:bb:cc:dd:ee:01"
MAC_REAL = "aa:bb:cc:dd:ee:05"
MAC_HOP  = "aa:bb:cc:dd:ee:02"

# ── 1. Bidirectional TCP (SRC <-> REAL) — not a ghost ─────────────────────
pkts.append(Ether(src=MAC_SRC, dst=MAC_REAL)/IP(src=SRC, dst=REAL)/TCP(sport=54321, dport=80, flags="S"))
pkts.append(Ether(src=MAC_REAL, dst=MAC_SRC)/IP(src=REAL, dst=SRC)/TCP(sport=80, dport=54321, flags="SA"))
pkts.append(Ether(src=MAC_SRC, dst=MAC_REAL)/IP(src=SRC, dst=REAL)/TCP(sport=54321, dport=80, flags="A"))

# ── 2. Ping sweep — GHOST_PING1 never replies (no-response, icmp-unreachable)
for _ in range(4):
    pkts.append(Ether(src=MAC_SRC)/IP(src=SRC, dst=GHOST_PING1)/ICMP(type=8, code=0))

# ── 3. Ping sweep — GHOST_PING2 never replies (no-response, icmp-unreachable)
for _ in range(3):
    pkts.append(Ether(src=MAC_SRC)/IP(src=SRC, dst=GHOST_PING2)/ICMP(type=8, code=0))

# ── 4. ARP scan — GHOST_ARP never replies (no-response, arp-no-reply) ──────
for _ in range(2):
    pkts.append(
        Ether(src=MAC_SRC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=MAC_SRC, psrc=SRC, pdst=GHOST_ARP)
    )

# ── 5. Traceroute hop — HOP sends ICMP TTL-exceeded back (ttl-exceeded) ────
# The probe packet (SRC -> external) with TTL=1 triggers TTL-exceeded from HOP
pkts.append(Ether(src=MAC_SRC)/IP(src=SRC, dst="8.8.8.8", ttl=1)/UDP(dport=33434))
# HOP replies with ICMP TTL-exceeded — this is what makes HOP appear as a node
pkts.append(Ether(src=MAC_HOP, dst=MAC_SRC)/IP(src=HOP, dst=SRC)/ICMP(type=11, code=0))
pkts.append(Ether(src=MAC_SRC)/IP(src=SRC, dst="8.8.8.8", ttl=1)/UDP(dport=33435))
pkts.append(Ether(src=MAC_HOP, dst=MAC_SRC)/IP(src=HOP, dst=SRC)/ICMP(type=11, code=0))

out = "ghost_test.pcap"
wrpcap(out, pkts)
print(f"Written {len(pkts)} packets to {out}")
print()
print("Expected ghost nodes after upload:")
print(f"  {GHOST_PING1}  → no-response, icmp-unreachable")
print(f"  {GHOST_PING2}  → no-response, icmp-unreachable")
print(f"  {GHOST_ARP}  → no-response, arp-no-reply")
print(f"  {HOP}  → ttl-exceeded")
print()
print("Real nodes (should NOT be tagged as ghost):")
print(f"  {SRC}  (initiator)")
print(f"  {REAL}   (TCP server, bidirectional)")
