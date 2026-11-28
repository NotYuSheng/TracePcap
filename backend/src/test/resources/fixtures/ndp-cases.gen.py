# IPv6 Neighbor Discovery: who owns an IPv6 address, as ARP says it for IPv4 (#1357).
#   python3 ndp-cases.gen.py ndp-cases.pcap
# - LAPTOP (aa:aa:aa:00:00:10) holds three addresses, as an IPv6 host does: link-local, global
#   (SLAAC) and a temporary one. It sends from all three and claims each by NDP. Without NDP its MAC
#   fronts three unclaimed IPs, which reads as a router and leaves the laptop with no MAC at all.
# - fd00::99 is claimed by two MACs (a same-segment conflict, as two ARP claims would be).
# - A duplicate-address probe (from ::) and a proxy NA (override flag clear) are not ownership.
from scapy.all import Ether, IPv6, UDP, wrpcap
from scapy.layers.inet6 import ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr
import sys
T0 = 1730000000.0
pk = []
def at(p, t): p.time = T0 + t; pk.append(p)
LAPTOP = 'aa:aa:aa:00:00:10'; GW = 'bb:bb:bb:00:00:01'
ADDRS = ['fe80::10', 'fd00::10', 'fd00::5eed:10']
for i, a in enumerate(ADDRS):
    # traffic from each address (to the gateway, so eth.src is the laptop's own MAC)
    at(Ether(src=LAPTOP, dst=GW)/IPv6(src=a, dst='fd00::1')/UDP(sport=40000 + i, dport=53), i)
    # NS asking for the gateway, carrying the laptop's link-layer address: "a is at LAPTOP"
    at(Ether(src=LAPTOP, dst='33:33:ff:00:00:01')/IPv6(src=a, dst='ff02::1:ff00:1', hlim=255)/ICMPv6ND_NS(tgt='fd00::1')/ICMPv6NDOptSrcLLAddr(lladdr=LAPTOP), i + 0.1)
# NA from the laptop for its global address (override set): "fd00::10 is at LAPTOP"
at(Ether(src=LAPTOP, dst=GW)/IPv6(src='fd00::10', dst='fd00::1', hlim=255)/ICMPv6ND_NA(tgt='fd00::10', R=0, S=1, O=1)/ICMPv6NDOptDstLLAddr(lladdr=LAPTOP), 5)
# fd00::99 claimed by two machines
for t, mac in [(10, 'cc:cc:cc:00:00:01'), (11, 'cc:cc:cc:00:00:02')]:
    at(Ether(src=mac, dst='33:33:00:00:00:01')/IPv6(src='fd00::99', dst='ff02::1', hlim=255)/ICMPv6ND_NA(tgt='fd00::99', R=0, S=0, O=1)/ICMPv6NDOptDstLLAddr(lladdr=mac), t)
# DAD probe: from ::, no claim
at(Ether(src='dd:dd:dd:00:00:01', dst='33:33:ff:00:00:77')/IPv6(src='::', dst='ff02::1:ff00:77', hlim=255)/ICMPv6ND_NS(tgt='fd00::77'), 20)
# proxy NA (override clear): a router answering for fd00::88, not owning it
at(Ether(src=GW, dst=LAPTOP)/IPv6(src='fe80::1', dst='fe80::10', hlim=255)/ICMPv6ND_NA(tgt='fd00::88', R=1, S=1, O=0)/ICMPv6NDOptDstLLAddr(lladdr=GW), 21)
pk.sort(key=lambda p: p.time)
wrpcap(sys.argv[1], pk)
