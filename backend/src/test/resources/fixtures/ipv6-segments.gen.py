# IPv6 networks from router advertisements and DHCPv6 (#1357), as DHCPv4 tells IPv4's apart (#462).
#   python3 ipv6-segments.gen.py ipv6-segments.pcap
# - VLAN 10 is dual-stack: one router (R10) leases 10.0.10.0/24 by DHCPv4, advertises fd00:10::/64,
#   and leases LAPTOP fd00:10::100 by DHCPv6. One network, with both ranges.
# - VLAN 20 is IPv6 only: its router (R20) advertises fd00:20::/64, and is also at fe80::1. Link-local
#   repeats per link, so fe80::1 is two machines: the networks overlap there and nowhere else.
# - An untagged router (R30) advertises 2001:db8:30::/64: a network known by its router's MAC.
# - Not networks: a Relay-Reply (a relay's hop, carrying a Reply for another client) and an ICMPv6
#   error quoting an RA for fd00:bad::/64.
from scapy.all import Ether, Dot1Q, IP, IPv6, UDP, BOOTP, DHCP, wrpcap
from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDNSSL, ICMPv6ParamProblem
from scapy.layers.dhcp6 import (DHCP6_Reply, DHCP6_RelayReply, DHCP6OptRelayMsg, DHCP6OptClientId, DHCP6OptServerId,
    DUID_LL, DHCP6OptIA_NA, DHCP6OptIAAddress, DHCP6OptClientFQDN, DHCP6OptDNSDomains)
import sys
T0 = 1730000000.0
pk = []
def at(p, t): p.time = T0 + t; pk.append(p)
R10, R20, R30 = 'aa:00:00:00:00:0a', 'aa:00:00:00:00:14', 'cc:cc:cc:00:00:01'
LAPTOP, OTHER = '10:00:00:00:00:01', '10:00:00:00:00:02'
def mac_bytes(m): return bytes.fromhex(m.replace(':', ''))
def ra(src_mac, vlan, src_ip, prefixes, domain=None):
    p = Ether(src=src_mac, dst='33:33:00:00:00:01')
    if vlan is not None: p = p/Dot1Q(vlan=vlan)
    p = p/IPv6(src=src_ip, dst='ff02::1', hlim=255)/ICMPv6ND_RA(M=1)/ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    for pre in prefixes: p = p/ICMPv6NDOptPrefixInfo(prefix=pre, prefixlen=64)
    if domain: p = p/ICMPv6NDOptDNSSL(searchlist=[domain + '.'])
    return p
def reply(client, addr, fqdn):
    return (DHCP6_Reply()/DHCP6OptClientId(duid=DUID_LL(lladdr=client))/DHCP6OptServerId(duid=DUID_LL(lladdr=R10))
            /DHCP6OptIA_NA(iaid=1, ianaopts=[DHCP6OptIAAddress(addr=addr, preflft=3600, validlft=7200)])
            /DHCP6OptClientFQDN(fqdn=fqdn)/DHCP6OptDNSDomains(dnsdomains=['hq.example.']))
# VLAN 10: DHCPv4 ACK, RA, DHCPv6 Reply
at(Ether(src=R10, dst=LAPTOP)/Dot1Q(vlan=10)/IP(src='10.0.10.1', dst='10.0.10.100')/UDP(sport=67, dport=68)
   /BOOTP(op=2, yiaddr='10.0.10.100', chaddr=mac_bytes(LAPTOP))
   /DHCP(options=[('message-type', 'ack'), ('server_id', '10.0.10.1'), ('router', '10.0.10.1'), ('domain', b'hq.example'),
                  ('subnet_mask', '255.255.255.0'), ('lease_time', 3600), 'end']), 0)
at(ra(R10, 10, 'fe80::1', ['fd00:10::'], 'hq.example'), 1)
at(Ether(src=R10, dst=LAPTOP)/Dot1Q(vlan=10)/IPv6(src='fe80::1', dst='fe80::100')/UDP(sport=547, dport=546)
   /reply(LAPTOP, 'fd00:10::100', 'laptop-a.hq.example.'), 2)
at(ra(R10, 10, 'fe80::1', ['fd00:10::'], 'hq.example'), 60)  # periodic: one router, not two
# VLAN 20: IPv6 only, its router also at fe80::1
at(ra(R20, 20, 'fe80::1', ['fd00:20::']), 3)
# untagged router
at(ra(R30, None, 'fe80::30', ['2001:db8:30::']), 4)
# a relay's hop: Relay-Reply carrying a Reply for OTHER; not a lease (the relay hands it on)
at(Ether(src=R30, dst='dd:dd:dd:00:00:01')/IPv6(src='2001:db8:30::547', dst='2001:db8:30::1')/UDP(sport=547, dport=547)
   /DHCP6_RelayReply(linkaddr='2001:db8:30::', peeraddr='fe80::2')/DHCP6OptRelayMsg(message=reply(OTHER, '2001:db8:30::200', 'other.')), 5)
# an ICMPv6 error quoting an RA: the quoted prefix is not anyone's network
quoted = IPv6(src='fe80::bad', dst='ff02::1', hlim=255)/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix='fd00:bad::', prefixlen=64)
at(Ether(src=R30, dst='33:33:00:00:00:01')/IPv6(src='fe80::30', dst='fe80::bad')/ICMPv6ParamProblem(code=0, ptr=6)/quoted, 6)
pk.sort(key=lambda p: p.time)
wrpcap(sys.argv[1], pk)
