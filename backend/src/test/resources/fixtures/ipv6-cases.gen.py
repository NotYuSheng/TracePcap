# IPv6 counterparts of what the extractors read over IPv4 (#1357): every packet here is IPv6, so a
# pass asking tshark for ip.src only finds nothing.
#   python3 ipv6-cases.gen.py ipv6-cases.pcap
from scapy.all import Ether, IPv6, UDP, TCP, DNS, DNSQR, DNSRR, Raw, wrpcap
from scapy.layers.kerberos import KRB_AS_REQ, KRB_KDC_REQ_BODY, PrincipalName, Kerberos
from scapy.layers.vrrp import VRRPv3
from scapy.asn1.asn1 import ASN1_GENERAL_STRING
import sys
T0 = 1730000000.0
pk = []
def at(p, t): p.time = T0 + t; pk.append(p)
CLIENT, RESOLVER, WEB, DC = 'fd00::10', 'fd00::53', 'fd00::80', 'fd00::1'
# (a) DNS: the resolver answers over IPv6
at(Ether()/IPv6(src=CLIENT, dst=RESOLVER)/UDP(sport=53000, dport=53)/DNS(id=1, rd=1, qd=DNSQR(qname='intranet.example', qtype='AAAA')), 0)
at(Ether()/IPv6(src=RESOLVER, dst=CLIENT)/UDP(sport=53, dport=53000)/DNS(id=1, qr=1, ra=1, qd=DNSQR(qname='intranet.example', qtype='AAAA'),
   an=DNSRR(rrname='intranet.example', type='AAAA', rdata='fd00::80')), 0.01)
# (b) HTTP: a request and its JSON response on one stream
req = b'GET /api/v1/items HTTP/1.1\r\nHost: intranet.example\r\n\r\n'
resp = b'HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}'
at(Ether()/IPv6(src=CLIENT, dst=WEB)/TCP(sport=41000, dport=80, flags='S', seq=100), 1)
at(Ether()/IPv6(src=WEB, dst=CLIENT)/TCP(sport=80, dport=41000, flags='SA', seq=500, ack=101), 1.01)
at(Ether()/IPv6(src=CLIENT, dst=WEB)/TCP(sport=41000, dport=80, flags='A', seq=101, ack=501), 1.02)
at(Ether()/IPv6(src=CLIENT, dst=WEB)/TCP(sport=41000, dport=80, flags='PA', seq=101, ack=501)/Raw(req), 1.03)
at(Ether()/IPv6(src=WEB, dst=CLIENT)/TCP(sport=80, dport=41000, flags='PA', seq=501, ack=101 + len(req))/Raw(resp), 1.04)
# (c) Kerberos: an AS-REQ for dave from a client on IPv6
body = KRB_KDC_REQ_BODY(cname=PrincipalName(nameType=1, nameString=[ASN1_GENERAL_STRING('dave')]),
                        realm=ASN1_GENERAL_STRING('EXAMPLE.COM'),
                        sname=PrincipalName(nameType=2, nameString=[ASN1_GENERAL_STRING('krbtgt'), ASN1_GENERAL_STRING('EXAMPLE.COM')]),
                        nonce=12345, etype=[18])
at(Ether()/IPv6(src=CLIENT, dst=DC)/UDP(sport=50000, dport=88)/Kerberos(root=KRB_AS_REQ(reqBody=body)), 2)
# (d) VRRPv3 over IPv6: two routers advertise virtual address fd00::fe
for src, prio, t in [('fe80::2', 200, 3), ('fe80::3', 100, 3.01)]:
    at(Ether(src='00:00:5e:00:02:0a', dst='33:33:00:00:00:12')/IPv6(src=src, dst='ff02::12', nh=112, hlim=255)/VRRPv3(vrid=10, priority=prio, addrlist=['fd00::fe']), t)
pk.sort(key=lambda p: p.time)
wrpcap(sys.argv[1], pk)
