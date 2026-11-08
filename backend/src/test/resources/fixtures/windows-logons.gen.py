from scapy.all import IP, UDP, TCP, Ether, wrpcap
from scapy.layers.kerberos import KRB_AS_REQ, KRB_KDC_REQ_BODY, PrincipalName, Kerberos
from scapy.layers.ldap import LDAP, LDAP_SearchRequest
from scapy.asn1.asn1 import ASN1_GENERAL_STRING
import sys
DC='10.0.0.1'
T0=1730000000.0
def asreq(src, user, t, realm='EXAMPLE.COM'):
    body = KRB_KDC_REQ_BODY(cname=PrincipalName(nameType=1, nameString=[ASN1_GENERAL_STRING(user)]),
                           realm=ASN1_GENERAL_STRING(realm),
                           sname=PrincipalName(nameType=2, nameString=[ASN1_GENERAL_STRING('krbtgt'), ASN1_GENERAL_STRING(realm)]),
                           nonce=12345, etype=[18])
    p = Ether()/IP(src=src, dst=DC)/UDP(sport=50000, dport=88)/Kerberos(root=KRB_AS_REQ(reqBody=body))
    p.time = t; return p
def ldap(src, dn, t, sport=50100):
    p = Ether()/IP(src=src, dst=DC)/TCP(sport=sport, dport=389, flags='PA', seq=1000)/LDAP(messageID=7, protocolOp=LDAP_SearchRequest(baseObject=dn))
    p.time = t; return p
pkts = [
  asreq('10.0.0.10', 'alice', T0),
  asreq('10.0.0.10', 'bob', T0 + 5*3600),
  asreq('10.0.0.10', 'bob', T0 + 5*3600 + 60),
  asreq('10.0.0.11', 'carol', T0 + 100),
  asreq('10.0.0.11', 'DESKTOP-01$', T0 + 101),
  ldap('10.0.0.12', 'CN=Clark Collier,CN=Users,DC=example,DC=com', T0 + 200),
  ldap('10.0.0.12', 'CN=Clark Collier,CN=Users,DC=example,DC=com', T0 + 900, sport=50101),
  ldap('10.0.0.12', 'CN=Dana Lee,OU=Sales,OU=Staff,DC=example,DC=com', T0 + 300, sport=50102),
  ldap('10.0.0.12', 'CN=Configuration,DC=example,DC=com', T0 + 301, sport=50103),
]
wrpcap(sys.argv[1], pkts)

# Two LDAP searchRequests in one TCP segment (DNs contain commas: the aggregator must not split them).
two = Ether()/IP(src='10.0.0.13', dst=DC)/TCP(sport=50200, dport=389, flags='PA', seq=5000)/ \
      LDAP(messageID=8, protocolOp=LDAP_SearchRequest(baseObject='CN=Erin Yu,CN=Users,DC=example,DC=com'))/ \
      LDAP(messageID=9, protocolOp=LDAP_SearchRequest(baseObject='CN=Frank Ho,CN=Users,DC=example,DC=com'))
two.time = T0 + 400
# Kerberos over TCP: a KRB-ERROR (msg_type 30) then an AS-REQ in the same segment (#812 item 4).
from scapy.layers.kerberos import KerberosTCPHeader, KRB_ERROR
err = KRB_ERROR(errorCode=25, realm=ASN1_GENERAL_STRING('EXAMPLE.COM'),
                sname=PrincipalName(nameType=2, nameString=[ASN1_GENERAL_STRING('krbtgt'), ASN1_GENERAL_STRING('EXAMPLE.COM')]),
                stime='20241027000000Z', susec=0)
body = KRB_KDC_REQ_BODY(cname=PrincipalName(nameType=1, nameString=[ASN1_GENERAL_STRING('grace')]),
                        realm=ASN1_GENERAL_STRING('EXAMPLE.COM'),
                        sname=PrincipalName(nameType=2, nameString=[ASN1_GENERAL_STRING('krbtgt'), ASN1_GENERAL_STRING('EXAMPLE.COM')]),
                        nonce=777, etype=[18])
m1 = bytes(Kerberos(root=err)); m2 = bytes(Kerberos(root=KRB_AS_REQ(reqBody=body)))
import struct
payload = struct.pack('>I', len(m1)) + m1 + struct.pack('>I', len(m2)) + m2
mixed = Ether()/IP(src='10.0.0.14', dst=DC)/TCP(sport=50300, dport=88, flags='PA', seq=9000)/payload
mixed.time = T0 + 500
wrpcap(sys.argv[1], pkts + [two, mixed])
