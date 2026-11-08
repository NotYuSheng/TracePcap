from scapy.all import Ether, ARP, IP, TCP, UDP, BOOTP, DHCP, wrpcap
import sys
T0=1730000000.0
pk=[]
def at(p,t): p.time=T0+t; pk.append(p)
GW_MAC='aa:aa:aa:00:00:01'; GW_IP='10.0.0.1'
LAPTOP='bb:bb:bb:00:00:01'; PHONE='cc:cc:cc:00:00:02'
# (a) DHCP reuse: 10.0.0.50 is a laptop, then a phone an hour later (ARP claims + traffic, DHCP hostnames)
at(Ether(src=LAPTOP,dst='ff:ff:ff:ff:ff:ff')/ARP(op=2,hwsrc=LAPTOP,psrc='10.0.0.50',pdst=GW_IP),0)
at(Ether(src=LAPTOP,dst=GW_MAC)/IP(src='10.0.0.50',dst='10.0.0.1',ttl=128)/TCP(sport=40000,dport=445,flags='S'),1)
at(Ether(src=LAPTOP,dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)/BOOTP(chaddr=bytes.fromhex(LAPTOP.replace(':','')))/DHCP(options=[('message-type','request'),('hostname','LAPTOP-ALICE'),('requested_addr','10.0.0.50'),'end']),2)
at(Ether(src=PHONE,dst='ff:ff:ff:ff:ff:ff')/ARP(op=2,hwsrc=PHONE,psrc='10.0.0.50',pdst=GW_IP),3600)
at(Ether(src=PHONE,dst=GW_MAC)/IP(src='10.0.0.50',dst='10.0.0.1',ttl=64)/TCP(sport=50000,dport=443,flags='S'),3601)
at(Ether(src=PHONE,dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)/BOOTP(chaddr=bytes.fromhex(PHONE.replace(':','')))/DHCP(options=[('message-type','request'),('hostname','iPhone-Bob'),('requested_addr','10.0.0.50'),'end']),3602)
# (b) routed hosts: three external servers reach us through the gateway, so eth.src is the gateway MAC
for i,ext in enumerate(['93.184.216.34','151.101.1.69','140.82.112.3']):
    at(Ether(src=GW_MAC,dst=LAPTOP)/IP(src=ext,dst='10.0.0.60',ttl=52)/TCP(sport=443,dport=41000+i,flags='SA'),100+i)
# (c) VRRP: two routers share virtual MAC 00:00:5e:00:01:0a for VIP 10.0.0.254 (adverts from their real IPs)
from scapy.layers.vrrp import VRRP
for src_ip,real_mac,prio,t in [('10.0.0.2','dd:dd:dd:00:00:02',200,200),('10.0.0.3','dd:dd:dd:00:00:03',100,201)]:
    at(Ether(src='00:00:5e:00:01:0a',dst='01:00:5e:00:00:12')/IP(src=src_ip,dst='224.0.0.18',ttl=255,proto=112)/VRRP(vrid=10,priority=prio,addrlist=['10.0.0.254']),t)
at(Ether(src='00:00:5e:00:01:0a',dst='ff:ff:ff:ff:ff:ff')/ARP(op=2,hwsrc='00:00:5e:00:01:0a',psrc='10.0.0.254',pdst='10.0.0.254'),202)
# (d) cloned VMs: same MAC + IP, different TTL (Linux 64 vs Windows 128) and DHCP hostname, interleaved
CLONE='ee:ee:ee:00:00:09'
for t,ttl,name in [(300,64,'web-vm-a'),(301,128,'web-vm-b'),(302,64,'web-vm-a'),(303,128,'web-vm-b')]:
    at(Ether(src=CLONE,dst=GW_MAC)/IP(src='10.0.0.70',dst='10.0.0.1',ttl=ttl)/TCP(sport=30000+t,dport=80,flags='S'),t)
for t,name in [(304,'web-vm-a'),(305,'web-vm-b')]:
    at(Ether(src=CLONE,dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)/BOOTP(chaddr=bytes.fromhex(CLONE.replace(':','')))/DHCP(options=[('message-type','request'),('hostname',name),('requested_addr','10.0.0.70'),'end']),t)
pk.sort(key=lambda p:p.time)
wrpcap(sys.argv[1], pk)
