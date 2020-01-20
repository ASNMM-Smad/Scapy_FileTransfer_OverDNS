#!/usr/bin/python3
 
import scapy.all as scapy
from scapy.layers.inet import IP as IP
from scapy.layers.inet import UDP as UDP
from scapy.layers.dns import DNS as DNS
from scapy.layers.dns import DNSQR
from scapy.all import sniff
 
def start_sniff():
    print ("Server listening...: ")
    sniff(iface='eth0', filter='udp port 53',count=4, prn=packet_build)
 
counter = []
packetBytes=[]
def packet_build(p):
    ip_layer = p.getlayer(IP)
    src_ip = ip_layer.src
    udp_layer = p.getlayer(UDP)
    src_port = udp_layer.sport
    udp_layer.dport
 
    dns_layer = p.getlayer(DNS)
    dns_id = dns_layer.id
   
    dnsqr_layer = p[DNSQR].qname
 
    if dns_id == 2:
        counter.append(1)
        coun = len(counter)
        print(f"Received_Packets No. {coun}, From IP : {src_ip}, on Port : {src_port}.")
        data_dencoded = dnsqr_layer.decode('utf-8').replace(".", "")
    f = open ('/root/Downloads/Scapy/received/data.txt', 'a')
    f.write(data_dencoded)
 
start_sniff()