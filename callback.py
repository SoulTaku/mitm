#!/usr/bin/python
from scapy.all import *

def callback(packet):
    if packet.haslayer(DNSRR):
        print(packet[DNSRR].show())
