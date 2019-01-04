#!/usr/bin/python2
from scapy.all import *

def callback(packet):
    if packet.haslayer(DNSRR):
        print(packet[DNSRR].show())
