#!/usr/bin/python2
import nfqueue
from scapy.all import *

def callback(packet):
    #print('in')
    #data = packet.get_data()
    #pkt = IP(data)
    #print(data, pkt)
    #payload.set_verdict(nfqueue.ACCEPT)
    return packet.show()
