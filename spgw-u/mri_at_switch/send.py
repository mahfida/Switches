#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "ens6" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find ens6 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print('pass 1 arguments: <destination> <msg>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print("sending on interface %s to %s" % (iface, str(addr)))
    
    pkt =  Ether(src=get_if_hwaddr(iface) , dst="ff:ff:ff:ff:ff:ff")
    #pkt = Ether()
    pkt = pkt /IP(src="10.254.1.213",dst=addr) / UDP(dport=20001, sport=random.randint(49152,65535)) / sys.argv[2]
    for i in range(0,2):
        pkt.show2()
        sendp(pkt,iface=iface, verbose=False)


if __name__ == '__main__':
    main()
