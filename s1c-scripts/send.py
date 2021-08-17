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
    iface=None
    for i in get_if_list():
        if "ens5" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find ens4 interface")
        exit(1)
    return iface
def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether()
    pkt = pkt /IP(dst=addr) / UDP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    pkt.show2()
    for i in range(0, 1):
        sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()

