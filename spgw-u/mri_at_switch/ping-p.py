#!/usr/bin/python
from scapy.all import *

TIMEOUT = 2
conf.verb = 0
for ip in range(0, 256):
    packet = IP(dst="128.39.37.171" + str(ip), ttl=20)/ICMP()
    reply = sr1(packet, timeout=TIMEOUT)
    if not (reply is None):
         print reply.dst, "is online"
    else:
         print "Timeout waiting for %s" % packet[IP].dst

