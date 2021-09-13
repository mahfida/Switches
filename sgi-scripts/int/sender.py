#!/usr/bin/env python
import sys
import time
from switch_header import *

def main():

    switch_pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=get_if_hwaddr('veth0'))/ \
            SwitchData(bos=1, swid=0,  time_delta=0, in_ts=0)
    switch_pkt =switch_pkt/IP(dst='12.12.0.1')
    switch_pkt.show2()
    while True:
        try:
            sendp(switch_pkt, iface='veth0')
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()

if __name__ == '__main__':
    main()
