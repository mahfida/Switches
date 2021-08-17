#!/usr/bin/env python

from switch_header import *

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

def handle_pkt(pkt):
    if SwitchData in pkt:
       # print("I am here");
        data_layers = [l for l in expand(pkt) if l.name=='SwitchData']
       # print("length:", len(data_layers))
        for sw in data_layers:
            #utilization = 0 if sw.cur_time == sw.last_time else 8.0*sw.byte_cnt/(sw.cur_time - sw.last_time)
            print("Switch {} - Queue time: {}  microsec. - Incoming ts: {} microsec.".format(sw.swid, sw.time_delta,  sw.in_ts))
    else:
        print("No  switch added")

def main():
    iface = 'veth5'
    print("sniffing on {}".format(iface))
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
