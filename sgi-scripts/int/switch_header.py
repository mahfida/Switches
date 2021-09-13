from scapy.all import *

TYPE_SWITCH = 0x812

class SwitchData(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("swid", 0, 7),
                   BitField("time_delta", 0, 32),
                   BitField("in_ts", 0, 48)]

bind_layers(Ether, SwitchData, type=TYPE_SWITCH)
bind_layers(SwitchData, SwitchData, bos=0)
