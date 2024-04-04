#!/usr/bin/env python3
import os
import sys
import struct

from scapy.all import TCP,FieldLenField,FieldListField,IntField,IPOption,ShortField,get_if_list,sniff,Ether,Raw
from scapy.layers.inet import _IPOption_HDR


id_ethertype = 0x0812
geo_ethertype = 0x8947
mf_ethertype = 0x27c0
ndn_ethertype = 0x8624

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    if pkt.haslayer("Ether") and pkt[Ether].type == id_ethertype:
        print("got an ID packet")
        pkt.show2()
    elif pkt.haslayer("Ether") and pkt[Ether].type == geo_ethertype:
        print("got an GEO packet")
        pkt.show2()
    elif pkt.haslayer("Ether") and pkt[Ether].type == mf_ethertype:
        print("got an MF packet")
        pkt.show2()
    elif pkt.haslayer("Ether") and pkt[Ether].type == ndn_ethertype:
        print("got an NDN packet")
        pkt.show2()
       
        
    
    sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()