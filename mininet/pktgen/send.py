#!/usr/bin/env python3
import random
import socket
import sys
import struct

from scapy.all import IP, TCP, Ether, Raw, get_if_hwaddr, get_if_list, sendp

id_ethertype = 0x0812

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    destination = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(destination)))
    pkt =  Ether(type=id_ethertype)
    pkt = pkt / Raw(load=struct.pack("!LL", 0xC0E6C2D, 0xC0E6C1A))
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()