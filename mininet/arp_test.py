from scapy.all import ARP, Ether, sendp
from scapy.all import IP, TCP, Ether, Raw, get_if_hwaddr, get_if_list, sendp


# find the interface eth0
def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

# 发送ARP请求报文
iface = get_if()
mac_address = get_if_hwaddr(iface)

arp_request = ARP(pdst="192.168.1.1")  # 目标IP地址
ether = Ether(src=mac_address,dst="ff:ff:ff:ff:ff:ff")  # 广播MAC地址
arp_packet = ether / arp_request


sendp(arp_packet,iface=iface,verbose=False)
