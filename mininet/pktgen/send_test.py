#!/usr/bin/env python3
import random
import socket
import sys
import struct

from scapy.all import IP, TCP, Ether, Raw, get_if_hwaddr, get_if_list, sendp

#ethertype for each modal type
id_ethertype = 0x0812
geo_ethertype = 0x8947
mf_ethertype = 0x27c0
ndn_ethertype = 0x8624

#find the interface eth0
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

#generate geo packet
def generate_geo_pkt(ethertype, parameters):
    geoAreaPosLat = int(parameters[0])
    geoAreaPosLon = int(parameters[1])
    disa = int(parameters[2])
    disb = int(parameters[3])
    pkt = Ether(type=ethertype)
    pkt = pkt / Raw(
        load=struct.pack("!LLLLLLLLLLLLLL", 0x00000000, 0x00400000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                         0x00000000, 0x00000000, 0x00000000, 0x00000000, geoAreaPosLat, geoAreaPosLon, disa << 16 | disb, 0x00000000))
    pkt.show2()
    return pkt

#generate id packet
def generate_id_pkt(ethertype, parameters):
    srcIdentity = int(parameters[0])
    dstIdentity = int(parameters[1])
    pkt = Ether(type=ethertype)
    pkt = pkt / Raw(load=struct.pack("!LL", srcIdentity, dstIdentity))
    pkt.show2()
    return pkt

#generate mf packet
def generate_mf_pkt(ethertype, parameters):
    srcIdentity = int(parameters[0])
    dstIdentity = int(parameters[1])
    pkt = Ether(type=ethertype)
    pkt = pkt / Raw(load=struct.pack("!LLL", 0x0000001, srcIdentity, dstIdentity))
    pkt.show2()
    return pkt

#generate ndn packet
def generate_ndn_pkt(ethertype, parameters):
    name_component_src = int(parameters[0])
    name_component_dst = int(parameters[1])
    content = int(parameters[2])
    pkt = Ether(type=ethertype)
    pkt = pkt / Raw(load=struct.pack("!LLLLLLLLL", 0x6fd0020,0x80c0804,name_component_src, 0x08040000 | ((name_component_dst >> 16) & 0xffff) 
        ,(name_component_dst & 0xffff) | 0x1e00 ,0x18020000,0x19020000,0x1b020000, 0x1a020000 | content ))
    pkt.show2()
    return pkt
    
def required_parameters_number(modal_type):
    if modal_type == "id":
        return 2
    if modal_type == "mf":
        return 2
    if modal_type == "geo":
        return 4
    if modal_type == "ndn":
        return 3

def main():
    if len(sys.argv) < 3:
        print('至少需要两个参数"模态类型"和"参数数量"(pass 2 arguments: "<modal_type>" <parameter_numbers>)')
        exit(1)

    modal_type = sys.argv[1]
    parameter_numbers = int(sys.argv[2])

    parameters = sys.argv[3:]

    if parameter_numbers == 0:
        if len(sys.argv) != 5 + required_parameters_number(modal_type):
            print('缺少"发包时长"或"发包频率"或"模态参数"（missing parameters for duration or frequency or modal）')
            exit(1)

        duration = int(parameters[0])
        frequency = float(parameters[1])

        # 计算发送数据包的结束时间
        end_time = time.time() + duration

        while time.time() < end_time:
            # 生成随机参数列表
            modal_parameters = parameters[2:]
            #check the modal type and generate the packet
            if modal_type == "geo":
                pkt = generate_geo_pkt(geo_ethertype, modal_parameters)
            elif modal_type == "id":
                pkt = generate_id_pkt(id_ethertype, modal_parameters)
            elif modal_type == "mf":
                pkt = generate_mf_pkt(mf_ethertype, modal_parameters)
            elif modal_type == "ndn":
                pkt = generate_ndn_pkt(ndn_ethertype, modal_parameters)
            else:
                print("Invalid modal type")
                exit(1)
            #get the interface
            iface = get_if()
            #print the interface and parameters
            print("sending on interface %s with parameters: %s" % (iface, str(modal_parameters)))

            # 发送数据包
            sendp(pkt, iface=iface, verbose=False)
            
            # 控制发送频率
            time.sleep(1 / frequency)

    else:
        if len(sys.argv) != 3 + parameter_numbers:
            print('缺少"模态参数"（missing modal parameter）')
            exit(1)
        # 根据 modal_type 生成对应的数据包
        if modal_type == "geo":
            pkt = generate_geo_pkt(geo_ethertype, parameters)
        elif modal_type == "id":
            pkt = generate_id_pkt(id_ethertype, parameters)
        elif modal_type == "mf":
            pkt = generate_mf_pkt(mf_ethertype, parameters)
        elif modal_type == "ndn":
            pkt = generate_ndn_pkt(ndn_ethertype, parameters)
        else:
            print("Invalid modal type")
            exit(1)
        
        # 获取接口
        iface = get_if()
        # 打印接口和参数
        print("sending on interface %s with parameters: %s" % (iface, str(parameters)))

        # 发送数据包
        sendp(pkt, iface=iface, verbose=False)
        
if __name__ == '__main__':
    main()