#!/usr/bin/env python3
import random
import socket
import sys
import struct
import math
import time
import subprocess
import json

from scapy.all import IP, TCP, Ether, Raw, get_if_hwaddr, get_if_list, sendp

# ethertype for each modal type
ip_ethertype = 0x0800
id_ethertype = 0x0812
geo_ethertype = 0x8947
mf_ethertype = 0x27c0
ndn_ethertype = 0x8624
flexip_ethertype = 0x3690


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


def float_to_custom_bin(number):
    # 转换输入为浮点数，防止传入的是字符串
    number = float(number)
    # 确定符号位并取绝对值
    sign_bit = '01' if number < 0 else '00'
    number = abs(number)

    # 分离整数部分和小数部分
    integer_part, fractional_part = divmod(number, 1)
    integer_part = int(integer_part)

    # 将整数部分转换为 15 位二进制
    integer_bits = format(integer_part, '015b')

    # 将小数部分转换为 15 位二进制
    fractional_bits = ''
    while len(fractional_bits) < 15:
        fractional_part *= 2
        bit, fractional_part = divmod(fractional_part, 1)
        fractional_bits += str(int(bit))

    # 拼接符号位、整数二进制和小数二进制
    binary_representation = sign_bit + integer_bits + fractional_bits
    decimal_representation = int(binary_representation, 2)
    return decimal_representation


# generate geo packet
def generate_geo_pkt(ethertype, source_host, destination_host):
    hostId = destination_host - 64
    vmx = math.floor(hostId / 100)
    i = hostId % 100 + 64
    geoAreaPosLat = i - 63
    geoAreaPosLon = float_to_custom_bin(-180 + vmx * 20 + (i - 64) * 0.4)
    disa = 0
    disb = 0
    pkt = Ether(type=ethertype)
    pkt = pkt / Raw(
        load=struct.pack("!LLLLLLLLLLLLLL", 0x00000000, 0x00400000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                         0x00000000, 0x00000000, 0x00000000, 0x00000000, geoAreaPosLat, geoAreaPosLon,
                         disa << 16 | disb, 0x00000000))
    pkt.show2()
    return pkt


# generate id packet
def hostToIDParam(parameter):
    hostId = parameter - 64
    vmx = math.floor(hostId / 100)
    i = hostId % 100 + 64
    return 202271720 + vmx * 100000 + i - 64


def generate_id_pkt(ethertype, source_host, destination_host):  # 从主机信息中提取参数信息
    srcIdentity = hostToIDParam(source_host)
    dstIdentity = hostToIDParam(destination_host)
    pkt = Ether(type=ethertype)
    pkt = pkt / Raw(load=struct.pack("!LL", srcIdentity, dstIdentity))
    pkt.show2()
    return pkt


# generate mf packet
def hostToMFParam(parameter):
    hostId = parameter - 64
    vmx = math.floor(hostId / 100)
    i = hostId % 100 + 64
    return 1 + vmx * 100 + i - 64


def generate_mf_pkt(ethertype, source_host, destination_host):
    srcIdentity = hostToMFParam(source_host)
    dstIdentity = hostToMFParam(destination_host)
    pkt = Ether(type=ethertype)
    pkt = pkt / Raw(load=struct.pack("!LLL", 0x0000001, srcIdentity, dstIdentity))
    pkt.show2()
    return pkt


# generate ndn packet
def hostToNDNParam(parameter):
    hostId = parameter - 64
    vmx = math.floor(hostId / 100)
    i = hostId % 100 + 64
    return 202271720 + vmx * 100000 + i - 64


def generate_ndn_pkt(ethertype, source_host, destination_host):
    hostId = source_host - 64  # 取参数1
    vmx = math.floor(hostId / 100)
    i = hostId % 100 + 64
    name_component_src = hostToNDNParam(source_host)
    name_component_dst = hostToNDNParam(destination_host)
    content = 2048 + vmx * 100 + i - 64
    print(name_component_dst, content)
    pkt = Ether(type=ethertype)
    pkt = pkt / Raw(load=struct.pack("!LLLLLLLLL", 0x6fd0020, 0x80c0804, name_component_src,
                                     0x08840000 | ((name_component_dst >> 16) & 0xffff)
                                     , (((name_component_dst & 0xffff)) << 16) | 0x1e00, 0x18020000, 0x19020000,0x1b020000,0x1a020000 | content))
    pkt.show2()
    return pkt


# generate IP packet
def hostToIPParam(parameter):
    hostId = parameter - 64
    vmx = math.floor(hostId / 100)
    i = hostId % 100 + 64
    return "172.20.{}.{}".format(vmx + 1, i - 64 + 12)  # ip与拓扑中的一致


def generate_ip_pkt(ethertype, source_host, destination_host):
    print("generate_ip_pkt", source_host, destination_host)
    srcIp = hostToIPParam(source_host)
    dstIp = hostToIPParam(destination_host)
    pkt = Ether(type=ethertype) / IP(src=srcIp, dst=dstIp) / TCP(dport=1234,sport=49152)
    # pkt = pkt / Raw(load=struct.pack("!LL", srcIp, dstIp))
    pkt.show2()
    return pkt

# generate FlexIP packet

length_index = 8
length_restrained = 8
length_extendable_F0 = 16
length_extendable_F1 = 32
length_extendable_F2 = 64
length_extendable_F4 = 256

format_restrained = 0
format_extendable = 1
format_hierarchical = 2
format_multiSemantics = 3

def customFlexIP(vmx, i):
    F0 = 2048 + vmx * 100 + i - 64
    F1 = 202271720 + vmx * 100000 + i - 64
    F2 = (1<<50) + vmx * 100000000 + i - 64
    F4 = (1<<200) + vmx * 100000000000 + i - 64
    if 65<=i<=68:
        return "F0{:04X}".format(F0), length_index + length_extendable_F0, format_extendable
    elif 69<=i<=72:
        return "F1{:08X}".format(F1), length_index + length_extendable_F1, format_extendable
    elif 73<=i<=76:
        return "F2{:016X}".format(F2), length_index + length_extendable_F2, format_extendable
    elif 77<=i<=80:
        return "F4{:064X}".format(F4), length_index + length_extendable_F4, format_extendable
    elif i==81:
        return "F6{:02X}F0{:04X}".format(i, F0), length_index + length_restrained + length_index + length_extendable_F0, format_hierarchical
    elif i==82:
        return "F6{:02X}F1{:08X}".format(i, F1), length_index + length_restrained + length_index + length_extendable_F1, format_hierarchical
    elif i==83:
        return "F6{:02X}F2{:016X}".format(i, F2), length_index + length_restrained + length_index + length_extendable_F2, format_hierarchical
    elif i==84:
        return "F6{:02X}F4{:064X}".format(i, F4), length_index + length_restrained + length_index + length_extendable_F4, format_hierarchical
    elif i==85:
        return "F6F0{:04X}F1{:08X}".format(F0, F1), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F1, format_hierarchical
    elif i==86:
        return "F6F0{:04X}F2{:016X}".format(F0, F2), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F2, format_hierarchical
    elif i==87:
        return "F6F0{:04X}F4{:064X}".format(F0, F4), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F4, format_hierarchical
    elif i==88:
        return "F6F1{:08X}F2{:016X}".format(F1, F2), length_index + length_index + length_extendable_F1 + length_index + length_extendable_F2, format_hierarchical
    elif i==89:
        return "F6F1{:08X}F4{:064X}".format(F1, F4), length_index + length_index + length_extendable_F1 + length_index + length_extendable_F4, format_hierarchical
    elif i==90:
        return "F6F2{:016X}F4{:064X}".format(F2, F4), length_index + length_index + length_extendable_F2 + length_index + length_extendable_F4, format_hierarchical
    elif i==91:
        return "F7{:02X}F0{:04X}F1{:08X}".format(i, F0, F1), length_index + length_restrained + length_index + length_extendable_F0 + length_index + length_extendable_F1, format_hierarchical
    elif i==92:
        return "F7{:02X}F0{:04X}F2{:016X}".format(i, F0, F2), length_index + length_restrained + length_index + length_extendable_F0 + length_index + length_extendable_F2, format_hierarchical
    elif i==93:
        return "F7{:02X}F0{:04X}F4{:064X}".format(i, F0, F4), length_index + length_restrained + length_index + length_extendable_F0 + length_index + length_extendable_F4, format_hierarchical
    elif i==94:
        return "F7{:02X}F1{:08X}F2{:016X}".format(i, F1, F2), length_index + length_restrained + length_index + length_extendable_F1 + length_index + length_extendable_F2, format_hierarchical
    elif i==95:
        return "F7{:02X}F1{:08X}F4{:064X}".format(i, F1, F4), length_index + length_restrained + length_index + length_extendable_F1 + length_index + length_extendable_F4, format_hierarchical
    elif i==96:
        return "F7{:02X}F2{:016X}F4{:064X}".format(i, F2, F4), length_index + length_restrained + length_index + length_extendable_F2 + length_index + length_extendable_F4, format_hierarchical
    elif i==97:
        return "F7F0{:04X}F1{:08X}F2{:016X}".format(F0, F1, F2), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F1 + length_index + length_extendable_F2, format_hierarchical
    elif i==98:
        return "F7F0{:04X}F1{:08X}F4{:064X}".format(F0, F1, F4), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F1 + length_index + length_extendable_F4, format_hierarchical
    elif i==99:
        return "F7F0{:04X}F2{:016X}F4{:064X}".format(F0, F2, F4), length_index + length_index + length_extendable_F0 + length_index + length_extendable_F2 + length_index + length_extendable_F4, format_hierarchical
    elif i==100:
        return "F7F1{:08X}F2{:016X}F4{:064X}".format(F1, F2, F4), length_index + length_index + length_extendable_F1 + length_index + length_extendable_F2 + length_index + length_extendable_F4, format_hierarchical
    return "{:02X}".format(i), length_restrained, format_restrained

def hostToFlexIPParam(parameter):
    hostId = parameter - 64
    vmx = math.floor(hostId / 100)
    i = hostId % 100 + 64
    return customFlexIP(vmx, i)

def generate_flexip_pkt(ethertype, source_host, destination_host):
    print("generate_flexip_pkt", source_host, destination_host)
    srcFlexIP, srcLength, srcFormat = hostToFlexIPParam(source_host)
    dstFlexIP, dstLength, dstFormat = hostToFlexIPParam(destination_host)
    flexip_prefix = dstLength + (srcLength << 12) + (dstFormat << 24) + (srcFormat << 26)
    src = []
    for i in range(0, len(srcFlexIP), 8):
        substring = ""
        if i+8 <= len(srcFlexIP):
            substring = srcFlexIP[i:i+8]
        else:
            substring = srcFlexIP[i:]
            for j in range(0, i+8-len(srcFlexIP)):
                substring += '0'
        print("substring", substring)
        try:
            src.append(int(substring, 16))
        except ValueError:
            print(f"Invalid hexadecimal substring: {substring}")
    dst = []
    for i in range(0, len(dstFlexIP), 8):
        substring = ""
        if i+8 <= len(dstFlexIP):
            substring = dstFlexIP[i:i+8]
        else:
            substring = dstFlexIP[i:]
            for j in range(0, i+8-len(dstFlexIP)):
                substring += '0'
        print("substring", substring)
        try:
            dst.append(int(substring, 16))
        except ValueError:
            print(f"Invalid hexadecimal substring: {substring}")
    src += [0] * (12 - len(src))
    dst += [0] * (12 - len(dst))
    print("src:{}, dst:{}, flexip_prefix", src, dst, flexip_prefix)
    pkt = Ether(type=ethertype)
    # pkt = pkt / Raw(load=struct.pack("!LLLLLLLLLLLLLLLLLLLLLLLLL", flexip_prefix, *src[:12], *dst[:12]))
    hex_string = hex(flexip_prefix)[2:10].zfill(8) + srcFlexIP.zfill(96) + dstFlexIP.zfill(96)
    print(hex_string)
    raw_data = bytes.fromhex(hex_string)
    pkt = pkt / Raw(load=raw_data)
    pkt.show2()
    return pkt

def getFileInfo(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()
        if lines:
            last_line = lines[-1].strip()
            line_count = len(lines)
            return last_line.split(), line_count
        else:
            return [], 0

def main():
    # 检查参数数量是否正确
    if len(sys.argv) != 5:
        print('Usage: <modal_type> <frequency> <source_host> <destination_host>')
        exit(1)

    modal_type = sys.argv[1]
    frequency = int(sys.argv[2])
    source_host = int(sys.argv[3][1:])
    destination_host = int(sys.argv[4][1:])

    print("modal_type:%s, frequency:%d, source_host:%s, destination_host:%s" % (modal_type, frequency, source_host, destination_host))

    # 下发流表
    # message = f"{modal_type},{source_host},{destination_host}\n"
    # with open('flows.out', 'a') as file:
    #     file.write(message)
    # time.sleep(0.8)

    # 生成数据包

    if modal_type == "geo":
        pkt = generate_geo_pkt(geo_ethertype, source_host, destination_host)
    elif modal_type == "id":
        pkt = generate_id_pkt(id_ethertype, source_host, destination_host)
    elif modal_type == "mf":
        pkt = generate_mf_pkt(mf_ethertype, source_host, destination_host)
    elif modal_type == "ndn":
        pkt = generate_ndn_pkt(ndn_ethertype, source_host, destination_host)
    elif modal_type == "ip":
        pkt = generate_ip_pkt(ip_ethertype, source_host, destination_host)
    elif modal_type == "flexip":
        pkt = generate_flexip_pkt(flexip_ethertype, source_host, destination_host)
    else:
        print("Invalid modal type")
        exit(1)
    # get the interface
    iface = get_if()
    # print the interface and parameters
    print("sending on interface %s form %s to %s, model : %s " % (iface, source_host, destination_host, modal_type))
        
    # print("消息生产中...")
    # try:
    #   producer.send('multimodel', json.dumps(message).encode('utf-8'))
    #   print(f"Message published to kafka: {message}")
    # except Exception as e:
    #   print(f"Error on publishing message: {e}")
    # producer.flush()
    
    # 发送数据包
    for i in range (1, frequency+1):
        line_before, cnt_before = getFileInfo("/home/onos/Desktop/ngsdn-tutorial/mininet/flows.out")
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.5)
        line_after, cnt_after = getFileInfo("/home/onos/Desktop/ngsdn-tutorial/mininet/flows.out")
        print(line_before, cnt_before, line_after, cnt_after)
        if cnt_after == cnt_before + 1:
            print(line_after[0], line_after[1], line_after[2], modal_type, source_host, destination_host)
            if line_after[0] == modal_type and int(line_after[1]) == source_host and int(line_after[2]) == destination_host:
                print("resend!")
                sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()

