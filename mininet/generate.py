import time
import math
import requests
import subprocess
from requests.auth import HTTPBasicAuth

# 监控的文件路径
file_path = '/home/onos/Desktop/ngsdn-tutorial/mininet/flows.out'

vmx = 1
ip = '218.199.84.171'
appId= 'org.stratumproject.basic-tna'

def tail_file(file_object):
    """
    生成器函数，模拟tail -f命令，持续读取文件新追加的内容。
    """
    file_object.seek(0, 2)  # 移动到文件末尾
    while True:
        line = file_object.readline()
        if not line:
            time.sleep(0.5)  # 短暂休眠，避免CPU占用过高
            continue
        yield line

def float_to_custom_bin(number):
    # 确定符号位并取绝对值
    if number < 0:
        sign_bit = '01'
        number = -number
    else:
        sign_bit = '00'

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

def ip_to_hex(ip_address):
    # 将 IP 地址分割为四个部分
    parts = ip_address.split('.')
    # 转换每个部分为十六进制，并格式化为两位数
    hex_parts = [format(int(part), '02X') for part in parts]
    # 将四个十六进制部分合并成一个字符串
    hex_address = ''.join(hex_parts)
    print("ip_to_hex", hex_address)
    return hex_address

def decimal_to_8hex(value):
    hex_number = format(value, 'x').zfill(8)
    return hex_number

def decimal_to_4hex(value):
    hex_number = format(value, 'x').zfill(4)
    return hex_number

def generate_ip_flows(switch, port, src, dst):
    ip_src = f"172.20.{vmx + 1}.{src - 64 + 12}"
    ip_dst = f"172.20.{vmx + 1}.{dst - 64 + 12}"
    return {
        "flows": [
          {
            "priority": 10,
            "timeout": 0,
            "isPermanent": "true",
            "tableId": "1",     # ip的tableId=1
            "deviceId": f"device:domain1:group4:level{math.floor(math.log2(switch))+1}:s{switch+300}",
            "treatment": {
              "instructions": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "subtype": "ACTION",
                  "actionId": "ingress.set_next_v4_hop",
                  "actionParams": {
                    "dst_port": f"{port}"
                  }
                }
              ]
            },
            "clearDeferred": "true",
            "selector": {
              "criteria": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "matches": [
                    {
                      "field": "hdr.ethernet.ether_type",
                      "match": "exact",
                      "value": "0800"
                    },
                    {
                      "field": "hdr.ipv4.srcAddr",
                      "match": "exact",
                      "value": ip_to_hex(ip_src)
                    },
                    {
                      "field": "hdr.ipv4.dstAddr",
                      "match": "exact",
                      "value": ip_to_hex(ip_dst)
                    }
                  ]
                }
              ]
            }
          }
        ]
    }

def generate_mf_flows(switch, port, src, dst):
    mf_src_guid = 1 + vmx * 100 + src - 64
    mf_dst_guid = 1 + vmx * 100 + dst - 64
    return {
        "flows": [
          {
            "priority": 10,
            "timeout": 0,
            "isPermanent": "true",
            "tableId": "2",     # mf的tableId=2
            "deviceId": f"device:domain1:group4:level{math.floor(math.log2(switch))+1}:s{switch+300}",
            "treatment": {
              "instructions": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "subtype": "ACTION",
                  "actionId": "ingress.set_next_mf_hop",
                  "actionParams": {
                    "dst_port": f"{port}"
                  }
                }
              ]
            },
            "clearDeferred": "true",
            "selector": {
              "criteria": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "matches": [
                    {
                      "field": "hdr.ethernet.ether_type",
                      "match": "exact",
                      "value": "27c0"
                    },
                    {
                      "field": "hdr.mf.src_guid",
                      "match": "exact",
                      "value": decimal_to_8hex(mf_src_guid)
                    },
                    {
                      "field": "hdr.mf.dest_guid",
                      "match": "exact",
                      "value": decimal_to_8hex(mf_dst_guid)
                    }
                  ]
                }
              ]
            }
          }
        ]
    }

def generate_geo_flows(switch, port, src, dst):
    geoPosLat = dst - 63
    geoPosLon = float_to_custom_bin(-180 + vmx * 20 + (dst - 64) * 0.4)
    return {
        "flows": [
          {
            "priority": 10,
            "timeout": 0,
            "isPermanent": "true",
            "tableId": "3",     # geo的tableId=3
            "deviceId": f"device:domain1:group4:level{math.floor(math.log2(switch))+1}:s{switch+300}",
            "treatment": {
              "instructions": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "subtype": "ACTION",
                  "actionId": "ingress.geo_ucast_route",
                  "actionParams": {
                    "dst_port": f"{port}"
                  }
                }
              ]
            },
            "clearDeferred": "true",
            "selector": {
              "criteria": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "matches": [
                    {
                      "field": "hdr.ethernet.ether_type",
                      "match": "exact",
                      "value": "8947"
                    },
                    {
                      "field": "hdr.gbc.geoAreaPosLat",
                      "match": "exact",
                      "value": decimal_to_8hex(geoPosLat)
                    },
                    {
                      "field": "hdr.gbc.geoAreaPosLon",
                      "match": "exact",
                      "value": decimal_to_8hex(geoPosLon)
                    },
                    {
                      "field": "hdr.gbc.disa",
                      "match": "exact",
                      "value": "0"
                    },
                    {
                      "field": "hdr.gbc.disb",
                      "match": "exact",
                      "value": "0"
                    }
                  ]
                }
              ]
            }
          }
        ]
    }

def generate_ndn_flows(switch, port, src, dst):
    ndn_src_name = 202271720 + vmx * 100000 + src - 64
    ndn_dst_name = 202271720 + vmx * 100000 + dst - 64
    ndn_content = 2048 + vmx * 100 + src - 64
    return {
        "flows": [
          {
            "priority": 10,
            "timeout": 0,
            "isPermanent": "true",
            "tableId": "4",     # ndn的tableId=4
            "deviceId": f"device:domain1:group4:level{math.floor(math.log2(switch))+1}:s{switch+300}",
            "treatment": {
              "instructions": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "subtype": "ACTION",
                  "actionId": "ingress.set_next_ndn_hop",
                  "actionParams": {
                    "dst_port": f"{port}"
                  }
                }
              ]
            },
            "clearDeferred": "true",
            "selector": {
              "criteria": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "matches": [
                    {
                      "field": "hdr.ethernet.ether_type",
                      "match": "exact",
                      "value": "8624"
                    },
                    {
                      "field": "hdr.ndn.ndn_prefix.code",
                      "match": "exact",
                      "value": "06"
                    },
                    {
                      "field": "hdr.ndn.name_tlv.components[0].value",
                      "match": "exact",
                      "value": decimal_to_8hex(ndn_src_name)
                    },
                    {
                      "field": "hdr.ndn.name_tlv.components[1].value",
                      "match": "exact",
                      "value": decimal_to_8hex(ndn_dst_name)
                    },
                    {
                      "field": "hdr.ndn.content_tlv.value",
                      "match": "exact",
                      "value": decimal_to_4hex(ndn_content)
                    }
                  ]
                }
              ]
            }
          }
        ]
    }

def generate_id_flows(switch, port, src, dst):
    identity_src = 202271720 + vmx * 100000 + src - 64
    identity_dst = 202271720 + vmx * 100000 + dst - 64
    return {
        "flows": [
          {
            "priority": 10,
            "timeout": 0,
            "isPermanent": "true",
            "tableId": "5",     # id的tableId=5
            "deviceId": f"device:domain1:group4:level{math.floor(math.log2(switch))+1}:s{switch+300}",
            "treatment": {
              "instructions": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "subtype": "ACTION",
                  "actionId": "ingress.set_next_id_hop",
                  "actionParams": {
                    "dst_port": f"{port}"
                  }
                }
              ]
            },
            "clearDeferred": "true",
            "selector": {
              "criteria": [
                {
                  "type": "PROTOCOL_INDEPENDENT",
                  "matches": [
                    {
                      "field": "hdr.ethernet.ether_type",
                      "match": "exact",
                      "value": "0812"
                    },
                    {
                      "field": "hdr.id.srcIdentity",
                      "match": "exact",
                      "value": decimal_to_8hex(identity_src)
                    },
                    {
                      "field": "hdr.id.dstIdentity",
                      "match": "exact",
                      "value": decimal_to_8hex(identity_dst)
                    },
                  ]
                }
              ]
            }
          }
        ]
    }

def post_flow(modelType, switch, port, src, dst):
    url = f'http://{ip}:8181/onos/v1/flows?appId={appId}'
    auth = HTTPBasicAuth('onos', 'rocks')
    headers = {'Content-Type': 'application/json'}

    if modelType == 'ip':
        data = generate_ip_flows(switch, port, src, dst)
    elif modelType == 'mf':
        data = generate_mf_flows(switch, port, src, dst)
    elif modelType == 'geo':
        data = generate_geo_flows(switch, port, src, dst)
    elif modelType == 'ndn':
        data = generate_ndn_flows(switch, port, src, dst)
    elif modelType == 'id':
        data = generate_id_flows(switch, port, src, dst)

    # 发送请求
    try:
        print("------------data------------\n", data)
        response = requests.post(url, headers=headers, auth=auth, json=data, proxies={"http": None, "https": None})
        response.raise_for_status()  # 这将在请求返回失败状态码时抛出异常
        print("Success:", response.text)
    except requests.exceptions.RequestException as err:
        # 打印响应
        print("Status Code:", response.status_code)
        print("Response Body:", response.text)
        print("OOps: Something Else", err)
    return 0

def execute_add_flow(line):
    action_array = line.split(',')
    modelType = action_array[0]
    src = int(action_array[1][1:]) # h164
    dst = int(action_array[2][1:]) # h165
    # print(action_array)

    involve_switchs = []
    srcSwitch = src-100 # h164-eth0 <—> s64-eth2
    dstSwitch = dst-100 # h165-eth0 <-> s65-eth2
    srcIdentifier = src-100 # 64
    dstIdentifier = dst-100 # 65

    # 交换机的eth0\eth1\eth2对应转发端口0\1\2
    # src至lca(src,dst)路径中交换机需要下发流表（当前节点向父节点转发）
    # lca(src,dst)至dst路径中交换机需要下发流表（当前节点的父节点向当前节点转发）

    post_flow(modelType, dstSwitch, 2, srcIdentifier, dstIdentifier) # dstSwitch需要向网卡eth2的端口转发
    involve_switchs.append(dstSwitch)

    depth_src = math.floor(math.log2(srcSwitch)) + 1
    depth_dst = math.floor(math.log2(dstSwitch)) + 1

    print(src, dst, srcSwitch, dstSwitch, depth_src, depth_dst, dstIdentifier)

    # srcSwitch深度更大
    if depth_src > depth_dst:
        while depth_src != depth_dst:
            post_flow(modelType, srcSwitch, 1, srcIdentifier, dstIdentifier) # 只能通过eth1向父节点转发
            involve_switchs.append(srcSwitch)
            srcSwitch = math.floor(srcSwitch / 2)
            depth_src = depth_src - 1

    # dstSwitch深度更大
    if depth_src < depth_dst:
        while depth_src != depth_dst:
            father = math.floor(dstSwitch / 2)
            if father*2 == dstSwitch:
                post_flow(modelType, father, 2, srcIdentifier, dstIdentifier) # 通过eth2向左儿子转发
            elif father*2+1 == dstSwitch:
                post_flow(modelType, father, 3, srcIdentifier, dstIdentifier) # 通过eth3向右儿子转发
            involve_switchs.append(father)
            dstSwitch = math.floor(dstSwitch / 2)
            depth_dst = depth_dst - 1

    # srcSwitch和dstSwitch在同一层，srcSwitch向父节点转发，dstSwitch的父节点向dstSwitch转发
    while True:
        post_flow(modelType, srcSwitch, 1, srcIdentifier, dstIdentifier)
        father = math.floor(dstSwitch / 2)
        if father*2 == dstSwitch:
            post_flow(modelType, father, 2, srcIdentifier, dstIdentifier)
        elif father*2+1 == dstSwitch:
            post_flow(modelType, father, 3, srcIdentifier, dstIdentifier)
        involve_switchs.append(srcSwitch)
        involve_switchs.append(father)
        srcSwitch = math.floor(srcSwitch / 2)
        dstSwitch = math.floor(dstSwitch / 2)
        if srcSwitch == dstSwitch:
            break
    print("involve_switchs:", involve_switchs)

def monitor_file(file_path):
    """
    监控文件，如果检测到新行，则输出新行，并执行外部Python脚本。
    """
    with open(file_path, 'r') as file:
        last_line = ""
        print(f"开始监控文件：{file_path}")
        for line in tail_file(file):
            if line != last_line:
                print(line.strip())  # 输出新行内容，使用strip()去除可能的换行符
                last_line = line
                execute_add_flow(line.strip())  # 解析内容，添加流表
                

if __name__ == '__main__':
    monitor_file(file_path)