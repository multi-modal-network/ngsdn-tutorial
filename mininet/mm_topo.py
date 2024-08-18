# coding=utf-8
# Multi-Model topology
"""
Copyright 2019-present Open Networking Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import stratum
from stratum import StratumBmv2Switch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Host
from mininet.topo import Topo
from mininet.node import Controller, RemoteController
from mininet.link import Intf




import subprocess

CPU_PORT = 255
vmx = 1 #0-7代表虚拟机t1-t8
def ovs_service_start():
    try:
        subprocess.check_call(["service", "openvswitch-switch", "start"])
        print("Command executed successfully")
    except subprocess.CalledProcessError as e:
        print("An error occurred while trying to execute the command: {}".format(e))
    except Exception as e:
        print("An unexpected error occurred: {}".format(e))
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

class ONOSHost(Host):
    def __init__(self, name, inNamespace=True, **params):
        Host.__init__(self, name, inNamespace=inNamespace, **params)

    def config(self, identity=None, guid=None, geoPosLat=None, geoPosLon=None, disa=None, disb=None, ndn_name=None, ndn_content=None, **params):
        r = super(Host, self).config(**params)
        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload %s %s off" \
                  % (self.defaultIntf(), off)
            self.cmd(cmd)
        self.identity = identity
        self.guid = guid
        self.geoPosLat = geoPosLat
        self.geoPosLon = geoPosLon
        self.disa = disa
        self.disb = disb
        self.ndn_name = ndn_name
        self.ndn_content = ndn_content
        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        # 设置默认路由
        self.cmd("ip route add default via 218.199.84.161")
        return r


class TutorialTopo(Topo):
    """2x2 fabric topology with IPv6 hosts"""

    def __init__(self):
        Topo.__init__(self)
        ovs_service_start()
        switch_list = []
        s1 = self.addSwitch('s1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        switch_list.append('s1')
        ovs1 = self.addSwitch('ovs1')
        self.addLink(ovs1, s1)
        for i in range(2, 101):
            switch_name = 's{}'.format(i)
            switch = self.addSwitch(switch_name, cls=StratumBmv2Switch, cpuport=CPU_PORT)
            switch_list.append(switch_name)

        for i in range(1, 50):
            self.addLink(switch_list[i-1], switch_list[2 * i-1])
            self.addLink(switch_list[i-1], switch_list[2 * i])
        self.addLink(switch_list[49], switch_list[99])



        #domain1_group1_ovs1 = self.addSwitch('domain1_group1_ovs1')
        # IPv6 hosts attached to leaf 1
        for i in range(64, 101):
            host = self.addHost('h{}'.format(vmx*100+i),
                                cls=ONOSHost,
                                mac="00:00:00:00:{:02x}:{:02x}".format((vmx + 1) & 0xFF, i & 0xFF),
                                ip="172.20.{}.{}/16".format(vmx + 1, i - 64 + 12),
                                identity=202271720 + vmx * 100000 + i - 64,
                                mf_guid=1 + vmx * 100 + i - 64,
                                geoPosLat=i - 63,
                                geoPosLon=float_to_custom_bin(-180 + vmx * 20 + (i - 64) * 0.4),
                                disa=0,
                                disb=0,
                                ndn_name=202271720 + vmx * 100000 + i - 64,
                                ndn_content=2048 + vmx * 100 + i - 64,
                                defautRoute =None, vlan="-1")
            self.addLink(host, switch_list[i - 1])
            # host.cmd('dhclient '+host.defaultIntf().name)



switches = {'stratum-bmv2': StratumBmv2Switch}

TOPOS = {'tutorialtopo':TutorialTopo}

topos = {'custom': (lambda: TutorialTopo())}


def main():
    #modify_port('/home/eis/P4/onos/tools/dev/mininet/stratum.py', 'nextGrpcPort', 60000)
    #reload(stratum)
    ovs_service_start()
    net = Mininet(topo=TutorialTopo(), controller=None)
    #c0 = net.addController(name='c0', controller=RemoteController, ip='192.168.2.139', port=6653)
    net.start()

    #add_port_to_ovs('domain1_group1_veth1', 'domain1_group1_ovs1')

    CLI(net)
    net.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Mininet topology script for 2x2 fabric with stratum_bmv2 and IPv6 hosts')
    args = parser.parse_args()
    setLogLevel('info')

    main()


