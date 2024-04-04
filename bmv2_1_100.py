# coding=utf-8
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

import sys
sys.path.append('/root/stratum.py')

import subprocess

CPU_PORT = 255

def add_port_to_ovs(veth,switch):
    command = ["ovs-vsctl", "add-port",switch,veth]
    subprocess.check_call(command)

def ovs_service_start():
    try:
        subprocess.check_call(["service", "openvswitch-switch", "start"])
        print("Command executed successfully")
    except subprocess.CalledProcessError as e:
        print("An error occurred while trying to execute the command: {}".format(e))
    except Exception as e:
        print("An unexpected error occurred: {}".format(e))

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
        self.addLink(s1, ovs1)

        for i in range(2, 101):
            switch_name = 's{}'.format(i)
            switch = self.addSwitch(switch_name, cls=StratumBmv2Switch, cpuport=CPU_PORT)
            switch_list.append(switch_name)

        for i in range(1, 50):
            self.addLink(switch_list[i-1], switch_list[2 * i-1])
            self.addLink(switch_list[i-1], switch_list[2 * i])
        self.addLink(switch_list[49], switch_list[99])




        # IPv6 hosts attached to leaf 1
        for i in range(64, 101):
            host = self.addHost('h{}'.format(i),
                                cls=ONOSHost,
                                mac="00:00:00:00:04:{:02x}".format(i & 0xFF),
                                ip="10.1.4.{}".format(i - 64 + 12),
                                identity = 202271720 + i - 64,
                                guid = 1 + i - 64,
                                geoPosLat = -180 + i - 64,
                                geoPosLon = -90 + i - 64,
                                disa = 0,
                                disb = 0,
                                ndn_name = "2022717{}".format(i - 64 + 20),
                                ndn_content = 2048 + i - 64,
                                defautRoute = None, vlan="-1")
            self.addLink(host, switch_list[i - 1])
            
            



switches = {'stratum-bmv2': StratumBmv2Switch}

TOPOS = {'tutorialtopo':TutorialTopo}

topos = {'custom': (lambda: TutorialTopo())}

