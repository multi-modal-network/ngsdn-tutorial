/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <core.p4>
#include <v1model.p4>

#include "./include/headers.p4"
#include "./include/defines.p4"
#include "./include/parsers.p4"
#include "./include/control/actions.p4"
#include "./include/control/port_counters.p4"
#include "./include/control/port_meters.p4"
#include "./include/control/checksums.p4"
#include "./include/control/packet_io.p4"
#include "./include/control/table0.p4"
#include "./include/control/host_meter_table.p4"

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control ingress(inout headers_t hdr,
                inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {
    
    // Drop action definition, shared by many tables. Hence we define it on top.
    action drop() {
        // Sets an architecture-specific metadata field to signal that the
        // packet should be dropped at the end of this pipeline.
        mark_to_drop(standard_metadata);
    }

    // *** L2 BRIDGING
    //
    // Here we define tables to forward packets based on their Ethernet
    // destination address. There are two types of L2 entries that we
    // need to support:
    //
    // 1. Unicast entries: which will be filled in by the control plane when the
    //    location (port) of new hosts is learned.
    // 2. Broadcast/multicast entries: used replicate NDP Neighbor Solicitation
    //    (NS) messages to all host-facing ports;
    //
    // For (2), unlike ARP messages in IPv4 which are broadcasted to Ethernet
    // destination address FF:FF:FF:FF:FF:FF, NDP messages are sent to special
    // Ethernet addresses specified by RFC2464. These addresses are prefixed
    // with 33:33 and the last four octets are the last four octets of the IPv6
    // destination multicast address. The most straightforward way of matching
    // on such IPv6 broadcast/multicast packets, without digging in the details
    // of RFC2464, is to use a ternary match on 33:33:**:**:**:**, where * means
    // "don't care".
    //
    // For this reason, we define two tables. One that matches in an exact
    // fashion (easier to scale on switch ASIC memory) and one that uses ternary
    // matching (which requires more expensive TCAM memories, usually much
    // smaller).

    // --- l2_exact_table (for unicast entries) --------------------------------

    action set_egress_port(port_num_t dst_port) {
        standard_metadata.egress_spec = dst_port;
    }

    table l2_exact_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            set_egress_port;
            @defaultonly drop;
        }
        const default_action = drop;
        // The @name annotation is used here to provide a name to this table
        // counter, as it will be needed by the compiler to generate the
        // corresponding P4Info entity.
        @name("l2_exact_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- l2_ternary_table (for broadcast/multicast entries) ------------------

    action set_multicast_group(mcast_group_id_t gid) {
        // gid will be used by the Packet Replication Engine (PRE) in the
        // Traffic Manager--located right after the ingress pipeline, to
        // replicate a packet to multiple egress ports, specified by the control
        // plane by means of P4Runtime MulticastGroupEntry messages.
        standard_metadata.mcast_grp = gid;
        local_metadata.is_multicast = true;
    }

    table l2_ternary_table {
        key = {
            hdr.ethernet.dst_addr: ternary;
        }
        actions = {
            set_multicast_group;
            @defaultonly drop;
        }
        const default_action = drop;
        @name("l2_ternary_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // *** L3 ROUTING
    //
    // Here we define tables to route packets based on their IPv6 destination
    // address. We assume the following:
    //
    // * Not all packets need to be routed, but only those that have destination
    //   MAC address the "router MAC" addres, which we call "my_station" MAC.
    //   Such address is defined at runtime by the control plane.
    // * If a packet matches a routing entry, it should be forwarded to a
    //   given next hop and the packet's Ethernet addresses should be modified
    //   accordingly (source set to my_station MAC and destination to the next
    //   hop one);
    // * When routing packets to a different leaf across the spines, leaf
    //   switches should be able to use ECMP to distribute traffic via multiple
    //   links.

    action to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        hdr.packet_in.setValid();
    }

    // --- routing_id_table ----------------------------------------------------
    //  身份模态
    action set_next_id_hop(port_num_t dst_port){
        standard_metadata.egress_spec = dst_port;
    }

    table routing_id_table {
        key = {
            hdr.ethernet.ether_type: exact;
            hdr.id.srcIdentity: exact;
            hdr.id.dstIdentity: exact;
        }
        actions = {
            set_next_id_hop;
            to_cpu;
        }
        default_action = to_cpu;
        @name("routing_id_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- routing_mf_table -----------------------------------------------------
    // mf模态
    action set_next_mf_hop(port_num_t dst_port) {
        standard_metadata.egress_spec = dst_port;
    }
    table routing_mf_table {
        key = {
            hdr.ethernet.ether_type: exact;
            hdr.mf.src_guid: exact;
            hdr.mf.dest_guid : exact;
        }

        actions = {
            set_next_mf_hop;
            to_cpu;
        }
        default_action = to_cpu;
        @name("routing_mf_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- routing_geo_table -----------------------------------------------------
    // 地理模态
    action geo_ucast_route(port_num_t dst_port) {
        standard_metadata.egress_spec = dst_port;
    }
    action geo_mcast_route(mcast_group_id_t mgid1) {
        standard_metadata.mcast_grp = mgid1;
    }
    table routing_geo_table {
        key = {
            hdr.ethernet.ether_type: exact;
            hdr.gbc.geoAreaPosLat: exact;
            hdr.gbc.geoAreaPosLon: exact;
            hdr.gbc.disa: exact;
            hdr.gbc.disb: exact;
        }

        actions = {
            geo_ucast_route;
            geo_mcast_route;
            to_cpu;
        }
        default_action = to_cpu;
        @name("routing_geo_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }


    // IP模态
    // --- routing_v6_table ----------------------------------------------------

    // To implement ECMP, we use Action Selectors, a v1model-specific construct.
    // A P4Runtime controller, can use action selectors to associate a group of
    // actions to one table entry. The speficic action in the group will be
    // selected by perfoming a hash function over a pre-determined set of header
    // fields. Here we instantiate an action selector named "ecmp_selector" that
    // uses crc16 as the hash function, can hold up to 1024 entries (distinct
    // action specifications), and produces a selector key of size 16 bits.

    action_selector(HashAlgorithm.crc16, 32w1024, 32w16) ecmp_selector;

    action set_next_v6_hop(port_num_t dst_port) {
        standard_metadata.egress_spec = dst_port;
    }

    // Look for the "implementation" property in the table definition.
    table routing_v6_table {
      key = {
          hdr.ethernet.ether_type: exact;
          hdr.ipv6.src_addr: exact;
          hdr.ipv6.dst_addr: exact;
      }
      actions = {
          set_next_v6_hop;
          to_cpu;
      }
      default_action = to_cpu;
      implementation = ecmp_selector;
      @name("routing_v6_table_counter")
      counters = direct_counter(CounterType.packets_and_bytes);
    }

    action set_next_v4_hop(port_num_t dst_port) {
        standard_metadata.egress_spec = dst_port;
    }
    
    table routing_v4_table {
        key = {
            hdr.ethernet.ether_type: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            set_next_v4_hop;
            to_cpu;
        }
        default_action = to_cpu;
        @name("routing_v4_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // *** ACL
    //
    // Provides ways to override a previous forwarding decision, for example
    // requiring that a packet is cloned/sent to the CPU, or dropped.
    //
    // We use this table to clone all NDP packets to the control plane, so to
    // enable host discovery. When the location of a new host is discovered, the
    // controller is expected to update the L2 and L3 tables with the
    // correspionding brinding and routing entries.

    // --- acl_table -----------------------------------------------------------

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    action clone_to_cpu() {
        // Cloning is achieved by using a v1model-specific primitive. Here we
        // set the type of clone operation (ingress-to-egress pipeline), the
        // clone session ID (the CPU one), and the metadata fields we want to
        // preserve for the cloned packet replica.
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, { standard_metadata.ingress_port });
    }

    table acl_table {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dst_addr:          ternary;
            hdr.ethernet.src_addr:          ternary;
            hdr.ethernet.ether_type:        ternary;
            hdr.ipv6.next_hdr:              ternary;
            hdr.icmpv6.type:                ternary;
            local_metadata.l4_src_port:     ternary;
            local_metadata.l4_dst_port:     ternary;
        }
        actions = {
            send_to_cpu;
            clone_to_cpu;
            drop;
        }
        @name("acl_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // *** NDP HANDLING
    //
    // NDP Handling will be the focus of exercise 4. If you are still working on
    // a previous exercise, it's OK if you ignore this part for now.

    // Action that transforms an NDP NS packet into an NDP NA one for the given
    // target MAC address. The action also sets the egress port to the ingress
    // one where the NDP NS packet was received.

    action ndp_ns_to_na(mac_addr_t target_mac) {
        hdr.ethernet.src_addr = target_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp.length = 1;
        hdr.ndp.target_mac_addr = target_mac;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    apply {
        port_counters_ingress.apply(hdr, standard_metadata);
        port_meters_ingress.apply(hdr, standard_metadata);
        packetio_ingress.apply(hdr, standard_metadata);
        table0_control.apply(hdr, local_metadata, standard_metadata);
        host_meter_control.apply(hdr, local_metadata, standard_metadata);
        
        if (hdr.packet_out.isValid()) {
            // Set the egress port to that found in the packet-out metadata...
            standard_metadata.egress_spec = hdr.packet_out.egress_port;
            // Remove the packet-out header...
            hdr.packet_out.setInvalid();
            // Exit the pipeline here, no need to go through other tables.
            exit;
        }
        if (hdr.ethernet.ether_type == ETHERTYPE_ID && hdr.id.isValid()) {
            routing_id_table.apply();
        } else if (hdr.ethernet.ether_type == ETHERTYPE_GEO && hdr.geo.isValid()) {
            routing_geo_table.apply();
        } else if (hdr.ethernet.ether_type == ETHERTYPE_MF && hdr.mf.isValid()) {
            routing_mf_table.apply();
        } else if (hdr.ipv6.isValid()) {
            // Apply the L3 routing table to IPv6 packets, only if the
        // destination MAC is found in the my_station_table.
            routing_v6_table.apply();
        } else if (hdr.ipv4.isValid()) {
            routing_v4_table.apply();
        } else if (!l2_exact_table.apply().hit) {
        // L2 bridging. Apply the exact table first (for unicast entries)..
            // If an entry is NOT found, apply the ternary one in case this
            // is a multicast/broadcast NDP NS packet for another host
            // attached to this switch.
            l2_ternary_table.apply();
        }
        acl_table.apply();
    }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control egress(inout headers_t hdr,
               inout local_metadata_t local_metadata,
               inout standard_metadata_t standard_metadata) {

    apply {
        port_counters_egress.apply(hdr, standard_metadata);
        port_meters_egress.apply(hdr, standard_metadata);
        packetio_egress.apply(hdr, standard_metadata);
    }
}

//------------------------------------------------------------------------------
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

V1Switch(parser_impl(),
         verify_checksum_control(),
         ingress(),
         egress(),
         compute_checksum_control(),
         deparser()) main;
