/*
 * Copyright 2019-present Open Networking Foundation
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

// Any P4 program usually starts by including the P4 core library and the
// architecture definition, v1model in this case.
// https://github.com/p4lang/p4c/blob/master/p4include/core.p4
// https://github.com/p4lang/p4c/blob/master/p4include/v1model.p4
#include <core.p4>
#include <v1model.p4>

// *** V1MODEL
//
// V1Model is a P4_16 architecture that defines 7 processing blocks.
//
//   +------+  +------+  +-------+  +-------+  +------+  +------+  +--------+
// ->|PARSER|->|VERIFY|->|INGRESS|->|TRAFFIC|->|EGRESS|->|UPDATE|->+DEPARSER|->
//   |      |  |CKSUM |  |PIPE   |  |MANAGER|  |PIPE  |  |CKSUM |  |        |
//   +------+  +------+  +-------+  +--------  +------+  +------+  +--------+
//

//------------------------------------------------------------------------------
// PRE-PROCESSOR constants
// Can be defined at compile time.
//------------------------------------------------------------------------------

// CPU_PORT specifies the P4 port number associated to packet-in and packet-out.
// All packets forwarded via this port will be delivered to the controller as
// PacketIn messages. Similarly, PacketOut messages from the controller will be
// seen by the P4 pipeline as coming from the CPU_PORT.
#define CPU_PORT 255

// CPU_CLONE_SESSION_ID specifies the mirroring session for packets to be cloned
// to the CPU port. Packets associated with this session ID will be cloned to
// the CPU_PORT as well as being transmitted via their egress port as set by the
// bridging/routing/acl table. For cloning to work, the P4Runtime controller
// needs first to insert a CloneSessionEntry that maps this session ID to the
// CPU_PORT.
#define CPU_CLONE_SESSION_ID 99

#define MAX_COMPONENTS 8


//------------------------------------------------------------------------------
// TYPEDEF DECLARATIONS
// To favor readability.
//------------------------------------------------------------------------------
typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;
typedef bit<16>  mcast_group_id_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16>  l4_port_t;


//------------------------------------------------------------------------------
// CONSTANT VALUES
//------------------------------------------------------------------------------
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ID = 0x0812;
const bit<16> ETHERTYPE_GEO = 0x8947;
const bit<16> ETHERTYPE_MF = 0x27c0;
const bit<16> ETHERTYPE_NDN = 0x8624;

const bit<4> TYPE_geo_beacon = 1;
const bit<4> TYPE_geo_gbc = 4;

const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;
const bit<8> IP_PROTO_ICMPV6 = 58;

const mac_addr_t IPV6_MCAST_01 = 0x33_33_00_00_00_01;

const bit<8> ICMP6_TYPE_NS = 135;
const bit<8> ICMP6_TYPE_NA = 136;
const bit<8> NDP_OPT_TARGET_LL_ADDR = 2;
const bit<32> NDP_FLAG_ROUTER = 0x80000000;
const bit<32> NDP_FLAG_SOLICITED = 0x40000000;
const bit<32> NDP_FLAG_OVERRIDE = 0x20000000;


//------------------------------------------------------------------------------
// HEADER DEFINITIONS
//------------------------------------------------------------------------------
header ethernet_t {
    mac_addr_t  dst_addr;
    mac_addr_t  src_addr;
    bit<16>     ether_type;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_len;
    bit<8>   next_hdr;
    bit<8>   hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header tcp_t {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<3>   res;
    bit<3>   ecn;
    bit<6>   ctrl;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8>   type;
    bit<8>   icmp_code;
    bit<16>  checksum;
    bit<16>  identifier;
    bit<16>  sequence_number;
    bit<64>  timestamp;
}

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
}

header ndp_t {
    bit<32>      flags;
    ipv6_addr_t  target_ipv6_addr;
    // NDP option.
    bit<8>       type;
    bit<8>       length;
    bit<48>      target_mac_addr;
}

// 地理模态报文首部
header geo_t{
    bit<4> version;
    bit<4> nh_basic;
    bit<8> reserved_basic;
    bit<8> lt;
    bit<8> rhl;
    bit<4> nh_common;
    bit<4> reserved_common_a;
    bit<4> ht;  // 决定后续包型
    bit<4> hst;
    bit<8> tc;
    bit<8> flag;
    bit<16> pl;
    bit<8> mhl;
    bit<8> reserved_common_b;
}

header gbc_t{
    bit<16> sn;
    bit<16> reserved_gbc_a;
    bit<64> gnaddr;
    bit<32> tst;
    bit<32> lat;
    bit<32> longg;
    bit<1> pai;
    bit<15> s;
    bit<16> h;
    bit<32> geoAreaPosLat; //lat 请求区域中心点的纬度
    bit<32> geoAreaPosLon; //log 请求区域中心点的经度
    bit<16> disa;
    bit<16> disb;
    bit<16> angle;
    bit<16> reserved_gbc_b;
}


header beacon_t{
    bit<64> gnaddr;
    bit<32> tst;
    bit<32> lat;
    bit<32> longg;
    bit<1> pai;
    bit<15> s;
    bit<16> h;

}

// mf模态报文首部
header mf_t{
    bit<32> mf_type;
    bit<32> src_guid;
    bit<32> dest_guid;
}

// 身份模态报文首部
header id_t {
    bit<32> srcIdentity;
    bit<32> dstIdentity;
}

// Packet-in header. Prepended to packets sent to the CPU_PORT and used by the
// P4Runtime server (Stratum) to populate the PacketIn message metadata fields.
// Here we use it to carry the original ingress port where the packet was
// received.
@controller_header("packet_in")
header packet_in_t {
    port_num_t  ingress_port;
    bit<7>      _pad;
}

// Packet-out header. Prepended to packets received from the CPU_PORT. Fields of
// this header are populated by the P4Runtime server based on the P4Runtime
// PacketOut metadata fields. Here we use it to inform the P4 pipeline on which
// port this packet-out should be transmitted.
@controller_header("packet_out")
header packet_out_t {
    port_num_t  egress_port;
    bit<7>      _pad;
}

// We collect all headers under the same data structure, associated with each
// packet. The goal of the parser is to populate the fields of this struct.
struct parsed_headers_t {
    packet_out_t  packet_out;
    packet_in_t   packet_in;
    ethernet_t    ethernet;
    ipv6_t        ipv6;
    ipv4_t        ipv4;
    id_t          id;
    mf_t          mf;
    geo_t         geo;
    gbc_t         gbc;
    beacon_t      beacon;
    ndn_t         ndn;
    tcp_t         tcp;
    udp_t         udp;
    icmpv6_t      icmpv6;
    ndp_t         ndp;
}


//------------------------------------------------------------------------------
// USER-DEFINED METADATA
// User-defined data structures associated with each packet.
//------------------------------------------------------------------------------
struct local_metadata_t {
    l4_port_t  l4_src_port;
    l4_port_t  l4_dst_port;
    bit<8>     name_tlv_length;
    bool       is_multicast;
}

// *** INTRINSIC METADATA
//
// The v1model architecture also defines an intrinsic metadata structure, which
// fields are automatically populated by the target before feeding the
// packet to the parser. For convenience, we provide here its definition:
/*
struct standard_metadata_t {
    bit<9>  ingress_port;
    bit<9>  egress_spec; // Set by the ingress pipeline
    bit<9>  egress_port; // Read-only, available in the egress pipeline
    bit<32> instance_type;
    bit<32> packet_length;
    bit<48> ingress_global_timestamp;
    bit<48> egress_global_timestamp;
    bit<16> mcast_grp; // ID for the mcast replication table
    bit<1>  checksum_error; // 1 indicates that verify_checksum() method failed

    // Etc... See v1model.p4 for the complete definition.
}
*/


//------------------------------------------------------------------------------
// 1. PARSER IMPLEMENTATION
//
// Described as a state machine with one "start" state and two final states,
// "accept" (indicating successful parsing) and "reject" (indicating a parsing
// failure, not used here). Each intermediate state can specify the next state
// by using a select statement over the header fields extracted, or other
// values.
//------------------------------------------------------------------------------
parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    // We assume the first header will always be the Ethernet one, unless the
    // the packet is a packet-out coming from the CPU_PORT.
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ID: parse_id;
            ETHERTYPE_GEO: parse_geo;
            ETHERTYPE_MF: parse_mf;
            ETHERTYPE_NDN: parse_ndn;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROTO_TCP:   parse_tcp;
            IP_PROTO_UDP:   parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP:    parse_tcp;
            IP_PROTO_UDP:    parse_udp;
            default: accept;
        }
    }

    // 身份
    state parse_id {
        packet.extract(hdr.id);
        transition accept;
    }

    // NDN
    state parse_ndn {
        transition accept;
    }

    state parse_mf {
        packet.extract(hdr.mf);
        transition accept;
    }

    // 地理
    state parse_geo {
        packet.extract(hdr.geo);
        transition select(hdr.geo.ht) { //
            TYPE_geo_beacon: parse_beacon; //0x01
            TYPE_geo_gbc: parse_gbc; //0x04
            default: accept;
        }
    }


    state parse_beacon{
        packet.extract(hdr.beacon);
        transition accept;
    }

    state parse_gbc{
        packet.extract(hdr.gbc);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        // For convenience, we copy the port numbers on generic metadata fields
        // that are independent of the protocol type (TCP or UDP). This makes it
        // easier to specify the ECMP hash inputs, or when defining match fields
        // for the ACL table.
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        // Same here...
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }
}

//------------------------------------------------------------------------------
// 2. CHECKSUM VERIFICATION
//
// Used to verify the checksum of incoming packets.
//------------------------------------------------------------------------------
control VerifyChecksumImpl(inout parsed_headers_t hdr,
                           inout local_metadata_t meta)
{
    // Not used here. We assume all packets have valid checksum, if not, we let
    // the end hosts detect errors.
    apply { /* EMPTY */ }
}


//------------------------------------------------------------------------------
// 3. INGRESS PIPELINE IMPLEMENTATION
//
// All packets will be processed by this pipeline right after the parser block.
// It provides the logic for forwarding behaviors such as:
// - L2 bridging
// - L3 routing
// - ACL
// - NDP handling
//
// The first part of the block defines the match-action tables needed for the
// different behaviors, while the implementation is concluded with the *apply*
// statement, where we specify the order of tables in the pipeline.
//
// This block operates on the parsed headers (hdr), the user-defined metadata
// (local_metadata), and the architecture-specific instrinsic metadata
// (standard_metadata).
//------------------------------------------------------------------------------
control IngressPipeImpl (inout parsed_headers_t    hdr,
                         inout local_metadata_t    local_metadata,
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

    // --- routing_id_table ----------------------------------------------------
    //  身份模态
    action set_next_id_hop(port_num_t dst_port){
        standard_metadata.egress_spec = dst_port;
    }


    action to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
        hdr.packet_in.setValid();
    }

    table routing_id_table {
        key = {
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

    // --- routing_ndn_table ------------------------------------------------------
    // ndn模态
    action set_next_ndn_hop(port_num_t dst_port) {
        standard_metadata.egress_spec = dst_port;
    }
    table routing_ndn_table {
        key = {
            hdr.ndn.ndn_prefix.code: exact;
            hdr.ndn.name_tlv.components[0].value: exact;
            hdr.ndn.content_tlv.value: exact;
        }

        actions = {
            set_next_ndn_hop;
            to_cpu;
        }
        default_action = to_cpu;
        @name("routing_ndn_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- my_station_table ----------------------------------------------------

    // Matches on all possible my_station MAC addresses associated with this
    // switch. This table defines only one action that does nothing to the
    // packet. Later in the apply block, we define logic such that packets are
    // routed if and only if this table is "hit", i.e. a matching entry is found
    // for the given packet.

    table my_station_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = { NoAction; }
        @name("my_station_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- routing_v6_table ----------------------------------------------------

    // To implement ECMP, we use Action Selectors, a v1model-specific construct.
    // A P4Runtime controller, can use action selectors to associate a group of
    // actions to one table entry. The speficic action in the group will be
    // selected by perfoming a hash function over a pre-determined set of header
    // fields. Here we instantiate an action selector named "ecmp_selector" that
    // uses crc16 as the hash function, can hold up to 1024 entries (distinct
    // action specifications), and produces a selector key of size 16 bits.

    action_selector(HashAlgorithm.crc16, 32w1024, 32w16) ecmp_selector;

    action set_next_v6_hop(mac_addr_t dmac) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dmac;
        // Decrement TTL
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    // Look for the "implementation" property in the table definition.
    table routing_v6_table {
      key = {
          hdr.ipv6.dst_addr:          lpm;
          // The following fields are not used for matching, but as input to the
          // ecmp_selector hash function.
          hdr.ipv6.dst_addr:          selector;
          hdr.ipv6.src_addr:          selector;
          hdr.ipv6.flow_label:        selector;
          hdr.ipv6.next_hdr:          selector;
          local_metadata.l4_src_port: selector;
          local_metadata.l4_dst_port: selector;
      }
      actions = {
          set_next_v6_hop;
      }
      implementation = ecmp_selector;
      @name("routing_v6_table_counter")
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

    // *** TODO EXERCISE 4
    // Create a table to handle NDP NS packets for the switch IPv6 interface
    // addresses. This table should:
    //   * match on hdr.ndp.target_ipv6_addr (exact match)
    //   * provide action "ndp_ns_to_na" defined before
    //   * default_action should be "NoAction"
    //
    // You can name your table whatever you like, and you will need to fill
    // the name in elsewhere in this exercise.
    //
    // This table should have structure similar to l2_exact_table defined
    // before. Feel free to copy paste that table definition here as a starter.
    // ---- START SOLUTION ----

    /* Provide your table implementation here */

    // ---- END SOLUTION ----


    // *** APPLY BLOCK STATEMENT
    //
    // The apply { ... } block defines the main function applied to every packet
    // that goes though a given "control", the ingress pipeline in this case.
    //
    // This is where we define which tables a packets should traverse and in
    // which order. It contains a sequence of statements and declarations, which
    // are executed sequentially.

    apply {
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
        } else if (hdr.ethernet.ether_type == ETHERTYPE_NDN) {
            routing_ndn_table.apply();
        }  else if (hdr.ipv6.isValid() && my_station_table.apply().hit) {
            // Apply the L3 routing table to IPv6 packets, only if the
        // destination MAC is found in the my_station_table.
            routing_v6_table.apply();
            // Checl TTL, drop packet if necessary to avoid loops.
            if(hdr.ipv6.hop_limit == 0) { drop(); }
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
// 4. EGRESS PIPELINE
//
// In the v1model architecture, after the ingress pipeline, packets are
// processed by the Traffic Manager, which provides capabilities such as
// replication (for multicast or clone sessions), queuing, and scheduling.
//
// After the Traffic Manager, packets are processed by a so-called egress
// pipeline. Differently from the ingress one, egress tables can match on the
// egress_port intrinsic metadata as set by the Traffic Manager. If the Traffic
// Manager is configured to replicate the packet to multiple ports, the egress
// pipeline will see all replicas, each one with its own egress_port value.
//
// +---------------------+     +-------------+        +----------------------+
// | INGRESS PIPE        |     | TM          |        | EGRESS PIPE          |
// | ------------------- | pkt | ----------- | pkt(s) | -------------------- |
// | Set egress_spec,    |---->| Replication |------->| Match on egress port |
// | mcast_grp, or clone |     | Queues      |        |                      |
// | sess                |     | Scheduler   |        |                      |
// +---------------------+     +-------------+        +----------------------+
//
// Similarly to the ingress pipeline, the egress one operates on the parsed
// headers (hdr), the user-defined metadata (local_metadata), and the
// architecture-specific instrinsic one (standard_metadata) which now
// defines a read-only "egress_port" field.
//------------------------------------------------------------------------------
control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {
        
    }
}

//------------------------------------------------------------------------------
// 5. CHECKSUM UPDATE
//
// Provide logic to update the checksum of outgoing packets.
//------------------------------------------------------------------------------
control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t local_metadata)
{
    apply {
        // The following function is used to update the ICMPv6 checksum of NDP
        // NA packets generated by the ndp_reply_table in the ingress pipeline.
        // This function is executed only if the NDP header is present.
        update_checksum(hdr.ndp.isValid(),
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_ipv6_addr,
                hdr.ndp.type,
                hdr.ndp.length,
                hdr.ndp.target_mac_addr
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
    }
}


//------------------------------------------------------------------------------
// 6. DEPARSER
//
// This is the last block of the V1Model architecture. The deparser specifies in
// which order headers should be serialized on the wire. When calling the emit
// primitive, only headers that are marked as "valid" are serialized, otherwise,
// they are ignored.
//------------------------------------------------------------------------------
control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.id);
        packet.emit(hdr.geo);
	    packet.emit(hdr.gbc);
	    packet.emit(hdr.beacon);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
    }
}

//------------------------------------------------------------------------------
// V1MODEL SWITCH INSTANTIATION
//
// Finally, we instantiate a v1model switch with all the control block
// instances defined so far.
//------------------------------------------------------------------------------
V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;
