/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/util.p4"


struct metadata_t {
    bit<1>   l3;    // Set if routed
    bit<1>   ndn;    // Set if routed
    bit<8>   name_tlv_length;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_GEO  : parse_geo;
            ETHERTYPE_MF   : parse_mf;
            ETHERTYPE_NDN  : parse_ndn;
            ETHERTYPE_ID   : parse_id;
            default : accept;
        }

    }

    // IPv4
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

    // NDN
    state parse_ndn {
        pkt.extract(hdr.ndn.ndn_prefix);
        transition parse_ndn_name;
    }

    state parse_ndn_name {
        pkt.extract(hdr.ndn.name_tlv.ndn_tlv_prefix);
        ig_md.name_tlv_length = hdr.ndn.name_tlv.ndn_tlv_prefix.length;
        transition parse_ndn_name_components;
    }

    // state parse_ndn_name_components {
    //     pkt.extract(hdr.ndn.name_tlv.components.next);
    //     //ig_md.name_tlv_length = ig_md.name_tlv_length - 2 - hdr.ndn.name_tlv.components.last.length;
    //     transition select(ig_md.name_tlv_length) {
    //         0: parse_ndn_metainfo;
    //         default: parse_ndn_name_components;
    //     }
    // }

    state parse_ndn_name_components {
        pkt.extract(hdr.ndn.name_tlv.components.next);
        transition select(hdr.ndn.name_tlv.components.last.end) {
            0: parse_ndn_name_components;
            1: parse_ndn_metainfo;
        }
    }

    state parse_ndn_metainfo {
        pkt.extract(hdr.ndn.metaInfo_tlv.ndn_tlv_prefix);
        pkt.extract(hdr.ndn.metaInfo_tlv.content_type_tlv);
        pkt.extract(hdr.ndn.metaInfo_tlv.freshness_period_tlv);
        pkt.extract(hdr.ndn.metaInfo_tlv.final_block_id_tlv);
        transition parse_ndn_content;
    }

    state parse_ndn_content {
        pkt.extract(hdr.ndn.content_tlv);
        transition accept;
    }

    // ID
    state parse_id {
        pkt.extract(hdr.id);
        transition accept;
    }

    // IPv6
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition accept;
    }

    // MF
    state parse_mf {
        pkt.extract(hdr.mf_guid);
        transition accept;
    }

    // GEO
    state parse_geo {
        pkt.extract(hdr.geo);
        transition select(hdr.geo.ht) { //
            TYPE_geo_beacon: parse_beacon; //0x01
            TYPE_geo_gbc: parse_gbc;       //0x04
            default: accept;
        }
    }

    
    state parse_beacon{
        pkt.extract(hdr.beacon);
        transition accept;
    }

    state parse_gbc{
        pkt.extract(hdr.gbc);
        transition accept;
    }
    
 

}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr});

        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Switch Ingress MAU
// ---------------------------------------------------------------------------
control ingress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // Create direct counters
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) l2_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) id_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ndn_counter;
    // Create indirect counter
    // Counter<bit<32>, ether_type_t>(
    //     8, CounterType_t.PACKETS_AND_BYTES) indirect_counter;

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }



    action icmp_switch(PortId_t port) {
        l2_counter.count();
        ig_tm_md.ucast_egress_port = port;
    }

    action icmp6_switch(PortId_t port) {
        l2_counter.count();
        ig_tm_md.ucast_egress_port = port;
    }


    action route_l3() {
        l2_counter.count();
        ig_md.l3 = 1;
    }



    table ing_dmac {
        key = {
            hdr.ethernet.src_addr : ternary;
            hdr.ethernet.dst_addr : ternary;
            hdr.ethernet.ether_type : exact;
        }

        actions = {
            icmp_switch;
            icmp6_switch;
            route_l3;
        }
        size = 24;
        const default_action = route_l3;
        // Associate this table with a direct counter
        counters = l2_counter;
    }

    action set_next_id_hop(PortId_t dst_port){
        ig_tm_md.ucast_egress_port = dst_port;
        id_counter.count();
    }
    table routing_id_table {
        key = {
            hdr.id.dstIdentity : exact;
        }
        actions = {
            set_next_id_hop;
        }
        counters = id_counter;
        size = 1024;
    }

    // NDN
    action set_next_ndn_hop(PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
        ndn_counter.count();
    }
    table routing_ndn_table {
        key = {
            hdr.ndn.ndn_prefix.code: exact;
            hdr.ndn.name_tlv.components[0].value: exact;
            hdr.ndn.content_tlv.value: exact;
        }

        actions = {
            set_next_ndn_hop;
        }

        counters = ndn_counter;
        size = 1024;
    }

    apply {
            ing_dmac.apply();
            if (ig_md.l3 == 1)
            {
                if(hdr.ethernet.ether_type == ETHERTYPE_ID) {
                    routing_id_table.apply();
                }
                if(hdr.ethernet.ether_type == ETHERTYPE_NDN) {
                    routing_ndn_table.apply();
                }
            }
            

        // No need for egress processing, skip it and use empty controls for egress.
        ig_tm_md.bypass_egress = 1w1;
    }
}

Pipeline(SwitchIngressParser(),
         ingress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
