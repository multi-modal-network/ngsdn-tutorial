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
            default : accept;
        }

    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

    state parse_ndn {
    transition accept;
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition accept;
    }

    state parse_mf {
        pkt.extract(hdr.mf_guid);
        transition accept;
    }

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
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});

        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Switch Ingress MAU
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    // Create direct counters
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) l2_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv4_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv6_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) mf_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) geo_counter;
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


    action ipv4_ucast_route(mac_addr_t srcMac, mac_addr_t dstMac, PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
        hdr.ethernet.dst_addr = dstMac;
        hdr.ethernet.src_addr = srcMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        ipv4_counter.count();
    }
    table ing_ipv4_route {
        key = {
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr : ternary;
        }

        actions = {
            ipv4_ucast_route;
        }

        counters = ipv4_counter;
        size = 1024;
    }



   action ipv6_ucast_route(mac_addr_t srcMac, mac_addr_t dstMac, PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
        hdr.ethernet.dst_addr = dstMac;
        hdr.ethernet.src_addr = srcMac;
        ipv6_counter.count();
    }
    table ing_ipv6_route {
        key = {
            hdr.ipv6.src_addr : ternary;
            hdr.ipv6.dst_addr : ternary;
        }

        actions = {
            ipv6_ucast_route;
        }

        counters = ipv6_counter;
        size = 1024;
    }

   action mf_ucast_route(PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
        mf_counter.count();
    }
    table ing_mf_route {
        key = {
             hdr.mf_guid.dest_guid : exact;
        }

        actions = {
            mf_ucast_route;
        }

        counters = mf_counter;
        size = 1024;
    }



    action geo_ucast_route(PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
        geo_counter.count();
    }
    action geo_mcast_route(MulticastGroupId_t mgid1) {
        ig_tm_md.mcast_grp_a = mgid1;
        geo_counter.count();
    }
    table ing_geo_route {
        key = {
            hdr.gbc.geoAreaPosLat: exact;
            hdr.gbc.geoAreaPosLon: exact;
            hdr.gbc.disa: exact;
            hdr.gbc.disb: exact;
        }

        actions = {
            geo_ucast_route;
            geo_mcast_route;
        }

        counters = geo_counter;
        size = 1024;
    }

   action ndn_ucast_route(PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
        ndn_counter.count();
    }
    table ing_ndn_route {
        key = {
             ig_intr_md.ingress_port: exact;
        }

        actions = {
            ndn_ucast_route;
        }

        counters = ndn_counter;
        size = 1024;
    }

    apply {
            ing_dmac.apply();
            if (ig_md.l3 == 1)
            {
                if(hdr.ethernet.ether_type == ETHERTYPE_IPV4)
                {
                    ing_ipv4_route.apply();
                }
                if(hdr.ethernet.ether_type == ETHERTYPE_IPV6)
                {
                    ing_ipv6_route.apply();
                }
                if (hdr.ethernet.ether_type == ETHERTYPE_GEO)
                {
                    if (hdr.gbc.isValid())         
                        {
                            ing_geo_route.apply();
                        } ;
                }
                if (hdr.ethernet.ether_type == ETHERTYPE_MF)
                    {
                        ing_mf_route.apply();
                    }
                if (hdr.ethernet.ether_type == ETHERTYPE_NDN)
                    {
                        ing_ndn_route.apply();
                    }

            }
            

        // No need for egress processing, skip it and use empty controls for egress.
        ig_tm_md.bypass_egress = 1w1;
    }
}

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
