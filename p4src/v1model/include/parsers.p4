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

#ifndef __PARSERS__
#define __PARSERS__

#include "headers.p4"
#include "defines.p4"

parser parser_impl(packet_in packet,
                  out headers_t hdr,
                  inout local_metadata_t local_metadata,
                  inout standard_metadata_t standard_metadata) {

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
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ID: parse_id;
            ETHERTYPE_GEO: parse_geo;
            ETHERTYPE_MF: parse_mf;
            ETHERTYPE_NDN: parse_ndn;
            ETHERTYPE_FLEXIP: parse_flexip;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
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
        packet.extract(hdr.ndn.ndn_prefix);
        transition parse_ndn_name;
    }

    state parse_ndn_name {
        packet.extract(hdr.ndn.name_tlv.ndn_tlv_prefix);
        local_metadata.name_tlv_length = hdr.ndn.name_tlv.ndn_tlv_prefix.length;
        transition parse_ndn_name_components;
    }

    // state parse_ndn_name_components {
    //     packet.extract(hdr.ndn.name_tlv.components.next);
    //     local_metadata.name_tlv_length = local_metadata.name_tlv_length - 2 - hdr.ndn.name_tlv.components.last.length;
    //     transition select(local_metadata.name_tlv_length) {
    //         0: parse_ndn_metainfo;
    //         default: parse_ndn_name_components;
    //     }
    // }

    state parse_ndn_name_components {
        packet.extract(hdr.ndn.name_tlv.components.next);
        transition select(hdr.ndn.name_tlv.components.last.end) {
            0: parse_ndn_name_components;
            1: parse_ndn_metainfo;
        }
    }

    state parse_ndn_metainfo {
        packet.extract(hdr.ndn.metaInfo_tlv.ndn_tlv_prefix);
        packet.extract(hdr.ndn.metaInfo_tlv.content_type_tlv);
        packet.extract(hdr.ndn.metaInfo_tlv.freshness_period_tlv);
        packet.extract(hdr.ndn.metaInfo_tlv.final_block_id_tlv);
        transition parse_ndn_content;
    }

    state parse_ndn_content {
        packet.extract(hdr.ndn.content_tlv);
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

    // FlexIP
    state parse_flexip {
        packet.extract(hdr.flexip);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }
}

control deparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ndn);
	    packet.emit(hdr.mf);
        packet.emit(hdr.id);
        packet.emit(hdr.flexip);
        packet.emit(hdr.geo);
	    packet.emit(hdr.gbc);
	    packet.emit(hdr.beacon);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
    }
}

#endif
