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

#ifndef __HEADERS__
#define __HEADERS__

#include "defines.p4"

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

header flexip_t {
    bit<4>    version;
    bit<2>    srcFormat;
    bit<2>    dstFormat;
    bit<12>   srcLength;
    bit<12>   dstLength;
    bit<384>  srcAddr;
    bit<384>  dstAddr;
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

header ndn_prefix_t {
    bit<8> code;
    bit<8> len_code;
    bit<16> length;
}

header ndn_tlv_prefix_t {
    bit<8> code;
    bit<8> length;
}

header name_component_t {
    bit<8> code;
    bit<1> end;
    bit<7> length;
    // varbit
    bit<32> value;
}

struct name_tlv_t {
    ndn_tlv_prefix_t ndn_tlv_prefix;
    // 可嵌套多个component
    name_component_t[MAX_COMPONENTS] components;
}

header content_type_tlv_t {
    bit<8> code;
    bit<8> length;
    bit<16> value;
}

header freshness_period_tlv_t {
    bit<8> code;
    bit<8> length;
    bit<16> value;
}

header final_block_id_tlv_t {
    bit<8> code;
    bit<8> length;
    bit<16> value;
}

struct metaInfo_tlv_t {
    ndn_tlv_prefix_t ndn_tlv_prefix;
    // ContentType TLV
    content_type_tlv_t content_type_tlv;
    // FreshnessPeriod TLV
    freshness_period_tlv_t freshness_period_tlv;
    // FinalBlockId TLV
    final_block_id_tlv_t final_block_id_tlv;
}

header content_tlv_t {
    bit<8> code;
    bit<8> length;
    // varbit
    bit<16> value;
}

// ndn模态报文首部
struct ndn_t {
    ndn_prefix_t ndn_prefix;
    name_tlv_t name_tlv;
    metaInfo_tlv_t metaInfo_tlv;
    content_tlv_t content_tlv;
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

@controller_header("packet_in")
header packet_in_t {
    port_num_t ingress_port;
    bit<7> pad0;
}

@controller_header("packet_out")
header packet_out_t {
    port_num_t egress_port;
    bit<7> pad0;
}

struct headers_t {
    packet_out_t  packet_out;
    packet_in_t   packet_in;
    ethernet_t    ethernet;
    ipv6_t        ipv6;
    ipv4_t        ipv4;
    flexip_t      flexip;
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

struct local_metadata_t {
    l4_port_t       l4_src_port;
    l4_port_t       l4_dst_port;
    bit<8>          name_tlv_length;
    bool            is_multicast;
    next_hop_id_t   next_hop_id;
    bit<16>         selector;
    bool            compute_checksum;
}

#endif
