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

#ifndef _HEADERS_
#define _HEADERS_

#define MAX_COMPONENTS 8

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;
const ether_type_t ETHERTYPE_GEO = 16w0x8947;
const ether_type_t ETHERTYPE_MF = 16w0x27c0;
const ether_type_t ETHERTYPE_NDN = 16w0x8624;
const ether_type_t ETHERTYPE_ID = 16w0x0812;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


typedef bit<4> geo_protocol_t;
const geo_protocol_t TYPE_geo_beacon = 1;
const geo_protocol_t TYPE_geo_gbc = 4;     
const geo_protocol_t TYPE_geo_tsb = 5; 

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    vlan_id_t vid;
    bit<16> ether_type;
}

header mpls_h {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t srcAddr;
    ipv4_addr_t dstAddr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    bit<8> next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

header icmp_h {
    bit<8> type_;
    bit<8> code;
    bit<16> hdr_checksum;
}

// Address Resolution Protocol -- RFC 6747
header arp_h {
    bit<16> hw_type;
    bit<16> proto_type;
    bit<8> hw_addr_len;
    bit<8> proto_addr_len;
    bit<16> opcode;
    // ...
}

// Segment Routing Extension (SRH) -- IETFv7
header ipv6_srh_h {
    bit<8> next_hdr;
    bit<8> hdr_ext_len;
    bit<8> routing_type;
    bit<8> seg_left;
    bit<8> last_entry;
    bit<8> flags;
    bit<16> tag;
}

// VXLAN -- RFC 7348
header vxlan_h {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

// Generic Routing Encapsulation (GRE) -- RFC 1701
header gre_h {
    bit<1> C;
    bit<1> R;
    bit<1> K;
    bit<1> S;
    bit<1> s;
    bit<3> recurse;
    bit<5> flags;
    bit<3> version;
    bit<16> proto;
}



header geo_t{
    bit<4>  version;
    bit<4>  nh_basic;
    bit<8>  reserved_basic;
    bit<8>  lt;
    bit<8>  rhl;
    bit<4> nh_common;
    bit<4> reserved_common_a;
    bit<4> ht;
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
    bit<32> geoAreaPosLat; //lat
    bit<32> geoAreaPosLon; //log
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

header id_t {
    bit<32> srcIdentity;
    bit<32> dstIdentity;
}

header mf_guid_t{
    bit<32> mf_type;
	bit<32> src_guid;
    bit<32> dest_guid;
}

header ndp_t {
    bit<32>      flags;
    ipv6_addr_t  target_ipv6_addr;
    // NDP option.
    bit<8>       type;
    bit<8>       length;
    bit<48>      target_mac_addr;
}

header ndn_tlv_prefix_t {
    bit<8> code;
    bit<8> length;
}

header ndn_prefix_t {
    bit<8> code;
    bit<8> len_code;
    bit<16> length;
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

struct header_t {
    ethernet_h ethernet;
    vlan_tag_h vlan_tag;
    ipv4_h ipv4;
    ipv6_h ipv6;
    tcp_h tcp;
    udp_h udp;
    geo_t geo;
    gbc_t gbc;
    beacon_t beacon;
    id_t id;
    mf_guid_t mf_guid;
    ndn_t ndn;
    // Add more headers here.
}

struct empty_header_t {}

struct empty_metadata_t {}

#endif /* _HEADERS_ */
