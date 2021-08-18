// Copyright 2018 Eotvos Lorand University, Budapest, Hungary
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "../include/otherheaders.p4"

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;
const bit<16> GTP_UDP_PORT     = 2152;
const bit<48> OWN_MAC = 0x001122334455;
//const bit<48> BCAST_MAC = 0xFFFFFFFFFFFF;
const bit<32> GW_IP = 0x0A000001; // 10.0.0.1

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<9> port_id_t;

/* GPRS Tunnelling Protocol (GTP) common part for v1 and v2 */

header gtp_common_t {
    bit<3> version; /* this should be 1 for GTPv1 and 2 for GTPv2 */
    bit<1> pFlag;   /* protocolType for GTPv1 and pFlag for GTPv2 */
    bit<1> tFlag;   /* only used by GTPv2 - teid flag */
    bit<1> eFlag;   /* only used by GTPv1 - E flag */
    bit<1> sFlag;   /* only used by GTPv1 - S flag */
    bit<1> pnFlag;  /* only used by GTPv1 - PN flag */
    bit<8> messageType;
    bit<16> messageLength;
}

header gtp_teid_t {
    bit<32> teid;
}

/* GPRS Tunnelling Protocol (GTP) v1 */

/*
This header part exists if any of the E, S, or PN flags are on.
*/

header gtpv1_optional_t {
    bit<16> sNumber;
    bit<8> pnNumber;
    bit<8> nextExtHdrType;
}

/* Extension header if E flag is on. */

header gtpv1_extension_hdr_t {
    bit<8> plength; /* length in 4-octet units */
    varbit<128> contents;
    bit<8> nextExtHdrType;
}


/* GPRS Tunnelling Protocol (GTP) v2 (also known as evolved-GTP or eGTP) */


header gtpv2_ending_t {
    bit<24> sNumber;
    bit<8> reserved;
}

/* Local metadata */

struct gtp_metadata_t {
    bit<32> teid;
    bit<8> color;
}

struct routing_metadata_t {
    bit<8> nhgrp;
}


struct metadata {
    gtp_metadata_t gtp_metadata;
    //routing_metadata_t routing_metadata;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv4_t       inner_ipv4;
    gtp_common_t gtp_common;
    gtp_teid_t gtp_teid;
    gtpv1_extension_hdr_t gtpv1_extension_hdr;
    gtpv1_optional_t gtpv1_optional;
    gtpv2_ending_t gtpv2_ending;
    udp_t udp;
    udp_t inner_udp;
}

/************************************************************************
************************ D I G E S T  ***********************************
*************************************************************************/

struct mac_learn_digest {
    bit<48> srcAddr;
    bit<8>  ingress_port;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        //meta.arp_metadata.dst_ipv4 = hdr.ipv4.dstAddr;
        transition select(hdr.ipv4.protocol){
            IPPROTO_UDP  : parse_udp;
            default      : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            GTP_UDP_PORT : parse_gtp;
            default      : accept;
        }
    }

    state parse_gtp {
        packet.extract(hdr.gtp_common);
        transition select(hdr.gtp_common.version, hdr.gtp_common.tFlag) {
            (1,0)   : parse_teid;
            (1,1) : parse_teid;
            (2,1) : parse_teid;
            (2,0) : parse_gtpv2;
            default : accept;
        }
    }

    state parse_teid {
        packet.extract(hdr.gtp_teid);
        transition accept;
	/*Following piece of code was commented and above was un-commented originally
	transition select( hdr.gtp_common.version, hdr.gtp_common.eFlag, hdr.gtp_common.sFlag, hdr.gtp_common.pnFlag ) {
            0x10 &  0x18 : parse_gtpv2; // v2 /
            0x0c & 0x1c : parse_gtpv1optional; // v1 + E /
            0x0a & 0x1a : parse_gtpv1optional; // v1 + S /
            0x09 & 0x19 : parse_gtpv1optional; // v1 + PN
            default     : parse_inner;
        }*/
    }

    state parse_gtpv2 {
        packet.extract(hdr.gtpv2_ending);
        transition accept;
    }

    state parse_gtpv1optional {
        packet.extract(hdr.gtpv1_optional);
        transition parse_inner;
    }

    state parse_inner {
        packet.extract(hdr.inner_ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    meter(256, MeterType.bytes) teid_meters;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(port_id_t port) {
        standard_metadata.egress_port = port;
        hdr.ethernet.srcAddr = OWN_MAC;
    }

   /* action bcast() {
        standard_metadata.egress_port = 100;
    }*/

   action gtp_encapsulate(bit<32> teid, bit<32> ip) {
        hdr.inner_ipv4.setValid();
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.inner_udp = hdr.udp;
        hdr.udp.setValid();
        hdr.gtp_common.setValid();
        hdr.gtp_teid.setValid();
        hdr.udp.srcPort = GTP_UDP_PORT;
        hdr.udp.dstPort = GTP_UDP_PORT;
        hdr.udp.checksum = 0;
        hdr.udp.plength = hdr.ipv4.totalLen + 8;
        hdr.gtp_teid.teid = teid;
        hdr.gtp_common.version = 1;
        hdr.gtp_common.pFlag = 1;
        hdr.gtp_common.messageType = 255;
        hdr.gtp_common.messageLength = hdr.ipv4.totalLen + 8;
        hdr.ipv4.srcAddr = GW_IP; //  This is src  IP of the GPRS tunnel
        hdr.ipv4.dstAddr = ip; // This is dst IP of the GPRS tunnel
        hdr.ipv4.protocol = IPPROTO_UDP;
        hdr.ipv4.ttl = 255;
        hdr.ipv4.totalLen = hdr.udp.plength + 28; // Total of UDP AND GPT AND OUTER IP length
        meta.gtp_metadata.teid = teid;
    }

    action gtp_decapsulate() {
        hdr.ipv4 = hdr.inner_ipv4;
        meta.gtp_metadata.teid =  hdr.gtp_teid.teid;
        hdr.udp.setInvalid();
        hdr.gtp_common.setInvalid();
        hdr.gtp_teid.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

/*
    action set_nhgrp(bit<8> nhgrp) {
        meta.routing_metadata.nhgrp = nhgrp;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }*/

    action apply_meter(bit<32> mid) {
        teid_meters.execute_meter(mid, meta.gtp_metadata.color );
    }

/*
    action pkt_send(mac_addr_t nhmac, port_id_t port) {
        hdr.ethernet.srcAddr = OWN_MAC; // simplified
        hdr.ethernet.dstAddr = nhmac;
        standard_metadata.egress_port = port;
    }

    table smac {
        key = {
            standard_metadata.ingress_port : exact;
            hdr.ethernet.srcAddr : exact;
        }
        actions = {mac_learn; NoAction;}
        size = 512;
        default_action = mac_learn;
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr : exact;
        }
        actions = {forward; bcast;}
        size = 512;
        default_action = bcast;
    }*/
    table ue_selector {
        key = {
            hdr.ipv4.dstAddr : lpm;
            hdr.udp.dstPort  : ternary; /* in most of the cases the mask is 0 */
        }
        actions = { drop; gtp_encapsulate; gtp_decapsulate;} // For encapsulate,dst outer IP address and TEID of the tunnel be defined
        size = 10000;
        default_action = drop;
    }

    table teid_rate_limiter {
        key = {
            meta.gtp_metadata.teid : exact;
        }
        actions = { apply_meter; NoAction; drop;} //  Meter ID should be defined in the table
        size = 256;
        default_action = drop;
    } 

    table m_filter {
        key = {
            meta.gtp_metadata.color : exact; // If color  of a meter is nor green then drop it
        }
        actions = { drop; NoAction; }
        size = 256;
        //const default_action = drop;
        //const entries = { ( 0 ) : NoAction();} /* GREEN */
    }


/*    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = { set_nhgrp; drop; }
        size = 256;
        default_action = drop;
    }


   table ipv4_forward {
        key = {
            meta.routing_metadata.nhgrp : exact;
        }
        actions = {pkt_send; drop; }
        size = 64;
        default_action = drop;
    }*/

    apply {
       /* smac.apply();
        dmac.apply();
        if ( (hdr.ethernet.dstAddr == OWN_MAC) || (hdr.ethernet.dstAddr == BCAST_MAC) )
        {*/
            if ( hdr.ipv4.isValid() ) {
                ue_selector.apply();
                teid_rate_limiter.apply();
                m_filter.apply();
  	   //   ipv4_lpm.apply();
           //   ipv4_forward.apply();
            }
       // }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control Ipv4ComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
/*  update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);*/
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        //packet.emit(hdr.arp);
        //packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
        //packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp_common);
        packet.emit(hdr.gtp_teid);
        packet.emit(hdr.inner_ipv4);
        //packet.emit(hdr.inner_icmp);
        packet.emit(hdr.inner_udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    Ipv4ComputeChecksum(),
    MyDeparser()
) main;
