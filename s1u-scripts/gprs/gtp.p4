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




struct metadata {
    gtp_metadata_t gtp_metadata;
   }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4_outer;
    udp_t        udp_outer;
    gtp_common_t gtp_common;
    gtp_teid_t gtp_teid;
    ipv4_t ipv4_inner;
    udp_t udp_inner;
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
            ETHERTYPE_IPV4: parse_ipv4_outer;
            default: accept;
        }
    }

    state parse_ipv4_outer {
        packet.extract(hdr.ipv4_outer);
        transition select(hdr.ipv4_outer.protocol){
            IPPROTO_UDP  : parse_udp;
            default      : accept;
        }
    }

    state parse_udp_outer {
        packet.extract(hdr.udp_outer);
        transition select(hdr.udp_outer.dstPort) {
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
            default : accept;
        }
    }

    state parse_teid {
        packet.extract(hdr.gtp_teid);
        transition parse_ipv4_inner;
    }

    state parse_ipv4_inner {
        packet.extract(hdr.ipv4_inner);
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

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(port_id_t port) {
        standard_metadata.egress_port = port;
    }


   table packet_forward {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {forward; drop; }
        size = 64;
        default_action = drop;
    }

    apply {
           packet_forward.apply();
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
        packet.emit(hdr.ipv4_outer);
        packet.emit(hdr.udp_outer);
        packet.emit(hdr.gtp_common);
        packet.emit(hdr.gtp_teid);
        packet.emit(hdr.ipv4_inner);
        packet.emit(hdr.udp_inner);
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
