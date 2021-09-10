
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

//HASH COUNT RELATED FIELDS
const bit<32> HASH_TABLE_SIZE = 1024;
register<bit<32>>(HASH_TABLE_SIZE) hashtable1;
register<bit<32>>(HASH_TABLE_SIZE) hashtable2;
register<bit<32>>(HASH_TABLE_SIZE) hashtable3;

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

struct metadata {
   	bit<72> flowid;

	//hash indices;
	bit<32> index1;
	bit<32> index2;
	bit<32> index3;

	//count at each index
	bit<32> count1;
	bit<32> count2;
	bit<32> count3;
	bit<32> min_count;
	   
   }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4_outer;
    udp_t        udp_outer;
    gtp_common_t gtp_common;
    gtp_teid_t   gtp_teid;
    ipv4_t 	 ipv4_inner;}

/*************************************************************************
************************* P A R S E R  ***********************************
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
            IPPROTO_UDP  : parse_udp_outer;
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

   table drop_packet{
        actions = {
            drop;
        }
     default_action = drop();
    }
    apply {

        if(hdr.ethernet.dstAddr == 0xffffffffffff)
                {
                if(hdr.ethernet.srcAddr == 0xfa163e301ed4)
                        {
                                if(standard_metadata.ingress_port==1)
                                {
                                        standard_metadata.egress_spec =0;
                                }
                        }
                else if(hdr.ethernet.srcAddr == 0x94c6911ef360)
                        {
                         if(standard_metadata.ingress_port==0)
                                {
                                standard_metadata.egress_spec =1;
                                }
                        }
                else{
                        drop_packet.apply();
                        }

                }

        else {
                if(hdr.ethernet.dstAddr == 0xfa163e301ed4)
                        {
                                standard_metadata.egress_spec =1-standard_metadata.ingress_port;
                        }
                else if(hdr.ethernet.dstAddr == 0x94c6911ef360){
                                standard_metadata.egress_spec =1-standard_metadata.ingress_port;
                        }
                else{
                        drop_packet.apply();
                        }
            }
        }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

  // MATCH-ACTIOON TBLE FOR THE PACKET COUNT
   action compute_flowid(){
   	meta.flowid[31:0] = hdr.ipv4_inner.srcAddr;
	meta.flowid[63:32] = hdr.ipv4_inner.dstAddr;
	meta.flowid[71:64] = hdr.ipv4_inner.protocol;
	}
   action compute_index(){
	hash(meta.index1, HashAlgorithm.crc16, 10w0, {meta.flowid, 10w33}, 10w1023);
	hash(meta.index2, HashAlgorithm.crc16, 10w0, {meta.flowid, 10w202}, 10w1023);
	hash(meta.index3, HashAlgorithm.crc16, 10w0, {meta.flowid, 10w514}, 10w1023);
	}
   action increment_count(){
	hashtable1.read(meta.count1, meta.index1);
	hashtable2.read(meta.count2, meta.index2);
	hashtable3.read(meta.count3, meta.index3);

	hashtable1.write(meta.index1, meta.count1 + 1);
	hashtable2.write(meta.index2, meta.count2 + 1);
	hashtable3.write(meta.index3, meta.count3 + 1);
	}
    action compute_mincount(in bit<32> cnt1, in bit<32> cnt2, in bit<32> cnt3){
     	meta.min_count = cnt1;
	if(meta.min_count > cnt2){
		meta.min_count = cnt2;
		}
	if(meta.min_count > cnt3){
		meta.min_count = cnt3;}
	}
    
    apply {
	#log_msg("ip-dst= {}, ip-src={}",{hdr.ipv4_inner.dstAddr, hdr.ipv4_inner.srcAddr});
        if(hdr.ethernet.srcAddr == 0x94c6911ef360){
	if(hdr.ipv4_inner.isValid()){
		compute_flowid();
		compute_index();
		increment_count();
		compute_mincount(meta.count1, meta.count2, meta.count3);
		hdr.ipv4_inner.diffserv = (bit<8>) meta.min_count;
		}}
	#log_msg("ip-after = {}",{hdr.ipv4_inner_option.optionLength});  
	}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {

	apply {

	 update_checksum(
            hdr.ipv4_inner.isValid(),
            { hdr.ipv4_inner.version,
              hdr.ipv4_inner.ihl,
              hdr.ipv4_inner.diffserv,
              hdr.ipv4_inner.totalLen,
              hdr.ipv4_inner.identification,
              hdr.ipv4_inner.flags,
              hdr.ipv4_inner.fragOffset,
              hdr.ipv4_inner.ttl,
              hdr.ipv4_inner.protocol,
              hdr.ipv4_inner.srcAddr,
              hdr.ipv4_inner.dstAddr },
            hdr.ipv4_inner.hdrChecksum,
            HashAlgorithm.csum16);

	update_checksum(
        hdr.ipv4_outer.isValid(),
            { hdr.ipv4_outer.version,
              hdr.ipv4_outer.ihl,
              hdr.ipv4_outer.diffserv,
              hdr.ipv4_outer.totalLen,
              hdr.ipv4_outer.identification,
              hdr.ipv4_outer.flags,
              hdr.ipv4_outer.fragOffset,
              hdr.ipv4_outer.ttl,
              hdr.ipv4_outer.protocol,
              hdr.ipv4_outer.srcAddr,
              hdr.ipv4_outer.dstAddr },
            hdr.ipv4_outer.hdrChecksum,
            HashAlgorithm.csum16);
   
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
#	packet.emit(hdr.ipv4_inner_option);
#	packet.emit(hdr.mri);
#	packet.emit(hdr.swtraces);
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
    MyComputeChecksum(),
    MyDeparser()
) main;
