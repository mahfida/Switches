
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "../include/otherheaders.p4"

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

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
//typedef bit<32> ipv4_addr_t;
typedef bit<9> port_id_t;
typedef bit<32> switchID_t;
typedef bit<32> packet_count_t;
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
        bit<8> num_lost_packets;	   
   }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
   }

error { IPHeaderTooShort }

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
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

        state parse_ipv4 {
        packet.extract(hdr.ipv4);
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
	//ONLY ALLOW  PACKETS WITH  CERTAIN  MAC ADDRESSES
        if(hdr.ethernet.dstAddr == 0xffffffffffff)
                {
                if(hdr.ethernet.srcAddr == 0x5254002cc5f9)
                        {
                                if(standard_metadata.ingress_port==1)
                                {
                                        standard_metadata.egress_spec =0;
                       		}
                        }
                else if(hdr.ethernet.srcAddr == 0xfa163e4c8769)
                        {
                         if(standard_metadata.ingress_port==0)
                                {
                                standard_metadata.egress_spec =1;
				}
                        }
                 else {
                        drop_packet.apply();
                        }
                }

        else {
                if(hdr.ethernet.dstAddr == 0x5254002cc5f9)
                        {
                                standard_metadata.egress_spec =1-standard_metadata.ingress_port;
                        }
                else if(hdr.ethernet.dstAddr == 0xfa163e4c8769){
                                standard_metadata.egress_spec =1-standard_metadata.ingress_port;
                        }
                 else {
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
   	meta.flowid[31:0] = hdr.ipv4.srcAddr;
	meta.flowid[63:32] = hdr.ipv4.dstAddr;
	meta.flowid[71:64] = hdr.ipv4.protocol;
	}
   action compute_index(){
	hash(meta.index1, HashAlgorithm.crc16, 10w0, {meta.flowid, 10w33}, 10w1023);
	hash(meta.index2, HashAlgorithm.crc16, 10w0, {meta.flowid, 10w202}, 10w1023);
	hash(meta.index3, HashAlgorithm.crc16, 10w0, {meta.flowid, 10w541}, 10w1023);
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
		meta.min_count = cnt3;
		}

	meta.num_lost_packets = hdr.ipv4.diffserv - (bit<8>) meta.min_count;
     }

    apply {
	if(hdr.ethernet.dstAddr == 0x5254002cc5f9){
	if(hdr.ethernet.srcAddr == 0xfa163e4c8769){
		compute_flowid();
		compute_index();
		increment_count();
		compute_mincount(meta.count1, meta.count2, meta.count3);
		log_msg("flow id = {},lasthop-packets={}, currenthop-packets={}, lost packets = {}",{meta.flowid, hdr.ipv4.diffserv, meta.min_count, meta.num_lost_packets});
		}  
       
	}}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {

	apply {
	update_checksum(
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
            HashAlgorithm.csum16);
   
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
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
