
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "../include/otherheaders.p4"
#include "../include/const_types.p4"

//HASH COUNT RELATED FIELDS
const bit<32> HASH_TABLE_SIZE = 1024;
register<bit<32>>(HASH_TABLE_SIZE) hashtable1;
register<bit<32>>(HASH_TABLE_SIZE) hashtable2;
register<bit<32>>(HASH_TABLE_SIZE) hashtable3;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<16> qdepth_t;
typedef bit<16> qtime_t;
typedef bit<16> packet_count_t;


// Option field for inner ipv4
header ipv4_inner_option_t{
	bit<8> value;
        bit<8> optionLength;
	//option data
	qdepth_t qdepth;
	qtime_t qtime;
	packet_count_t packet_count;
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
	bit<16> Len;	   
   }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4_outer;
    udp_t        udp_outer;
    gtp_t	 gtp;
    ipv4_t 	 ipv4_inner;
    ipv4_inner_option_t ipv4_inner_option;
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
        packet.extract(hdr.gtp);
        transition parse_ipv4_inner;
    }

    
        state parse_ipv4_inner {
        packet.extract(hdr.ipv4_inner);
        verify(hdr.ipv4_inner.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4_inner.ihl) {
            5             : accept;
            default       : parse_ipv4_inner_option;
         }
    }

    state parse_ipv4_inner_option {
        packet.extract(hdr.ipv4_inner_option);
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
                else if(hdr.ethernet.srcAddr == 0x00808e8d90ab) //0x94c6911ef360)
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
                else if(hdr.ethernet.dstAddr == 0x00808e8d90ab){ //0x94c6911ef360){
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
	}
    
    //MATCH-ACTION TABLE FOR  SWITCH HEADER
    action add_option_header(){
	hdr.ipv4_inner_option.setValid();
	hdr.ipv4_inner_option.value=68; //1 byte
	hdr.ipv4_inner_option.qdepth = (bit <16>) standard_metadata.enq_qdepth ; //2 bytes
	hdr.ipv4_inner_option.qtime = (bit <16>) standard_metadata.deq_timedelta;
	hdr.ipv4_inner_option.packet_count = (bit <16>) meta.min_count;//2 bytes


	hdr.ipv4_inner_option.optionLength =  8;

	
	hdr.ipv4_inner.ihl = hdr.ipv4_inner.ihl + 2;
	hdr.ipv4_inner.totalLen  = hdr.ipv4_inner.totalLen + 8;// increase in bytes

	hdr.gtp.messageLength  = hdr.gtp.messageLength +8;
        hdr.udp_outer.plength = hdr.udp_outer.plength +  8;
	

	//hdr.ipv4_outer.ihl  = hdr.ipv4_outer.ihl  + 2;
	hdr.ipv4_outer.totalLen  = hdr.ipv4_outer.totalLen  + 8;// increase in bytes
	}


    apply {
	if(hdr.ethernet.srcAddr == 0x00808e8d90ab){ //0x94c6911ef360){
	if(hdr.ipv4_inner.isValid()){
		compute_flowid();
		compute_index();
		increment_count();
		compute_mincount(meta.count1, meta.count2, meta.count3);

		
		hdr.udp_outer.checksum = 0;
		add_option_header();
		}}
	log_msg("flow id = {}, qtime={}",{standard_metadata.deq_timedelta}); 
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
              hdr.ipv4_inner.dstAddr
		},
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
        packet.emit(hdr.gtp);
        packet.emit(hdr.ipv4_inner);
	packet.emit(hdr.ipv4_inner_option);
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
