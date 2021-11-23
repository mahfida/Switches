
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
const int<19> THRESHOLD = 10000; // Threshold number of bytes to mark packet as part of a burst
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<3> switchID_t;
typedef bit<16> packet_count_t;


/* GPRS Tunnelling Protocol (GTP) common part for v1 and v2 */


// Option field for inner ipv4
header ipv4_outer_option_t{
	bit<1> copyFlag;
        bit<2> optClass;
        bit<5> option;
        bit<8> optionLength;
	
	//option data
	switchID_t swid; //3 bits
	packet_count_t flow_packet_count;//16 bits
	bit<10> packets_in_queue; // <10>
	bit<32> queue_timedelta; //<32>
	bit<1> hitter;// 
	bit<18> packet_length;
}

/* GRE TUNNEL */
header gre_t {
    bit<16> flag_ver;
    bit<16> protocol;

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
	bit<1> marker;	   
   }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4_outer;
    udp_t        udp_outer;
    gtp_t 	 gtp;
    gre_t	 gre;
    ipv4_t 	 ipv4_inner;
    ipv4_outer_option_t ipv4_outer_option;
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
        #transition select(hdr.ipv4_inner.ihl) {
        #    5             : accept;
        #    default       : parse_ipv4_inner_option;
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

  /* action clone_packet() {
        // Clone from ingress to egress pipeline
        clone(CloneType.I2E, 100);}*/
	
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
                else if(hdr.ethernet.srcAddr == 0x00808e8d90ab ) //0x94c6911ef360)
                        {
                         if(standard_metadata.ingress_port==0)
                                {
                                standard_metadata.egress_spec =1;
				//clone_packet();
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
				//clone_packet();
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



	/*Values of bytesRemaining need to be maintained between
        all incoming data packets. This variable is implemented using register.
        */

        register<int<19>>(1) bytesRemaining; // bytes count stored in a register
        int<19> bytes_int; // temporary bytes count in int<> format
        int<19> deqQdepth=0;

  // MATCH-ACTION TBLE FOR THE PACKET COUNT
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
    
    // ACTION FOR MARKING A PACKET, AS PART OF HEAVY HITTER
    action is_heavy_hitter(){
                bytesRemaining.read(bytes_int, 1);
                // See if the qdepth size in bytes > than threshold
                // qdepth gives only number of packets, it is therefore multiplied by MTU (1500 bytes)
		deqQdepth = (int<19>)(standard_metadata.deq_qdepth * 19w1500);
		if(deqQdepth > THRESHOLD){
                                bytes_int = (deqQdepth - (int<19>)(bit<19>)standard_metadata.packet_length);
                                meta.marker = 0;
                        }
                else{
                                if(bytes_int > 0){
                                    bytes_int = bytes_int - (int<19>)(bit<19>)standard_metadata.packet_length;
                                    meta.marker = 1;
                                }
                    }
                if(bytes_int < 0){
                                bytes_int = 0;
                }
                 bytesRemaining.write(1, bytes_int);

                }
                 


    //MATCH-ACTION TABLE FOR  SWITCH HEADER
    action add_option_header(){
		hdr.ipv4_outer_option.setValid();
                //Set UDP, GTP INVALID
                hdr.gtp.setInvalid();
                hdr.udp_outer.setInvalid();


                // Make outer ip header as a tunnel ip for GRE
                hdr.ipv4_outer.version=hdr.ipv4_inner.version;
                hdr.ipv4_outer.identification= hdr.ipv4_inner.identification;
                hdr.ipv4_outer.flags=hdr.ipv4_inner.flags;
                hdr.ipv4_outer.fragOffset=hdr.ipv4_inner.fragOffset;
                hdr.ipv4_outer.ttl=hdr.ipv4_inner.ttl;
                hdr.ipv4_outer.protocol=0x2f;


                //Change some fields
                hdr.ipv4_outer.srcAddr= 0x0ad000d6; //10.208.0.214
                hdr.ethernet.dstAddr = 0xfa163e47c489;
                hdr.ethernet.srcAddr = 0xfa163ea81795;
                hdr.ipv4_outer.dstAddr = 0x0ad00010; //10.208.0.16;

                //Inband Telemetry with IP OPTIONS...with OUTER IP
                hdr.ipv4_outer_option.setValid();
                hdr.ipv4_outer_option.copyFlag = 0;
                hdr.ipv4_outer_option.optClass = 0;
                hdr.ipv4_outer_option.option= 31;//1 byte
                hdr.ipv4_outer_option.swid = 1; //3 bits
                hdr.ipv4_outer_option.flow_packet_count = (bit<16>) meta.min_count;//2 bytes
                hdr.ipv4_outer_option.packets_in_queue = (bit<10>) standard_metadata.deq_qdepth;
                hdr.ipv4_outer_option.hitter = meta.marker; //1 bit
                hdr.ipv4_outer_option.queue_timedelta = standard_metadata.deq_timedelta;
                hdr.ipv4_outer_option.packet_length= (bit<18>)standard_metadata.packet_length;
		hdr.ipv4_outer_option.optionLength =  12; //total number of byte

                // Change Header Details Because of Adding IP Options
                hdr.ipv4_outer.ihl  = hdr.ipv4_inner.ihl;
                hdr.ipv4_inner.ihl =  hdr.ipv4_inner.ihl +3 ;//same as inner ip plus 2 (32 bits) from ip options
                hdr.ipv4_inner.totalLen =  hdr.ipv4_inner.totalLen + 12;
                hdr.ipv4_outer.totalLen  =  hdr.ipv4_inner.totalLen + 20 + 4; // inner ip len + this header + 8 bytes option +2 bytesgre


                // Have next header as GRE
                hdr.gre.setValid();
                hdr.gre.protocol = 0x0800;
                hdr.gre.flag_ver = 0;
	}


    apply {
	if(hdr.ethernet.srcAddr == 0x00808e8d90ab ){
		hdr.udp_outer.checksum = 0;
		if(hdr.ipv4_inner.isValid()){
		if(standard_metadata.instance_type==0){
				clone(CloneType.E2E, 100);
			}
		
		//handle the cloned packet... truncate payload
		if(standard_metadata.instance_type!=0){

			//COUNTING PACKETS IN A FLOW
			compute_flowid();
			compute_index();
			increment_count();
			compute_mincount(meta.count1, meta.count2, meta.count3);

			//CHECKING IF PACKET IS PART OF HEAVY HITTER
			is_heavy_hitter();

			//ADD OPTION HEADER
			add_option_header();
			hdr.udp_outer.checksum = 0;
			//truncate((bit<32>)50); //ethernet(14) + ip_outer(20) + option headers(8)+ udp_outer(8)
			}} 
	}} // end of apply
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
	   /*
	    update_checksum(
            hdr.ipv4_outer_option.isValid(),
            { hdr.ipv4_outer_option.value,
              hdr.ipv4_outer_option.optionLength,       // update checksum for IP Option header
              hdr.ipv4_outer_option.swid,
              hdr.ipv4_outer_option.packet_count},
            hdr.ipv4_outer.hdrChecksum,
            HashAlgorithm.csum16);*/


	   /*update_checksum_with_payload(hdr.udp_outer.isValid(),
		{
    		hdr.ipv4_outer.srcAddr,
    		hdr.ipv4_outer.dstAddr,
    		8w0,
    		hdr.ipv4_outer.protocol,
    		hdr.udp_outer.plength,
		hdr.udp_outer.srcPort,
		hdr.udp_outer.dstPort, 
		hdr.udp_outer.plength
		},
	    	hdr.udp_outer.checksum,
            HashAlgorithm.csum16);*/
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
                packet.emit(hdr.ethernet);
                packet.emit(hdr.ipv4_outer);//modify in the mirrored packet
                packet.emit(hdr.gre); // add this in mirrored packet
                packet.emit(hdr.udp_outer);//skip this in mirrored packet
                packet.emit(hdr.gtp);//skip this in mirrored packet
                packet.emit(hdr.ipv4_inner); //modify in the mirrored packet
                packet.emit(hdr.ipv4_outer_option);//add this in the mirrored packet    
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
