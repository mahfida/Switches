
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "../include/otherheaders.p4"
#include "../include/const_types.p4"

const int<19> THRESHOLD = 10000; // Threshold number of bytes to mark packet as part of a burst
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

struct metadata {
   bit<104> flowid;
   bit<16> transport_srcPort;
   bit<16> transport_dstPort;
   }
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4_outer;
    udp_t        udp_outer;
    gtp_t 	 gtp;
    ipv4_t 	 ipv4_inner;
    udp_t 	 udp_inner;
    tcp_t	 tcp_inner;
  }

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
        transition select(hdr.ipv4_inner.protocol){
	IPPROTO_UDP  : parse_udp_inner;
	IPPROTO_TCP  : parse_tcp_inner;	
	default	     : accept;
    }}

   state parse_udp_inner {
        packet.extract(hdr.udp_inner);
	meta.transport_srcPort = hdr.udp_inner.srcPort;
	meta.transport_dstPort = hdr.udp_inner.dstPort;
	transition accept;
    }

   state parse_tcp_inner {
        packet.extract(hdr.tcp_inner);
        meta.transport_srcPort = hdr.tcp_inner.srcPort;
        meta.transport_dstPort = hdr.tcp_inner.dstPort;
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
                else if(hdr.ethernet.srcAddr == 0x00808e8d90ab ) //0x94c6911ef360)
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


        /*
        Values of bytesRemaining need to be maintained between
        all incoming data packets. This variable is implemented using register.
	*/
        
	register<int<19>>(1) bytesRemaining; // bytes count stored in a register
     	int<19> bytes_int; // temporary bytes count in int<> format
        int<19> deqQdepth=0;
       
	
	action mark_packet(int<19> dq){
                 meta.flowid =  hdr.ipv4_inner.srcAddr ++ hdr.ipv4_inner.dstAddr 
                            ++ meta.transport_srcPort ++ meta.transport_dstPort
                            ++ hdr.ipv4_inner.protocol; // concatenate all required fields into one bitstring
      	
			
		log_msg("flow-id = {},ingress-ts={}, egress-ts={}, deq-depth = {}, deq-bytes={}",
			{ meta.flowid, standard_metadata.ingress_global_timestamp,standard_metadata.egress_global_timestamp, standard_metadata.deq_qdepth, dq});
		
		}


        apply {
		
		 if(hdr.ethernet.srcAddr == 0x00808e8d90ab) {
		// bytesRemaining register value is initialized to 0 from the control plane (simple_switch_CLI)
		bytesRemaining.read(bytes_int, 1);
                // See if the qdepth size in bytes > than threshold
                // qdepth gives only number of packets, it is therefore multiplied by MTU (1500 bytes)
              
		deqQdepth = (int<19>)(standard_metadata.deq_qdepth * 19w1500);
		
                        if(deqQdepth > THRESHOLD){
                                bytes_int = (deqQdepth - (int<19>)(bit<19>)standard_metadata.packet_length);
                                mark_packet(deqQdepth);
                        }
                        else{
                                if(bytes_int > 0){
                                    bytes_int = bytes_int - (int<19>)(bit<19>)standard_metadata.packet_length;
                                    mark_packet(deqQdepth);
                                }
                        }
                        if(bytes_int < 0){
                                bytes_int = 0;
                        }
                 bytesRemaining.write(1, bytes_int);
                 
       		 }
	}

       
 }

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
       apply{	/* empty */}
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
    	packet.emit(hdr.udp_inner);
	packet.emit(hdr.tcp_inner);
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

