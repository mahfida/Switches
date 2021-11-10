/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<48> macAddr_t;
struct metadata {
    /* empty */
}
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
struct  headers{
   ethernet_t ethernet;
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
     //   size = 1024;
        default_action = drop();
    }    
    apply {
	
        if(hdr.ethernet.dstAddr == 0xffffffffffff)
		{
		if(hdr.ethernet.srcAddr == 0xfa163e301ed4) //mac address of the SPGW-U
                	{
				if(standard_metadata.ingress_port==1)
                        	{
					standard_metadata.egress_spec =0;
				}
                	}
		else if(hdr.ethernet.srcAddr == 0x00808e8d90ab)// mac address of eNB)
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
  

    apply {
		if(hdr.ethernet.srcAddr == 0x00808e8d90ab ){
		bit <48> time_diff = (standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp);
		log_msg("qtime={}, timediff={}",{standard_metadata.deq_timedelta, time_diff});}
	
	 }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	/* empty */
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
		packet.emit(hdr.ethernet);
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
