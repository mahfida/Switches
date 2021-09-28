The burst_packet.p4 is a modified version of the BurstRadar.
In BurstRadar, a snapshot of the packets (marked packets) are stored in a ringbuffer (a register array), whenever the queue length in bytes exceeds a threshold value. The flowid along with ingress and egress timestamps of the packet are stored in ip option header of a clonned packet and the packet (with payload being removed) is mirrored to the egress port that is conneted to the controller (or server) for further processing. 
Details of BurstRadar can be found at the link: https://dl.acm.org/doi/10.1145/3265723.3265731
The github repository of th BurstRadar is at: https://github.com/harshgondaliya/burstradar

In burst_packet.p4, we do not clone the flowid of the marked packet to a packet and thus nothing is mirrored to the controller, rather we log the flowid, ingress and egress timestamp, queue depth in number of packets and approx. number of queued bytes when a packets becomes ppart of a burst.

Note: As soon as switch is started, set the value of "bytesRemaining" register to zero, i.e., by running "../cli.sh commands.txt"
