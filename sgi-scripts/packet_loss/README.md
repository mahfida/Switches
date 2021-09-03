The packet_loss.p4 expects tht the s1u-switch has added packet
count to the  diffServ field of the ipv4.
It uses min sketch count to count the number of packets, that sgi-switch
recieved from a flow and compares it with the value in the diffServ field
of the ipv4 of incoming packets, to compute the number of packets lost on
the intermediate link between the s1u and sgi p4 switches.
