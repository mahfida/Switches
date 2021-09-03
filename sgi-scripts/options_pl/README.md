This p4 program, expects that incoming packet (that passed via switch-s1u) has
switch id and the number of packets count for its flow, within an option header,that is added by the switch-s1u below the inner ipv4 header of the GPRS tunnel.

Current program parses these fields, (and removes them from the packet header).
It uses min sketch count to store the number of packets it recieved for the flow.
And from the recieved inline information, it assess if any packet(s) is lost at the link in-between the switch-s1u and the switch-sgi.

Lastly it updates the checksum field of the ipv4 and prints the lost packets information in the log files.

