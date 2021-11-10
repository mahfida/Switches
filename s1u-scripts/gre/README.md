grp.p4 file adds a gre tunnel to the incoming packet from the eNodeB.
It replaces its outer IP header by changing its source and destination
IP to the IP address of the s1u-switch and the controller, updates
its length fields, adds a gre header and updates the ethernet header
MAC addresses to the MAC address of the the ens3 of both the switch-s1u and
the controller.

It also adds an "ipv4 options" header that carries INT data to the controller.

The original packet is sent on the ens4 while the modified packet is mirrored
to the controller on port 2@ens3

NOTE: use './sw gre' and '../cli commands.txt' for correct execution
